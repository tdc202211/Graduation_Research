# eth_client.py
from __future__ import annotations

import os
import threading
from dataclasses import dataclass
from typing import Optional
from datetime import datetime, timezone, timedelta

from dotenv import load_dotenv
from web3 import Web3


_MIN_ABI = [
    {
        "inputs": [
            {"internalType": "bytes32", "name": "fileHash", "type": "bytes32"},
            {"internalType": "string", "name": "fileId", "type": "string"},
            {"internalType": "string", "name": "fileName", "type": "string"},
        ],
        "name": "recordOrUpdate",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function",
    },
    {
        "anonymous": False,
        "inputs": [
            {"indexed": True, "internalType": "bytes32", "name": "fileKey", "type": "bytes32"},
            {"indexed": False, "internalType": "string", "name": "fileId", "type": "string"},
            {"indexed": False, "internalType": "bytes32", "name": "fileHash", "type": "bytes32"},
            {"indexed": False, "internalType": "string", "name": "fileName", "type": "string"},
            {"indexed": False, "internalType": "uint256", "name": "updatedAt", "type": "uint256"},
        ],
        "name": "FileRecordedOrUpdated",
        "type": "event",
    },
    {
        "inputs": [
            {"internalType": "string", "name": "fileId", "type": "string"},
        ],
        "name": "getLatest",
        "outputs": [
            {"internalType": "bytes32", "name": "fileHash", "type": "bytes32"},
            {"internalType": "string", "name": "fileName", "type": "string"},
            {"internalType": "uint256", "name": "updatedAt", "type": "uint256"},
            {"internalType": "bool", "name": "exists", "type": "bool"},
        ],
        "stateMutability": "view",
        "type": "function",
    },
]

_TX_LOCK = threading.Lock()

@dataclass(frozen=True)
class EthConfig:
    rpc_url: str
    private_key: str
    contract_address: str


class EthereumClient:
    """
    Boxアップロード直後に、Ethereum(またはローカルHardhat)へ「ファイル情報」を書き込むクラス。

    必要な環境変数（.env でもOK）:
      - ETH_RPC_URL
      - ETH_PRIVATE_KEY
      - ETH_CONTRACT_ADDRESS
    """

    def __init__(
        self,
        rpc_url: Optional[str] = None,
        private_key: Optional[str] = None,
        contract_address: Optional[str] = None,
    ) -> None:
        load_dotenv()

        cfg = EthConfig(
            rpc_url=rpc_url or os.getenv("ETH_RPC_URL", ""),
            private_key=private_key or os.getenv("ETH_PRIVATE_KEY", ""),
            contract_address=contract_address or os.getenv("ETH_CONTRACT_ADDRESS", ""),
        )
        if not cfg.rpc_url:
            raise RuntimeError("ETH_RPC_URL is not set")
        if not cfg.private_key:
            raise RuntimeError("ETH_PRIVATE_KEY is not set")
        if not cfg.contract_address:
            raise RuntimeError("ETH_CONTRACT_ADDRESS is not set")

        self._w3 = Web3(Web3.HTTPProvider(cfg.rpc_url))
        if not self._w3.is_connected():
            raise RuntimeError(f"Failed to connect RPC: {cfg.rpc_url}")

        self._acct = self._w3.eth.account.from_key(cfg.private_key)
        self._contract = self._w3.eth.contract(
            address=Web3.to_checksum_address(cfg.contract_address),
            abi=_MIN_ABI,
        )

        self._tx_lock = _TX_LOCK

    @staticmethod
    def _looks_like_out_of_gas_error(exc: Exception) -> bool:
        msg = str(exc).lower()
        return "out of gas" in msg or "intrinsic gas too low" in msg

    @staticmethod
    def _looks_like_nonce_too_low(exc: Exception) -> bool:
        msg = str(exc).lower()
        return "nonce too low" in msg

    @staticmethod
    def _sha256_hex_to_bytes32(file_hash_hex: str) -> bytes:
        h = (file_hash_hex or "").lower().replace("0x", "").strip()
        if len(h) != 64:
            raise ValueError(f"file_hash must be 64 hex chars (sha256). got len={len(h)}")
        b = Web3.to_bytes(hexstr="0x" + h)
        if len(b) != 32:
            raise ValueError(f"file_hash bytes length must be 32. got {len(b)}")
        return b

    def store_file_record(self, file_hash: str, box_file_id: str, box_file_name: str) -> str:
        """
        Solidity: recordFile(bytes32 fileHash, string boxUrl, string fileName)

        NOTE:
          この実装では、boxUrl に Box の file_id を入れている（URLが必要なら shared link を作って渡す）。
        """
        file_hash32 = self._sha256_hex_to_bytes32(file_hash)

        with self._tx_lock:
            # build tx
            nonce = self._w3.eth.get_transaction_count(self._acct.address, "pending")
            chain_id = self._w3.eth.chain_id

            func = self._contract.functions.recordOrUpdate(file_hash32, str(box_file_id), str(box_file_name))

            tx = func.build_transaction(
                {
                    "from": self._acct.address,
                    "nonce": nonce,
                    "chainId": chain_id,
                }
            )

            # ガスは推定し、必要なら余裕を持たせる（環境変数で上書き可）
            if "gas" not in tx:
                gas_multiplier = float(os.getenv("ETH_GAS_MULTIPLIER", "3.0"))
                gas_limit_min = int(os.getenv("ETH_GAS_LIMIT_MIN", "800000"))
                gas_buffer = int(os.getenv("ETH_GAS_BUFFER", "200000"))
                try:
                    estimated = self._w3.eth.estimate_gas(tx)
                    tx["gas"] = max(int(estimated * gas_multiplier), estimated + gas_buffer, gas_limit_min)
                except Exception:
                    tx["gas"] = gas_limit_min

            # EIP-1559 料金が使える環境ならそれを使う（無理なら legacy にフォールバック）
            try:
                latest = self._w3.eth.get_block("latest")
                base_fee = latest.get("baseFeePerGas")
                if base_fee is not None:
                    # 雑に「baseFee*2 + priority」を採用（研究用の安全側設定）
                    priority = self._w3.to_wei("1.5", "gwei")
                    tx["maxPriorityFeePerGas"] = priority
                    tx["maxFeePerGas"] = int(base_fee * 2 + priority)
                else:
                    tx["gasPrice"] = self._w3.eth.gas_price
            except Exception:
                tx["gasPrice"] = self._w3.eth.gas_price

            attempts = 0
            while True:
                attempts += 1
                signed = self._acct.sign_transaction(tx)
                try:
                    tx_hash = self._w3.eth.send_raw_transaction(signed.raw_transaction)
                    break
                except Exception as ex:
                    if self._looks_like_nonce_too_low(ex) and attempts < 3:
                        tx["nonce"] = self._w3.eth.get_transaction_count(self._acct.address, "pending")
                        continue
                    if self._looks_like_out_of_gas_error(ex) and attempts < 3:
                        tx["gas"] = int(tx["gas"] * 1.5)
                        continue
                    raise

            receipt = self._w3.eth.wait_for_transaction_receipt(tx_hash)

        txh = receipt.transactionHash.hex()
        if not txh.startswith("0x"):
            txh = "0x" + txh
        return txh

    def get_latest(self, box_file_id: str) -> dict:
        file_hash, file_name, updated_at, exists = (
            self._contract.functions.getLatest(str(box_file_id)).call()
        )

        jst = timezone(timedelta(hours=9))
        return {
            "fileHash": file_hash.hex(),
            "fileName": file_name,
            "updatedAt": datetime.fromtimestamp(updated_at, tz=jst).isoformat(),
            "exists": bool(exists),
        }

    def fetch_all_records(self, from_block: int | None = None, to_block="latest") -> list[dict]:
        """
        FileRecordedOrUpdated イベントを走査して最新状態を集約する。
        同じ fileId は updatedAt が新しいものを優先。
        """
        start_block = 0 if from_block is None else from_block
        try:
            logs = self._contract.events.FileRecordedOrUpdated().get_logs(
                from_block=start_block, to_block=to_block
            )
        except Exception as ex:
            raise RuntimeError(f"failed to fetch logs: {ex}")

        jst = timezone(timedelta(hours=9))
        latest_by_id = {}
        for log in logs:
            args = log["args"]
            file_id = args.get("fileId")
            if not file_id:
                continue
            updated_at = int(args.get("updatedAt", 0))
            existing = latest_by_id.get(file_id)
            if existing and existing["updatedAt_ts"] >= updated_at:
                continue

            latest_by_id[file_id] = {
                "fileId": file_id,
                "fileName": args.get("fileName"),
                "fileHash": Web3.to_hex(args.get("fileHash")),
                "updatedAt": datetime.fromtimestamp(updated_at, tz=jst).isoformat(),
                "updatedAt_ts": updated_at,
                "blockNumber": log.get("blockNumber"),
                "txHash": log.get("transactionHash").hex(),
            }

        records = list(latest_by_id.values())
        records.sort(key=lambda x: x["updatedAt_ts"], reverse=True)
        for r in records:
            r.pop("updatedAt_ts", None)
        return records
