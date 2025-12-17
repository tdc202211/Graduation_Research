# eth_client.py
from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Optional

from dotenv import load_dotenv
from web3 import Web3


_MIN_ABI = [
    {
        "inputs": [
            {"internalType": "bytes32", "name": "fileHash", "type": "bytes32"},
            {"internalType": "string", "name": "boxUrl", "type": "string"},
            {"internalType": "string", "name": "fileName", "type": "string"},
        ],
        "name": "recordFile",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function",
    }
]


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

        # build tx
        nonce = self._w3.eth.get_transaction_count(self._acct.address)
        chain_id = self._w3.eth.chain_id

        func = self._contract.functions.recordFile(file_hash32, str(box_file_id), str(box_file_name))

        tx = func.build_transaction(
            {
                "from": self._acct.address,
                "nonce": nonce,
                "chainId": chain_id,
            }
        )

        # ガス・手数料はネットワークに合わせて自動推定（失敗時は例外）
        if "gas" not in tx:
            tx["gas"] = self._w3.eth.estimate_gas(tx)

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

        signed = self._acct.sign_transaction(tx)
        tx_hash = self._w3.eth.send_raw_transaction(signed.rawTransaction)
        receipt = self._w3.eth.wait_for_transaction_receipt(tx_hash)

        return receipt.transactionHash.hex()
