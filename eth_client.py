# eth_client.py
import json
from pathlib import Path
from typing import Any, Dict

from web3 import Web3
from models import FileMetadata


class EthereumClient:
    def __init__(
        self,
        rpc_url: str,
        private_key: str,
        contract_address: str,
        abi_path: str,
    ):
        self._w3 = Web3(Web3.HTTPProvider(rpc_url))
        if not self._w3.is_connected():
            raise RuntimeError("Failed to connect to Ethereum node")

        self._account = self._w3.eth.account.from_key(private_key)

        abi = json.loads(Path(abi_path).read_text(encoding="utf-8"))
        self._contract = self._w3.eth.contract(
            address=self._w3.to_checksum_address(contract_address),
            abi=abi,
        )

    def register_file(self, meta: FileMetadata) -> str:
        """
        FileMetadata から必要な情報を取り出し、コントラクトに送信する。
        戻り値はトランザクションハッシュ（hex）。
        """
        tx = self._contract.functions.registerFile(
            meta.box_file_id,
            meta.box_file_url,
            meta.file_hash,
        ).build_transaction({
            "from": self._account.address,
            "nonce": self._w3.eth.get_transaction_count(self._account.address),
            "gas": 300000,
            "maxFeePerGas": self._w3.to_wei("20", "gwei"),
            "maxPriorityFeePerGas": self._w3.to_wei("1", "gwei"),
        })

        signed = self._account.sign_transaction(tx)
        tx_hash = self._w3.eth.send_raw_transaction(signed.rawTransaction)
        return tx_hash.hex()
