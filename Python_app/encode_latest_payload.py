# encode_latest_payload.py
import json
import os
import sys
from pathlib import Path
from web3 import Web3

MIN_ABI = [
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
    }
]


def sha256_hex_to_bytes32(file_hash_hex: str) -> bytes:
    h = (file_hash_hex or "").lower().replace("0x", "").strip()
    if len(h) != 64:
        raise ValueError(f"fileHash must be 64 hex chars (sha256). got len={len(h)}")
    return bytes.fromhex(h)


def main() -> int:
    if len(sys.argv) > 1:
        payload_path = Path(sys.argv[1])
    else:
        payload_path = Path(__file__).resolve().parent / "payloads" / "latest.json"
    payload = json.loads(payload_path.read_text(encoding="utf-8"))

    file_hash32 = sha256_hex_to_bytes32(payload["fileHash"])
    file_id = str(payload.get("fileId") or "")
    if not file_id:
        raise KeyError("fileId is missing in payload")
    file_name = str(payload["fileName"])

    fn_name = os.getenv("ETH_FUNCTION_NAME", "recordOrUpdate")
    w3 = Web3()
    contract = w3.eth.contract(
        address="0x0000000000000000000000000000000000000000",
        abi=MIN_ABI,
    )

    args = [file_hash32, file_id, file_name]

    if hasattr(contract, "encodeABI"):
        data = contract.encodeABI(fn_name=fn_name, args=args)
    else:
        data = contract.encode_abi(fn_name, args=args)

    print("data={")
    print(data)
    print("}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
