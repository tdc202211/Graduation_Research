# encode_data.py
import json
import sys
from pathlib import Path
from web3 import Web3

MIN_ABI = [
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

def sha256_hex_to_bytes32(file_hash_hex: str) -> bytes:
    h = (file_hash_hex or "").lower().replace("0x", "").strip()
    if len(h) != 64:
        raise ValueError(f"fileHash must be 64 hex chars (sha256). got len={len(h)}")
    return bytes.fromhex(h)  # 32 bytes

def main() -> int:
    if len(sys.argv) < 2:
        print("Usage: python encode_data.py <payload_json_path>", file=sys.stderr)
        return 2

    payload_path = Path(sys.argv[1])
    payload = json.loads(payload_path.read_text(encoding="utf-8"))

    file_hash32 = sha256_hex_to_bytes32(payload["fileHash"])

    # コントラクト側が boxUrl(string) を受ける想定なので、とりあえず fileId をそのまま入れる
    box_url = str(payload.get("fileId") or payload.get("boxFileId") or payload.get("boxUrl") or "")
    if not box_url:
        raise KeyError("fileId (or boxFileId/boxUrl) is missing in payload")

    file_name = str(payload["fileName"])

    w3 = Web3()  # provider不要（エンコードだけ）
    contract = w3.eth.contract(
        address="0x0000000000000000000000000000000000000000",
        abi=MIN_ABI
    )

    args = [file_hash32, box_url, file_name]

    # web3.py v5系: encodeABI / v6+系: encode_abi
    if hasattr(contract, "encodeABI"):
        data = contract.encodeABI(fn_name="recordFile", args=args)
    else:
        data = contract.encode_abi("recordFile", args=args)

    print(data)
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
