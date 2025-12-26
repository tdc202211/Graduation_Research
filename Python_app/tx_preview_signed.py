# tx_preview_signed.py
from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from dotenv import load_dotenv
from web3 import Web3

FALLBACK_MIN_ABI = [
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

PREFERRED_ORDER = [
    "hash",
    "type",
    "nonce",
    "blockHash",
    "blockNumber",
    "transactionIndex",
    "from",
    "to",
    "value",
    "gas",
    "gasPrice",
    "maxFeePerGas",
    "maxPriorityFeePerGas",
    "input",
    "accessList",
    "chainId",
    "v",
    "r",
    "s",
]

def q(n: int | None) -> str | None:
    if n is None:
        return None
    return hex(n)

def parse_quantity(value) -> int | None:
    if value is None:
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        v = value.strip()
        if v.startswith("0x"):
            return int(v, 16)
        return int(v)
    raise TypeError(f"Unsupported quantity type: {type(value).__name__}")

def h32_from_int(x: int) -> str:
    return "0x" + x.to_bytes(32, "big").hex()

def load_abi_from_env() -> list:
    abi_path = os.getenv("ETH_ABI_PATH", "").strip()
    if not abi_path:
        return FALLBACK_MIN_ABI
    obj = json.loads(Path(abi_path).read_text(encoding="utf-8"))
    return obj["abi"] if isinstance(obj, dict) and "abi" in obj else obj

def sha256_hex_to_bytes32(h: str) -> bytes:
    s = (h or "").lower().replace("0x", "").strip()
    if len(s) != 64:
        raise ValueError(f"fileHash must be 64 hex chars. got len={len(s)}")
    return bytes.fromhex(s)

def pick_function_abi(abi: list, fn_name: str) -> dict:
    cands = [x for x in abi if x.get("type") == "function" and x.get("name") == fn_name]
    if not cands:
        raise RuntimeError(f"Function '{fn_name}' not found in ABI. Check ETH_FUNCTION_NAME / ETH_ABI_PATH.")
    return cands[0]

def build_args_from_payload(fn_abi: dict, payload: dict) -> list:
    file_hash32 = sha256_hex_to_bytes32(payload["fileHash"])
    file_id = str(payload.get("fileId") or payload.get("boxFileId") or payload.get("boxUrl") or "")
    if not file_id:
        raise KeyError("payload must include fileId (or boxFileId/boxUrl)")
    file_name = str(payload["fileName"])

    args = []
    for inp in fn_abi.get("inputs", []):
        t = inp.get("type")
        n = (inp.get("name") or "").lower()

        if t == "bytes32":
            args.append(file_hash32)
        elif t == "string":
            if "name" in n:
                args.append(file_name)
            elif "id" in n or "url" in n or "box" in n:
                args.append(file_id)
            else:
                args.append(file_id if file_id not in args else file_name)
        elif t.startswith("uint"):
            args.append(int(file_id))
        else:
            raise RuntimeError(f"Unsupported input type in ABI: {t} ({inp})")
    return args

def supports_eip1559(w3: Web3) -> bool:
    try:
        latest = w3.eth.get_block("latest")
        return latest.get("baseFeePerGas") is not None
    except Exception:
        return False

def reorder(d: dict) -> dict:
    out = {}
    for k in PREFERRED_ORDER:
        if k in d:
            out[k] = d[k]
    for k in sorted(d.keys()):
        if k not in out:
            out[k] = d[k]
    return out

def main() -> None:
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("payload", help="payload json path")
    ap.add_argument("--fn", default=None, help="override function name")
    ap.add_argument("--gas", type=int, default=None, help="override gas (no estimate)")
    ap.add_argument("--no-estimate", action="store_true", help="skip estimate_gas")
    ap.add_argument("--priority-gwei", type=float, default=1.5, help="EIP-1559 priority fee (gwei)")
    ap.add_argument("--from-presign", default=None, help="use tx_preview_presign json to keep values identical")
    args = ap.parse_args()

    load_dotenv()

    rpc_url = os.getenv("ETH_RPC_URL", "").strip()
    pk = os.getenv("ETH_PRIVATE_KEY", "").strip()
    contract_addr = os.getenv("ETH_CONTRACT_ADDRESS", "").strip()
    if not rpc_url or not pk or not contract_addr:
        raise RuntimeError("Need ETH_RPC_URL / ETH_PRIVATE_KEY / ETH_CONTRACT_ADDRESS in .env")

    fn_name = (args.fn or os.getenv("ETH_FUNCTION_NAME", "recordOrUpdate")).strip()

    payload = json.loads(Path(args.payload).read_text(encoding="utf-8"))

    w3 = Web3(Web3.HTTPProvider(rpc_url))
    if not w3.is_connected():
        raise RuntimeError(f"Failed to connect: {rpc_url}")

    acct = w3.eth.account.from_key(pk)
    abi = load_abi_from_env()
    c = w3.eth.contract(address=Web3.to_checksum_address(contract_addr), abi=abi)

    presign = None
    if args.from_presign:
        if args.from_presign == "-":
            presign = json.loads(sys.stdin.read())
        else:
            presign = json.loads(Path(args.from_presign).read_text(encoding="utf-8"))

    if presign:
        data_hex = presign.get("input") or presign.get("data")
        if not data_hex:
            raise RuntimeError("presign json must include input or data")

        nonce = parse_quantity(presign.get("nonce"))
        chain_id = parse_quantity(presign.get("chainId")) or w3.eth.chain_id
        gas = parse_quantity(presign.get("gas")) or 300_000

        tx_type = parse_quantity(presign.get("type")) or 0
        tx_for_sign = {
            "from": presign.get("from") or acct.address,
            "to": presign.get("to") or Web3.to_checksum_address(contract_addr),
            "nonce": nonce,
            "chainId": chain_id,
            "value": parse_quantity(presign.get("value")) or 0,
            "data": data_hex,
            "gas": gas,
        }

        if tx_type == 2:
            tx_for_sign["type"] = 2
            max_priority = parse_quantity(presign.get("maxPriorityFeePerGas"))
            max_fee = parse_quantity(presign.get("maxFeePerGas"))
            if max_priority is not None:
                tx_for_sign["maxPriorityFeePerGas"] = max_priority
            if max_fee is not None:
                tx_for_sign["maxFeePerGas"] = max_fee
            tx_for_sign["accessList"] = presign.get("accessList", [])
        else:
            gas_price = parse_quantity(presign.get("gasPrice"))
            if gas_price is not None:
                tx_for_sign["gasPrice"] = gas_price
    else:
        fn_abi = pick_function_abi(abi, fn_name)
        call_args = build_args_from_payload(fn_abi, payload)
        data_hex = c.encode_abi(fn_name, args=call_args)

        chain_id = w3.eth.chain_id
        nonce = w3.eth.get_transaction_count(acct.address)

        tx_for_sign = {
            "from": acct.address,
            "to": Web3.to_checksum_address(contract_addr),
            "nonce": nonce,
            "chainId": chain_id,
            "value": 0,
            "data": data_hex,
        }

        # gas
        if args.gas is not None:
            gas = args.gas
        elif args.no_estimate:
            gas = 300_000
        else:
            try:
                gas = w3.eth.estimate_gas(tx_for_sign)
            except Exception:
                gas = 300_000
        tx_for_sign["gas"] = gas

        # fee
        tx_type = 0
        if supports_eip1559(w3):
            tx_type = 2
            latest = w3.eth.get_block("latest")
            base = int(latest["baseFeePerGas"])
            max_priority = int(w3.to_wei(args.priority_gwei, "gwei"))
            max_fee = base * 2 + max_priority
            tx_for_sign["type"] = 2
            tx_for_sign["maxPriorityFeePerGas"] = max_priority
            tx_for_sign["maxFeePerGas"] = max_fee
            tx_for_sign["accessList"] = []
        else:
            tx_for_sign["gasPrice"] = int(w3.eth.gas_price)

    signed = w3.eth.account.sign_transaction(tx_for_sign, private_key=pk)

    # RPCっぽい tx オブジェクト（署名フィールド付き）
    if presign:
        rpc_tx = dict(presign)
        rpc_tx["hash"] = signed.hash.hex()
        rpc_tx["v"] = q(int(signed.v))
        rpc_tx["r"] = h32_from_int(int(signed.r))
        rpc_tx["s"] = h32_from_int(int(signed.s))
    else:
        rpc_tx = {
            "type": q(tx_type),
            "hash": signed.hash.hex(),
            "nonce": q(nonce),
            "blockHash": None,
            "blockNumber": None,
            "transactionIndex": None,
            "from": acct.address,
            "to": Web3.to_checksum_address(contract_addr),
            "value": q(0),
            "gas": q(gas),
            "input": data_hex,
            "chainId": q(chain_id),
            "v": q(int(signed.v)),
            "r": h32_from_int(int(signed.r)),
            "s": h32_from_int(int(signed.s)),
        }

        if tx_type == 2:
            rpc_tx["maxPriorityFeePerGas"] = q(int(tx_for_sign["maxPriorityFeePerGas"]))
            rpc_tx["maxFeePerGas"] = q(int(tx_for_sign["maxFeePerGas"]))
            rpc_tx["accessList"] = tx_for_sign.get("accessList", [])
        else:
            rpc_tx["gasPrice"] = q(int(tx_for_sign["gasPrice"]))

    print(json.dumps(reorder(rpc_tx), ensure_ascii=False, indent=2))

if __name__ == "__main__":
    main()
