# view_storage_format.py
from __future__ import annotations

import argparse
import json
import os
from math import ceil

from dotenv import load_dotenv
from web3 import Web3


def to_bytes32_int(n: int) -> bytes:
    return n.to_bytes(32, "big")


def keccak(b: bytes, w3: Web3) -> bytes:
    return w3.keccak(b)


def mapping_base_slot_for_string_key(w3: Web3, mapping_slot_index: int, key_str: str) -> int:
    """
    Solidity mapping(string => V) at slot p:
      base = keccak256( keccak256(bytes(key)) ++ bytes32(p) )
    返り値は base slot の整数値。
    """
    p = to_bytes32_int(mapping_slot_index)
    key_hash = w3.keccak(text=key_str)  # keccak256(bytes(key))
    base = w3.keccak(key_hash + p)
    return int.from_bytes(base, "big")


def read_storage_slot(w3: Web3, contract: str, slot_int: int) -> bytes:
    return w3.eth.get_storage_at(contract, slot_int)


def decode_uint256(slot_bytes: bytes) -> int:
    return int.from_bytes(slot_bytes, "big")


def decode_bool(slot_bytes: bytes) -> bool:
    # boolが単独slotの場合は末尾が 0/1 になることが多い（packedでも最下位ビットを見るのが無難）
    return (slot_bytes[-1] & 1) == 1


def decode_string_at_slot(w3: Web3, contract: str, slot_int: int, slot_bytes: bytes) -> str:
    """
    Solidity string/bytes の storage 形式:
    - 短い（<=31 bytes）: 1 slot 内にデータ + (len*2 + 1)
      最下位1bitが1（odd）になる
    - 長い（>=32 bytes）: slot に len*2（even）が入り、データは keccak256(slot) から連続
    """
    v = int.from_bytes(slot_bytes, "big")
    is_short = (v & 1) == 1

    if is_short:
        length = (v & 0xFF) // 2  # 最下位1byteが len*2+1
        # データは上位側に詰められる（左詰め）
        data_bytes = slot_bytes[:length]
        try:
            return data_bytes.decode("utf-8")
        except UnicodeDecodeError:
            return data_bytes.hex()

    # long
    length = v // 2
    if length == 0:
        return ""

    start = int.from_bytes(w3.keccak(to_bytes32_int(slot_int)), "big")
    nslots = ceil(length / 32)

    buf = b""
    for i in range(nslots):
        buf += read_storage_slot(w3, contract, start + i)

    data_bytes = buf[:length]
    try:
        return data_bytes.decode("utf-8")
    except UnicodeDecodeError:
        return data_bytes.hex()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--file-id", required=True, help="mapping key (Box fileId as string)")
    ap.add_argument("--mapping-slot", type=int, default=0, help="mapping's slot index (default: 0)")
    ap.add_argument("--schema", default="bytes32,string,uint256,bool", help="struct fields order (default: bytes32,string,uint256,bool)")
    ap.add_argument("--dump-slots", type=int, default=6, help="how many consecutive slots to dump from base (default: 6)")
    args = ap.parse_args()

    load_dotenv()
    rpc_url = os.getenv("ETH_RPC_URL", "").strip()
    contract_addr = os.getenv("ETH_CONTRACT_ADDRESS", "").strip()

    if not rpc_url:
        raise SystemExit("ETH_RPC_URL is not set in .env")
    if not contract_addr:
        raise SystemExit("ETH_CONTRACT_ADDRESS is not set in .env")

    w3 = Web3(Web3.HTTPProvider(rpc_url))
    if not w3.is_connected():
        raise SystemExit(f"Failed to connect RPC: {rpc_url}")

    contract = Web3.to_checksum_address(contract_addr)

    base_slot = mapping_base_slot_for_string_key(w3, args.mapping_slot, args.file_id)

    # raw slot dump
    raw = []
    for i in range(args.dump_slots):
        s = base_slot + i
        b = read_storage_slot(w3, contract, s)
        raw.append({"slot": hex(s), "value": "0x" + b.hex()})

    # decode by schema
    fields = [x.strip() for x in args.schema.split(",") if x.strip()]
    decoded = {}
    for idx, t in enumerate(fields):
        s = base_slot + idx
        b = read_storage_slot(w3, contract, s)

        if t == "bytes32":
            decoded[f"field{idx}_bytes32"] = "0x" + b.hex()
        elif t == "uint256":
            decoded[f"field{idx}_uint256"] = decode_uint256(b)
        elif t == "bool":
            decoded[f"field{idx}_bool"] = decode_bool(b)
        elif t == "string":
            decoded[f"field{idx}_string"] = decode_string_at_slot(w3, contract, s, b)
        else:
            decoded[f"field{idx}_{t}"] = "0x" + b.hex()

    out = {
        "contract": contract,
        "rpc": rpc_url,
        "mapping_slot_index": args.mapping_slot,
        "key(fileId)": args.file_id,
        "base_slot": hex(base_slot),
        "schema": args.schema,
        "raw_slots": raw,
        "decoded_by_schema": decoded,
    }

    print(json.dumps(out, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
