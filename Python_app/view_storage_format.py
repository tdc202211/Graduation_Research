# view_storage_format.py
from __future__ import annotations

import argparse
import json
import os
from math import ceil
from datetime import datetime
from pathlib import Path

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


def read_storage_slot(
    w3: Web3,
    contract: str,
    slot_int: int,
    cache: dict[int, bytes] | None = None,
) -> bytes:
    if cache is not None and slot_int in cache:
        return cache[slot_int]
    b = w3.eth.get_storage_at(contract, slot_int)
    if cache is not None:
        cache[slot_int] = b
    return b


def decode_uint256(slot_bytes: bytes) -> int:
    return int.from_bytes(slot_bytes, "big")


def decode_bool(slot_bytes: bytes) -> bool:
    # boolが単独slotの場合は末尾が 0/1 になることが多い（packedでも最下位ビットを見るのが無難）
    return (slot_bytes[-1] & 1) == 1


def decode_string_at_slot(
    w3: Web3,
    contract: str,
    slot_int: int,
    slot_bytes: bytes,
    cache: dict[int, bytes] | None = None,
) -> str:
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
        buf += read_storage_slot(w3, contract, start + i, cache=cache)

    data_bytes = buf[:length]
    try:
        return data_bytes.decode("utf-8")
    except UnicodeDecodeError:
        return data_bytes.hex()


def epoch_from_iso(value: str) -> int | None:
    try:
        dt = datetime.fromisoformat(value)
        return int(dt.timestamp())
    except Exception:
        return None


def build_offline_decoded(schema: str, payload: dict) -> dict:
    fields = [x.strip() for x in schema.split(",") if x.strip()]
    decoded = {}
    file_hash = payload.get("fileHash", "")
    if file_hash and not str(file_hash).startswith("0x"):
        file_hash = "0x" + str(file_hash)
    file_name = payload.get("fileName", "")
    uploaded_at = payload.get("uploadedAt", "")
    updated_at = epoch_from_iso(str(uploaded_at)) or 0

    for idx, t in enumerate(fields):
        if t == "bytes32":
            decoded[f"field{idx}_bytes32"] = file_hash
        elif t == "string":
            decoded[f"field{idx}_string"] = file_name
        elif t == "uint256":
            decoded[f"field{idx}_uint256"] = updated_at
        elif t == "bool":
            decoded[f"field{idx}_bool"] = True
        else:
            decoded[f"field{idx}_{t}"] = ""
    return decoded


def encode_short_string_slot(value: str) -> bytes:
    data = value.encode("utf-8")
    if len(data) > 31:
        raise ValueError("short string must be <= 31 bytes")
    # left-aligned data, length*2+1 in last byte
    padded = data + b"\x00" * (31 - len(data))
    return padded + bytes([len(data) * 2 + 1])


def encode_long_string_header(value: str) -> bytes:
    data = value.encode("utf-8")
    length = len(data)
    return to_bytes32_int(length * 2)


def build_offline_raw_slots(
    w3: Web3,
    base_slot: int,
    schema: str,
    payload: dict,
    dump_slots: int,
) -> list[dict]:
    fields = [x.strip() for x in schema.split(",") if x.strip()]
    raw_by_slot: dict[int, bytes] = {}

    file_hash = str(payload.get("fileHash", "")).lower().replace("0x", "")
    file_name = str(payload.get("fileName", ""))
    uploaded_at = payload.get("uploadedAt", "")
    updated_at = epoch_from_iso(str(uploaded_at)) or 0

    for idx, t in enumerate(fields):
        slot = base_slot + idx
        if t == "bytes32":
            raw_by_slot[slot] = bytes.fromhex(file_hash.ljust(64, "0")[:64])
        elif t == "string":
            data = file_name.encode("utf-8")
            if len(data) <= 31:
                raw_by_slot[slot] = encode_short_string_slot(file_name)
            else:
                raw_by_slot[slot] = encode_long_string_header(file_name)
                # data lives at keccak256(slot); not part of base dump normally
                start = int.from_bytes(w3.keccak(to_bytes32_int(slot)), "big")
                for i in range((len(data) + 31) // 32):
                    chunk = data[i * 32 : (i + 1) * 32]
                    raw_by_slot[start + i] = chunk.ljust(32, b"\x00")
        elif t == "uint256":
            raw_by_slot[slot] = to_bytes32_int(updated_at)
        elif t == "bool":
            raw_by_slot[slot] = to_bytes32_int(1)
        else:
            raw_by_slot[slot] = b"\x00" * 32

    raw = []
    for i in range(dump_slots):
        s = base_slot + i
        b = raw_by_slot.get(s, b"\x00" * 32)
        raw.append({"slot": hex(s), "value": "0x" + b.hex()})
    return raw


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--file-id", required=True, help="mapping key (Box fileId as string)")
    ap.add_argument("--mapping-slot", type=int, default=0, help="mapping's slot index (default: 0)")
    ap.add_argument("--schema", default="bytes32,string,uint256,bool", help="struct fields order (default: bytes32,string,uint256,bool)")
    ap.add_argument("--dump-slots", type=int, default=6, help="how many consecutive slots to dump from base (default: 6)")
    ap.add_argument("--rpc-timeout", type=int, default=None, help="RPC timeout seconds (default: ETH_RPC_TIMEOUT or 5)")
    ap.add_argument("--offline", action="store_true", help="skip RPC and build a simulated view")
    ap.add_argument("--payload", default=None, help="payload json path used in offline mode")
    args = ap.parse_args()

    load_dotenv()
    rpc_url = os.getenv("ETH_RPC_URL", "").strip()
    contract_addr = os.getenv("ETH_CONTRACT_ADDRESS", "").strip()

    if not contract_addr:
        raise SystemExit("ETH_CONTRACT_ADDRESS is not set in .env")

    if args.offline:
        w3 = Web3()
        contract = Web3.to_checksum_address(contract_addr)
        base_slot = mapping_base_slot_for_string_key(w3, args.mapping_slot, args.file_id)

        payload = {}
        if args.payload:
            payload = json.loads(Path(args.payload).read_text(encoding="utf-8"))

        raw = build_offline_raw_slots(
            w3=w3,
            base_slot=base_slot,
            schema=args.schema,
            payload=payload,
            dump_slots=args.dump_slots,
        )
        out = {
            "contract": contract,
            "rpc": rpc_url or "(offline)",
            "mapping_slot_index": args.mapping_slot,
            "key(fileId)": args.file_id,
            "base_slot": hex(base_slot),
            "schema": args.schema,
            "raw_slots": raw,
            "decoded_by_schema": build_offline_decoded(args.schema, payload),
        }

        print(json.dumps(out, ensure_ascii=False, indent=2))
        return

    if not rpc_url:
        raise SystemExit("ETH_RPC_URL is not set in .env")

    timeout_s = args.rpc_timeout if args.rpc_timeout is not None else int(os.getenv("ETH_RPC_TIMEOUT", "5"))
    w3 = Web3(Web3.HTTPProvider(rpc_url, request_kwargs={"timeout": timeout_s}))
    if not w3.is_connected():
        raise SystemExit(f"Failed to connect RPC: {rpc_url}")

    contract = Web3.to_checksum_address(contract_addr)

    base_slot = mapping_base_slot_for_string_key(w3, args.mapping_slot, args.file_id)

    # raw slot dump
    cache: dict[int, bytes] = {}
    raw = []
    for i in range(args.dump_slots):
        s = base_slot + i
        b = read_storage_slot(w3, contract, s, cache=cache)
        raw.append({"slot": hex(s), "value": "0x" + b.hex()})

    # decode by schema
    fields = [x.strip() for x in args.schema.split(",") if x.strip()]
    decoded = {}
    for idx, t in enumerate(fields):
        s = base_slot + idx
        b = read_storage_slot(w3, contract, s, cache=cache)

        if t == "bytes32":
            decoded[f"field{idx}_bytes32"] = "0x" + b.hex()
        elif t == "uint256":
            decoded[f"field{idx}_uint256"] = decode_uint256(b)
        elif t == "bool":
            decoded[f"field{idx}_bool"] = decode_bool(b)
        elif t == "string":
            decoded[f"field{idx}_string"] = decode_string_at_slot(w3, contract, s, b, cache=cache)
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
