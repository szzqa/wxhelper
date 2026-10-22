"""Generate synthetic Weixin 4 snapshot bytes. Never reads a client or account."""
import argparse
import json
from pathlib import Path
import struct


def fixture():
    module = 0x180000000
    memory = bytearray(0x9000)

    def put(address, fmt, *values):
        struct.pack_into(fmt, memory, address - 0x1000, *values)

    def text(address, value):
        raw = value.encode("utf-8")
        assert len(raw) < 16
        memory[address - 0x1000:address - 0x1000 + len(raw)] = raw
        put(address + 16, "<QQ", len(raw), 15)

    put(0x1000, "<Q", module + 0x8D804E8)
    put(0x1068, "<QQ", 0x2000, 0)
    put(0x2000, "<Q", module + 0x8DFE2F8)
    put(0x2038, "<BB", 1, 0)
    text(0x2048, "fixture_user")
    put(0x3008, "<QQ", 0x4000, 1)
    put(0x3040, "<B", 1)
    put(0x4000, "<QQ", 0x5000, 0x5000)
    put(0x5000, "<QQII", 0x4000, 0x4000, 42, 0)
    put(0x5018, "<I", 42)
    for offset in (8, 0x28, 0x48, 0x78, 0x98, 0xb8, 0xd8, 0xf8, 0x118, 0x138, 0x158, 0x178, 0x1a0):
        text(0x5018 + offset, "")
    text(0x5020, "fixture_user")
    text(0x50f0, "测试昵称")
    text(0x6018, "fixture_call")
    put(0x6038, "<QQQ", 0x6800, 0x7000, 0x7100)
    text(0x68b0, "fixture_chat")
    put(0x7008, "<II", 1, 1)
    put(0x7200, "<II", 0, 0)
    put(0x7800, "<QQQ", 0x8000, 0x82e8, 0x85d0)
    text(0x8018, "fixture_user")
    text(0x8038, "fixture_peer")
    text(0x8058, "fixture_sender")
    text(0x8180, "测试正文")
    put(0x800c, "<I", 12345)  # Raw type value, not a claimed native enum member.
    put(0x8148, "<Q", 0xfedcba9876543210)
    put(0x8150, "<Q", 0x123456789abcdef0)  # Sort sequence, not the server ID.
    put(0x8164, "<IIII", 5678, 2, 3, 4)
    put(0x8178, "<I", 5)
    return {
        "format": "weixin4_snapshot_v1",
        "synthetic": True,
        "identity": {"version": "4.1.15.13", "machine": "0x8664",
                     "sha256": "10f8e995453e2da46d4f2b5080cd6da1f13cc5147746adc119ceae38cb039de5"},
        "segments": [{"address": "0x1000", "hex": memory.hex()},
                     {"address": hex(module + 0xb912690), "hex": struct.pack("<Q", 0x1000).hex()}],
        "requests": [{"feature": feature, "address": hex(address)} for feature, address in
                     (("login", module), ("contacts", 0x3000), ("send_task", 0x6000),
                      ("send_result", 0x7200), ("receive_batch", 0x7800))],
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(fixture(), ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"Synthetic fixture written to {args.output}")
