"""Generate synthetic Weixin 4 snapshot bytes. Never reads a client or account."""
import argparse
import json
from pathlib import Path
import struct


def fixture():
    module = 0x180000000
    memory = bytearray(0xd000)

    def put(address, fmt, *values):
        struct.pack_into(fmt, memory, address - 0x1000, *values)

    def text(address, value):
        raw = value.encode("utf-8")
        assert len(raw) < 16
        memory[address - 0x1000:address - 0x1000 + len(raw)] = raw
        put(address + 16, "<QQ", len(raw), 15)

    put(0x1000, "<Q", module + 0x8D804E8)
    put(0x1068, "<QQ", 0x2000, 0)
    put(0x1330, "<I", 1)  # Kernel initialized; not an authentication assertion.
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
    put(0x7400, "<II", 0, 0)
    text(0x7408, "fixture detail")
    put(0x7428, "<QQ", 0, 0)
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
    put(0x8638, "<QQQ", 0x8700, 0x8740, 0x8760)
    text(0x8700, "fixture_user")
    text(0x8720, "fixture_peer")
    put(0x8800, "<QQQB", 0x8000, 0x82e8, 0x85d0, 1)
    # One synthetic host-auth entry in an eight-bucket native-shaped map.
    host = "fixture.test"
    host_hash = 14695981039346656037
    for byte in host.encode("utf-8"):
        host_hash = ((host_hash ^ byte) * 1099511628211) & 0xffffffffffffffff
    put(0x2510, "<QQQQQQQ", 0x9100, 1, 0x9200, 0x9280, 0x9280, 7, 8)
    put(0x9100, "<QQ", 0x9300, 0x9300)
    for bucket in range(8):
        node = 0x9300 if bucket == (host_hash & 7) else 0x9100
        put(0x9200 + bucket * 16, "<QQ", node, node)
    put(0x9300, "<QQ", 0x9100, 0x9100)
    text(0x9310, host)
    put(0x9330, "<QQ", 0x9410, 0x9400)
    put(0x9400, "<QII", module + 0x8DFEAD8, 1, 1)
    put(0x9510, "<I", 3)
    # Completed optional list of shared Contact records; not a full-address-book claim.
    put(0xa000, "<QQB", 0xa100, 1, 1)
    put(0xa100, "<QQ", 0xa200, 0xa200)
    put(0xa200, "<QQQQ", 0xa100, 0xa100, 0x5018, 0xa300)
    # Selected text factory shape: control + embedded object with self weak pair.
    put(0xb800, "<QQ", 0xb010, 0xb000)
    put(0xb000, "<QII", module + 0x8e534f8, 1, 2)
    put(0xb010, "<QQQ", module + 0x8e53588, 0xb010, 0xb000)
    put(0xb128, "<I", 1)
    text(0xb0c0, "fixture_chat")
    text(0xb768, "fixture text")
    put(0xc000, "<Q", module + 0x950a548)
    put(0xc058, "<QQQQ", 0xc210, 0xc200, 0xc410, 0xc400)
    put(0xc0bc, "<I", 4)  # Raw stage, not a cancellation enum.
    for control in (0xc200, 0xc400):
        put(control, "<QII", module + 0x8f784d8, 1, 1)
        put(control + 0x10, "<Q", module + 0x8f78568)
        put(control + 0x188, "<BBBB", 1, 0, 0, 1)
    put(0xd000, "<QQQ", module + 0x90d86e8, 0, 0x123456789abcdef0)
    put(0xd048, "<QQQ", 0xd100, 0, 0)
    put(0xd068, "<QQQ", 0x8000, 0x82e8, 0x85d0)
    return {
        "format": "weixin4_snapshot_v1",
        "synthetic": True,
        "identity": {"version": "4.1.15.13", "machine": "0x8664",
                     "sha256": "10f8e995453e2da46d4f2b5080cd6da1f13cc5147746adc119ceae38cb039de5"},
        "segments": [{"address": "0x1000", "hex": memory.hex()},
                     {"address": hex(module + 0xb912690), "hex": struct.pack("<Q", 0x1000).hex()}],
        "requests": [{"feature": feature, "address": hex(address)} for feature, address in
                     (("login", module), ("contacts", 0x3000), ("send_task", 0x6000),
                      ("send_result", 0x7200), ("receive_batch", 0x7800))] +
                    [{"feature": "auth_host", "address": hex(module), "host": host},
                     {"feature": "contact_task", "address": "0x8600"},
                     {"feature": "receive_storage", "address": "0x8800"},
                     {"feature": "send_completion", "address": "0x7400"},
                     {"feature": "contact_type_query", "address": "0xa000"},
                     {"feature": "text_draft", "address": "0xb800", "module_base": hex(module)},
                     {"feature": "send_cancel_context", "address": "0xc000", "module_base": hex(module)},
                     {"feature": "notification_dispatch", "address": "0xd000", "module_base": hex(module)}],
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(fixture(), ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"Synthetic fixture written to {args.output}")
