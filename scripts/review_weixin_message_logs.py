"""Review composite encoded log formats referenced by existing message IDA reports.

Static literals mix independently encoded segments with ordinary ``%_`` argument
markers. Reuse the bounded known-plaintext XOR hypothesis; never execute the
target's decoder, read live memory, or infer bytes beyond its verified prefix.
"""

import argparse
import hashlib
import json
from pathlib import Path
import re

from inspect_weixin import PE, PEError
from review_weixin_login_logs import SHA256, derive_hypothesis, verify_instruction_bytes


BASE = 0x180000000
SEGMENT = re.compile(rb"\xa1([0-9A-F]{4})\xb1([0-9A-F]+)\xc1")
DEFAULT_REPORTS = [
    "message-migration-pass1.json", "message-migration-receive-pass1.json",
    "message-migration-receive-pass2.json", "message-migration-receive-pass3.json",
    "message-migration-semantic-pass4.json", "message-migration-semantic-pass5.json",
]


def review(binary, directory, reports):
    data = binary.read_bytes()
    if hashlib.sha256(data).hexdigest() != SHA256:
        raise ValueError("This review requires the original 4.1.15.13 SHA-256")
    pe = PE(data)
    if pe.machine != 0x8664:
        raise ValueError("Expected AMD64")
    stream, anchors = derive_hypothesis(pe)
    references, inputs = {}, []
    for name in reports:
        path = directory / name
        raw = path.read_bytes()
        report = json.loads(raw.decode("utf-8-sig"))
        checked = verify_instruction_bytes(pe, report["functions"])
        inputs.append({"path": str(path), "sha256": hashlib.sha256(raw).hexdigest(),
                       "instruction_byte_records_verified_against_original": checked})
        for function in report["functions"]:
            if function.get("pseudocode_truncated"):
                continue
            for match in re.finditer(r"(?:unk|a|byte|qword)_([0-9A-Fa-f]+)",
                                     function.get("pseudocode", "")):
                rva = int(match[1], 16) - BASE
                if rva >= 0:
                    references.setdefault(rva, set()).add(function["name"])
    if len(references) > 2000:
        raise ValueError("Refusing unbounded report expansion")
    literals = []
    for rva, consumers in sorted(references.items()):
        try:
            raw = pe.rva_bytes(rva, 4096).split(b"\0", 1)[0]
        except PEError:
            continue
        if not raw.startswith(b"\xa1") or len(raw) == 4096 or not SEGMENT.search(raw):
            continue
        segments = []

        def decode(match):
            size = int.from_bytes(bytes.fromhex(match[1].decode("ascii")), "little")
            cipher = bytes.fromhex(match[2].decode("ascii"))
            if len(cipher) != size:
                raise ValueError(f"Encoded segment length mismatch at RVA {rva:#x}")
            prefix = bytes(a ^ b for a, b in zip(cipher, stream))
            complete = size <= len(stream)
            segments.append({"literal_offset": match.start(), "encoded_length": size,
                             "decoded_prefix_hex": prefix.hex(), "complete": complete})
            return prefix if complete else prefix + b"<UNRESOLVED_SUFFIX>"

        display = SEGMENT.sub(decode, raw).decode("utf-8", errors="backslashreplace")
        literals.append({"rva": hex(rva), "consumers": sorted(consumers),
                         "raw_hex": raw.hex(), "segments": segments,
                         "decoded_under_xor_hypothesis": display,
                         "complete_under_hypothesis": all(x["complete"] for x in segments)})
    return {"kind": "composite-static-log-known-plaintext-review",
            "binary": str(binary), "original_sha256": SHA256,
            "target_executed": False, "live_memory_read": False,
            "xor_stream_hex": stream.hex(), "xor_stream_bytes": len(stream),
            "anchors": anchors, "input_reports": inputs, "literals": literals,
            "limitations": [
                "Known-plaintext XOR inference, not target decoder execution.",
                "Only literal references in the supplied existing message pseudocode were inspected.",
                "UNRESOLVED_SUFFIX is display metadata, never a decoded suffix.",
                "Log labels require independent argument data flow to establish object-field semantics.",
            ]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--directory", required=True, type=Path)
    parser.add_argument("--report", action="append", default=[])
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    reports = args.report or DEFAULT_REPORTS
    inputs = [args.binary] + [args.directory / name for name in reports]
    if args.output.resolve() in {path.resolve() for path in inputs}:
        parser.error("Output must not overwrite the original binary or an input report")
    report = review(args.binary, args.directory, reports)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"Recorded {len(report['literals'])} composite static literals; no target code executed")


if __name__ == "__main__":
    main()
