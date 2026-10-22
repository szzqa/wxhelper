"""Reproduce a bounded known-plaintext hypothesis for static Weixin log literals.

Reads only the original PE and existing IDA JSON. This does not execute the
binary, decrypt user data, or establish the binary's actual encryption routine.
The 60-byte XOR stream is an inference, cross-checked against independent log
literals; decoded text must be considered with disassembly and data flow.
"""

import argparse
import hashlib
import json
from pathlib import Path
import re

from inspect_weixin import PE, PEError


SHA256 = "10f8e995453e2da46d4f2b5080cd6da1f13cc5147746adc119ceae38cb039de5"
BASE = 0x180000000
DEFAULT_REPORTS = [
    "login-migration-pass1.json", "login-migration-pass2.json",
    "login-migration-pass3.json", "login-migration-pass4.json",
    "login-semantic-pass5.json",
    "contact-migration-pass1.json", "contact-migration-pass2.json",
    "contact-migration-pass3.json",
]
ANCHORS = [
    (0x8D83D50, b"kernel.cc", "Independent filename; identical plaintext exists at RVA 0x8d80598."),
    (0x8E0A658, b"login_manager.cc", "Same IDA function 0x3bbd60 also passes plaintext at RVA 0x8e055a8."),
    (0x8E0B038, b"kernel::manager::LoginManager::Quit",
     "Function-name hypothesis from file/context and Quit behavior, not an exported symbol."),
    (0x8DFEB88, b"kernel::foundation::LoginContextPrivate::LoginContextPrivate",
     "Constructor-name hypothesis; constructor 0x365bf0 writes the service vtable. Not an exported symbol."),
]


def encoded_literal(pe, rva):
    header = pe.rva_bytes(rva, 6)
    if header[:1] != b"\xa1" or header[5:6] != b"\xb1":
        return None
    if not re.fullmatch(rb"[0-9A-F]{4}", header[1:5]):
        return None
    length = int.from_bytes(bytes.fromhex(header[1:5].decode("ascii")), "little")
    if not 1 <= length <= 4096:
        return None
    raw = pe.rva_bytes(rva, 8 + 2 * length)
    if raw[-2:] != b"\xc1\0" or not re.fullmatch(rb"[0-9A-F]+", raw[6:-2]):
        return None
    return raw, bytes.fromhex(raw[6:-2].decode("ascii"))


def derive_hypothesis(pe):
    stream = b""
    evidence = []
    for rva, plaintext, basis in ANCHORS:
        item = encoded_literal(pe, rva)
        if item is None or len(item[1]) != len(plaintext):
            raise ValueError("Anchor encoding/length mismatch")
        candidate = bytes(a ^ b for a, b in zip(item[1], plaintext))
        overlap = min(len(stream), len(candidate))
        if stream[:overlap] != candidate[:overlap]:
            raise ValueError("Independent XOR hypothesis prefixes disagree")
        if len(candidate) > len(stream):
            stream = candidate
        evidence.append({"rva": hex(rva), "plaintext_hypothesis": plaintext.decode(),
                         "basis": basis, "overlap_verified_bytes": overlap,
                         "encoded_bytes_hex": item[0].hex()})
    return stream, evidence


def verify_instruction_bytes(pe, functions):
    checked = 0
    for function in functions:
        for instruction in function.get("assembly", []):
            raw = bytes.fromhex(instruction.get("bytes_hex", ""))
            if not raw:
                continue
            rva = int(instruction["rva"], 16)
            if pe.rva_bytes(rva, len(raw)) != raw:
                raise ValueError(f"IDA instruction differs from the original PE at {rva:#x}")
            checked += 1
    return checked


def review(binary, directory, reports):
    data = binary.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    if digest != SHA256:
        raise ValueError("This investigation is specific to the original 4.1.15.13 SHA-256")
    pe = PE(data)
    if pe.machine != 0x8664:
        raise ValueError("Expected AMD64")
    if pe.rva_bytes(0x8D80598, 10) != b"kernel.cc\0" or pe.rva_bytes(0x8E055A8, 17) != b"login_manager.cc\0":
        raise ValueError("Independent plaintext filename anchors are missing")
    stream, anchors = derive_hypothesis(pe)
    references = {}
    provenance = []
    for name in reports:
        path = directory / name
        report_bytes = path.read_bytes()
        report = json.loads(report_bytes.decode("utf-8-sig"))
        checked = verify_instruction_bytes(pe, report["functions"])
        provenance.append({"path": str(path), "sha256": hashlib.sha256(report_bytes).hexdigest(),
                           "instruction_byte_records_verified_against_original": checked})
        for function in report["functions"]:
            if function.get("pseudocode_truncated"):
                continue
            pseudocode = function.get("pseudocode", "")
            for match in re.finditer(r"(?:unk|a|byte|qword)_([0-9A-Fa-f]+)", pseudocode):
                rva = int(match[1], 16) - BASE
                if rva < 0:
                    continue
                try:
                    item = encoded_literal(pe, rva)
                except PEError:
                    continue
                if item is None:
                    continue
                entry = references.setdefault(rva, {"rva": hex(rva), "consumers": []})
                consumer = {"report": name, "function": function["name"],
                            "resolved_start": function["resolved_start"],
                            "resolved_end": function["resolved_end"]}
                if consumer not in entry["consumers"]:
                    entry["consumers"].append(consumer)
    if len(references) > 1000:
        raise ValueError("Refusing unbounded report expansion")
    output = []
    for rva, entry in sorted(references.items()):
        raw, cipher = encoded_literal(pe, rva)
        decoded = bytes(a ^ b for a, b in zip(cipher, stream))
        entry.update({"encoded_length": len(cipher), "encoded_bytes_hex": raw.hex(),
                      "decoded_prefix_hex": decoded.hex(),
                      "decoded_prefix": decoded.decode("utf-8", errors="backslashreplace"),
                      "complete_under_hypothesis": len(cipher) <= len(stream),
                      "confidence": "known_plaintext_xor_inference_not_decoder_execution"})
        output.append(entry)
    return {
        "kind": "bounded-static-log-known-plaintext-review",
        "binary": str(binary), "original_sha256": digest,
        "target_executed": False, "live_memory_read": False,
        "xor_stream_hex": stream.hex(), "xor_stream_bytes": len(stream),
        "anchors": anchors, "input_reports": provenance, "literals": output,
        "limitations": [
            "Actual encryption/decryption implementation was not recovered or executed.",
            "First two filename anchors have independent plaintext witnesses; longer method-name anchors are explicit hypotheses.",
            "Coherent independent literals support a shared positional XOR stream but are not standalone proof of API or state semantics.",
            "Only references in the supplied existing IDA pseudocode reports were inspected. No user messages, account records or process memory were read.",
            "Prefixes longer than 60 bytes remain incomplete. No guessed suffix is emitted.",
        ],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--report", action="append", default=[])
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = review(args.binary, args.directory, args.report or DEFAULT_REPORTS)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"Recorded {len(report['literals'])} bounded static literals; no target code executed")


if __name__ == "__main__":
    main()
