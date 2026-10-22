"""Bounded-target raw x64 reference navigation for the original Weixin PE.

Does not decode instructions or execute/read a running target. Results require
instruction-boundary and register-flow verification before semantic use.
"""

import argparse
from bisect import bisect_right
import hashlib
import json
from pathlib import Path
import struct

from find_login_xref_candidates import LEA, runtime_functions
from inspect_weixin import PE
from review_weixin_login_logs import SHA256


def find_references(pe, targets):
    """Inspect PE bytes only; also usable with synthetic PE fixtures."""
    if not targets or len(targets) > 16:
        raise ValueError("Provide 1..16 explicit target RVAs")
    if any(not isinstance(target, int) or not 0 <= target <= 0xFFFFFFFF for target in targets):
        raise ValueError("Target RVAs must be unsigned 32-bit integers")
    if pe.machine != 0x8664:
        raise ValueError("Expected AMD64")
    data = pe.data
    entries, pdata = runtime_functions(pe)
    starts = [e["begin"] for e in entries]
    references = []

    def code_ref(offset, rva, target, kind, size):
        index = bisect_right(starts, rva) - 1
        entry = entries[index] if index >= 0 else None
        if entry and not entry["begin"] <= rva < entry["end"]:
            entry = None
        references.append({
            "kind": kind, "rva": hex(rva), "target": hex(target),
            "raw_bytes": data[offset:offset + size].hex(), "decoded": False,
            "function": {"start_rva": hex(entry["begin"]), "end_rva": hex(entry["end"])} if entry else None,
        })

    for section in pe.sections:
        start = section["raw_offset"]
        end = start + section["raw_size"]
        if section["name"] == ".text" and section["executable"]:
            for opcode, kind in [(b"\xe8", "raw-E8-call-rel32"), (b"\xe9", "raw-E9-jump-rel32")]:
                position = data.find(opcode, start, end - 4)
                while position >= 0:
                    rva = section["rva"] + position - start
                    target = rva + 5 + struct.unpack_from("<i", data, position + 1)[0]
                    if target in targets:
                        code_ref(position, rva, target, kind, 5)
                    position = data.find(opcode, position + 1, end - 4)
            for match in LEA.finditer(data, start, end):
                rva = section["rva"] + match.start() - start
                target = rva + 7 + struct.unpack_from("<i", data, match.start() + 3)[0]
                if target in targets:
                    code_ref(match.start(), rva, target, "raw-LEA-rip", 7)
        elif section["readable"] and not section["executable"]:
            for target in targets:
                needle = struct.pack("<Q", int(pe.header["image_base"], 16) + target)
                position = data.find(needle, start, end)
                while position >= 0:
                    references.append({
                        "kind": "absolute-data-pointer", "rva": hex(section["rva"] + position - start),
                        "target": hex(target), "raw_bytes": needle.hex(), "decoded": False,
                        "aligned_to_8": position % 8 == 0,
                    })
                    position = data.find(needle, position + 1, end)
    if len(references) > 1000:
        raise ValueError("Too many references: narrow the target list")
    return references, pdata


def scan(binary, targets):
    data = binary.read_bytes()
    if hashlib.sha256(data).hexdigest() != SHA256:
        raise ValueError("Expected the original Weixin 4.1.15.13 SHA-256")
    references, pdata = find_references(PE(data), targets)
    return {"original_sha256": SHA256, "binary": str(binary),
            "targets": [hex(t) for t in sorted(targets)], "pdata": pdata,
            "references": references, "target_executed": False, "live_memory_read": False,
            "limitations": ["Raw patterns, not decoded instruction boundaries.",
                            "No indirect call flow resolved. Data pointers are not code references."]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--target", action="append", type=lambda x: int(x, 0), required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.resolve() == args.binary.resolve():
        raise ValueError("Output must not overwrite the original PE")
    report = scan(args.binary, set(args.target))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"Recorded {len(report['references'])} raw navigation candidates")


if __name__ == "__main__":
    main()
