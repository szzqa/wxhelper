"""Find raw static x64 login-string references for subsequent IDA validation.

No instruction decoder is used: matching bytes may start inside another
instruction or in inline data. PE unwind ranges are compiler metadata, not a
recovered calling convention or proof of an equivalent wxhelper function.
"""

import argparse
from bisect import bisect_right
from collections import defaultdict
import hashlib
import json
import mmap
from pathlib import Path
import re
import struct

from inspect_weixin import PE, PEError


LEA = re.compile(rb"[\x48\x4c]\x8d[\x05\x0d\x15\x1d\x25\x2d\x35\x3d]....", re.DOTALL)


def runtime_functions(pe):
    rva, size = pe.directory(3)
    if not rva or not size or size % 12:
        raise PEError("Missing or unaligned x64 exception directory")
    raw = pe.rva_bytes(rva, size)
    entries = []
    for index, (begin, end, unwind) in enumerate(struct.iter_unpack("<III", raw)):
        if begin >= end:
            raise PEError(f"Invalid RUNTIME_FUNCTION entry {index}: {begin:#x}..{end:#x}")
        entries.append({"begin": begin, "end": end, "unwind": unwind,
                        "record_rva": rva + index * 12})
    original_sorted = all(a["begin"] <= b["begin"] for a, b in zip(entries, entries[1:]))
    entries.sort(key=lambda entry: entry["begin"])
    overlaps = sum(a["end"] > b["begin"] for a, b in zip(entries, entries[1:]))
    if overlaps:
        raise PEError("Overlapping runtime function ranges require a disassembler; refusing ambiguous lookup")
    return entries, {"directory_rva": hex(rva), "directory_bytes": size,
                     "entry_count": len(entries), "originally_sorted": original_sorted,
                     "overlapping_ranges": overlaps}


def find_references(pe, seeds):
    entries, metadata = runtime_functions(pe)
    starts = [entry["begin"] for entry in entries]
    targets = {int(seed["string_rva"], 16): seed for seed in seeds}
    references = []
    matched_byte_patterns = 0
    scanned_sections = []
    for section in pe.sections:
        if section["name"] != ".text" or not section["executable"]:
            continue
        raw_start, raw_end = section["raw_offset"], section["raw_offset"] + section["raw_size"]
        scanned_sections.append({"name": section["name"], "rva": hex(section["rva"]),
                                 "raw_offset": raw_start, "bytes": section["raw_size"]})
        for match in LEA.finditer(pe.data, raw_start, raw_end):
            matched_byte_patterns += 1
            offset = match.start()
            instruction_rva = section["rva"] + offset - raw_start
            displacement = struct.unpack_from("<i", pe.data, offset + 3)[0]
            target = instruction_rva + 7 + displacement
            seed = targets.get(target)
            if seed is None:
                continue
            index = bisect_right(starts, instruction_rva) - 1
            function = entries[index] if index >= 0 else None
            if function is not None and not (function["begin"] <= instruction_rva < function["end"]):
                function = None
            references.append({
                "seed_id": seed["seed_id"], "seed_text": seed["text"], "seed_priority": seed["priority"],
                "target_string_rva": hex(target), "raw_instruction_candidate_rva": hex(instruction_rva),
                "file_offset": offset, "bytes_hex": match.group().hex(" "),
                "signed_displacement": displacement,
                "decoded_by_disassembler": False,
                "runtime_function": None if function is None else {
                    "start_rva": hex(function["begin"]), "end_rva_exclusive": hex(function["end"]),
                    "unwind_info_rva": hex(function["unwind"]), "record_rva": hex(function["record_rva"]),
                },
            })
    return references, metadata, scanned_sections, matched_byte_patterns


def find_data_pointer_candidates(pe, seeds, code_references, limit=8):
    referenced = {reference["seed_id"] for reference in code_references}
    image_base = int(pe.header["image_base"], 16)
    output = []
    for seed in seeds:
        if seed["seed_id"] in referenced:
            continue
        pointer = image_base + int(seed["string_rva"], 16)
        needle = struct.pack("<Q", pointer)
        matches = []
        for section in pe.sections:
            if section["executable"] or not section["raw_size"]:
                continue
            cursor, end = section["raw_offset"], section["raw_offset"] + section["raw_size"]
            while len(matches) <= limit:
                offset = pe.data.find(needle, cursor, end)
                if offset < 0:
                    break
                matches.append({"file_offset": offset, **pe.offset_location(offset),
                                "aligned_to_8_bytes": offset % 8 == 0,
                                "bytes_hex": needle.hex(" "), "is_code_xref": False})
                cursor = offset + 8
            if len(matches) > limit:
                break
        output.append({"seed_id": seed["seed_id"], "seed_text": seed["text"],
                       "target_string_rva": seed["string_rva"],
                       "preferred_image_pointer_value": hex(pointer),
                       "more_matches_exist": len(matches) > limit, "matches": matches[:limit]})
    return output


def inspect(binary, seed_path, max_functions=30):
    seed_report = json.loads(seed_path.read_text(encoding="utf-8"))
    seeds = [seed for seed in seed_report["seeds"] if seed["priority"] <= 2]
    with binary.open("rb") as file:
        digest = hashlib.file_digest(file, "sha256").hexdigest()
        if digest != seed_report["artifact"]["sha256"]:
            raise PEError("Binary SHA-256 differs from the seed report")
        with mmap.mmap(file.fileno(), 0, access=mmap.ACCESS_READ) as data:
            pe = PE(data)
            if pe.machine != 0x8664:
                raise PEError("This raw pattern and exception-record workflow requires an x86-64 PE")
            references, metadata, sections, match_count = find_references(pe, seeds)
            grouped = defaultdict(list)
            for reference in references:
                if reference["runtime_function"]:
                    grouped[reference["runtime_function"]["start_rva"]].append(reference)
            ranked = sorted(grouped.values(), key=lambda refs: (
                min(ref["seed_priority"] for ref in refs), -len(refs),
                int(refs[0]["runtime_function"]["start_rva"], 16)))
            functions = [{**refs[0]["runtime_function"], "raw_references": refs} for refs in ranked[:max_functions]]
            return {
                "schema_version": 1, "evidence_kind": "raw_byte_reference_candidates_with_pe_unwind_ranges",
                "artifact": {"path": str(binary.resolve()), "sha256": digest, "bytes": len(data)},
                "seed_report": str(seed_path.resolve()), "seeds_considered": seeds,
                "runtime_function_metadata": metadata,
                "scan": {"sections": sections, "rex_bytes": ["48", "4c"], "opcode": "8d",
                         "modrm_predicate": "(modrm & 0xc7) == 0x05",
                         "instruction_candidate_size": 7, "raw_pattern_count": match_count,
                         "matched_string_reference_count": len(references),
                         "function_candidate_count": len(grouped), "selection_limit": max_functions},
                "selected_function_candidates": functions,
                "references_without_runtime_function": [ref for ref in references if not ref["runtime_function"]],
                "data_pointer_candidates_for_seeds_without_raw_code_reference": find_data_pointer_candidates(pe, seeds, references),
                "limitations": [
                    "This is raw byte-pattern matching, not instruction decoding. Matches can begin inside instructions or inline data.",
                    "The RUNTIME_FUNCTION ranges are read from PE exception metadata; a range can represent a fragment and does not establish a complete C++ function or ABI.",
                    "Absolute pointer matches are data candidates, not code xrefs; preferred-image values do not prove runtime pointer contents.",
                    "Negative results only cover the declared LEA pattern and exact string starts. Relative metadata, other opcodes, and indirect references are not searched.",
                    "Only static file bytes were read. No target execution, injection, process-memory reading, IDA, or Ghidra was used.",
                ],
            }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--seeds", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--max-functions", type=int, default=30)
    args = parser.parse_args()
    if not 1 <= args.max_functions <= 30:
        parser.error("--max-functions must be 1..30")
    if args.output.resolve() in (args.binary.resolve(), args.seeds.resolve()):
        parser.error("Output must not overwrite an input")
    try:
        report = inspect(args.binary, args.seeds, args.max_functions)
    except (OSError, ValueError, struct.error) as error:
        parser.exit(1, f"Inspection failed: {error}\n")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"output": str(args.output.resolve()), **report["scan"]}))


if __name__ == "__main__":
    main()
