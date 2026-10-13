"""Prepare a static-analysis-only PE view with the exception directory hidden.

The original file is only read. The derived file must never be executed or
injected: its header was modified, and any original Authenticode signature is
no longer valid. Original .pdata bytes remain intact; use the original PE's
RUNTIME_FUNCTION metadata for function ranges.
"""

import argparse
from datetime import datetime, timezone
import hashlib
import json
import mmap
import os
from pathlib import Path
import shutil

from inspect_weixin import PE, PEError


def sha256_file(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def section_hashes(pe):
    return [{"index": index, "name": section["name"], "rva": hex(section["rva"]),
             "raw_offset": section["raw_offset"], "raw_size": section["raw_size"],
             "sha256": hashlib.sha256(memoryview(pe.data)[
                 section["raw_offset"]:section["raw_offset"] + section["raw_size"]]).hexdigest()}
            for index, section in enumerate(pe.sections)]


def prepare(source, target, manifest):
    source = source.resolve(strict=True)
    target = target.resolve()
    manifest = manifest.resolve()
    if len({source, target, manifest}) != 3:
        raise ValueError("Source, target, and manifest must be different paths")
    if target.exists() or manifest.exists():
        raise FileExistsError("Refusing to overwrite an existing target or manifest")

    with source.open("rb") as stream:
        with mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ) as original:
            pe = PE(original)
            if pe.machine != 0x8664 or pe.format != "PE32+":
                raise PEError("Only PE32+ AMD64 inputs are supported")
            directory_rva, directory_size = pe.directory(3)
            if not directory_rva or not directory_size:
                raise PEError("Input has no populated exception directory")
            directory_mapping = pe.map_rva(directory_rva)
            if directory_mapping["available_bytes"] < directory_size:
                raise PEError("Original exception directory is not fully backed by file bytes")
            patch_offset = pe.pe_offset + 24 + 112 + 3 * 8
            before = pe.read(patch_offset, 8)
            after = b"\0" * 8
            source_size = len(original)
            source_sha256 = hashlib.sha256(original).hexdigest()
            original_sections = section_hashes(pe)

            target.parent.mkdir(parents=True, exist_ok=True)
            # Exclusive creation also closes the race after the earlier exists check.
            with target.open("xb") as derived_stream:
                stream.seek(0)
                shutil.copyfileobj(stream, derived_stream, 1024 * 1024)
                derived_stream.seek(patch_offset)
                derived_stream.write(after)
                derived_stream.flush()
                os.fsync(derived_stream.fileno())

            with target.open("rb") as derived_stream:
                with mmap.mmap(derived_stream.fileno(), 0, access=mmap.ACCESS_READ) as derived:
                    if len(derived) != source_size:
                        raise PEError("Derived size differs from original; do not use the partial view")
                    # Verify every byte except the one declared patch interval.
                    for region_start, region_end in ((0, patch_offset), (patch_offset + 8, source_size)):
                        for cursor in range(region_start, region_end, 1024 * 1024):
                            end = min(cursor + 1024 * 1024, region_end)
                            if original[cursor:end] != derived[cursor:end]:
                                raise PEError("Bytes outside the exception-directory header changed")
                    derived_pe = PE(derived)
                    if derived_pe.directory(3) != (0, 0):
                        raise PEError("Derived exception-directory entry is not zero")
                    derived_sections = section_hashes(derived_pe)
                    if original_sections != derived_sections:
                        raise PEError("Section metadata or raw bytes changed")
                    derived_sha256 = hashlib.sha256(derived).hexdigest()
            if hashlib.sha256(original).hexdigest() != source_sha256:
                raise PEError("Source changed during preparation; derived evidence is not stable")

    report = {
        "schema_version": 1,
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "purpose": "STATIC ANALYSIS ONLY: skip automatic exception-table ingestion in IDA 7",
        "must_not_execute_or_inject": True,
        "signature_status": "The header modification invalidates any original Authenticode signature. No signature re-signing or validation was performed.",
        "source": {"path": str(source), "bytes": source_size, "sha256": source_sha256},
        "derived": {"path": str(target), "bytes": source_size, "sha256": derived_sha256},
        "patch": {"description": "Clear PE32+ data-directory index 3 (Exception Directory) RVA and Size",
                  "file_offset": patch_offset, "file_offset_hex": hex(patch_offset), "bytes": 8,
                  "before_hex": before.hex(" "), "after_hex": after.hex(" "),
                  "actual_changed_byte_offsets": [patch_offset + i for i, (old, new) in enumerate(zip(before, after)) if old != new]},
        "verification": {"all_bytes_outside_patch_identical": True, "all_section_metadata_identical": True,
                         "all_complete_raw_section_hashes_identical": True,
                         "source_sha256_unchanged_after_copy": True},
        "sections": [{**old, "derived_sha256": new["sha256"], "hashes_equal": True}
                     for old, new in zip(original_sections, derived_sections)],
        "original_exception_directory": {"rva": hex(directory_rva), "bytes": directory_size,
                                         "mapping": directory_mapping,
                                         "physical_bytes_preserved": True,
                                         "range_source": "Use the original PE and original PE-layout/runtime-function evidence, not the zeroed directory in the derived view."},
        "limitations": [
            "Only the eight-byte Exception Directory header entry was patched; .pdata and every other section's complete file bytes are preserved.",
            "This view intentionally omits loader-visible exception-directory metadata and is not a repaired or runnable Weixin client.",
            "The PE checksum and certificate bytes were not changed; the existing signature does not authenticate this modified image.",
            "Preparation does not launch IDA or confirm any disassembly, function boundary, calling convention, or application behavior.",
        ],
    }
    manifest.parent.mkdir(parents=True, exist_ok=True)
    with manifest.open("x", encoding="utf-8") as stream:
        json.dump(report, stream, ensure_ascii=False, indent=2)
        stream.write("\n")
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--target", type=Path, required=True)
    parser.add_argument("--manifest", type=Path,
                        help="Defaults to <target>.manifest.json; must not already exist")
    args = parser.parse_args()
    manifest = args.manifest or Path(str(args.target) + ".manifest.json")
    try:
        report = prepare(args.source, args.target, manifest)
    except (OSError, ValueError) as error:
        parser.exit(1, f"Preparation failed: {error}\n")
    print(json.dumps({"target": report["derived"]["path"], "manifest": str(manifest.resolve()),
                      "source_sha256": report["source"]["sha256"],
                      "derived_sha256": report["derived"]["sha256"],
                      "patch_offset": report["patch"]["file_offset_hex"],
                      "verified_sections": len(report["sections"]), "must_not_execute_or_inject": True}))


if __name__ == "__main__":
    main()
