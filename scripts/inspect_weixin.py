"""Read-only PE evidence collector. Never loads or executes the inspected DLL.

Usage:
  python scripts/inspect_weixin.py --binary "C:/Program Files/Tencent/Weixin/4.1.15.13/Weixin.dll" --output out/analysis/weixin-4.1.15.13/pe-layout.json

The old constants are mapped mechanically, not recovered or verified functions.
"""

import argparse
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
import mmap
from pathlib import Path
import re
import struct


FIELD_OFFSETS = {
    "kMicroMsgDB", "kChatMsgDB", "kMiscDB", "kEmotionDB", "kMediaDB",
    "kBizchatMsgDB", "kFunctionMsgDB", "kDBName", "kStorageStart", "kStorageEnd",
}
GLOBAL_RVAS = {"kGPInstance", "kMultiDBMgr", "kPublicMsgMgr", "kFavoriteStorageMgr"}
DEFAULT_TERMS = (
    "SendTextMsg", "SendMsg", "GetContact", "ChatRoom", "AccountService",
    "MicroMsg.db", "message_0.db", "sqlite3", "WeChatWin.dll", "Weixin.dll",
)
LIMITATIONS = [
    "Only on-disk bytes and PE metadata were examined. The target was not loaded, executed, or injected.",
    "Section mapping and bytes at a legacy RVA do not establish a function boundary, signature, ABI, or semantic equivalence.",
    "The source constants mix module-relative RVAs and structure-field offsets; structure offsets are not valid module-relative function addresses.",
    "String matches search file-backed non-executable sections only and are case-sensitive, bounded navigation candidates. They do not recover functions or establish runtime behavior.",
    "Without the corresponding old binary, this report cannot compare old/new function bytes or prove that any old RVA remains valid.",
]


class PEError(ValueError):
    pass


class PE:
    def __init__(self, data):
        self.data = data
        if self.read(0, 2) != b"MZ":
            raise PEError("Missing DOS MZ signature")
        self.pe_offset = self.unpack("I", 0x3C)[0]
        if self.read(self.pe_offset, 4) != b"PE\0\0":
            raise PEError("Missing PE signature")
        coff = self.unpack("HHIIIHH", self.pe_offset + 4)
        self.machine, count, timestamp, _, _, optional_size, characteristics = coff
        if count > 1024:
            raise PEError("Unreasonable section count")
        optional = self.pe_offset + 24
        self.read(optional, optional_size)
        magic = self.unpack("H", optional)[0]
        if magic == 0x20B:
            self.format, minimum, directory_at = "PE32+", 112, 112
            image_base = self.unpack("Q", optional + 24)[0]
        elif magic == 0x10B:
            self.format, minimum, directory_at = "PE32", 96, 96
            image_base = self.unpack("I", optional + 28)[0]
        else:
            raise PEError(f"Unsupported optional-header magic: {magic:#x}")
        if optional_size < minimum:
            raise PEError("Truncated optional header")
        self.header_size = self.unpack("I", optional + 60)[0]
        directory_count = self.unpack("I", optional + directory_at - 4)[0]
        if directory_count > (optional_size - directory_at) // 8:
            raise PEError("Data directories exceed optional header")
        self.directories = [self.unpack("II", optional + directory_at + 8 * i)
                            for i in range(directory_count)]
        self.header = {
            "format": self.format,
            "machine": self.machine,
            "machine_hex": hex(self.machine),
            "architecture": {0x8664: "x86-64", 0x14C: "x86", 0xAA64: "arm64"}.get(self.machine, "unknown"),
            "image_base": hex(image_base),
            "entrypoint_rva": hex(self.unpack("I", optional + 16)[0]),
            "size_of_image": self.unpack("I", optional + 56)[0],
            "size_of_headers": self.header_size,
            "section_alignment": self.unpack("I", optional + 32)[0],
            "file_alignment": self.unpack("I", optional + 36)[0],
            "coff_timestamp_raw": timestamp,
            "coff_timestamp_note": "Not interpreted as a reliable build date; reproducible PE builds can repurpose it.",
            "characteristics": hex(characteristics),
            "dll_characteristics": hex(self.unpack("H", optional + 70)[0]),
            "data_directories": [{"index": i, "address": hex(rva),
                                  "address_kind": "file_offset" if i == 4 else "rva", "size": size}
                                 for i, (rva, size) in enumerate(self.directories)],
        }
        self.sections = []
        for i in range(count):
            position = optional + optional_size + 40 * i
            raw = self.read(position, 40)
            virtual_size, rva, raw_size, raw_offset = struct.unpack_from("<IIII", raw, 8)
            flags = struct.unpack_from("<I", raw, 36)[0]
            if raw_size and raw_offset + raw_size > len(data):
                raise PEError(f"Section {i} raw data exceeds file length")
            self.sections.append({
                "name": raw[:8].split(b"\0", 1)[0].decode("ascii", errors="replace"),
                "rva": rva, "virtual_size": virtual_size,
                "raw_offset": raw_offset, "raw_size": raw_size,
                "characteristics": hex(flags),
                "executable": bool(flags & 0x20000000),
                "readable": bool(flags & 0x40000000),
                "writable": bool(flags & 0x80000000),
            })

    def read(self, offset, size):
        if offset < 0 or size < 0 or offset + size > len(self.data):
            raise PEError(f"File range out of bounds: {offset:#x}+{size:#x}")
        return self.data[offset:offset + size]

    def unpack(self, fmt, offset):
        return struct.unpack("<" + fmt, self.read(offset, struct.calcsize("<" + fmt)))

    def map_rva(self, rva):
        for section in self.sections:
            delta = rva - section["rva"]
            if 0 <= delta < max(section["virtual_size"], section["raw_size"]):
                backed = delta < section["raw_size"]
                return {
                    "section": section["name"], "executable": section["executable"],
                    "status": "file_backed" if backed else "zero_fill",
                    "file_offset": section["raw_offset"] + delta if backed else None,
                    "available_bytes": section["raw_size"] - delta if backed else 0,
                }
        if 0 <= rva < min(self.header_size, len(self.data)):
            return {"section": "<headers>", "executable": False, "status": "headers",
                    "file_offset": rva, "available_bytes": min(self.header_size, len(self.data)) - rva}
        return {"section": None, "executable": False, "status": "unmapped",
                "file_offset": None, "available_bytes": 0}

    def rva_bytes(self, rva, size):
        mapped = self.map_rva(rva)
        if mapped["file_offset"] is None or mapped["available_bytes"] < size:
            raise PEError(f"RVA has no contiguous file bytes: {rva:#x}+{size:#x}")
        return self.read(mapped["file_offset"], size)

    def cstring(self, rva):
        mapped = self.map_rva(rva)
        raw = self.rva_bytes(rva, min(mapped["available_bytes"], 4096))
        if b"\0" not in raw:
            raise PEError(f"Unterminated string at RVA {rva:#x}")
        return raw.split(b"\0", 1)[0].decode("ascii", errors="replace")

    def offset_location(self, offset):
        for section in self.sections:
            if section["raw_offset"] <= offset < section["raw_offset"] + section["raw_size"]:
                return {"section": section["name"],
                        "rva": hex(section["rva"] + offset - section["raw_offset"])}
        return {"section": "<headers>" if offset < self.header_size else None,
                "rva": hex(offset) if offset < self.header_size else None}

    def directory(self, index):
        return self.directories[index] if index < len(self.directories) else (0, 0)

    def exports(self):
        rva, size = self.directory(0)
        if not rva or not size:
            return {"dll_name": None, "entries": []}
        fields = struct.unpack("<IIHHIIIIIII", self.rva_bytes(rva, 40))
        _, _, _, _, name, base, function_count, name_count, functions, names, ordinals = fields
        if max(function_count, name_count) > 1000000:
            raise PEError("Unreasonable export table size")
        function_rvas = struct.unpack(f"<{function_count}I", self.rva_bytes(functions, function_count * 4)) if function_count else ()
        name_rvas = struct.unpack(f"<{name_count}I", self.rva_bytes(names, name_count * 4)) if name_count else ()
        name_ordinals = struct.unpack(f"<{name_count}H", self.rva_bytes(ordinals, name_count * 2)) if name_count else ()
        aliases = {}
        for name_rva, ordinal in zip(name_rvas, name_ordinals):
            if ordinal >= function_count:
                raise PEError("Export name ordinal outside address table")
            aliases.setdefault(ordinal, []).append(self.cstring(name_rva))
        entries = []
        for index, function_rva in enumerate(function_rvas):
            if not function_rva:
                continue
            entries.append({"ordinal": base + index, "names": aliases.get(index, []),
                            "rva": hex(function_rva),
                            "forwarder": self.cstring(function_rva) if rva <= function_rva < rva + size else None,
                            "mapping": self.map_rva(function_rva)})
        return {"dll_name": self.cstring(name), "address_slots": function_count,
                "named_count": name_count, "entries": entries}

    def file_versions(self):
        """Parse the fixed portion of RT_VERSION resources without Windows APIs."""
        resource_rva, resource_size = self.directory(2)
        if not resource_rva or not resource_size:
            return []
        visited = set()

        def resource_bytes(relative, size):
            if relative < 0 or relative + size > resource_size:
                raise PEError("Resource directory offset outside directory extent")
            return self.rva_bytes(resource_rva + relative, size)

        def leaves(relative, depth=0):
            if depth > 4 or relative in visited or len(visited) > 4096:
                raise PEError("Cyclic or excessive resource directories")
            visited.add(relative)
            header = resource_bytes(relative, 16)
            count = sum(struct.unpack_from("<HH", header, 12))
            records = resource_bytes(relative + 16, count * 8)
            for i in range(count):
                name, child = struct.unpack_from("<II", records, i * 8)
                if depth == 0 and name != 16:  # RT_VERSION
                    continue
                if child & 0x80000000:
                    yield from leaves(child & 0x7FFFFFFF, depth + 1)
                else:
                    yield struct.unpack("<IIII", resource_bytes(child, 16))[:2]

        versions = []
        for rva, size in leaves(0):
            raw = self.rva_bytes(rva, size)
            if len(raw) < 6:
                raise PEError("Truncated version resource")
            block_length, value_length, _ = struct.unpack_from("<HHH", raw)
            if block_length > len(raw) or block_length < 6:
                raise PEError("Invalid version resource length")
            key = "VS_VERSION_INFO\0".encode("utf-16-le")
            if raw[6:6 + len(key)] != key:
                continue
            value_at = (6 + len(key) + 3) & ~3
            if value_length < 52 or value_at + 52 > block_length:
                continue
            fixed = struct.unpack_from("<13I", raw, value_at)
            if fixed[0] != 0xFEEF04BD:
                continue
            def version(ms, ls):
                return f"{ms >> 16}.{ms & 0xFFFF}.{ls >> 16}.{ls & 0xFFFF}"
            versions.append({"resource_rva": hex(rva), "resource_bytes": size,
                             "file_version": version(fixed[2], fixed[3]),
                             "product_version": version(fixed[4], fixed[5])})
        return versions


def legacy_constants(source, pe, sample_bytes):
    text = source.read_text(encoding="utf-8-sig")
    result = []
    for match in re.finditer(r"const\s+UINT64\s+(k\w+)\s*=\s*(0x[0-9a-fA-F]+|\d+)\s*;", text):
        name, raw_value = match.groups()
        value = int(raw_value, 0)
        role = "structure_field_offset" if name in FIELD_OFFSETS else "global_rva" if name in GLOBAL_RVAS else "function_rva"
        mapped = pe.map_rva(value)
        count = min(sample_bytes, mapped["available_bytes"])
        sample = pe.read(mapped["file_offset"], count) if count else b""
        result.append({"name": name, "source_line": text.count("\n", 0, match.start()) + 1,
                       "legacy_value": hex(value), "source_role": role,
                       "interpretation": "Mechanical mapping only; not validated for this binary.",
                       "mapping_if_used_as_rva": mapped, "sample_bytes_hex": sample.hex(" "),
                       "sample_bytes_count": len(sample)})
    return result


def string_candidates(pe, terms, max_hits):
    result = []
    ranges = [(s["raw_offset"], s["raw_offset"] + s["raw_size"])
              for s in pe.sections if s["raw_size"] and not s["executable"]]
    for term in terms:
        for encoding in ("ascii", "utf-16-le"):
            needle = term.encode(encoding)
            hits = []
            for range_start, range_end in ranges:
                cursor = range_start
                while len(hits) < max_hits + 1:
                    offset = pe.data.find(needle, cursor, range_end)
                    if offset < 0:
                        break
                    cursor = offset + len(needle)
                    step = 2 if encoding == "utf-16-le" else 1
                    left, right = offset, offset + len(needle)
                    def printable(position):
                        chunk = pe.data[position:position + step]
                        return len(chunk) == step and 32 <= int.from_bytes(chunk, "little") <= 126
                    while left - step >= range_start and offset - left < 100 * step and printable(left - step):
                        left -= step
                    while right + step <= range_end and right - offset < (len(term) + 100) * step and printable(right):
                        right += step
                    hits.append({"file_offset": offset, **pe.offset_location(offset),
                                 "context": pe.read(left, right - left).decode(encoding, errors="replace")})
                if len(hits) > max_hits:
                    break
            result.append({"term": term, "encoding": encoding, "case_sensitive": True,
                           "search_scope": "file-backed non-executable sections",
                           "more_matches_exist": len(hits) > max_hits, "matches": hits[:max_hits]})
    return result


def inspect(binary, source, terms, max_hits=3, sample_bytes=16):
    with binary.open("rb") as stream:
        digest = hashlib.file_digest(stream, "sha256").hexdigest()
        with mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ) as data:
            pe = PE(data)
            constants = legacy_constants(source, pe, sample_bytes)
            return {
                "schema_version": 1,
                "evidence_kind": "offline_pe_static_observation",
                "created_at_utc": datetime.now(timezone.utc).isoformat(),
                "artifact": {"path": str(binary.resolve()), "bytes": len(data), "sha256": digest},
                "header": pe.header, "sections": pe.sections, "versions": pe.file_versions(),
                "exports": pe.exports(),
                "legacy_source": {"path": str(source.resolve()),
                                  "sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
                                  "constant_count": len(constants),
                                  "roles": dict(Counter(item["source_role"] for item in constants))},
                "legacy_constant_mappings": constants,
                "string_candidates": string_candidates(pe, terms, max_hits),
                "limitations": LIMITATIONS,
            }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--source", type=Path,
                        default=Path(__file__).resolve().parents[1] / "src/wechat_function.h")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--term", action="append", help="Case-sensitive string term; repeat to replace defaults")
    parser.add_argument("--max-hits", type=int, default=3)
    parser.add_argument("--sample-bytes", type=int, default=16)
    args = parser.parse_args()
    if not 1 <= args.max_hits <= 100 or not 1 <= args.sample_bytes <= 256:
        parser.error("--max-hits must be 1..100 and --sample-bytes must be 1..256")
    if args.output.resolve() in (args.binary.resolve(), args.source.resolve()):
        parser.error("Output must not overwrite the inspected binary or source")
    try:
        report = inspect(args.binary, args.source, args.term or DEFAULT_TERMS, args.max_hits, args.sample_bytes)
    except (OSError, ValueError, struct.error) as error:
        parser.exit(1, f"Inspection failed: {error}\n")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"output": str(args.output.resolve()), "sha256": report["artifact"]["sha256"],
                      "architecture": report["header"]["architecture"], "sections": len(report["sections"]),
                      "exports": len(report["exports"]["entries"]),
                      "legacy_constants": report["legacy_source"]["constant_count"]}))


if __name__ == "__main__":
    main()
