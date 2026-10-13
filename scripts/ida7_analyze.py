"""Bounded, static IDAPython job runner for the user-supplied IDA 7.0.

Run inside IDA with -A -a -S<this file>. WXHELPER_IDA_JOB names a JSON job.
Only an owned analysis database is written; the inspected program is not run.
Output is direct IDA evidence, not an REA Evidence envelope.
Python 2.7 syntax is intentional for this installed IDAPython runtime.
"""
from __future__ import print_function

import datetime
import binascii
import codecs
import hashlib
import json
import os
import sys
import traceback

import idaapi
import ida_auto
import ida_bytes
import ida_funcs
import ida_hexrays
import ida_loader
import ida_pro
import ida_ua
import idautils
import idc


def hx(value):
    return format(value, "#x")


def number(value):
    return int(value, 0) if isinstance(value, basestring) else int(value)


def write_json(path, value):
    with open(path, "wb") as stream:
        stream.write(json.dumps(value, indent=2, sort_keys=True))


def read_json(path):
    # Windows PowerShell 5 writes a UTF-8 BOM by default.
    with codecs.open(path, "r", "utf-8-sig") as stream:
        return json.load(stream)


def digest_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def inspect_function(request, base, max_chars):
    start = base + number(request["start_rva"])
    end = base + number(request["end_rva"])
    if end <= start or end - start > 0x40000:
        raise ValueError("Function range must be positive and at most 256 KiB")
    item = {"requested_start": hx(start), "requested_end": hx(end),
            "request": request}
    existing = ida_funcs.get_func(start)
    ida_auto.enable_auto(True)
    if not existing:
        # Fresh imports with -a have bytes but no instruction at the entry yet.
        item["entry_instruction_size"] = ida_ua.create_insn(start)
        item["function_created"] = bool(ida_funcs.add_func(start, end))
    # Analyze only this declared range. Other queued work is not waited for.
    item["range_analysis_result"] = ida_auto.plan_and_wait(start, end, False)
    ida_auto.enable_auto(False)
    func = ida_funcs.get_func(start)
    if not func:
        item["error"] = "IDA did not establish a function at the requested address"
        return item
    item["resolved_start"] = hx(func.start_ea)
    item["resolved_end"] = hx(func.end_ea)
    item["name"] = ida_funcs.get_func_name(func.start_ea)
    item["assembly"] = []
    item["strings"] = []
    item["calls"] = []
    seen_data = set()
    for ea in idautils.Heads(func.start_ea, func.end_ea):
        if len(item["assembly"]) >= 4096:
            item["assembly_truncated"] = True
            break
        if not ida_bytes.is_code(ida_bytes.get_full_flags(ea)):
            continue
        line = idc.generate_disasm_line(ea, 0)
        instruction_bytes = ida_bytes.get_bytes(ea, ida_bytes.get_item_size(ea))
        item["assembly"].append({
            "ea": hx(ea), "rva": hx(ea - base), "text": line,
            "bytes_hex": binascii.hexlify(instruction_bytes) if instruction_bytes else None,
            "data_refs": [hx(x) for x in idautils.DataRefsFrom(ea)]
        })
        if idc.print_insn_mnem(ea).lower() == "call":
            item["calls"].append({"ea": hx(ea), "operand": idc.print_operand(ea, 0),
                                  "code_refs": [hx(x) for x in idautils.CodeRefsFrom(ea, False)]})
        for target in idautils.DataRefsFrom(ea):
            if target in seen_data:
                continue
            seen_data.add(target)
            raw = ida_bytes.get_bytes(target, 512)
            # IDA 7's size_t wrapper rejects -1. Read bounded ASCII candidates
            # instead of interpreting arbitrary referenced objects as strings.
            if raw and b"\0" in raw:
                data = raw.split(b"\0", 1)[0]
                if len(data) >= 4 and all(32 <= ord(c) < 127 for c in data):
                    item["strings"].append({"ea": hx(target), "text": data,
                                            "kind": "ascii_string_candidate"})
    if ida_hexrays.init_hexrays_plugin():
        try:
            recovered = ida_hexrays.decompile(func.start_ea)
            if recovered is None:
                raise RuntimeError("Hex-Rays returned no pseudocode")
            pseudocode = str(recovered)
            item["pseudocode"] = pseudocode[:max_chars]
            item["pseudocode_truncated"] = len(pseudocode) > max_chars
        except Exception:
            item["decompile_error"] = traceback.format_exc()
    else:
        item["decompile_error"] = "Hex-Rays is unavailable; only assembly was recovered"
    return item


try:
    job = read_json(os.environ["WXHELPER_IDA_JOB"])
    output = job["output"]
except Exception:
    traceback.print_exc()
    ida_pro.qexit(1)
result = {
    "kind": "direct_idapython_static_analysis",
    "target_executed": False,
    "started_at_utc": datetime.datetime.utcnow().isoformat() + "Z",
    "limitations": [
        "Analysis is limited to the imported image and explicitly selected ranges.",
        "Strings and data references are navigation candidates, not validated APIs.",
        "Decompiler output is inferred pseudocode, not original source or runtime evidence.",
        "String summaries contain bounded ASCII NUL-terminated candidates only.",
        "Caller-supplied PE runtime-function ranges are not proof of semantic function identity."
    ],
    "functions": []
}
exit_code = 1
try:
    idaapi.set_script_timeout(0)
    ida_auto.enable_auto(False)
    path = idc.get_input_file_path()
    result["input_path"] = path
    result["sha256"] = digest_file(path)
    if result["sha256"] != job["expected_sha256"]:
        raise ValueError("Input hash does not match the selected artifact")
    if job.get("provenance_manifest"):
        manifest_path = job["provenance_manifest"]
        manifest = read_json(manifest_path)
        if manifest["derived"]["sha256"] != result["sha256"]:
            raise ValueError("Derived input hash does not match its provenance manifest")
        if digest_file(manifest["source"]["path"]) != manifest["source"]["sha256"]:
            raise ValueError("Original input changed since the analysis view was prepared")
        result["provenance_manifest"] = manifest_path
        result["provenance_manifest_sha256"] = digest_file(manifest_path)
        result["original_source"] = manifest["source"]
        result["limitations"].append(
            "Input is a static analysis derivative; consult its manifest for omitted loader metadata.")
    result["ida_version"] = idaapi.get_kernel_version()
    result["python_version"] = sys.version
    result["image_base"] = hx(idaapi.get_imagebase())
    result["database"] = idc.get_idb_path()
    result["initial_function_count"] = ida_funcs.get_func_qty()
    result["stage"] = "imported"
    write_json(output, result)
    ida_loader.load_plugin("hexx64")
    result["hexrays_available"] = bool(ida_hexrays.init_hexrays_plugin())
    if result["hexrays_available"]:
        result["hexrays_version"] = ida_hexrays.get_hexrays_version()
    functions = job.get("functions", [])
    if len(functions) > 30:
        raise ValueError("Select at most 30 functions per job")
    for request in functions:
        result["stage"] = "analyzing " + str(request["start_rva"])
        write_json(output, result)
        try:
            item = inspect_function(request, idaapi.get_imagebase(),
                                    min(int(job.get("max_pseudocode_chars", 50000)), 100000))
        except Exception:
            ida_auto.enable_auto(False)
            item = {"request": request, "error": traceback.format_exc()}
        result["functions"].append(item)
        write_json(output, result)
    result["auto_analysis_complete"] = bool(ida_auto.auto_is_ok())
    result["final_function_count"] = ida_funcs.get_func_qty()
    result["database_saved"] = bool(ida_loader.save_database(idc.get_idb_path(), 0))
    if not result["database_saved"]:
        raise RuntimeError("IDA failed to save the analysis database")
    result["function_error_count"] = sum(
        bool(item.get("error") or item.get("decompile_error")) for item in result["functions"])
    result["pseudocode_truncated_count"] = sum(
        bool(item.get("pseudocode_truncated")) for item in result["functions"])
    result["stage"] = "complete_with_errors" if result["function_error_count"] else "complete"
    exit_code = 1 if result["function_error_count"] else 0
except Exception:
    result["error"] = traceback.format_exc()
    result["stage"] = "failed"
finally:
    result["finished_at_utc"] = datetime.datetime.utcnow().isoformat() + "Z"
    write_json(output, result)
ida_pro.qexit(exit_code)
