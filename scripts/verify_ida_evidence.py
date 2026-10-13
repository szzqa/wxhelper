"""Verify retained IDA instruction bytes against the original on-disk PE.

This checks provenance only, never executes the image or verifies business ABI.
"""
import argparse
import hashlib
import json
from pathlib import Path

from inspect_weixin import PE


def verify(binary, results):
    raw = binary.read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    pe = PE(raw)
    report = {"kind": "original_pe_instruction_verification",
              "source_sha256": digest, "target_executed": False,
              "runtime_compatibility_verified": False, "results": []}
    for path in results:
        retained = path.read_bytes()
        data = json.loads(retained.decode("utf-8-sig"))
        identity = data.get("original_source", {}).get("sha256", data.get("sha256"))
        if identity != digest or data.get("kind") != "direct_idapython_static_analysis":
            raise ValueError(f"Wrong source identity or evidence type: {path.name}")
        if data.get("target_executed") is not False or data.get("stage") != "complete":
            raise ValueError(f"Incomplete/nonstatic analysis: {path.name}")
        if not data.get("database_saved") or data.get("function_error_count") != 0:
            raise ValueError(f"Unsuccessful analysis: {path.name}")
        functions = []
        for function in data["functions"]:
            instructions = function.get("assembly", [])
            if not instructions:
                raise ValueError(f"Missing instructions: {path.name}")
            for instruction in instructions:
                rva = int(instruction["rva"], 16)
                code = bytes.fromhex(instruction["bytes_hex"])
                if not code or pe.rva_bytes(rva, len(code)) != code:
                    raise ValueError(f"Instruction mismatch: {path.name} at {rva:#x}")
            functions.append({"start_rva": function["request"]["start_rva"],
                              "end_rva": function["request"]["end_rva"],
                              "instructions_matched": len(instructions),
                              "pseudocode_truncated": function.get("pseudocode_truncated", False)})
        report["results"].append({"file": path.name,
                                  "sha256": hashlib.sha256(retained).hexdigest(),
                                  "functions": functions})
    report["function_count"] = sum(len(r["functions"]) for r in report["results"])
    report["instruction_count"] = sum(f["instructions_matched"] for r in report["results"] for f in r["functions"])
    report["limitations"] = ["Byte identity does not prove inferred types, field names, calling conventions, or runtime behavior.",
                              "Individual functions were analyzed with global automatic analysis disabled."]
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--results", required=True, nargs="+", type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    report = verify(args.binary, args.results)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"Verified {report['function_count']} function results / {report['instruction_count']} instructions; runtime compatibility remains unverified.")


if __name__ == "__main__":
    main()
