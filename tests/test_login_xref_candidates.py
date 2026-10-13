"""Raw-reference scanner checks against synthetic bytes; no client is loaded."""

import importlib.util
from pathlib import Path
import struct
import unittest
from unittest.mock import patch

from test_inspect_weixin import INSPECTOR, synthetic_pe


SCRIPT = Path(__file__).resolve().parents[1] / "scripts/find_login_xref_candidates.py"
SPEC = importlib.util.spec_from_file_location("login_candidates", SCRIPT)
CANDIDATES = importlib.util.module_from_spec(SPEC)
with patch.dict("sys.modules", {"inspect_weixin": INSPECTOR}):
    SPEC.loader.exec_module(CANDIDATES)


def reference_fixture():
    data = synthetic_pe()
    struct.pack_into("<II", data, 0x98 + 112 + 3 * 8, 0x2120, 12)
    struct.pack_into("<III", data, 0x720, 0x1000, 0x1020, 0x2200)
    data[0x400:0x403] = b"\x48\x8d\x05"
    struct.pack_into("<i", data, 0x403, 0x2180 - (0x1000 + 7))
    data[0x420:0x423] = b"\x4c\x8d\x35"
    struct.pack_into("<i", data, 0x423, 0x2180 - (0x1020 + 7))
    data[0x780:0x78B] = b"LoginState\0"
    data[0x790:0x797] = b"NoCode\0"
    struct.pack_into("<Q", data, 0x760, 0x180002190)
    seeds = [
        {"seed_id": "login", "text": "LoginState", "priority": 1, "string_rva": "0x2180"},
        {"seed_id": "data", "text": "NoCode", "priority": 1, "string_rva": "0x2190"},
    ]
    return data, seeds


class RawLoginReferenceTests(unittest.TestCase):
    def test_target_and_exclusive_runtime_boundary(self):
        data, seeds = reference_fixture()
        references, metadata, _, _ = CANDIDATES.find_references(INSPECTOR.PE(data), seeds)
        self.assertEqual(metadata["entry_count"], 1)
        self.assertEqual(len(references), 2)
        self.assertEqual(references[0]["target_string_rva"], "0x2180")
        self.assertEqual(references[0]["runtime_function"]["start_rva"], "0x1000")
        self.assertFalse(references[0]["decoded_by_disassembler"])
        self.assertIsNone(references[1]["runtime_function"])

    def test_absolute_data_pointer_is_not_a_code_reference(self):
        data, seeds = reference_fixture()
        pe = INSPECTOR.PE(data)
        references, _, _, _ = CANDIDATES.find_references(pe, seeds)
        candidates = CANDIDATES.find_data_pointer_candidates(pe, seeds, references)
        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0]["seed_id"], "data")
        self.assertEqual(candidates[0]["matches"][0]["rva"], "0x2160")
        self.assertFalse(candidates[0]["matches"][0]["is_code_xref"])

    def test_rejects_ambiguous_runtime_ranges(self):
        data, _ = reference_fixture()
        struct.pack_into("<II", data, 0x98 + 112 + 3 * 8, 0x2120, 24)
        struct.pack_into("<III", data, 0x72C, 0x1010, 0x1030, 0x2200)
        with self.assertRaises(INSPECTOR.PEError):
            CANDIDATES.runtime_functions(INSPECTOR.PE(data))


if __name__ == "__main__":
    unittest.main()
