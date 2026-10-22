"""Bounded raw-reference navigation tests using synthetic PE bytes only."""

from pathlib import Path
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from find_weixin_direct_refs import find_references, scan
from inspect_weixin import PE
from test_inspect_weixin import synthetic_pe


def fixture():
    data = synthetic_pe()
    struct.pack_into("<II", data, 0x98 + 112 + 3 * 8, 0x2120, 12)
    struct.pack_into("<III", data, 0x720, 0x1000, 0x1020, 0x2200)
    # Include a negative rel32 displacement, an exclusive .pdata end, and LEA.
    data[0x400:0x405] = b"\xe8" + struct.pack("<i", 0x1010 - 0x1005)
    data[0x420:0x425] = b"\xe9" + struct.pack("<i", 0x1010 - 0x1025)
    data[0x430:0x437] = b"\x48\x8d\x05" + struct.pack("<i", 0x1010 - 0x1037)
    struct.pack_into("<Q", data, 0x760, 0x180001010)
    return data


class DirectReferenceTests(unittest.TestCase):
    def test_calls_jumps_lea_and_data_are_distinguished(self):
        refs, pdata = find_references(PE(fixture()), {0x1010})
        self.assertEqual(pdata["entry_count"], 1)
        self.assertEqual([r["kind"] for r in refs], [
            "raw-E8-call-rel32", "raw-E9-jump-rel32", "raw-LEA-rip", "absolute-data-pointer"])
        self.assertTrue(all(r["target"] == "0x1010" and not r["decoded"] for r in refs))
        self.assertEqual(refs[0]["function"], {"start_rva": "0x1000", "end_rva": "0x1020"})
        self.assertIsNone(refs[1]["function"])
        self.assertIsNone(refs[2]["function"])
        self.assertNotIn("function", refs[3])
        self.assertTrue(refs[3]["aligned_to_8"])

    def test_no_pattern_may_cross_the_text_section_end(self):
        data = fixture()
        data[0x5FC:0x601] = b"\xe8" + struct.pack("<i", 0x1010 - 0x1201)
        refs, _ = find_references(PE(data), {0x1010})
        self.assertFalse(any(r["rva"] == "0x11fc" for r in refs))
        data[0x5FB:0x600] = b"\xe8" + struct.pack("<i", 0x1010 - 0x1200)
        refs, _ = find_references(PE(data), {0x1010})
        self.assertTrue(any(r["rva"] == "0x11fb" for r in refs))

    def test_target_bounds_and_hash_gate(self):
        for targets in (set(), set(range(17)), {-1}, {0x100000000}):
            with self.assertRaises(ValueError):
                find_references(PE(fixture()), targets)
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / "fixture.pe"
            binary.write_bytes(fixture())
            with self.assertRaisesRegex(ValueError, "SHA-256"):
                scan(binary, {0x1010})


if __name__ == "__main__":
    unittest.main()
