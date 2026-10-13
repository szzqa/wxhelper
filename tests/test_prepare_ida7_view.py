"""Verify the analysis-only copy with a small synthetic PE file."""

import importlib.util
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch

from test_inspect_weixin import INSPECTOR, synthetic_pe


SCRIPT = Path(__file__).resolve().parents[1] / "scripts/prepare_ida7_view.py"
SPEC = importlib.util.spec_from_file_location("prepare_ida7_view", SCRIPT)
PREPARE = importlib.util.module_from_spec(SPEC)
with patch.dict("sys.modules", {"inspect_weixin": INSPECTOR}):
    SPEC.loader.exec_module(PREPARE)


class IDAViewTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="wxhelper-ida-view-")
        self.addCleanup(self.directory.cleanup)
        root = Path(self.directory.name)
        self.source, self.target, self.manifest = root / "source.pe", root / "view.pe", root / "manifest.json"
        data = synthetic_pe()
        self.patch_offset = 0x98 + 112 + 3 * 8
        struct.pack_into("<II", data, self.patch_offset, 0x2120, 12)
        struct.pack_into("<III", data, 0x720, 0x1000, 0x1020, 0x2200)
        self.source.write_bytes(data)

    def test_only_directory_header_changes_and_source_remains_identical(self):
        original = self.source.read_bytes()
        report = PREPARE.prepare(self.source, self.target, self.manifest)
        expected = bytearray(original)
        expected[self.patch_offset:self.patch_offset + 8] = b"\0" * 8
        self.assertEqual(self.source.read_bytes(), original)
        self.assertEqual(self.target.read_bytes(), expected)
        self.assertTrue(report["verification"]["all_complete_raw_section_hashes_identical"])
        self.assertEqual(report["original_exception_directory"]["mapping"]["file_offset"], 0x720)
        self.assertTrue(report["must_not_execute_or_inject"])

    def test_refuses_same_or_existing_paths(self):
        original = self.source.read_bytes()
        with self.assertRaises(ValueError):
            PREPARE.prepare(self.source, self.source, self.manifest)
        self.target.write_bytes(b"existing")
        with self.assertRaises(FileExistsError):
            PREPARE.prepare(self.source, self.target, self.manifest)
        self.assertEqual(self.target.read_bytes(), b"existing")
        self.assertEqual(self.source.read_bytes(), original)

    def test_rejects_non_amd64_before_creating_target(self):
        data = bytearray(self.source.read_bytes())
        struct.pack_into("<H", data, 0x84, 0xAA64)
        self.source.write_bytes(data)
        with self.assertRaises(INSPECTOR.PEError):
            PREPARE.prepare(self.source, self.target, self.manifest)
        self.assertFalse(self.target.exists())


if __name__ == "__main__":
    unittest.main()
