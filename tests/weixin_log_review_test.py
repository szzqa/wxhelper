"""Synthetic byte tests; never loads the Weixin binary or any process memory."""

from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from inspect_weixin import PEError
from review_weixin_login_logs import ANCHORS, derive_hypothesis, encoded_literal, verify_instruction_bytes


class BytesOnly:
    def __init__(self, blobs):
        self.blobs = blobs

    def rva_bytes(self, rva, size):
        raw = self.blobs.get(rva, b"")
        if len(raw) < size:
            raise PEError("synthetic truncated bytes")
        return raw[:size]


def encode(payload):
    length = len(payload).to_bytes(2, "little").hex().upper().encode()
    return b"\xa1" + length + b"\xb1" + payload.hex().upper().encode() + b"\xc1\0"


class LogLiteralTests(unittest.TestCase):
    def test_little_endian_length_and_exact_bytes(self):
        payload = bytes(range(256))
        blob = encode(payload)
        self.assertEqual(blob[1:5], b"0001")
        self.assertEqual(encoded_literal(BytesOnly({1: blob}), 1), (blob, payload))

    def test_non_literals_and_bound(self):
        for blob in [b"normal text", b"\xa1GGGG\xb1", b"\xa10000\xb1", b"\xa1FFFF\xb1"]:
            self.assertIsNone(encoded_literal(BytesOnly({1: blob}), 1))

    def test_marker_and_hex_validation(self):
        for blob in [b"\xa10100\xb1GG\xc1\0", b"\xa10100\xb101\xc2\0", b"\xa10100\xb101\xc1!"]:
            self.assertIsNone(encoded_literal(BytesOnly({1: blob}), 1))

    def test_truncated_bytes_are_not_read(self):
        for blob in [b"\xa1", encode(b"abc")[:-1], b"\xa10010\xb1"]:
            with self.assertRaises(PEError):
                encoded_literal(BytesOnly({1: blob}), 1)

    def test_anchors_must_agree(self):
        stream = bytes(range(60))
        blobs = {rva: encode(bytes(a ^ b for a, b in zip(plain, stream)))
                 for rva, plain, _ in ANCHORS}
        observed, anchors = derive_hypothesis(BytesOnly(blobs))
        self.assertEqual(observed, stream)
        self.assertEqual([a["overlap_verified_bytes"] for a in anchors], [0, 9, 16, 35])
        changed = bytearray(blobs[ANCHORS[-1][0]])
        changed[6:8] = b"00"
        blobs[ANCHORS[-1][0]] = bytes(changed)
        with self.assertRaisesRegex(ValueError, "disagree"):
            derive_hypothesis(BytesOnly(blobs))

    def test_anchor_length_mismatch(self):
        blobs = {rva: encode(b"x") for rva, _, _ in ANCHORS}
        with self.assertRaisesRegex(ValueError, "length mismatch"):
            derive_hypothesis(BytesOnly(blobs))

    def test_ida_instruction_records_must_match_original_bytes(self):
        functions = [{"assembly": [{"rva": "0x42", "bytes_hex": "864839"}]}]
        self.assertEqual(verify_instruction_bytes(BytesOnly({0x42: b"\x86\x48\x39"}), functions), 1)
        with self.assertRaisesRegex(ValueError, "differs from the original"):
            verify_instruction_bytes(BytesOnly({0x42: b"\x86\x48\x38"}), functions)


if __name__ == "__main__":
    unittest.main()
