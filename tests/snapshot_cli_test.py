"""Black-box tests of the offline JSON interface; all bytes are synthetic."""
import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


CLI = Path(sys.argv.pop(1)).resolve() if len(sys.argv) > 1 else None


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from make_weixin4_fixture import fixture


class SnapshotCliTests(unittest.TestCase):
    def run_input(self, value):
        with tempfile.TemporaryDirectory(prefix="wxhelper-synthetic-") as folder:
            path = Path(folder) / "snapshot.json"
            path.write_text(json.dumps(value), encoding="utf-8")
            return subprocess.run([str(CLI), str(path)], capture_output=True, encoding="utf-8", timeout=10)

    def test_all_supported_features(self):
        result = self.run_input(fixture())
        self.assertEqual(result.returncode, 0, result.stderr)
        output = json.loads(result.stdout)
        self.assertFalse(output["runtime_supported"])
        self.assertFalse(output["snapshot_provenance_verified"])
        login, contacts, task, sent, received = [r["data"] for r in output["results"]]
        self.assertEqual(login["state"], "unknown")
        self.assertEqual(login["account_lookup_key"], "fixture_user")
        self.assertEqual(contacts["contacts"][0]["nick_name"], "测试昵称")
        self.assertEqual(task["call_id"], "fixture_call")
        self.assertTrue(sent["call_succeeded"])
        self.assertFalse(sent["delivery_verified"])
        self.assertEqual(len(received["messages"]), 1)
        self.assertEqual(received["messages"][0]["server_id"], str(0xfedcba9876543210))
        self.assertFalse(received["content_decoded"])

    def test_profile_mismatch_is_explicit(self):
        value = fixture()
        value["identity"]["sha256"] = "0" * 64
        result = self.run_input(value)
        self.assertEqual(result.returncode, 2)
        self.assertTrue(all(item["error"] == "profile_mismatch" and "data" not in item
                            for item in json.loads(result.stdout)["results"]))

    def test_overlapping_segments_are_rejected(self):
        value = fixture()
        value["segments"].append(copy.deepcopy(value["segments"][0]))
        result = self.run_input(value)
        self.assertEqual(result.returncode, 1)
        self.assertIn("overlapping", json.loads(result.stderr)["detail"])

    def test_overflow_and_bad_hex_are_rejected(self):
        for segment in ({"address": "0xffffffffffffffff", "hex": "0000"},
                        {"address": "0x1000", "hex": "xz"},
                        {"address": -1, "hex": "00"}):
            value = fixture()
            value["segments"] = [segment]
            self.assertEqual(self.run_input(value).returncode, 1)

    def test_unknown_feature_is_not_reported_as_success(self):
        value = fixture()
        value["requests"] = [{"feature": "send_live_message", "address": "0x1000"}]
        result = self.run_input(value)
        self.assertEqual(result.returncode, 2)
        self.assertEqual(json.loads(result.stdout)["results"][0]["error"], "unsupported_layout")

    def test_unreadable_login_does_not_become_logged_out(self):
        value = fixture()
        value["segments"].pop()
        result = self.run_input(value)
        self.assertEqual(result.returncode, 2)
        login = json.loads(result.stdout)["results"][0]
        self.assertEqual(login["error"], "unreadable")
        self.assertNotIn("data", login)


if __name__ == "__main__":
    if CLI is None:
        raise SystemExit("Usage: python tests/snapshot_cli_test.py <weixin4_snapshot_cli.exe>")
    unittest.main()
