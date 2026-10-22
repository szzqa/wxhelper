"""Black-box tests of the offline JSON interface; all bytes are synthetic."""
import copy
import json
from pathlib import Path
import subprocess
import struct
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
        login, contacts, task, sent, received, auth = [r["data"] for r in output["results"]]
        self.assertEqual(login["state"], "unknown")
        self.assertEqual(login["kernel_stage_raw"], 1)
        self.assertEqual(login["kernel_phase"], "initialized")
        self.assertFalse(login["network_authentication_verified"])
        self.assertIs(login["logout_started"], False)
        self.assertEqual(login["account_lookup_key"], "fixture_user")
        self.assertEqual(contacts["contacts"][0]["nick_name"], "测试昵称")
        self.assertEqual(task["call_id"], "fixture_call")
        self.assertEqual(task["chat_id"], "fixture_chat")
        self.assertTrue(sent["call_succeeded"])
        self.assertFalse(sent["delivery_verified"])
        self.assertEqual(len(received["messages"]), 1)
        self.assertEqual(received["messages"][0]["server_id"], str(0xfedcba9876543210))
        self.assertTrue(received["content_decoded"])
        self.assertFalse(received["direction_verified"])
        self.assertEqual(received["content_semantics"], "raw_native_string")
        message = received["messages"][0]
        self.assertEqual(message["sort_sequence"], str(0x123456789abcdef0))
        self.assertEqual(message["message_type"], 12345)
        self.assertEqual(message["time_raw"], 5678)
        self.assertEqual(message["message_status"], 2)
        self.assertEqual(message["upload_status"], 3)
        self.assertEqual(message["download_status"], 4)
        self.assertEqual(message["origin_source"], 5)
        self.assertEqual(message["sender"], "fixture_sender")
        self.assertEqual(message["from_username"], "fixture_user")
        self.assertEqual(message["to_username"], "fixture_peer")
        self.assertEqual(message["content"], "测试正文")
        self.assertEqual(auth["host"], "fixture.test")
        self.assertTrue(auth["host_entry_present"])
        self.assertEqual(auth["state_raw"], 3)
        self.assertEqual(auth["state"], "success_recorded")
        self.assertFalse(auth["global_login_verified"])
        self.assertFalse(auth["connection_verified"])

    def test_host_authentication_is_scoped_and_missing_is_distinct(self):
        for raw, name in ((0, "unknown"), (1, "idle_or_retryable"),
                          (2, "authenticating"), (3, "success_recorded"),
                          (0xffffffff, "unknown")):
            value = fixture()
            value["requests"] = [value["requests"][-1]]
            memory = bytearray.fromhex(value["segments"][0]["hex"])
            struct.pack_into("<I", memory, 0x9510 - 0x1000, raw)
            value["segments"][0]["hex"] = memory.hex()
            result = self.run_input(value)
            self.assertEqual(result.returncode, 0, result.stderr)
            auth = json.loads(result.stdout)["results"][0]["data"]
            self.assertTrue(auth["host_entry_present"])
            self.assertEqual(auth["state_raw"], raw)
            self.assertEqual(auth["state"], name)
            self.assertFalse(auth["global_login_verified"])
        value = fixture()
        value["requests"] = [value["requests"][-1]]
        value["requests"][0]["host"] = "Fixture.test"
        result = self.run_input(value)
        self.assertEqual(result.returncode, 0, result.stderr)
        auth = json.loads(result.stdout)["results"][0]["data"]
        self.assertFalse(auth["host_entry_present"])
        self.assertIsNone(auth["state_raw"])
        self.assertEqual(auth["state"], "unknown")

    def test_profile_mismatch_is_explicit(self):
        value = fixture()
        value["identity"]["sha256"] = "0" * 64
        result = self.run_input(value)
        self.assertEqual(result.returncode, 2)
        self.assertTrue(all(item["error"] == "profile_mismatch" and "data" not in item
                            for item in json.loads(result.stdout)["results"]))

    def test_logout_flag_is_not_authentication_state(self):
        for flag in (0, 1, 2, 3):
            value = fixture()
            memory = bytearray.fromhex(value["segments"][0]["hex"])
            memory[0x2039 - 0x1000] = flag
            value["segments"][0]["hex"] = memory.hex()
            result = self.run_input(value)
            self.assertEqual(result.returncode, 0, result.stderr)
            login = json.loads(result.stdout)["results"][0]["data"]
            self.assertIs(login["logout_started"], bool(flag & 1))
            self.assertEqual(login["state"], "unknown")
        value = fixture()
        memory = bytearray.fromhex(value["segments"][0]["hex"])
        struct.pack_into("<QQ", memory, 0x1068 - 0x1000, 0, 0)
        value["segments"][0]["hex"] = memory.hex()
        result = self.run_input(value)
        self.assertEqual(result.returncode, 0, result.stderr)
        login = json.loads(result.stdout)["results"][0]["data"]
        self.assertIsNone(login["logout_started"])
        self.assertEqual(login["state"], "unknown")

    def test_kernel_stage_is_not_authentication(self):
        for raw, phase in ((0, "unknown"), (1, "initialized"), (2, "login_flow"),
                           (3, "setup_callback_complete"), (4, "logout_flow"),
                           (0xffffffff, "unknown")):
            value = fixture()
            memory = bytearray.fromhex(value["segments"][0]["hex"])
            struct.pack_into("<I", memory, 0x1330 - 0x1000, raw)
            value["segments"][0]["hex"] = memory.hex()
            result = self.run_input(value)
            self.assertEqual(result.returncode, 0, result.stderr)
            login = json.loads(result.stdout)["results"][0]["data"]
            self.assertEqual(login["kernel_stage_raw"], raw)
            self.assertEqual(login["kernel_phase"], phase)
            self.assertEqual(login["state"], "unknown")
            self.assertFalse(login["network_authentication_verified"])
        value = fixture()
        value["segments"][1]["hex"] = "00" * 8
        result = self.run_input(value)
        self.assertEqual(result.returncode, 0, result.stderr)
        login = json.loads(result.stdout)["results"][0]["data"]
        self.assertIsNone(login["kernel_stage_raw"])
        self.assertEqual(login["kernel_phase"], "unknown")
        self.assertEqual(login["state"], "unknown")

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
