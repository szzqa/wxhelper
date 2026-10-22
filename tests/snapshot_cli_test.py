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
        login, contacts, task, sent, received, auth, contact_task, storage, completion = [r["data"] for r in output["results"]]
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
        self.assertEqual(contact_task["usernames"], ["fixture_user", "fixture_peer"])
        self.assertFalse(contact_task["query_executed"])
        self.assertFalse(contact_task["all_contacts_verified"])
        self.assertTrue(storage["storage_result_flag"])
        self.assertEqual(storage["success_subset"], received["messages"])
        self.assertFalse(storage["all_input_succeeded_verified"])
        self.assertFalse(storage["realtime_notification_verified"])
        self.assertFalse(storage["disk_durability_verified"])
        self.assertEqual(completion["detail_string"], "fixture detail")
        self.assertTrue(completion["call_succeeded"])
        self.assertEqual(completion["payload_object_address"], "0")
        self.assertEqual(completion["payload_control_address"], "0")
        self.assertFalse(completion["delivery_verified"])
        self.assertFalse(completion["server_acknowledgement_verified"])

    def test_send_completion_preserves_failure_words_and_opaque_payload(self):
        value = fixture()
        value["requests"] = [{"feature": "send_completion", "address": "0x7400"}]
        memory = bytearray.fromhex(value["segments"][0]["hex"])
        struct.pack_into("<II", memory, 0x7400 - 0x1000, 0xffffffff, 17)
        struct.pack_into("<QQ", memory, 0x7428 - 0x1000, 0xfedcba9876543210, 0xabcdef9876543210)
        value["segments"][0]["hex"] = memory.hex()
        result = self.run_input(value)
        self.assertEqual(result.returncode, 0, result.stderr)
        item = json.loads(result.stdout)["results"][0]["data"]
        self.assertEqual(item["status_word0"], 0xffffffff)
        self.assertEqual(item["status_word1"], 17)
        self.assertFalse(item["call_succeeded"])
        self.assertEqual(item["payload_object_address"], str(0xfedcba9876543210))
        self.assertEqual(item["payload_control_address"], str(0xabcdef9876543210))
        struct.pack_into("<Q", memory, 0x7418 - 0x1000, 16)  # size exceeds SSO capacity.
        value["segments"][0]["hex"] = memory.hex()
        result = self.run_input(value)
        self.assertEqual(result.returncode, 2)
        self.assertNotIn("data", json.loads(result.stdout)["results"][0])

    def test_storage_result_is_not_whole_batch_success_or_notification(self):
        for flag in (0, 1, 2, 255):
            value = fixture()
            value["requests"] = [{"feature": "receive_storage", "address": "0x8800"}]
            memory = bytearray.fromhex(value["segments"][0]["hex"])
            memory[0x8818 - 0x1000] = flag
            value["segments"][0]["hex"] = memory.hex()
            result = self.run_input(value)
            item = json.loads(result.stdout)["results"][0]
            if flag > 1:
                self.assertEqual(result.returncode, 2)
                self.assertEqual(item["error"], "invalid_object")
                self.assertNotIn("data", item)
            else:
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIs(item["data"]["storage_result_flag"], bool(flag))
                self.assertEqual(len(item["data"]["success_subset"]), 1)
                self.assertFalse(item["data"]["all_input_succeeded_verified"])
        struct.pack_into("<QQQB", memory, 0x8800 - 0x1000, 0, 0, 0, 1)
        value["segments"][0]["hex"] = memory.hex()
        result = self.run_input(value)
        self.assertEqual(result.returncode, 0, result.stderr)
        item = json.loads(result.stdout)["results"][0]["data"]
        self.assertTrue(item["storage_result_flag"])
        self.assertEqual(item["success_subset"], [])
        self.assertFalse(item["realtime_notification_verified"])

    def test_host_authentication_is_scoped_and_missing_is_distinct(self):
        for raw, name in ((0, "unknown"), (1, "idle_or_retryable"),
                          (2, "authenticating"), (3, "success_recorded"),
                          (0xffffffff, "unknown")):
            value = fixture()
            value["requests"] = [next(r for r in value["requests"] if r["feature"] == "auth_host")]
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
        value["requests"] = [next(r for r in value["requests"] if r["feature"] == "auth_host")]
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

    def test_contact_task_requires_valid_input_even_when_empty(self):
        value = fixture()
        value["requests"] = [{"feature": "contact_task", "address": "0x8600"}]
        memory = bytearray.fromhex(value["segments"][0]["hex"])
        struct.pack_into("<QQQ", memory, 0x8638 - 0x1000, 0, 0, 0)
        value["segments"][0]["hex"] = memory.hex()
        result = self.run_input(value)
        self.assertEqual(result.returncode, 0, result.stderr)
        data = json.loads(result.stdout)["results"][0]["data"]
        self.assertEqual(data["usernames"], [])
        self.assertFalse(data["all_contacts_verified"])
        struct.pack_into("<QQQ", memory, 0x8638 - 0x1000, 0x8700, 0x8741, 0x8760)
        value["segments"][0]["hex"] = memory.hex()
        result = self.run_input(value)
        self.assertEqual(result.returncode, 2)
        self.assertNotIn("data", json.loads(result.stdout)["results"][0])

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

    def test_kernel_login_predicate_is_not_network_authentication(self):
        for flag in (0, 1, 2, 255):
            value = fixture()
            value["requests"] = value["requests"][:1]
            memory = bytearray.fromhex(value["segments"][0]["hex"])
            memory[0x2038 - 0x1000] = flag
            memory[0x2039 - 0x1000] = 1  # Logout may already have started.
            value["segments"][0]["hex"] = memory.hex()
            result = self.run_input(value)
            self.assertEqual(result.returncode, 0, result.stderr)
            login = json.loads(result.stdout)["results"][0]["data"]
            self.assertIs(login["kernel_is_login"], bool(flag & 1))
            self.assertEqual(login["state"], "unknown")
            self.assertFalse(login["network_authentication_verified"])
        for root_present in (False, True):
            value = fixture()
            value["requests"] = value["requests"][:1]
            if root_present:
                memory = bytearray.fromhex(value["segments"][0]["hex"])
                struct.pack_into("<Q", memory, 0x1068 - 0x1000, 0)
                value["segments"][0]["hex"] = memory.hex()
            else:
                value["segments"][1]["hex"] = "00" * 8
            result = self.run_input(value)
            self.assertEqual(result.returncode, 0, result.stderr)
            login = json.loads(result.stdout)["results"][0]["data"]
            self.assertIs(login["kernel_is_login"], False if root_present else None)

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
