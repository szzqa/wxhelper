"""Offline checks: no socket or WeChat process is used."""

import ast
import contextlib
import io
import json
from pathlib import Path
import re
import runpy
import sys
import types
import unittest
from unittest.mock import Mock, patch
from urllib.parse import urlsplit


ROOT = Path(__file__).resolve().parents[1]
CLIENTS = (ROOT / "python/client.py", ROOT / "python/3.9.5.81/http_client.py")
UNSUPPORTED = {
    "hook_img", "unhook_img", "hook_voice", "unhook_voice",
    "del_friend", "search_friend", "add_friend", "get_member_nickname",
    "logout", "confirm_receipt",
}


def server_contracts():
    source = (ROOT / "src/http_server_callback.cc").read_text(encoding="utf-8")
    matches = list(re.finditer(r'mg_http_match_uri\(hm, "(/api/[^"*]+)"\)', source))
    contracts = {}
    for index, match in enumerate(matches):
        end = matches[index + 1].start() if index + 1 < len(matches) else len(source)
        block = source[match.end():end]
        contracts[match.group(1)] = set(re.findall(
            r'Get(?:Int|INT64|UINT64|String|WString|Array)Param\(j_param, "([^"]+)"\)',
            block,
        ))
    return contracts


class PythonClientTests(unittest.TestCase):
    def setUp(self):
        self.requests = types.ModuleType("requests")
        self.requests.request = Mock(return_value=types.SimpleNamespace(text="{}"))
        self.module_patch = patch.dict(sys.modules, {"requests": self.requests})
        self.module_patch.start()
        self.addCleanup(self.module_patch.stop)
        self.contracts = server_contracts()

    def check_request(self, url, payload):
        parsed = urlsplit(url)
        self.assertEqual(parsed.scheme, "http")
        self.assertEqual(parsed.netloc, "127.0.0.1:19088")
        self.assertFalse(parsed.query)
        self.assertIn(parsed.path, self.contracts)
        required = self.contracts[parsed.path].copy()
        if parsed.path == "/api/hookSyncMsg" and not int(payload.get("enableHttp", 0)):
            required -= {"url", "timeout"}
        self.assertFalse(required - payload.keys(), (parsed.path, required - payload.keys()))

    def test_all_examples_match_server_routes_and_parameters(self):
        # Inspect guarded examples too, without removing their user-edit guards.
        for path in CLIENTS:
            for function in ast.parse(path.read_text(encoding="utf-8")).body:
                if not isinstance(function, ast.FunctionDef):
                    continue
                values = {}
                for statement in function.body:
                    if isinstance(statement, ast.Assign) and isinstance(statement.targets[0], ast.Name):
                        name = statement.targets[0].id
                        if name not in {"url", "payload"}:
                            continue
                        value = statement.value
                        if isinstance(value, ast.Call):
                            value = value.args[0]  # json.dumps of the example dictionary
                        values[name] = ast.literal_eval(value)
                with self.subTest(client=path.name, function=function.name):
                    if path == CLIENTS[0] and function.name in UNSUPPORTED:
                        self.assertNotIn("url", values)
                    else:
                        self.check_request(values["url"], values["payload"])

    def test_legacy_examples_dispatch_or_fail_explicitly(self):
        module = runpy.run_path(str(CLIENTS[0]), run_name="client_offline_test")
        functions = [node.name for node in ast.parse(CLIENTS[0].read_text(encoding="utf-8")).body
                     if isinstance(node, ast.FunctionDef)]
        for name in functions:
            with self.subTest(function=name), contextlib.redirect_stdout(io.StringIO()):
                self.requests.request.reset_mock()
                if name in UNSUPPORTED:
                    with self.assertRaises(NotImplementedError):
                        module[name]()
                    self.requests.request.assert_not_called()
                    continue
                module[name]()
                self.requests.request.assert_called_once()
                args, kwargs = self.requests.request.call_args
                self.assertEqual(args[0], "POST")
                payload = kwargs["data"]
                self.check_request(args[1], json.loads(payload) if isinstance(payload, str) else payload)

    def test_running_examples_only_checks_login(self):
        for path in CLIENTS:
            with self.subTest(client=str(path)), contextlib.redirect_stdout(io.StringIO()):
                self.requests.request.reset_mock()
                runpy.run_path(str(path), run_name="__main__")
                self.requests.request.assert_called_once()
                self.assertEqual(self.requests.request.call_args.args[:2],
                                 ("POST", "http://127.0.0.1:19088/api/checkLogin"))


if __name__ == "__main__":
    unittest.main()
