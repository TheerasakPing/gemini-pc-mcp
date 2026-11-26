import atexit
import http.client
import json
import logging
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

import uvicorn

_TEST_WORKSPACE = tempfile.mkdtemp(prefix="gpm-server-ws-")
atexit.register(shutil.rmtree, _TEST_WORKSPACE, ignore_errors=True)
os.environ["MCP_WORKSPACE"] = _TEST_WORKSPACE
os.environ["MCP_SECRET"] = "unit-test-secret"

import server  # noqa: E402  (needs MCP_WORKSPACE / MCP_SECRET above)


class _Server(uvicorn.Server):
    def install_signal_handlers(self):
        pass  # running in a test thread; signal handlers are main-thread only


def _free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def _initialize_status(port: int, path: str, *, headers=None, host=None) -> int:
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    body = json.dumps({
        "jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {"protocolVersion": "2025-03-26", "capabilities": {},
                   "clientInfo": {"name": "unit-test", "version": "0"}},
    })
    request_headers = {"Content-Type": "application/json",
                       "Accept": "application/json, text/event-stream"}
    if host:
        request_headers["Host"] = host
    request_headers.update(headers or {})
    try:
        connection.request("POST", path, body=body, headers=request_headers)
        response = connection.getresponse()
        response.read()
        return response.status
    finally:
        connection.close()


class TransportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.port = _free_port()
        os.environ["MCP_ALLOWED_HOSTS"] = f"127.0.0.1:{cls.port},localhost:{cls.port}"
        cls.httpd = _Server(uvicorn.Config(
            server.make_app(), host="127.0.0.1", port=cls.port,
            log_level="warning", lifespan="on",
        ))
        cls.thread = threading.Thread(target=cls.httpd.run, daemon=True)
        cls.thread.start()
        deadline = time.time() + 15
        while not cls.httpd.started and time.time() < deadline:
            time.sleep(0.05)
        if not cls.httpd.started:
            raise RuntimeError("uvicorn did not start")

    @classmethod
    def tearDownClass(cls):
        cls.httpd.should_exit = True
        cls.thread.join(timeout=10)

    def test_initialize_with_path_secret(self):
        self.assertEqual(_initialize_status(self.port, f"/{server.MCP_SECRET}/mcp"), 200)

    def test_initialize_with_bearer_token(self):
        status = _initialize_status(
            self.port, "/mcp", headers={"Authorization": f"Bearer {server.MCP_SECRET}"}
        )
        self.assertEqual(status, 200)

    def test_missing_or_wrong_secret_is_404(self):
        self.assertEqual(_initialize_status(self.port, "/mcp"), 404)
        self.assertEqual(_initialize_status(self.port, "/wrong-secret/mcp"), 404)
        self.assertEqual(
            _initialize_status(self.port, "/mcp", headers={"Authorization": "Bearer wrong"}), 404
        )

    def test_non_ascii_bearer_is_404_not_500(self):
        status = _initialize_status(
            self.port, "/mcp", headers={"Authorization": "Bearer caf\xe9"}
        )
        self.assertEqual(status, 404)

    def test_tunnel_host_not_on_allowlist_is_421(self):
        status = _initialize_status(
            self.port, f"/{server.MCP_SECRET}/mcp", host="abc.trycloudflare.com"
        )
        self.assertEqual(status, 421)

    def test_access_log_filter_survives_uvicorn_logging_config(self):
        filters = logging.getLogger("uvicorn.access").filters
        self.assertTrue(any(isinstance(item, server._SecretRedactor) for item in filters))


class AccessLogRedactionTests(unittest.TestCase):
    def test_secret_is_removed_from_log_line(self):
        record = logging.LogRecord(
            "uvicorn.access", logging.INFO, __file__, 1, '%s - "%s %s HTTP/%s" %d',
            ("127.0.0.1:1", "POST", f"/{server.MCP_SECRET}/mcp", "1.1", 200), None,
        )
        self.assertIn(server.MCP_SECRET, record.getMessage())
        self.assertTrue(server._SecretRedactor().filter(record))
        self.assertNotIn(server.MCP_SECRET, record.getMessage())
        self.assertIn("<redacted>", record.getMessage())


class ToolPolicyTests(unittest.TestCase):
    def setUp(self):
        self.workspace = Path(server.WORKSPACE_DIR)

    def test_hidden_names_are_case_insensitive(self):
        with self.assertRaises(ValueError):
            server.write_file(".GIT/HEAD", "ref: refs/heads/x")
        with self.assertRaises(ValueError):
            server.read_file(".MCP_SECRET")

    def test_bytecode_and_native_extensions_are_blocked(self):
        for name in ("hmac.pyc", "evil.pyd", "x.pth", "x.so"):
            with self.assertRaises(ValueError, msg=name):
                server.write_file(name, "x")
        with self.assertRaises(ValueError):
            server.write_binary_file("evil.pyd", "AAAA")
        self.assertEqual(
            [entry.name for entry in self.workspace.iterdir() if entry.suffix in (".pyc", ".pyd")], []
        )

    def test_trailing_dot_cannot_create_py_file(self):
        with self.assertRaises(ValueError):
            server.write_file("newmod.py.", "print(1)")
        self.assertFalse((self.workspace / "newmod.py").exists())

    def test_write_read_list_roundtrip(self):
        server.write_file("notes/hello.txt", "hi")
        self.assertEqual(server.read_file("notes/hello.txt"), "hi")
        listed = {name.replace("\\", "/") for name in server.list_files()}
        self.assertIn("notes/hello.txt", listed)

    def test_list_files_is_capped(self):
        for index in range(3):
            server.write_file(f"cap{index}.txt", "x")
        with patch.object(server, "MAX_LIST_ENTRIES", 2):
            self.assertEqual(len(server.list_files()), 2)

    def test_read_file_rejects_non_utf8(self):
        server.write_binary_file("binary.dat", "//4=")  # b"\xff\xfe"
        with self.assertRaises(ValueError):
            server.read_file("binary.dat")


class CommandTests(unittest.TestCase):
    def test_output_is_capped(self):
        result = server._run_bounded(
            [sys.executable, "-c", "import sys; sys.stdout.write('x' * 100000)"], max_output=1000
        )
        self.assertIn("x" * 1000, result)
        self.assertLess(len(result), 1100)
        self.assertIn("truncated", result)

    def test_timeout_kills_child(self):
        started = time.monotonic()
        result = server._run_bounded(
            [sys.executable, "-c", "import time; time.sleep(30)"], timeout=0.5
        )
        self.assertLess(time.monotonic() - started, 10)
        self.assertIn("ยกเลิก", result)

    def test_child_does_not_inherit_secret(self):
        result = server._run_bounded(
            [sys.executable, "-c", "import os; print(os.environ.get('MCP_SECRET'))"]
        )
        self.assertIn("None", result)

    @unittest.skipUnless(shutil.which("git"), "git not installed")
    def test_git_status_does_not_run_repository_hooks(self):
        workspace = Path(server.WORKSPACE_DIR)
        subprocess.run(["git", "init", "-q"], cwd=workspace, check=True)
        hook = workspace / ".git" / "hooks" / "fsmon"
        hook.write_text("#!/bin/sh\necho ran > hook-ran.txt\n")
        hook.chmod(0o755)
        (workspace / ".git" / "config").write_text("[core]\n\tfsmonitor = .git/hooks/fsmon\n")
        (workspace / "tracked.txt").write_text("x")

        result = server.run_allowed_command("git_status")
        self.assertFalse((workspace / "hook-ran.txt").exists(), result)

        # Control: a plain status call must trigger the hook, proving the fixture works.
        subprocess.run(["git", "status"], cwd=workspace, capture_output=True, check=True)
        self.assertTrue((workspace / "hook-ran.txt").exists())


if __name__ == "__main__":
    unittest.main()
