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


class _AccessLogCapture(logging.Handler):
    def __init__(self):
        super().__init__()
        self.lines: list[str] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.lines.append(record.getMessage())


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
            log_level="info", lifespan="on",
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

    def test_bearer_scheme_is_case_insensitive(self):
        status = _initialize_status(
            self.port, "/mcp", headers={"Authorization": f"bearer {server.MCP_SECRET}"}
        )
        self.assertEqual(status, 200)
        status = _initialize_status(
            self.port, "/mcp", headers={"Authorization": f"Basic {server.MCP_SECRET}"}
        )
        self.assertEqual(status, 404)

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

    def test_real_access_log_line_is_redacted(self):
        logger = logging.getLogger("uvicorn.access")
        capture = _AccessLogCapture()
        logger.addHandler(capture)
        try:
            self.assertEqual(_initialize_status(self.port, f"/{server.MCP_SECRET}/mcp"), 200)
            deadline = time.time() + 5
            line = None
            while line is None and time.time() < deadline:
                line = next((item for item in capture.lines if "/mcp" in item), None)
                time.sleep(0.02)
        finally:
            logger.removeHandler(capture)
        self.assertIsNotNone(line, capture.lines)
        self.assertNotIn(server.MCP_SECRET, line)
        self.assertIn("<redacted>/mcp", line)
        self.assertIn("200", line)

    def test_access_formatter_renders_redacted_line(self):
        record = logging.LogRecord(
            "uvicorn.access", logging.INFO, __file__, 1,
            '%s - "%s %s HTTP/%s" %d',
            ("127.0.0.1:1", "POST", f"/{server.MCP_SECRET}/mcp", "1.1", 200),
            None,
        )
        for item in logging.getLogger("uvicorn.access").filters:
            item.filter(record)
        formatter = uvicorn.logging.AccessFormatter(
            '%(client_addr)s - "%(request_line)s" %(status_code)s', use_colors=False
        )
        text = formatter.format(record)
        self.assertNotIn(server.MCP_SECRET, text)
        self.assertIn("<redacted>/mcp", text)


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

    def test_hidden_patterns_block_read_write_and_list(self):
        folder = Path(tempfile.mkdtemp(dir=self.workspace))
        try:
            names = [".env", ".ENV.local", "prod.env", "prod.env.bak", ".mcp_secret.bak",
                     ".TUNNEL_TOKEN.bak", ".gitconfig", "server.key", "id_dsa", "id_dss",
                     "cert.jks", ".vault-token", ".mcp-tmp-abc"]
            for name in names:
                (folder / name).write_text("private")
                relative = f"{folder.name}/{name}"
                with self.assertRaises(ValueError, msg=name):
                    server.read_file(relative)
                with self.assertRaises(ValueError, msg=name):
                    server.write_file(relative, "x")
            (folder / ".ssh").mkdir()
            (folder / ".ssh" / "id_ed25519").write_text("private")
            with self.assertRaises(ValueError):
                server.read_file(f"{folder.name}/.ssh/id_ed25519")
            (folder / ".azure").mkdir()
            (folder / ".azure" / "profile.json").write_text("private")
            with self.assertRaises(ValueError):
                server.read_file(f"{folder.name}/.azure/profile.json")
            self.assertFalse(
                any(name.startswith(folder.name) for name in server.list_files())
            )
        finally:
            shutil.rmtree(folder)

    def test_dependency_ci_build_and_shell_config_files_are_blocked(self):
        blocked = ("requirements.txt", "requirements-dev.txt", "pyproject.toml", "package.json",
                   ".github/workflows/x.yml", ".gitlab-ci.yml", "Jenkinsfile", "Makefile",
                   "Dockerfile.prod", ".gitmodules", ".bashrc", ".zshenv", ".envrc",
                   ".vscode/tasks.json", ".cargo/config.toml", ".claude/settings.json",
                   "x.code-workspace", "pom.xml", "compose.yaml", "flake.nix", "vite.config.ts")
        for name in blocked:
            with self.assertRaises(ValueError, msg=name):
                server.write_file(name, "x")
        for name in ("README.md", "notes.txt", "app.ts", "src/main.rs", "config.yaml"):
            server.write_file(name, "x")
            self.assertEqual(server.read_file(name), "x")
        self.assertFalse((self.workspace / ".github").exists())

    def test_executable_and_loadable_extensions_are_blocked(self):
        blocked = ("hmac.pyc", "evil.pyd", "x.pth", "x.so", "server.py", "x.bat", "x.hta",
                   "x.ps1", "x.cjs", "x.mjs", "x.sh", "x.jar", "x.desktop", "x.service",
                   "x.dylib", "x.command")
        for name in blocked:
            with self.assertRaises(ValueError, msg=name):
                server.write_file(name, "x")
        with self.assertRaises(ValueError):
            server.write_binary_file("evil.pyd", "AAAA")
        self.assertEqual(
            [entry.name for entry in self.workspace.iterdir()
             if entry.suffix.lower() in (".py", ".pyc", ".pyd", ".sh", ".jar", ".bat")], []
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


class WorkspaceTests(unittest.TestCase):
    def test_default_workspace_is_the_workspace_subfolder(self):
        self.assertEqual(
            server.DEFAULT_WORKSPACE, Path(server.__file__).resolve().parent / "workspace"
        )
        self.assertEqual(server.resolve_workspace(None), server.DEFAULT_WORKSPACE)
        self.assertEqual(server.resolve_workspace("  "), server.DEFAULT_WORKSPACE)

    def test_filesystem_root_is_refused(self):
        with self.assertRaises(ValueError):
            server.resolve_workspace(Path(server.DEFAULT_WORKSPACE.anchor))

    def test_home_directory_is_refused(self):
        with self.assertRaises(ValueError):
            server.resolve_workspace(Path.home())

    @unittest.skipUnless(os.name == "nt", "Windows verbatim path prefix")
    def test_verbatim_home_prefix_is_refused(self):
        with self.assertRaises(ValueError):
            server.resolve_workspace("\\\\?\\" + str(Path.home()))

    def test_relative_path_is_based_on_the_app_folder(self):
        self.assertEqual(
            server.resolve_workspace("ws-relative"),
            (server.DEFAULT_WORKSPACE.parent / "ws-relative").resolve(),
        )


class CommandTests(unittest.TestCase):
    def test_allowed_commands_use_absolute_executables(self):
        self.assertEqual(Path(server.ALLOWED_COMMANDS["python_version"][0]), Path(sys.executable))
        for key, argv in server.ALLOWED_COMMANDS.items():
            if argv[0]:
                self.assertTrue(Path(argv[0]).is_absolute(), f"{key} ใช้ชื่อเปล่า: {argv[0]!r}")

    @unittest.skipUnless(os.name != "nt", "POSIX ls")
    def test_posix_list_dir_uses_absolute_ls(self):
        argv = server.build_allowed_commands("posix")["list_dir"]
        self.assertTrue(Path(argv[0]).is_absolute())
        self.assertEqual(Path(argv[0]).name, "ls")
        self.assertNotIn("/c", argv)

    def test_windows_list_dir_uses_cmd_exe(self):
        argv = server.build_allowed_commands("nt")["list_dir"]
        self.assertTrue(argv[0].lower().endswith("cmd.exe"), argv)
        self.assertEqual(argv[1:3], ["/c", "dir"])

    def test_missing_executable_has_no_bare_name_fallback(self):
        with patch.object(server.shutil, "which", return_value=None):
            commands = server.build_allowed_commands("posix")
        self.assertFalse(commands["git_status"][0])
        self.assertFalse(commands["list_dir"][0])

    def test_missing_executable_reports_instead_of_spawning(self):
        with patch.dict(server.ALLOWED_COMMANDS, {"git_status": [None, "status"]}):
            result = server.run_allowed_command("git_status")
        self.assertIn("ไม่พบโปรแกรม", result)

    @unittest.skipUnless(os.name == "nt" and shutil.which("whoami"), "Windows whoami.exe")
    def test_workspace_executable_is_not_picked_up(self):
        workspace = Path(server.WORKSPACE_DIR)
        marker = workspace / f"marker-{os.getpid()}.txt"
        marker.write_text("x")
        fake = workspace / "cmd.exe"
        shutil.copy(shutil.which("whoami"), fake)
        previous = os.getcwd()
        search_flag = os.environ.pop("NoDefaultCurrentDirectoryInExePath", None)
        try:
            os.chdir(workspace)
            result = server.run_allowed_command("list_dir")
        finally:
            os.chdir(previous)
            if search_flag is not None:
                os.environ["NoDefaultCurrentDirectoryInExePath"] = search_flag
            fake.unlink()
            marker.unlink()
        self.assertIn(marker.name, result)

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

    def test_grandchild_holding_pipe_does_not_block_caller(self):
        spawner = (
            "import os, subprocess, sys\n"
            "subprocess.Popen([sys.executable, '-c',"
            " 'import os, time; os.chdir(os.environ.get(\"SystemRoot\") or \"/\");"
            " time.sleep(60)'])\n"
        )
        started = time.monotonic()
        result = server._run_bounded([sys.executable, "-c", spawner], timeout=10)
        self.assertEqual(result, "")
        self.assertLess(time.monotonic() - started, 20)

    @unittest.skipUnless(shutil.which("git"), "git not installed")
    def test_git_status_does_not_run_repository_hooks(self):
        workspace = Path(server.WORKSPACE_DIR)
        subprocess.run(["git", "init", "-q"], cwd=workspace, check=True)
        hook = workspace / ".git" / "hooks" / "fsmon"
        hook.write_text("#!/bin/sh\necho ran > hook-ran.txt\n")
        hook.chmod(0o755)
        post = workspace / ".git" / "hooks" / "post-index-change"
        post.write_text("#!/bin/sh\necho ran > post-index-ran.txt\n")
        post.chmod(0o755)
        (workspace / ".git" / "config").write_text("[core]\n\tfsmonitor = .git/hooks/fsmon\n")
        tracked = workspace / "tracked.txt"
        tracked.write_text("x")
        git = [
            "git", "-c", "user.name=t", "-c", "user.email=t@example.com",
            "-c", "commit.gpgsign=false",
        ]
        subprocess.run([*git, "add", "tracked.txt"], cwd=workspace, check=True)
        subprocess.run([*git, "commit", "-q", "-m", "init"], cwd=workspace, check=True)
        # Same content, new mtime: the index stat data is stale, so a plain
        # status refreshes and rewrites the index, which fires post-index-change.
        tracked.write_text("x")

        def clear_markers():
            for name in ("hook-ran.txt", "post-index-ran.txt"):
                (workspace / name).unlink(missing_ok=True)

        clear_markers()
        result = server.run_allowed_command("git_status")
        self.assertFalse((workspace / "hook-ran.txt").exists(), result)
        self.assertFalse((workspace / "post-index-ran.txt").exists(), result)

        # Control: a plain status call must trigger both hooks, proving the fixture works.
        clear_markers()
        subprocess.run(["git", "status"], cwd=workspace, capture_output=True, check=True)
        self.assertTrue((workspace / "hook-ran.txt").exists())
        self.assertTrue((workspace / "post-index-ran.txt").exists())


if __name__ == "__main__":
    unittest.main()
