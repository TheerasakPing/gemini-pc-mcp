import ctypes
import os
import shutil
import tempfile
import unittest
from pathlib import Path

from filesystem import (
    WorkspaceSecurityError,
    atomic_write,
    list_workspace_files,
    read_file_bytes,
    safe_workspace_path,
)

HIDDEN = {
    ".env", ".env.*", ".mcp_secret", ".mcp_secret.*", ".git", ".tunnel_token", ".tunnel_token.*",
    "*.env",
    ".ssh", "*.pem",
}


def _short_path(path: str) -> str:
    buffer = ctypes.create_unicode_buffer(1024)
    ctypes.windll.kernel32.GetShortPathNameW(path, buffer, 1024)
    return buffer.value


class WorkspaceFilesystemTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name).resolve()

    def tearDown(self):
        self.temp.cleanup()

    def test_accepts_normal_relative_path(self):
        self.assertEqual(safe_workspace_path(self.root, "docs/readme.txt"),
                         self.root / "docs" / "readme.txt")

    def test_rejects_parent_traversal(self):
        with self.assertRaises(WorkspaceSecurityError):
            safe_workspace_path(self.root, "../outside.txt")

    def test_rejects_absolute_path(self):
        with self.assertRaises(WorkspaceSecurityError):
            safe_workspace_path(self.root, str(self.root / "secret.txt"))

    def test_rejects_hidden_path_component(self):
        with self.assertRaises(WorkspaceSecurityError):
            safe_workspace_path(self.root, ".env/key", HIDDEN)

    def test_hidden_component_match_ignores_case(self):
        for name in (".ENV/key", ".Git/HEAD", ".MCP_SECRET"):
            with self.assertRaises(WorkspaceSecurityError, msg=name):
                safe_workspace_path(self.root, name, HIDDEN)

    def test_hidden_patterns_cover_variants(self):
        hidden = (".ENV.local", "prod.env", ".env.bak", ".mcp_secret.old", ".tunnel_token.bak",
                  ".ssh/id_ed25519", "cert.pem", "CERT.PEM")
        for name in hidden:
            with self.assertRaises(WorkspaceSecurityError, msg=name):
                safe_workspace_path(self.root, name, HIDDEN)
        for name in ("environment.md", "env.txt", "pem.notes.txt"):
            safe_workspace_path(self.root, name, HIDDEN)

    def test_rejects_trailing_dot_or_space_component(self):
        for name in ("newmod.py.", "dir /x.txt", "x.txt ", "dir./x.txt"):
            with self.assertRaises(WorkspaceSecurityError, msg=name):
                safe_workspace_path(self.root, name, HIDDEN)

    def test_rejects_invalid_component_characters(self):
        for name in ("a:b.txt", "a?.txt", "a<b.txt", "a\x00b"):
            with self.assertRaises(WorkspaceSecurityError, msg=repr(name)):
                safe_workspace_path(self.root, name, HIDDEN)

    def test_rejects_windows_reserved_device_names(self):
        for name in ("NUL", "con.txt", "COM1.dat", "lpt9", "COM¹", "LPT².txt", "CONOUT$",
                     "CONIN$", "CLOCK$", "NUL .txt"):
            with self.assertRaises(WorkspaceSecurityError, msg=name):
                safe_workspace_path(self.root, name, HIDDEN)
        self.assertEqual(safe_workspace_path(self.root, "console.txt", HIDDEN),
                         self.root / "console.txt")
        self.assertEqual(safe_workspace_path(self.root, "com10.txt", HIDDEN),
                         self.root / "com10.txt")

    @unittest.skipUnless(os.name == "nt", "Windows 8.3 short names")
    def test_rejects_short_name_alias_of_hidden_file(self):
        secret = self.root / ".mcp_secret"
        secret.write_text("x")
        short_root = _short_path(str(self.root))
        alias = _short_path(str(secret))[len(short_root) + 1:]
        if "~" not in alias:
            self.skipTest("8.3 names disabled on this volume")
        with self.assertRaises(WorkspaceSecurityError):
            safe_workspace_path(self.root, alias, HIDDEN)

    @unittest.skipUnless(os.name == "nt", "Windows junctions")
    def test_rejects_junction_to_outside(self):
        import _winapi
        outside = self.root.parent / (self.root.name + "-junction-target")
        outside.mkdir()
        junction = self.root / "junction"
        try:
            (outside / "secret.txt").write_text("x")
            _winapi.CreateJunction(str(outside), str(junction))
            with self.assertRaises(WorkspaceSecurityError):
                safe_workspace_path(self.root, "junction/secret.txt", HIDDEN)
            with self.assertRaises(WorkspaceSecurityError):
                atomic_write(junction / "new.txt", b"x", root=self.root)
            self.assertFalse((outside / "new.txt").exists())
            self.assertEqual(list_workspace_files(self.root, HIDDEN, max_entries=10, max_depth=2), [])
        finally:
            if junction.exists():
                os.rmdir(junction)
            shutil.rmtree(outside, ignore_errors=True)

    def test_rejects_symlink_to_outside(self):
        outside = self.root.parent / (self.root.name + "-outside")
        outside.mkdir(exist_ok=True)
        try:
            (self.root / "escape").symlink_to(outside, target_is_directory=True)
            with self.assertRaises(WorkspaceSecurityError):
                safe_workspace_path(self.root, "escape/secret.txt")
        finally:
            try:
                outside.rmdir()
            except OSError:
                pass

    def test_atomic_replace_and_append(self):
        target = self.root / "result.bin"
        self.assertEqual(atomic_write(target, b"first"), 5)
        self.assertEqual(atomic_write(target, b"-second", append=True), 12)
        self.assertEqual(target.read_bytes(), b"first-second")

    def test_append_limit_preserves_original(self):
        target = self.root / "bounded.txt"
        target.write_bytes(b"1234")
        with self.assertRaises(WorkspaceSecurityError):
            atomic_write(target, b"5678", append=True, max_existing_bytes=6)
        self.assertEqual(target.read_bytes(), b"1234")

    def test_refuses_symlink_destination(self):
        outside = self.root / "outside.txt"
        outside.write_text("safe")
        link = self.root / "link.txt"
        link.symlink_to(outside)
        with self.assertRaises(WorkspaceSecurityError):
            atomic_write(link, b"overwrite")
        self.assertEqual(outside.read_text(), "safe")

    def test_atomic_write_rejects_parent_outside_root(self):
        other_root = self.root / "other"
        other_root.mkdir()
        target = self.root / "a" / "f.txt"
        with self.assertRaises(WorkspaceSecurityError):
            atomic_write(target, b"x", root=other_root)
        self.assertFalse(target.exists())

    def test_atomic_write_creates_no_directory_through_link(self):
        outside = self.root / "outside"
        outside.mkdir()
        inside = self.root / "inside"
        inside.mkdir()
        (inside / "link").symlink_to(outside, target_is_directory=True)
        with self.assertRaises(WorkspaceSecurityError):
            atomic_write(inside / "link" / "sub" / "f.txt", b"x", root=inside)
        self.assertEqual(list(outside.iterdir()), [])
        self.assertEqual(
            atomic_write(inside / "new" / "f.txt", b"x", root=inside), 1
        )

    def test_read_file_bytes_roundtrip_and_limits(self):
        target = self.root / "read.txt"
        target.write_bytes(b"hello")
        self.assertEqual(read_file_bytes(target, 5), b"hello")
        with self.assertRaises(WorkspaceSecurityError):
            read_file_bytes(target, 4)
        with self.assertRaises(WorkspaceSecurityError):
            read_file_bytes(self.root, 10)

    def test_read_file_bytes_rejects_symlink(self):
        outside = self.root / "outside.txt"
        outside.write_text("safe")
        link = self.root / "link.txt"
        link.symlink_to(outside)
        with self.assertRaises(WorkspaceSecurityError):
            read_file_bytes(link, 10)

    def test_list_workspace_files_caps_and_prunes(self):
        for name in ("a.txt", "b.txt", "sub/c.txt", "sub/deep/d.txt", ".env", ".git/config",
                     ".env.local", "prod.env", ".ssh/id_ed25519", "cert.pem"):
            target = self.root / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text("x")
        outside = self.root.parent / (self.root.name + "-list-target")
        outside.mkdir()
        try:
            (self.root / "link").symlink_to(outside, target_is_directory=True)
            listed = list_workspace_files(self.root, HIDDEN, max_entries=10, max_depth=1)
        finally:
            link = self.root / "link"
            os.rmdir(link) if os.name == "nt" else os.unlink(link)
            shutil.rmtree(outside, ignore_errors=True)
        self.assertEqual(sorted(p.replace("\\", "/") for p in listed), ["a.txt", "b.txt", "sub/c.txt"])
        self.assertEqual(len(list_workspace_files(self.root, HIDDEN, max_entries=2, max_depth=8)), 2)


if __name__ == "__main__":
    unittest.main()
