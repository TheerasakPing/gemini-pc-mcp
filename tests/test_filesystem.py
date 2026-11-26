import tempfile
import unittest
from pathlib import Path

from filesystem import (
    WorkspaceSecurityError,
    atomic_write,
    safe_workspace_path,
)


class WorkspaceFilesystemTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

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
            safe_workspace_path(self.root, ".env/key", {".env"})

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


if __name__ == "__main__":
    unittest.main()
