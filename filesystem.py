"""Workspace filesystem guards and atomic file transactions."""
from __future__ import annotations

import os
import tempfile
import threading
from pathlib import Path

_LOCKS_GUARD = threading.Lock()
_PATH_LOCKS: dict[str, threading.RLock] = {}


class WorkspaceSecurityError(ValueError):
    """Raised when a workspace path violates filesystem policy."""


def _lock_for(path: Path) -> threading.RLock:
    key = os.path.normcase(str(path))
    with _LOCKS_GUARD:
        return _PATH_LOCKS.setdefault(key, threading.RLock())


def safe_workspace_path(workspace: Path, relative_path: str,
                        hidden_names: set[str] | None = None) -> Path:
    if not isinstance(relative_path, str) or not relative_path.strip():
        raise WorkspaceSecurityError("ต้องระบุพาธไฟล์ภายใน Workspace")
    candidate = Path(relative_path)
    if candidate.is_absolute() or candidate.drive or any(part == ".." for part in candidate.parts):
        raise WorkspaceSecurityError("ไม่อนุญาตพาธ absolute หรือ parent traversal")

    root = workspace.resolve(strict=True)
    current = root
    hidden = hidden_names or set()
    for part in candidate.parts:
        if part in ("", "."):
            continue
        if part in hidden:
            raise WorkspaceSecurityError("ไฟล์นี้เป็นไฟล์ลับของระบบ เข้าถึงไม่ได้")
        current = current / part
        try:
            info = current.lstat()
        except FileNotFoundError:
            continue
        if current.is_symlink():
            raise WorkspaceSecurityError("ไม่อนุญาตให้เข้าถึง symbolic link ใน Workspace")
        # Windows junctions/reparse points may not report as symlinks.
        if hasattr(info, "st_file_attributes"):
            reparse = getattr(info, "st_file_attributes", 0) & getattr(
                __import__("stat"), "FILE_ATTRIBUTE_REPARSE_POINT", 0x400
            )
            if reparse:
                raise WorkspaceSecurityError("ไม่อนุญาตให้เข้าถึง reparse point ใน Workspace")

    resolved = current.resolve(strict=False)
    if not resolved.is_relative_to(root):
        raise WorkspaceSecurityError("ไม่อนุญาตให้เข้าถึงไฟล์นอก Workspace")
    return resolved


def atomic_write(path: Path, data: bytes, *, append: bool = False,
                 max_existing_bytes: int = 100 * 1024 * 1024) -> int:
    """Atomically replace a file; append is implemented as locked read+replace."""
    path.parent.mkdir(parents=True, exist_ok=True)
    lock = _lock_for(path)
    with lock:
        if path.is_symlink():
            raise WorkspaceSecurityError("ไม่อนุญาตให้เขียนทับ symbolic link")
        existing = b""
        if append and path.exists():
            if not path.is_file():
                raise WorkspaceSecurityError("ปลายทางไม่ใช่ไฟล์ปกติ")
            size = path.stat().st_size
            if size > max_existing_bytes or size + len(data) > max_existing_bytes:
                raise WorkspaceSecurityError("ขนาดไฟล์หลัง append เกินขีดจำกัด")
            existing = path.read_bytes()
        payload = existing + data
        if len(payload) > max_existing_bytes:
            raise WorkspaceSecurityError("ขนาดไฟล์เกินขีดจำกัด")

        fd, temp_name = tempfile.mkstemp(prefix=".mcp-tmp-", dir=str(path.parent))
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
            if path.is_symlink():
                raise WorkspaceSecurityError("ตรวจพบ symbolic link ก่อน commit")
            os.replace(temp_name, path)
        except Exception:
            try:
                os.unlink(temp_name)
            except FileNotFoundError:
                pass
            raise
        return len(payload)
