"""Workspace filesystem guards and atomic file transactions."""
from __future__ import annotations

import os
import re
import stat
import tempfile
import threading
from pathlib import Path

_LOCKS_GUARD = threading.Lock()
_PATH_LOCKS: dict[str, threading.RLock] = {}
_INVALID_COMPONENT = re.compile(r'[<>:"|?*\x00-\x1f]')
_RESERVED_NAMES = {"con", "prn", "aux", "nul"} | {f"com{digit}" for digit in range(1, 10)} | {
    f"lpt{digit}" for digit in range(1, 10)
}
_REPARSE_POINT = 0x400


class WorkspaceSecurityError(ValueError):
    """Raised when a workspace path violates filesystem policy."""


def _lock_for(path: Path) -> threading.RLock:
    key = os.path.normcase(str(path))
    with _LOCKS_GUARD:
        return _PATH_LOCKS.setdefault(key, threading.RLock())


def _is_link_or_reparse(info: os.stat_result) -> bool:
    if stat.S_ISLNK(info.st_mode):
        return True
    # Windows junctions/reparse points may not report as symlinks.
    return bool(getattr(info, "st_file_attributes", 0) & _REPARSE_POINT)


def _reject_link_or_reparse(path: Path, message: str) -> None:
    try:
        info = path.lstat()
    except FileNotFoundError:
        return
    if _is_link_or_reparse(info):
        raise WorkspaceSecurityError(message)


def _validate_component(part: str, hidden: set[str]) -> None:
    folded = part.casefold()
    if folded in hidden:
        raise WorkspaceSecurityError("ไฟล์นี้เป็นไฟล์ลับของระบบ เข้าถึงไม่ได้")
    # Win32 silently strips trailing dots/spaces and rewrites the remaining name.
    if part != part.rstrip(" .") or _INVALID_COMPONENT.search(part):
        raise WorkspaceSecurityError("ชื่อไฟล์มีอักขระหรือรูปแบบที่ไม่อนุญาต")
    if folded.split(".")[0] in _RESERVED_NAMES:
        raise WorkspaceSecurityError("ชื่อไฟล์เป็นชื่ออุปกรณ์ที่ Windows สงวนไว้")


def _assert_in_root(directory: Path, root: Path | None) -> None:
    if root is None:
        return
    real_root = Path(os.path.realpath(root))
    real_directory = Path(os.path.realpath(directory))
    if real_directory != real_root and not real_directory.is_relative_to(real_root):
        raise WorkspaceSecurityError("ไม่อนุญาตให้เขียนไฟล์นอก Workspace")


def safe_workspace_path(workspace: Path, relative_path: str,
                        hidden_names: set[str] | None = None) -> Path:
    if not isinstance(relative_path, str) or not relative_path.strip():
        raise WorkspaceSecurityError("ต้องระบุพาธไฟล์ภายใน Workspace")
    candidate = Path(relative_path)
    if candidate.is_absolute() or candidate.drive or any(part == ".." for part in candidate.parts):
        raise WorkspaceSecurityError("ไม่อนุญาตพาธ absolute หรือ parent traversal")

    root = workspace.resolve(strict=True)
    current = root
    hidden = {name.casefold() for name in (hidden_names or set())}
    for part in candidate.parts:
        if part in ("", "."):
            continue
        _validate_component(part, hidden)
        current = current / part
        _reject_link_or_reparse(
            current, "ไม่อนุญาตให้เข้าถึง symbolic link หรือ reparse point ใน Workspace"
        )

    resolved = current.resolve(strict=False)
    if not resolved.is_relative_to(root):
        raise WorkspaceSecurityError("ไม่อนุญาตให้เข้าถึงไฟล์นอก Workspace")
    # resolve() expands 8.3 short names and canonical case, so re-check the final form.
    for part in resolved.relative_to(root).parts:
        _validate_component(part, hidden)
    return resolved


def read_file_bytes(path: Path, max_bytes: int) -> bytes:
    """Bounded read that verifies type, identity, and size on the open descriptor."""
    before = path.lstat()
    if _is_link_or_reparse(before):
        raise WorkspaceSecurityError("ไม่อนุญาตให้อ่านผ่าน symbolic link หรือ reparse point")
    if not stat.S_ISREG(before.st_mode):
        raise WorkspaceSecurityError("ปลายทางไม่ใช่ไฟล์ปกติ")
    # O_NONBLOCK keeps a swapped-in FIFO from blocking the open; fstat rejects it below.
    flags = (os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
             | getattr(os, "O_NONBLOCK", 0))
    descriptor = os.open(path, flags)
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode):
            raise WorkspaceSecurityError("ปลายทางไม่ใช่ไฟล์ปกติ")
        if before.st_ino and (info.st_dev, info.st_ino) != (before.st_dev, before.st_ino):
            raise WorkspaceSecurityError("ไฟล์ถูกเปลี่ยนระหว่างตรวจสอบ")
        if info.st_size > max_bytes:
            raise WorkspaceSecurityError("ไฟล์มีขนาดเกินขีดจำกัดการอ่าน")
        with os.fdopen(descriptor, "rb") as stream:
            descriptor = -1
            data = stream.read(max_bytes + 1)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if len(data) > max_bytes:
        raise WorkspaceSecurityError("ไฟล์มีขนาดเกินขีดจำกัดการอ่าน")
    return data


def list_workspace_files(workspace: Path, hidden_names: set[str], *,
                         max_entries: int, max_depth: int) -> list[str]:
    """Walk the workspace without following links, capped by entry count and depth."""
    root = workspace.resolve(strict=True)
    hidden = {name.casefold() for name in hidden_names}
    found: list[str] = []
    pending = [(root, 0)]
    while pending and len(found) < max_entries:
        directory, depth = pending.pop()
        try:
            with os.scandir(directory) as entries:
                for entry in entries:
                    if entry.name.casefold() in hidden:
                        continue
                    try:
                        info = entry.stat(follow_symlinks=False)
                    except OSError:
                        continue
                    if _is_link_or_reparse(info):
                        continue
                    if stat.S_ISDIR(info.st_mode):
                        if depth < max_depth:
                            pending.append((Path(entry.path), depth + 1))
                    elif stat.S_ISREG(info.st_mode):
                        found.append(str(Path(entry.path).relative_to(root)))
                        if len(found) >= max_entries:
                            break
        except OSError:
            continue
    return found


def atomic_write(path: Path, data: bytes, *, append: bool = False,
                 max_existing_bytes: int = 100 * 1024 * 1024,
                 root: Path | None = None) -> int:
    """Atomically replace a file; append is implemented as locked read+replace.

    root: re-check the real parent directory against this root before creating
    the temporary file and again before the replace (narrows the directory-swap race).
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    lock = _lock_for(path)
    with lock:
        _assert_in_root(path.parent, root)
        _reject_link_or_reparse(path, "ไม่อนุญาตให้เขียนทับ symbolic link")
        existing = b""
        if append and path.exists():
            existing = read_file_bytes(path, max_existing_bytes)
        payload = existing + data
        if len(payload) > max_existing_bytes:
            raise WorkspaceSecurityError("ขนาดไฟล์เกินขีดจำกัด")

        fd, temp_name = tempfile.mkstemp(prefix=".mcp-tmp-", dir=str(path.parent))
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
            _reject_link_or_reparse(path, "ตรวจพบ symbolic link หรือ reparse point ก่อน commit")
            _assert_in_root(path.parent, root)
            os.replace(temp_name, path)
        except Exception:
            try:
                os.unlink(temp_name)
            except FileNotFoundError:
                pass
            raise
        return len(payload)
