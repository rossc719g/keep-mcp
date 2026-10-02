"""Private local state; no note cache or credentials are stored here."""

import fcntl
import json
import os
import stat
import threading
import time
from contextlib import contextmanager
from pathlib import Path


class SafetyError(ValueError):
    """A message safe to return to an MCP caller."""


class InputError(TypeError):
    """A validation error safe to return to an MCP caller."""


def private_directory(path: Path) -> Path:
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = path.lstat()
    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.getuid()
        or info.st_mode & 0o077
    ):
        raise SafetyError("Local state must be an owner-only directory, not a symlink.")
    return path


def state_directory() -> Path:
    return private_directory(
        Path(
            os.environ.get("KEEP_MCP_STATE_DIR", Path.home() / ".local/state/keep-mcp")
        )
    )


def private_open(path: Path, flags: int) -> int:
    fd = os.open(path, flags | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    info = os.fstat(fd)
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid != os.getuid()
        or info.st_mode & 0o077
        or info.st_nlink != 1
    ):
        os.close(fd)
        raise SafetyError(
            "Local state must be an owner-only regular file with one link."
        )
    return fd


_thread_lock = threading.RLock()


@contextmanager
def operation_lock():
    with _thread_lock:
        fd = private_open(state_directory() / "operation.lock", os.O_CREAT | os.O_RDWR)
        try:
            deadline = time.monotonic() + 30
            while True:
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    if time.monotonic() >= deadline:
                        raise SafetyError(
                            "Another Keep operation is still running. No change was sent."
                        ) from None
                    time.sleep(0.05)
            yield
        finally:
            os.close(fd)


def append_audit(record: dict) -> None:
    fd = private_open(
        state_directory() / "mutations.jsonl", os.O_CREAT | os.O_WRONLY | os.O_APPEND
    )
    try:
        data = (
            json.dumps(record, separators=(",", ":"), sort_keys=True) + "\n"
        ).encode()
        while data:
            count = os.write(fd, data)
            if count <= 0:
                raise OSError("Audit append failed")
            data = data[count:]
        os.fsync(fd)
    finally:
        os.close(fd)


def export_directory(destination: str) -> Path:
    root = private_directory(state_directory() / "exports")
    path = Path(destination)
    if path.is_absolute():
        try:
            path = path.relative_to(root)
        except ValueError:
            raise SafetyError(
                "Media exports must stay inside the private Keep exports directory."
            ) from None
    current = root
    for part in path.parts:
        if part in ("..", ".") or len(part) > 100:
            raise SafetyError("Invalid media export subdirectory.")
        current = private_directory(current / part)
    return current
