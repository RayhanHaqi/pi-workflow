#!/usr/bin/env python3
"""Narrow Linux flock guardian for pi-bounded-coding-workflow M3.

The open file description and kernel flock are authoritative. The JSON owner
marker is diagnostic only and is written only after successful acquisition.
"""

from __future__ import annotations

import ctypes
import errno
import fcntl
import json
import os
import select
import signal
import stat
import sys
from typing import NoReturn

PROTOCOL = "flock-guardian-v1"
MAX_CONTROL_LINE = 4096


def emit(message: dict[str, object]) -> None:
    sys.stdout.write(json.dumps(message, sort_keys=True, separators=(",", ":")) + "\n")
    sys.stdout.flush()


def fail(code: str, message: str, exit_code: int = 70) -> NoReturn:
    emit({"type": "ERROR", "protocol": PROTOCOL, "code": code, "message": message})
    raise SystemExit(exit_code)


def exact_regular_mode(st: os.stat_result, mode: int) -> bool:
    return stat.S_ISREG(st.st_mode) and stat.S_IMODE(st.st_mode) == mode


def open_lock(path: str) -> int:
    existing: os.stat_result | None
    try:
        existing = os.lstat(path)
    except FileNotFoundError:
        existing = None
    except OSError:
        fail("INVALID_LOCK_PATH", "lock entry cannot be inspected")
    if existing is not None and not exact_regular_mode(existing, 0o600):
        fail("INVALID_LOCK_PATH", "existing lock entry is not a mode-0600 regular file")

    flags = os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC
    try:
        fd = os.open(path, flags, 0o600)
    except OSError:
        fail("INVALID_LOCK_PATH", "lock entry cannot be opened safely")
    try:
        observed = os.fstat(fd)
        if not stat.S_ISREG(observed.st_mode):
            fail("INVALID_LOCK_PATH", "lock entry is not a regular file")
        if existing is not None and (existing.st_dev != observed.st_dev or existing.st_ino != observed.st_ino):
            fail("INVALID_LOCK_PATH", "lock entry changed during open")
        if existing is None:
            os.fchmod(fd, 0o600)
        if stat.S_IMODE(os.fstat(fd).st_mode) != 0o600:
            fail("INVALID_LOCK_PATH", "lock entry mode is not 0600")
        return fd
    except BaseException:
        os.close(fd)
        raise


def write_marker(path: str, metadata: dict[str, object]) -> None:
    try:
        existing = os.lstat(path)
    except FileNotFoundError:
        existing = None
    except OSError:
        fail("INVALID_LOCK_PATH", "owner marker cannot be inspected")
    if existing is not None and not stat.S_ISREG(existing.st_mode):
        fail("INVALID_LOCK_PATH", "owner marker is not a regular file")
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW | os.O_CLOEXEC
    try:
        fd = os.open(path, flags, 0o600)
    except OSError:
        fail("INVALID_LOCK_PATH", "owner marker cannot be opened safely")
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            fail("INVALID_LOCK_PATH", "owner marker is not a regular file")
        os.fchmod(fd, 0o600)
        payload = (json.dumps(metadata, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
        offset = 0
        while offset < len(payload):
            written = os.write(fd, payload[offset:])
            if written <= 0:
                fail("INVALID_LOCK_PATH", "owner marker write made no progress")
            offset += written
        os.fsync(fd)
    finally:
        os.close(fd)
    directory_fd = os.open(os.path.dirname(path), os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)


def install_parent_death_signal(expected_parent: int) -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(1, signal.SIGTERM, 0, 0, 0) != 0:  # PR_SET_PDEATHSIG
        fail("LOCK_GUARDIAN_START_FAILED", "parent-death monitoring is unavailable")
    if os.getppid() != expected_parent:
        fail("LOCK_GUARDIAN_START_FAILED", "controller exited during guardian startup")


def main() -> None:
    if len(sys.argv) != 9:
        fail("LOCK_GUARDIAN_START_FAILED", "guardian argv is invalid")
    lock_path, marker_path, worktree_key, worktree_root, git_common_dir, acquired_at, parent_text, acquisition_nonce = sys.argv[1:]
    try:
        expected_parent = int(parent_text)
    except ValueError:
        fail("LOCK_GUARDIAN_START_FAILED", "controller pid is invalid")
    if len(acquisition_nonce) != 32 or any(character not in "0123456789abcdef" for character in acquisition_nonce):
        fail("LOCK_GUARDIAN_START_FAILED", "acquisition nonce is invalid")
    install_parent_death_signal(expected_parent)

    fd = open_lock(lock_path)
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as error:
            if error.errno in (errno.EACCES, errno.EAGAIN):
                fail("CONCURRENT_WRITER", "kernel lock is already held", 73)
            fail("LOCK_GUARDIAN_START_FAILED", "kernel lock acquisition failed")

        marker = {
            "protocol_version": PROTOCOL,
            "worktree_key": worktree_key,
            "worktree_root": worktree_root,
            "git_common_dir": git_common_dir,
            "controller_pid": expected_parent,
            "guardian_pid": os.getpid(),
            "acquired_at": acquired_at,
            "acquisition_nonce": acquisition_nonce,
        }
        write_marker(marker_path, marker)
        emit({
            "type": "READY",
            "protocol": PROTOCOL,
            "guardian_pid": os.getpid(),
            "acquisition_nonce": acquisition_nonce,
        })

        while True:
            if os.getppid() != expected_parent:
                return
            readable, _, _ = select.select([sys.stdin], [], [], 1.0)
            if not readable:
                continue
            line = sys.stdin.buffer.readline(MAX_CONTROL_LINE + 1)
            if line == b"":
                return
            if len(line) > MAX_CONTROL_LINE or not line.endswith(b"\n"):
                fail("LOCK_LOST", "control message exceeds protocol bound")
            try:
                message = json.loads(line.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                fail("LOCK_LOST", "control message is malformed")
            if not isinstance(message, dict) or set(message) not in ({"type", "nonce"}, {"type"}):
                fail("LOCK_LOST", "control message shape is invalid")
            kind = message.get("type")
            if kind == "PING" and set(message) == {"type", "nonce"} and isinstance(message.get("nonce"), str):
                nonce = message["nonce"]
                if len(nonce) > 128:
                    fail("LOCK_LOST", "health nonce exceeds protocol bound")
                emit({"type": "PONG", "protocol": PROTOCOL, "nonce": nonce})
            elif kind == "RELEASE" and set(message) == {"type"}:
                emit({"type": "RELEASED", "protocol": PROTOCOL})
                return
            else:
                fail("LOCK_LOST", "unsupported control message")
    finally:
        try:
            fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)


if __name__ == "__main__":
    main()
