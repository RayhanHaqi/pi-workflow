#!/usr/bin/env python3
"""Linux FD-relative secure filesystem helper for the bounded M4 gateway."""
from __future__ import annotations

import base64
import ctypes
import errno
import hashlib
import json
import os
import platform
import re
import socket
import stat
import sys
import tempfile
from pathlib import Path
from typing import Any

PROTOCOL = "pi-gacw-secure-fs-v1"
MAX_REQUEST = 2 * 1024 * 1024
MAX_RESPONSE = 8 * 1024 * 1024
RESOLVE_NO_MAGICLINKS = 0x02
RESOLVE_NO_SYMLINKS = 0x04
RESOLVE_BENEATH = 0x08
REQUIRED_RESOLVE = RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS
RENAME_NOREPLACE = 1
RENAME_EXCHANGE = 2
SYS_BY_ARCH = {
    "x86_64": {"openat2": 437, "renameat2": 316, "landlock_create_ruleset": 444},
    "aarch64": {"openat2": 437, "renameat2": 276, "landlock_create_ruleset": 444},
}
libc = ctypes.CDLL(None, use_errno=True)


class OpenHow(ctypes.Structure):
    _fields_ = [("flags", ctypes.c_uint64), ("mode", ctypes.c_uint64), ("resolve", ctypes.c_uint64)]


class SecureError(Exception):
    def __init__(self, code: str, detail: str, journal: dict[str, Any] | None = None):
        super().__init__(detail)
        self.code = code
        self.detail = detail
        self.journal = journal


def new_mutation_journal() -> dict[str, Any]:
    return {
        "temporary_file_created": False, "temporary_bytes_written": 0,
        "temporary_file_fsync_attempted": False, "temporary_file_fsync_completed": False,
        "atomic_operation": "NONE", "atomic_rename_attempted": False, "atomic_rename_completed": False,
        "directory_fsync_attempt_count": 0, "directory_fsync_completed_count": 0,
        "preimage_validation": "NOT_RUN", "rollback_required": False, "rollback_attempted": False,
        "rollback_completed": False, "rollback_directory_fsync_completed": False,
        "final_verification": "NOT_RUN", "operation_nonce": None,
        "temporary_device": None, "temporary_inode": None, "temporary_nlink": None,
        "tombstone_created": False, "tombstone_device": None, "tombstone_inode": None, "tombstone_nlink": None,
        "preimage_device": None, "preimage_inode": None, "preimage_nlink": None,
        "recovery_attempted": False, "recovery_outcome": "NOT_RUN", "recovery_residue_count": None,
        "recovery_target_verification": "NOT_RUN", "recovery_directory_fsync": "NOT_RUN", "recovery_helper_sha256": None,
    }


def emit_journal(journal: dict[str, Any]) -> None:
    try:
        encoded = (json.dumps({"protocol": PROTOCOL, "mutation_journal": journal}, sort_keys=True, separators=(",", ":")) + "\n").encode()
        os.write(3, encoded)
    except OSError:
        pass


def journal_set(journal: dict[str, Any], **values: Any) -> None:
    journal.update(values)
    emit_journal(journal)


def journal_fsync(parent_fd: int, journal: dict[str, Any], request: dict[str, Any], rollback: bool = False) -> None:
    prefix = "ROLLBACK_" if rollback else ""
    mutation_stage(request, f"BEFORE_{prefix}DIRECTORY_FSYNC", journal)
    journal_set(journal, directory_fsync_attempt_count=journal["directory_fsync_attempt_count"] + 1)
    checkpoint(request, f"DURING_{prefix}DIRECTORY_FSYNC")
    fail_seam(request, f"DURING_{prefix}DIRECTORY_FSYNC")
    os.fsync(parent_fd)
    journal_set(journal, directory_fsync_completed_count=journal["directory_fsync_completed_count"] + 1,
                rollback_directory_fsync_completed=journal["rollback_directory_fsync_completed"] or rollback)
    mutation_stage(request, f"AFTER_{prefix}DIRECTORY_FSYNC", journal)


def syscalls() -> dict[str, int]:
    result = SYS_BY_ARCH.get(platform.machine())
    if result is None:
        raise SecureError("SECURE_WRITE_PRIMITIVE_UNAVAILABLE", "Unsupported kernel architecture")
    return result


def syscall(number: int, *args: Any) -> int:
    result = libc.syscall(number, *args)
    if result < 0:
        value = ctypes.get_errno()
        raise OSError(value, os.strerror(value))
    return int(result)


def openat2(directory_fd: int, path: str, flags: int, mode: int = 0) -> int:
    encoded = os.fsencode(path)
    how = OpenHow(flags, mode, REQUIRED_RESOLVE)
    return syscall(syscalls()["openat2"], directory_fd, ctypes.c_char_p(encoded), ctypes.byref(how), ctypes.sizeof(how))


def renameat2(old_fd: int, old: str, new_fd: int, new: str, flags: int) -> None:
    syscall(syscalls()["renameat2"], old_fd, ctypes.c_char_p(os.fsencode(old)), new_fd, ctypes.c_char_p(os.fsencode(new)), flags)


def canonical_path(value: Any) -> str:
    if not isinstance(value, str) or not value or len(value) > 4096 or "\x00" in value:
        raise SecureError("INVALID_CANONICAL_PATH", "Path is not a bounded nonempty string")
    if value.startswith("/") or "\\" in value or value.endswith("/"):
        raise SecureError("INVALID_CANONICAL_PATH", "Path is not repository-relative canonical form")
    parts = value.split("/")
    if any(part in ("", ".", "..") for part in parts):
        raise SecureError("INVALID_CANONICAL_PATH", "Path contains a forbidden component")
    if value.startswith("proc/self/fd/"):
        raise SecureError("MAGICLINK_PATH", "Magic-link path is forbidden")
    return value


def exact_keys(value: dict[str, Any], required: set[str], optional: set[str] = set()) -> None:
    if set(value) != required | (set(value) & optional) or not required.issubset(value):
        raise SecureError("INVALID_ARGUMENT", "Request has unexpected or missing fields")


def fd_identity(fd: int) -> dict[str, int]:
    st = os.fstat(fd)
    return {"device": st.st_dev, "inode": st.st_ino}


def open_root(request: dict[str, Any]) -> tuple[int, dict[str, int]]:
    root = request.get("root")
    expected = request.get("root_identity")
    if not isinstance(root, str) or not os.path.isabs(root) or os.path.normpath(root) != root or not isinstance(expected, dict):
        raise SecureError("PATH_OUTSIDE_ROOT", "Root authority is malformed")
    try:
        fd = os.open(root, os.O_PATH | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
    except OSError as error:
        raise SecureError("PATH_OUTSIDE_ROOT", f"Root descriptor open failed ({error.errno})") from error
    try:
        st = os.fstat(fd)
        if not stat.S_ISDIR(st.st_mode):
            raise SecureError("PATH_OUTSIDE_ROOT", "Root descriptor is not a directory")
        if os.path.realpath(root) != expected.get("realpath") or st.st_dev != expected.get("device") or st.st_ino != expected.get("inode"):
            raise SecureError("SECURE_FS_CAPABILITY_MISMATCH", "Root physical identity differs")
        return fd, {"device": st.st_dev, "inode": st.st_ino}
    except BaseException:
        os.close(fd)
        raise


def open_parent(root_fd: int, path: str) -> tuple[int, str, dict[str, int]]:
    parent, name = path.rsplit("/", 1) if "/" in path else ("", path)
    try:
        fd = os.open(".", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC, dir_fd=root_fd) if parent == "" else openat2(root_fd, parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    except OSError as error:
        code = "SYMLINK_PATH" if error.errno in (errno.ELOOP, errno.EXDEV) else "TARGET_MISSING"
        raise SecureError(code, f"Parent descriptor open failed ({error.errno})") from error
    return fd, name, fd_identity(fd)


def revalidate_parent(root_fd: int, path: str, expected: dict[str, int]) -> bool:
    parent = path.rsplit("/", 1)[0] if "/" in path else ""
    try:
        fd = os.open(".", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC, dir_fd=root_fd) if parent == "" else openat2(root_fd, parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    except OSError:
        return False
    try:
        return fd_identity(fd) == expected
    finally:
        os.close(fd)


def same_inode(left: dict[str, Any], right: dict[str, Any]) -> bool:
    return left.get("device") == right.get("device") and left.get("inode") == right.get("inode")


def stable_tuple(st: os.stat_result) -> tuple[int, ...]:
    return (st.st_dev, st.st_ino, st.st_mode, st.st_size, st.st_mtime_ns, st.st_ctime_ns, st.st_nlink)


def hash_fd(fd: int, maximum: int) -> tuple[str, int, os.stat_result]:
    before = os.fstat(fd)
    if not stat.S_ISREG(before.st_mode):
        raise SecureError("SPECIAL_FILE", "Target is not a regular file")
    if before.st_size < 0 or before.st_size > maximum:
        raise SecureError("READ_LIMIT_EXCEEDED", "File exceeds the authorized hashing limit")
    digest = hashlib.sha256()
    offset = 0
    while offset < before.st_size:
        chunk = os.pread(fd, min(65536, before.st_size - offset), offset)
        if not chunk:
            raise SecureError("PREIMAGE_MISMATCH", "File changed while hashing")
        digest.update(chunk)
        offset += len(chunk)
    after = os.fstat(fd)
    if stable_tuple(before) != stable_tuple(after):
        raise SecureError("PREIMAGE_MISMATCH", "File identity changed while hashing")
    return "sha256:" + digest.hexdigest(), before.st_size, before


def metadata(fd: int, maximum: int) -> dict[str, Any]:
    digest, size, st = hash_fd(fd, maximum)
    return {"digest": digest, "size": size, "mode": stat.S_IMODE(st.st_mode), "device": st.st_dev, "inode": st.st_ino, "nlink": st.st_nlink}


def open_regular(root_fd: int, path: str, maximum: int) -> tuple[int, dict[str, Any]]:
    try:
        fd = openat2(root_fd, path, os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC)
    except OSError as error:
        if error.errno in (errno.ELOOP, errno.EXDEV):
            raise SecureError("SYMLINK_PATH", "Symlink or magic-link resolution was denied") from error
        if error.errno == errno.ENOENT:
            raise SecureError("TARGET_MISSING", "Target does not exist") from error
        raise SecureError("PATH_NOT_READABLE", f"Target open failed ({error.errno})") from error
    try:
        return fd, metadata(fd, maximum)
    except BaseException:
        os.close(fd)
        raise


def checkpoint(request: dict[str, Any], stage: str) -> None:
    checkpoints = [
        (request.get("_checkpoint_stage"), request.get("_checkpoint_socket")),
        (request.get("_secondary_checkpoint_stage"), request.get("_secondary_checkpoint_socket")),
    ]
    for selected, address in checkpoints:
        if selected != stage or not isinstance(address, str):
            continue
        client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            client.connect(address)
            client.sendall((stage + "\n").encode())
            if client.recv(1) != b"1":
                raise SecureError("SECURE_WRITE_UNCERTAIN", "Private checkpoint controller aborted")
            if request.get("_kill_stage") == stage: os.kill(os.getpid(), 9)
        finally:
            client.close()


def fail_seam(request: dict[str, Any], stage: str) -> None:
    if request.get("_fail_stage") == stage:
        raise OSError(errno.EIO, "injected private failure")


def recovery_checkpoint(request: dict[str, Any], stage: str) -> None:
    if request.get("_recovery_checkpoint_stage") != stage or not isinstance(request.get("_recovery_checkpoint_socket"), str):
        if request.get("_recovery_fail_stage") == stage:
            raise OSError(errno.EIO, f"injected recovery failure ({stage})")
        if request.get("_recovery_kill_stage") == stage:
            os.kill(os.getpid(), 9)
        return
    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        client.connect(request["_recovery_checkpoint_socket"])
        client.sendall((stage + "\n").encode())
        if client.recv(1) != b"1": raise SecureError("SECURE_WRITE_UNCERTAIN", "Private recovery checkpoint controller aborted")
        if request.get("_recovery_kill_stage") == stage: os.kill(os.getpid(), 9)
    finally:
        client.close()
    if request.get("_recovery_fail_stage") == stage:
        raise OSError(errno.EIO, f"injected recovery failure ({stage})")


def recovery_fail_seam(request: dict[str, Any], stage: str) -> None:
    if request.get("_recovery_kill_stage") == stage:
        os.kill(os.getpid(), 9)
    if request.get("_recovery_fail_stage") == stage:
        raise OSError(errno.EIO, f"injected recovery failure ({stage})")


def validate_operation_identity(request: dict[str, Any], path: str, operation: str, parent_identity: dict[str, int]) -> dict[str, Any]:
    value = request.get("operation_identity")
    required = {"run_id", "repository_identity_content_sha256", "worktree_identity", "target_path", "parent_path", "operation",
                "operation_nonce", "temporary_name", "tombstone_name", "parent_identity", "prior_state_token_content_sha256", "secure_fs_capability_content_sha256"}
    if not isinstance(value, dict) or set(value) != required:
        raise SecureError("INVALID_ARGUMENT", "Mutation operation identity is malformed")
    if value["target_path"] != path or value["operation"] != operation:
        raise SecureError("INVALID_ARGUMENT", "Mutation operation identity differs from the request")
    expected_parent = path.rsplit("/", 1)[0] if "/" in path else ""
    if value["parent_path"] != expected_parent or value["parent_identity"] != parent_identity:
        raise SecureError("PARENT_IDENTITY_DRIFT", "Mutation parent identity differs from the controller authority")
    if not isinstance(value["run_id"], str) or not 1 <= len(value["run_id"]) <= 64 or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}", value["run_id"]):
        raise SecureError("INVALID_ARGUMENT", "Mutation run identity is malformed")
    for key in ("repository_identity_content_sha256", "worktree_identity", "secure_fs_capability_content_sha256"):
        if not isinstance(value[key], str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", value[key]):
            raise SecureError("INVALID_ARGUMENT", "Mutation authority digest is malformed")
    prior = value["prior_state_token_content_sha256"]
    if prior is not None and (not isinstance(prior, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", prior)):
        raise SecureError("INVALID_ARGUMENT", "Prior state-token identity is malformed")
    nonce = value["operation_nonce"]
    if not isinstance(nonce, str) or not re.fullmatch(r"[0-9a-f]{32}", nonce):
        raise SecureError("INVALID_ARGUMENT", "Mutation operation nonce is malformed")
    name = path.rsplit("/", 1)[-1]
    temporary = value["temporary_name"]; tombstone = value["tombstone_name"]
    expected_temporary = None if operation == "DELETE" else f".{name}.m4tmp-{nonce}"
    expected_tombstone = f".{name}.m4tomb-{nonce}" if operation == "DELETE" else None
    if temporary != expected_temporary or tombstone != expected_tombstone:
        raise SecureError("INVALID_ARGUMENT", "Mutation residue names are not controller-derived")
    for residue in (temporary, tombstone):
        if residue is not None and (len(residue) > 255 or "/" in residue or not re.fullmatch(r"\.[^/]+\.m4(?:tmp|tomb)-[0-9a-f]{32}", residue)):
            raise SecureError("INVALID_ARGUMENT", "Mutation residue name is malformed")
    return value


def identity_from_journal(journal: Any, prefix: str) -> dict[str, int] | None:
    if not isinstance(journal, dict): return None
    values = {key: journal.get(f"{prefix}_{key}") for key in ("device", "inode", "nlink")}
    if any(not isinstance(value, int) or isinstance(value, bool) or value < 0 for value in values.values()): return None
    return values


def mutation_stage(request: dict[str, Any], stage: str, journal: dict[str, Any]) -> None:
    """Publish the current append-forward journal before a private deterministic seam."""
    emit_journal(journal)
    checkpoint(request, stage)
    fail_seam(request, stage)


def perform_read(request: dict[str, Any]) -> dict[str, Any]:
    path = canonical_path(request.get("path"))
    offset, length, maximum, hash_limit = (request.get(k) for k in ("offset", "length", "maximum", "hash_limit"))
    if not all(isinstance(x, int) and not isinstance(x, bool) and x >= 0 for x in (offset, length, maximum, hash_limit)) or length > maximum:
        raise SecureError("READ_LIMIT_EXCEEDED", "Read bounds are invalid")
    root_fd, root_identity = open_root(request)
    try:
        fd, before = open_regular(root_fd, path, hash_limit)
        try:
            if offset > before["size"]:
                data = b""
            else:
                data = os.pread(fd, min(length, before["size"] - offset), offset)
            after = metadata(fd, hash_limit)
            if before != after:
                raise SecureError("PREIMAGE_MISMATCH", "File changed during read")
            return {"root_identity": root_identity, "path": path, "metadata": after, "offset": offset, "bytes": len(data), "data_base64": base64.b64encode(data).decode("ascii")}
        finally:
            os.close(fd)
    finally:
        os.close(root_fd)


def entry_type(st: os.stat_result) -> str:
    if stat.S_ISREG(st.st_mode): return "REGULAR"
    if stat.S_ISDIR(st.st_mode): return "DIRECTORY"
    if stat.S_ISLNK(st.st_mode): return "SYMLINK"
    if stat.S_ISFIFO(st.st_mode): return "FIFO"
    if stat.S_ISSOCK(st.st_mode): return "SOCKET"
    if stat.S_ISCHR(st.st_mode): return "CHAR_DEVICE"
    if stat.S_ISBLK(st.st_mode): return "BLOCK_DEVICE"
    return "SPECIAL"


def perform_list(request: dict[str, Any]) -> dict[str, Any]:
    start = request.get("path")
    if start == "":
        start = None
    elif start is not None:
        start = canonical_path(start)
    max_depth, max_entries, max_metadata, hash_limit = (request.get(k) for k in ("max_depth", "max_entries", "max_metadata_bytes", "hash_limit"))
    if not all(isinstance(x, int) and not isinstance(x, bool) and x >= 0 for x in (max_depth, max_entries, max_metadata, hash_limit)):
        raise SecureError("LIST_LIMIT_EXCEEDED", "List bounds are invalid")
    root_fd, root_identity = open_root(request)
    entries: list[dict[str, Any]] = []
    metadata_bytes = 0
    try:
        if start is None:
            initial = os.dup(root_fd)
            prefix = ""
        else:
            try: initial = openat2(root_fd, start, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
            except OSError as error:
                code = "SYMLINK_PATH" if error.errno in (errno.ELOOP, errno.EXDEV) else "PATH_NOT_READABLE"
                raise SecureError(code, "List root cannot be opened safely") from error
            prefix = start
        queue: list[tuple[int, str, int]] = [(initial, prefix, 0)];queue_index = 0
        while queue_index < len(queue):
            directory_fd, directory_path, depth = queue[queue_index];queue_index += 1
            try:
                names = sorted(os.listdir(directory_fd), key=lambda x: os.fsencode(x))
                for name in names:
                    child = f"{directory_path}/{name}" if directory_path else name
                    try: canonical_path(child)
                    except SecureError: raise SecureError("INVALID_CANONICAL_PATH", "Directory contains an unsupported path")
                    st = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                    kind = entry_type(st)
                    item: dict[str, Any] = {"path": child, "type": kind, "mode": stat.S_IMODE(st.st_mode), "size": st.st_size, "digest": None}
                    if kind == "REGULAR" and request.get("hash_files") is True:
                        fd, meta = open_regular(root_fd, child, hash_limit)
                        os.close(fd); item["digest"] = meta["digest"]
                    encoded = json.dumps(item, separators=(",", ":")).encode()
                    metadata_bytes += len(encoded)
                    if len(entries) >= max_entries or metadata_bytes > max_metadata:
                        raise SecureError("LIST_LIMIT_EXCEEDED", "List result exceeds its bound")
                    entries.append(item)
                    if kind == "DIRECTORY" and depth < max_depth:
                        try: child_fd = openat2(root_fd, child, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
                        except OSError as error: raise SecureError("PARENT_IDENTITY_DRIFT", "Directory changed during listing") from error
                        queue.append((child_fd, child, depth + 1))
            finally:
                os.close(directory_fd)
        entries.sort(key=lambda x: os.fsencode(x["path"]))
        return {"root_identity": root_identity, "path": start, "entries": entries, "metadata_bytes": metadata_bytes}
    finally:
        os.close(root_fd)


def assert_preimage(actual: dict[str, Any], expected: dict[str, Any]) -> None:
    for key in ("digest", "size", "mode"):
        if actual.get(key) != expected.get(key):
            raise SecureError("PREIMAGE_MISMATCH", "Target preimage metadata differs")
    if actual.get("nlink") != 1:
        raise SecureError("HARDLINK_TARGET", "Multiply linked mutation target is forbidden")


def create_temp(parent_fd: int, temp: str, data: bytes, mode: int, request: dict[str, Any], journal: dict[str, Any]) -> tuple[str, int, dict[str, int]]:
    mutation_stage(request, "BEFORE_TEMPORARY_CREATION", journal)
    fd = os.open(temp, os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_RDWR | os.O_CLOEXEC, mode, dir_fd=parent_fd)
    temporary_stat = os.fstat(fd)
    journal_set(journal, temporary_file_created=True, temporary_device=temporary_stat.st_dev, temporary_inode=temporary_stat.st_ino, temporary_nlink=temporary_stat.st_nlink)
    try:
        mutation_stage(request, "AFTER_TEMPORARY_CREATION", journal)
        os.fchmod(fd, mode)
        offset = 0
        while offset < len(data):
            written = os.write(fd, data[offset:])
            if written <= 0: raise SecureError("SECURE_WRITE_UNCERTAIN", "Temporary write made no progress")
            offset += written
            journal_set(journal, temporary_bytes_written=offset)
        checkpoint(request, "TEMP_WRITTEN")
        mutation_stage(request, "AFTER_BYTES_WRITTEN", journal)
        mutation_stage(request, "BEFORE_TEMPORARY_FSYNC", journal)
        journal_set(journal, temporary_file_fsync_attempted=True)
        fail_seam(request, "FILE_FSYNC")
        checkpoint(request, "DURING_TEMPORARY_FSYNC")
        fail_seam(request, "DURING_TEMPORARY_FSYNC")
        os.fsync(fd)
        journal_set(journal, temporary_file_fsync_completed=True)
        checkpoint(request, "FILE_SYNCED")
        mutation_stage(request, "AFTER_TEMPORARY_FSYNC", journal)
        identity = fd_identity(fd)
        return temp, fd, identity
    except BaseException:
        os.close(fd)
        try: os.unlink(temp, dir_fd=parent_fd)
        except OSError as cleanup_error: raise SecureError("SECURE_WRITE_UNCERTAIN", "Temporary-file cleanup failed", journal.copy()) from cleanup_error
        raise


def unlink_quiet(parent_fd: int, name: str) -> None:
    try: os.unlink(name, dir_fd=parent_fd)
    except FileNotFoundError: pass


def perform_mutation(request: dict[str, Any]) -> dict[str, Any]:
    journal = new_mutation_journal();emit_journal(journal)
    path = canonical_path(request.get("path"));operation = request.get("mutation")
    if operation not in ("CREATE", "REPLACE", "DELETE"):
        raise SecureError("INVALID_ARGUMENT", "Mutation operation is invalid", journal.copy())
    maximum = request.get("hash_limit")
    if not isinstance(maximum, int) or isinstance(maximum, bool) or maximum < 0:
        raise SecureError("INVALID_ARGUMENT", "Hash bound is invalid", journal.copy())
    replacement = b"";final_mode = request.get("final_mode")
    if operation != "DELETE":
        try: replacement = base64.b64decode(request.get("replacement_base64"), validate=True)
        except Exception as error: raise SecureError("INVALID_ARGUMENT", "Replacement encoding is invalid", journal.copy()) from error
        if not isinstance(final_mode, int) or final_mode < 0 or final_mode > 0o777:
            raise SecureError("INVALID_ARGUMENT", "Final mode is invalid", journal.copy())
        if len(replacement) > maximum:
            raise SecureError("PATCH_LIMIT_EXCEEDED", "Replacement exceeds patch limit", journal.copy())
    expected = request.get("expected")
    if not isinstance(expected, dict): raise SecureError("INVALID_ARGUMENT", "Preimage authority is missing", journal.copy())
    root_fd, root_identity = open_root(request)
    parent_fd = -1;installed_fd = -1;temp_fd = -1;temp: str | None = None;tomb: str | None = None
    before: dict[str, Any] | None = None;created_identity: dict[str, int] | None = None;installed_signature: tuple[int, ...] | None = None
    try:
        parent_fd, name, parent_identity = open_parent(root_fd, path)
        authority = validate_operation_identity(request, path, operation, parent_identity)
        journal_set(journal, operation_nonce=authority["operation_nonce"])
        checkpoint(request, "PARENT_OPENED")
        mutation_stage(request, "BEFORE_PREIMAGE_VALIDATION", journal)
        if operation == "CREATE":
            try:
                existing = openat2(root_fd, path, os.O_PATH | os.O_CLOEXEC);os.close(existing)
                raise SecureError("TARGET_ALREADY_EXISTS", "Create target already exists")
            except OSError as error:
                if error.errno != errno.ENOENT:
                    if error.errno in (errno.ELOOP, errno.EXDEV): raise SecureError("SYMLINK_PATH", "Create target is a symlink") from error
                    raise
            journal_set(journal, preimage_validation="PASS")
            temp, temp_fd, created_identity = create_temp(parent_fd, authority["temporary_name"], replacement, final_mode, request, journal)
            if not revalidate_parent(root_fd, path, parent_identity): raise SecureError("PARENT_IDENTITY_DRIFT", "Parent path identity changed")
            journal_set(journal, atomic_operation="RENAME_NOREPLACE", atomic_rename_attempted=True)
            checkpoint(request, "BEFORE_RENAME");checkpoint(request, "BEFORE_ATOMIC_RENAME");fail_seam(request, "BEFORE_ATOMIC_RENAME")
            try: renameat2(parent_fd, temp, parent_fd, name, RENAME_NOREPLACE);temp = None
            except OSError as error:
                if error.errno == errno.EEXIST: raise SecureError("TARGET_ALREADY_EXISTS", "Create lost a no-replace race") from error
                raise
            journal_set(journal, atomic_rename_completed=True)
            mutation_stage(request, "AFTER_ATOMIC_RENAME", journal)
            checkpoint(request, "RENAMED_BEFORE_FINAL_OPEN")
            try:
                installed_fd = openat2(parent_fd, name, os.O_PATH | os.O_CLOEXEC)
                if created_identity is None or fd_identity(installed_fd) != created_identity or fd_identity(temp_fd) != created_identity:
                    raise SecureError("FINAL_TARGET_IDENTITY_MISMATCH", "Created target is not the retained temporary inode")
                installed_signature = stable_tuple(os.fstat(installed_fd))
            except BaseException as identity_error:
                journal_set(journal, final_verification="FAIL", rollback_required=True, rollback_attempted=True)
                try:
                    mutation_stage(request, "BEFORE_ROLLBACK", journal)
                    mutation_stage(request, "DURING_ROLLBACK", journal)
                    unlink_quiet(parent_fd, name)
                    journal_set(journal, rollback_completed=True)
                    mutation_stage(request, "AFTER_ROLLBACK_EXCHANGE", journal)
                    journal_fsync(parent_fd, journal, request, rollback=True)
                except BaseException as rollback_error:
                    raise SecureError("ROLLBACK_UNCERTAIN", "Create rollback could not be proven", journal.copy()) from rollback_error
                if isinstance(identity_error, SecureError): raise SecureError(identity_error.code, identity_error.detail, journal.copy())
                raise SecureError("FINAL_TARGET_IDENTITY_MISMATCH", "Created target cannot be rebound to the retained temporary inode", journal.copy()) from identity_error
            checkpoint(request, "RENAMED")
            fail_seam(request, "DIRECTORY_FSYNC");journal_fsync(parent_fd, journal, request)
        elif operation == "REPLACE":
            target_fd, before = open_regular(root_fd, path, maximum)
            journal_set(journal, preimage_device=before["device"], preimage_inode=before["inode"], preimage_nlink=before["nlink"])
            try:
                try: assert_preimage(before, expected);journal_set(journal, preimage_validation="PASS")
                except SecureError:
                    journal_set(journal, preimage_validation="FAIL")
                    mutation_stage(request, "AFTER_FAILED_PREIMAGE_VALIDATION", journal)
                    raise
            finally: os.close(target_fd)
            temp, temp_fd, created_identity = create_temp(parent_fd, authority["temporary_name"], replacement, final_mode, request, journal)
            if not revalidate_parent(root_fd, path, parent_identity): raise SecureError("PARENT_IDENTITY_DRIFT", "Parent path identity changed")
            journal_set(journal, atomic_operation="RENAME_EXCHANGE", atomic_rename_attempted=True)
            checkpoint(request, "BEFORE_RENAME");checkpoint(request, "BEFORE_ATOMIC_RENAME");fail_seam(request, "BEFORE_ATOMIC_RENAME")
            try: renameat2(parent_fd, temp, parent_fd, name, RENAME_EXCHANGE)
            except OSError as error:
                if error.errno == errno.ENOENT: raise SecureError("TARGET_MISSING", "Replace target or temporary entry disappeared") from error
                raise
            journal_set(journal, atomic_rename_completed=True)
            mutation_stage(request, "AFTER_ATOMIC_RENAME", journal)
            checkpoint(request, "EXCHANGED_BEFORE_FINAL_OPEN")
            installed_mismatch = False;displaced_error: BaseException | None = None
            try:
                installed_fd = openat2(parent_fd, name, os.O_PATH | os.O_CLOEXEC)
                installed_mismatch = created_identity is None or fd_identity(installed_fd) != created_identity or fd_identity(temp_fd) != created_identity
                if not installed_mismatch: installed_signature = stable_tuple(os.fstat(installed_fd))
            except BaseException:
                installed_mismatch = True
            checkpoint(request, "EXCHANGED")
            try:
                displaced_fd = openat2(parent_fd, temp, os.O_RDONLY | os.O_CLOEXEC)
                try:
                    displaced = metadata(displaced_fd, maximum);assert_preimage(displaced, expected)
                    if before is None or not same_inode(displaced, before): raise SecureError("PREIMAGE_MISMATCH", "Replace target identity changed before exchange")
                finally: os.close(displaced_fd)
            except BaseException as mismatch:
                displaced_error = mismatch
            if installed_mismatch or displaced_error is not None:
                journal_set(journal, final_verification="FAIL" if installed_mismatch else journal["final_verification"],
                            preimage_validation="FAIL" if displaced_error is not None else journal["preimage_validation"], rollback_required=True, rollback_attempted=True)
                try:
                    mutation_stage(request, "BEFORE_ROLLBACK", journal)
                    fail_seam(request, "ROLLBACK")
                    mutation_stage(request, "DURING_ROLLBACK", journal)
                    try: renameat2(parent_fd, temp, parent_fd, name, RENAME_EXCHANGE)
                    except OSError as exchange_error:
                        if exchange_error.errno != errno.ENOENT: raise
                        renameat2(parent_fd, temp, parent_fd, name, RENAME_NOREPLACE);temp = None
                    journal_set(journal, rollback_completed=True)
                    mutation_stage(request, "AFTER_ROLLBACK_EXCHANGE", journal)
                    journal_fsync(parent_fd, journal, request, rollback=True)
                    if temp is not None: os.unlink(temp, dir_fd=parent_fd);temp = None
                    journal_fsync(parent_fd, journal, request, rollback=True)
                except BaseException as rollback_error:
                    raise SecureError("ROLLBACK_UNCERTAIN", "Replace rollback could not be proven", journal.copy()) from rollback_error
                if installed_mismatch: raise SecureError("FINAL_TARGET_IDENTITY_MISMATCH", "Replacement target is not the retained temporary inode", journal.copy())
                if isinstance(displaced_error, SecureError): raise SecureError(displaced_error.code, displaced_error.detail, journal.copy())
                raise SecureError("PREIMAGE_MISMATCH", "Displaced preimage cannot be validated", journal.copy()) from displaced_error
            os.unlink(temp, dir_fd=parent_fd);temp = None
            fail_seam(request, "DIRECTORY_FSYNC");journal_fsync(parent_fd, journal, request)
        else:
            target_fd, before = open_regular(root_fd, path, maximum)
            journal_set(journal, preimage_device=before["device"], preimage_inode=before["inode"], preimage_nlink=before["nlink"])
            try:
                try: assert_preimage(before, expected);journal_set(journal, preimage_validation="PASS")
                except SecureError:
                    journal_set(journal, preimage_validation="FAIL")
                    mutation_stage(request, "AFTER_FAILED_PREIMAGE_VALIDATION", journal)
                    raise
            finally: os.close(target_fd)
            tomb = authority["tombstone_name"]
            if not revalidate_parent(root_fd, path, parent_identity): raise SecureError("PARENT_IDENTITY_DRIFT", "Parent path identity changed")
            journal_set(journal, atomic_operation="TOMBSTONE_NOREPLACE", atomic_rename_attempted=True)
            checkpoint(request, "BEFORE_RENAME");checkpoint(request, "BEFORE_ATOMIC_RENAME");fail_seam(request, "BEFORE_ATOMIC_RENAME")
            try: renameat2(parent_fd, name, parent_fd, tomb, RENAME_NOREPLACE)
            except OSError as error:
                if error.errno == errno.ENOENT: raise SecureError("TARGET_MISSING", "Delete target disappeared") from error
                if error.errno == errno.EEXIST: raise SecureError("SECURE_WRITE_UNCERTAIN", "Tombstone collision") from error
                raise
            tombstone_stat = os.stat(tomb, dir_fd=parent_fd, follow_symlinks=False)
            journal_set(journal, tombstone_created=True, tombstone_device=tombstone_stat.st_dev, tombstone_inode=tombstone_stat.st_ino, tombstone_nlink=tombstone_stat.st_nlink, atomic_rename_completed=True)
            mutation_stage(request, "AFTER_ATOMIC_RENAME", journal)
            checkpoint(request, "TOMBSTONED")
            try:
                moved_fd = openat2(parent_fd, tomb, os.O_RDONLY | os.O_CLOEXEC)
                try:
                    moved = metadata(moved_fd, maximum);assert_preimage(moved, expected)
                    if before is None or not same_inode(moved, before): raise SecureError("PREIMAGE_MISMATCH", "Delete target identity changed before rename")
                finally: os.close(moved_fd)
            except BaseException as mismatch:
                journal_set(journal, preimage_validation="FAIL", rollback_required=True, rollback_attempted=True)
                try:
                    mutation_stage(request, "BEFORE_ROLLBACK", journal)
                    fail_seam(request, "ROLLBACK")
                    mutation_stage(request, "DURING_ROLLBACK", journal)
                    renameat2(parent_fd, tomb, parent_fd, name, RENAME_NOREPLACE);tomb = None
                    journal_set(journal, rollback_completed=True)
                    mutation_stage(request, "AFTER_ROLLBACK_EXCHANGE", journal)
                    journal_fsync(parent_fd, journal, request, rollback=True)
                except BaseException as rollback_error:
                    raise SecureError("ROLLBACK_UNCERTAIN", "Delete rollback could not be proven", journal.copy()) from rollback_error
                if isinstance(mismatch, SecureError): raise SecureError(mismatch.code, mismatch.detail, journal.copy())
                raise SecureError("PREIMAGE_MISMATCH", "Moved preimage cannot be validated", journal.copy()) from mismatch
            fail_seam(request, "DIRECTORY_FSYNC");journal_fsync(parent_fd, journal, request)
            os.unlink(tomb, dir_fd=parent_fd);tomb = None
            fail_seam(request, "FINAL_DIRECTORY_FSYNC");journal_fsync(parent_fd, journal, request)
        mutation_stage(request, "BEFORE_FINAL_VERIFICATION", journal)
        if not revalidate_parent(root_fd, path, parent_identity):
            journal_set(journal, final_verification="FAIL")
            raise SecureError("SECURE_WRITE_UNCERTAIN", "Parent path identity changed after mutation")
        if operation == "DELETE":
            try:
                fd = openat2(root_fd, path, os.O_PATH | os.O_CLOEXEC);os.close(fd)
                journal_set(journal, final_verification="FAIL")
                raise SecureError("SECURE_WRITE_UNCERTAIN", "Deleted target remains present")
            except OSError as error:
                if error.errno != errno.ENOENT: raise
            after = None;journal_set(journal, final_verification="PASS")
        else:
            final_fd, after = open_regular(root_fd, path, maximum)
            try:
                expected_digest = "sha256:" + hashlib.sha256(replacement).hexdigest()
                if created_identity is None or installed_signature is None or fd_identity(temp_fd) != created_identity or not same_inode(after, created_identity) or stable_tuple(os.fstat(final_fd)) != installed_signature or after["digest"] != expected_digest or after["size"] != len(replacement) or after["mode"] != final_mode or after["nlink"] != 1:
                    journal_set(journal, final_verification="FAIL")
                    raise SecureError("FINAL_TARGET_IDENTITY_MISMATCH", "Final target verification failed")
                journal_set(journal, final_verification="PASS")
            finally: os.close(final_fd)
        mutation_stage(request, "AFTER_FINAL_VERIFICATION", journal)
        mutation_stage(request, "BEFORE_HELPER_RESPONSE_COMPLETION", journal)
        return {"root_identity": root_identity, "path": path, "mutation": operation, "before": before, "after": after,
                "file_fsync": journal["temporary_file_fsync_completed"], "rename_atomic": journal["atomic_rename_completed"],
                "directory_fsync": journal["directory_fsync_completed_count"] > 0,
                "rollback": "SUCCEEDED" if journal["rollback_completed"] else "NOT_REQUIRED", "journal": journal}
    except SecureError as error:
        if error.journal is None: error.journal = journal.copy()
        raise
    except OSError as error:
        raise SecureError("SECURE_WRITE_UNCERTAIN", f"Secure mutation primitive failed ({error.errno})", journal.copy()) from error
    finally:
        if installed_fd >= 0: os.close(installed_fd)
        if temp_fd >= 0: os.close(temp_fd)
        if parent_fd >= 0:
            if temp is not None and not journal["atomic_rename_completed"]: unlink_quiet(parent_fd, temp)
            if tomb is not None:
                # A surviving tombstone is not removed when restoration is uncertain.
                pass
            os.close(parent_fd)
        os.close(root_fd)


def residue_metadata(parent_fd: int, name: str, maximum: int) -> dict[str, Any] | None:
    try:
        fd = os.open(name, os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=parent_fd)
    except FileNotFoundError:
        return None
    except OSError as error:
        if error.errno in (errno.ELOOP, errno.EXDEV): raise SecureError("RESIDUE_IDENTITY_MISMATCH", "Authorized residue is a symlink or magic link") from error
        raise SecureError("RESIDUE_IDENTITY_MISMATCH", "Authorized residue cannot be opened safely") from error
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1:
            raise SecureError("RESIDUE_IDENTITY_MISMATCH", "Authorized residue is not a single-link regular file")
        try:
            digest, size, stable = hash_fd(fd, maximum)
        except BaseException as error:
            raise SecureError("RESIDUE_IDENTITY_MISMATCH", "Authorized residue cannot be validated as a stable regular file") from error
        return {"digest": digest, "size": size, "mode": stat.S_IMODE(stable.st_mode), "device": stable.st_dev, "inode": stable.st_ino, "nlink": stable.st_nlink}
    finally:
        os.close(fd)


def target_metadata(root_fd: int, path: str, maximum: int) -> dict[str, Any] | None:
    try:
        fd, value = open_regular(root_fd, path, maximum)
        os.close(fd)
        return value
    except SecureError as error:
        if error.code == "TARGET_MISSING": return None
        if error.code in ("SYMLINK_PATH", "SPECIAL_FILE", "PATH_NOT_READABLE"):
            return {"_mismatch": True}
        raise


def identity_matches(value: dict[str, Any] | None, expected: dict[str, int] | None) -> bool:
    return value is not None and expected is not None and value.get("device") == expected["device"] and value.get("inode") == expected["inode"] and value.get("nlink") == expected["nlink"]


def expected_metadata_matches(value: dict[str, Any] | None, expected: dict[str, Any], identity: dict[str, int] | None = None) -> bool:
    return value is not None and "_mismatch" not in value and value.get("digest") == expected.get("digest") and value.get("size") == expected.get("size") and value.get("mode") == expected.get("mode") and value.get("nlink") == 1 and (identity is None or identity_matches(value, identity))


def replacement_matches(value: dict[str, Any] | None, request: dict[str, Any], identity: dict[str, int] | None = None) -> bool:
    return value is not None and "_mismatch" not in value and value.get("digest") == request.get("replacement_digest") and value.get("size") == request.get("replacement_size") and value.get("mode") == request.get("final_mode") and value.get("nlink") == 1 and (identity is None or identity_matches(value, identity))


def exact_residue_count(parent_fd: int, names: list[str]) -> int:
    count = 0
    for name in names:
        try: os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError: continue
        count += 1
    return count


def perform_recovery(request: dict[str, Any]) -> dict[str, Any]:
    path = canonical_path(request.get("path")); operation = request.get("mutation")
    if operation not in ("CREATE", "REPLACE", "DELETE"): raise SecureError("INVALID_ARGUMENT", "Recovery mutation is invalid")
    maximum = request.get("hash_limit")
    if not isinstance(maximum, int) or isinstance(maximum, bool) or maximum < 0: raise SecureError("INVALID_ARGUMENT", "Recovery hash bound is invalid")
    expected = request.get("expected")
    if not isinstance(expected, dict): raise SecureError("INVALID_ARGUMENT", "Recovery preimage authority is missing")
    root_fd, root_identity = open_root(request); parent_fd = -1
    try:
        parent_fd, _name, parent_identity = open_parent(root_fd, path)
        authority = validate_operation_identity(request, path, operation, parent_identity)
        observed = request.get("observed_journal")
        if observed is not None and not isinstance(observed, dict): raise SecureError("INVALID_ARGUMENT", "Recovery journal authority is malformed")
        atomic_completed = isinstance(observed, dict) and observed.get("atomic_rename_completed") is True
        rollback_required = isinstance(observed, dict) and observed.get("rollback_required") is True
        rollback_completed = isinstance(observed, dict) and observed.get("rollback_completed") is True
        temporary_identity = identity_from_journal(observed, "temporary")
        preimage_identity = identity_from_journal(observed, "preimage")
        tombstone_identity = identity_from_journal(observed, "tombstone") or preimage_identity
        temporary_name = authority["temporary_name"]
        tombstone_name = authority["tombstone_name"]
        residue_names = [name for name in (temporary_name, tombstone_name) if name is not None]
        recovery_checkpoint(request, "BEFORE_RECOVERY_INSPECTION")
        temporary = residue_metadata(parent_fd, temporary_name, maximum) if temporary_name is not None else None
        tombstone = residue_metadata(parent_fd, tombstone_name, maximum) if tombstone_name is not None else None
        if temporary is not None:
            temporary_owned = identity_matches(temporary, temporary_identity) or (operation == "REPLACE" and atomic_completed and (identity_matches(temporary, preimage_identity) or (rollback_required and expected_metadata_matches(temporary, request.get("expected", {}), None))))
            if not temporary_owned: raise SecureError("RESIDUE_IDENTITY_MISMATCH", "Temporary residue identity differs from the operation authority")
        if tombstone is not None and not identity_matches(tombstone, tombstone_identity): raise SecureError("RESIDUE_IDENTITY_MISMATCH", "Tombstone residue identity differs from the operation authority")
        target = target_metadata(root_fd, path, maximum)
        preimage_match = operation == "CREATE" and target is None or operation != "CREATE" and expected_metadata_matches(target, expected, preimage_identity)
        replacement_match = operation in ("CREATE", "REPLACE") and replacement_matches(target, request, temporary_identity)
        rollback_performed = False
        if rollback_required and not rollback_completed:
            if operation == "REPLACE" and replacement_match and temporary is not None and (identity_matches(temporary, preimage_identity) or expected_metadata_matches(temporary, request.get("expected", {}), None)):
                recovery_checkpoint(request, "BEFORE_RECOVERY_ROLLBACK")
                recovery_fail_seam(request, "DURING_RECOVERY_ROLLBACK")
                renameat2(parent_fd, temporary_name, parent_fd, path.rsplit("/", 1)[-1], RENAME_EXCHANGE)
                recovery_checkpoint(request, "AFTER_RECOVERY_ROLLBACK")
                temporary = residue_metadata(parent_fd, temporary_name, maximum)
                if not identity_matches(temporary, temporary_identity): raise SecureError("RESIDUE_IDENTITY_MISMATCH", "Rollback residue identity differs from the operation authority")
                target = target_metadata(root_fd, path, maximum)
                preimage_match = expected_metadata_matches(target, expected, preimage_identity)
                replacement_match = replacement_matches(target, request, temporary_identity)
                rollback_performed = True
            elif operation == "DELETE" and target is None and tombstone is not None:
                recovery_checkpoint(request, "BEFORE_RECOVERY_ROLLBACK")
                recovery_fail_seam(request, "DURING_RECOVERY_ROLLBACK")
                renameat2(parent_fd, tombstone_name, parent_fd, path.rsplit("/", 1)[-1], RENAME_NOREPLACE)
                recovery_checkpoint(request, "AFTER_RECOVERY_ROLLBACK")
                tombstone = None
                target = target_metadata(root_fd, path, maximum)
                preimage_match = expected_metadata_matches(target, expected, preimage_identity)
                rollback_performed = True
        if operation == "CREATE":
            if atomic_completed and replacement_match: target_state = "REPLACEMENT"
            elif (not atomic_completed or rollback_required or rollback_completed) and target is None: target_state = "ABSENT"
            else: target_state = "MISMATCH"
        elif operation == "REPLACE":
            if rollback_performed or (rollback_required and preimage_match): target_state = "PREIMAGE"
            elif atomic_completed and replacement_match: target_state = "REPLACEMENT"
            elif (not atomic_completed or rollback_completed) and preimage_match: target_state = "PREIMAGE"
            else: target_state = "MISMATCH"
        else:
            if rollback_performed or (rollback_required and preimage_match): target_state = "PREIMAGE"
            elif atomic_completed and target is None: target_state = "ABSENT"
            elif (not atomic_completed or rollback_completed) and preimage_match: target_state = "PREIMAGE"
            else: target_state = "MISMATCH"
        if operation == "REPLACE" and temporary is not None:
            displaced_expected = expected if target_state == "REPLACEMENT" else {"digest": request.get("replacement_digest"), "size": request.get("replacement_size"), "mode": request.get("final_mode")}
            if target_state == "REPLACEMENT" and not expected_metadata_matches(temporary, displaced_expected, preimage_identity): raise SecureError("RESIDUE_IDENTITY_MISMATCH", "Displaced preimage residue differs from the operation authority")
        if operation == "DELETE" and tombstone is not None and not expected_metadata_matches(tombstone, expected, tombstone_identity): raise SecureError("RESIDUE_IDENTITY_MISMATCH", "Tombstone content differs from the operation authority")
        if operation == "CREATE" and temporary is not None and temporary_identity is None: raise SecureError("RESIDUE_IDENTITY_MISMATCH", "Temporary residue has no recorded owner identity")
        if operation == "REPLACE" and temporary is not None and temporary_identity is None: raise SecureError("RESIDUE_IDENTITY_MISMATCH", "Replacement residue has no recorded owner identity")
        to_remove = []
        if temporary is not None: to_remove.append(temporary_name)
        if tombstone is not None: to_remove.append(tombstone_name)
        for name in to_remove:
            recovery_checkpoint(request, "BEFORE_RECOVERY_UNLINK")
            current = residue_metadata(parent_fd, name, maximum)
            expected_identity = (preimage_identity if operation == "REPLACE" and target_state == "REPLACEMENT" else temporary_identity) if name == temporary_name else tombstone_identity
            if not identity_matches(current, expected_identity): raise SecureError("RESIDUE_IDENTITY_MISMATCH", "Authorized residue changed before recovery unlink")
            recovery_fail_seam(request, "DURING_RECOVERY_UNLINK")
            os.unlink(name, dir_fd=parent_fd)
            recovery_checkpoint(request, "AFTER_RECOVERY_UNLINK")
        recovery_checkpoint(request, "BEFORE_RECOVERY_DIRECTORY_FSYNC")
        recovery_fail_seam(request, "DURING_RECOVERY_DIRECTORY_FSYNC")
        os.fsync(parent_fd)
        recovery_checkpoint(request, "AFTER_RECOVERY_DIRECTORY_FSYNC")
        recovery_checkpoint(request, "BEFORE_RECOVERY_TARGET_VERIFICATION")
        final_target = target_metadata(root_fd, path, maximum)
        final_preimage = operation == "CREATE" and final_target is None or operation != "CREATE" and expected_metadata_matches(final_target, expected, preimage_identity)
        final_replacement = operation in ("CREATE", "REPLACE") and replacement_matches(final_target, request, temporary_identity)
        if operation == "CREATE": target_verification = "REPLACEMENT" if final_replacement else "ABSENT" if final_target is None else "MISMATCH"
        elif operation == "REPLACE": target_verification = "REPLACEMENT" if final_replacement else "PREIMAGE" if final_preimage else "MISMATCH"
        else: target_verification = "ABSENT" if final_target is None else "PREIMAGE" if final_preimage else "MISMATCH"
        recovery_checkpoint(request, "AFTER_RECOVERY_TARGET_VERIFICATION")
        remaining = exact_residue_count(parent_fd, residue_names)
        if remaining != 0: raise SecureError("RESIDUE_IDENTITY_MISMATCH", "Operation-owned residue remains after recovery")
        return {"root_identity": root_identity, "path": path, "mutation": operation, "operation_nonce": authority["operation_nonce"],
                "cleanup_attempted": True, "recovery_outcome": "SUCCEEDED", "recovery_residue_count": remaining,
                "target_verification": target_verification, "directory_fsync": "SUCCEEDED"}
    finally:
        if parent_fd >= 0: os.close(parent_fd)
        os.close(root_fd)


def probe() -> dict[str, Any]:
    result = {"openat2": False, "resolve_beneath": False, "resolve_no_symlinks": False, "resolve_no_magiclinks": False, "renameat2": False, "rename_noreplace": False, "rename_exchange": False, "directory_fsync": False, "landlock_abi": None}
    with tempfile.TemporaryDirectory(prefix="pi-gacw-m4-probe-") as temporary:
        root = Path(temporary, "root");outside = Path(temporary, "outside");root.mkdir();outside.mkdir();(root / "file").write_bytes(b"x");(outside / "secret").write_bytes(b"s");os.symlink("../outside/secret", root / "link")
        root_fd = os.open(root, os.O_PATH | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
        try:
            fd = openat2(root_fd, "file", os.O_RDONLY | os.O_CLOEXEC);os.close(fd);result.update(openat2=True, resolve_beneath=True, resolve_no_symlinks=True, resolve_no_magiclinks=True)
            try: fd = openat2(root_fd, "link", os.O_RDONLY | os.O_CLOEXEC);os.close(fd);raise RuntimeError("symlink probe escaped")
            except OSError as error:
                if error.errno not in (errno.ELOOP, errno.EXDEV): raise
            directory_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
            try:
                (root / "a").write_bytes(b"a");(root / "b").write_bytes(b"b")
                renameat2(directory_fd, "a", directory_fd, "c", RENAME_NOREPLACE);result["rename_noreplace"] = (root / "c").read_bytes() == b"a"
                try: renameat2(directory_fd, "c", directory_fd, "b", RENAME_NOREPLACE);raise RuntimeError("noreplace overwrote")
                except OSError as error:
                    if error.errno != errno.EEXIST: raise
                renameat2(directory_fd, "b", directory_fd, "c", RENAME_EXCHANGE);result["rename_exchange"] = (root / "b").read_bytes() == b"a" and (root / "c").read_bytes() == b"b";result["renameat2"] = True
                os.fsync(directory_fd);result["directory_fsync"] = True
            finally: os.close(directory_fd)
        finally: os.close(root_fd)
    try: result["landlock_abi"] = syscall(syscalls()["landlock_create_ruleset"], 0, 0, 1)
    except OSError: result["landlock_abi"] = None
    return result


def main() -> None:
    raw = sys.stdin.buffer.read(MAX_REQUEST + 1)
    if len(raw) > MAX_REQUEST: raise SecureError("OUTPUT_LIMIT_EXCEEDED", "Helper request exceeds protocol limit")
    try: request = json.loads(raw)
    except Exception as error: raise SecureError("INVALID_ARGUMENT", "Helper request is not valid JSON") from error
    if not isinstance(request, dict) or request.get("protocol") != PROTOCOL: raise SecureError("SECURE_FS_CAPABILITY_MISMATCH", "Helper protocol identity is invalid")
    operation = request.get("operation")
    if operation == "PROBE": value = probe()
    elif operation == "READ": value = perform_read(request)
    elif operation == "LIST": value = perform_list(request)
    elif operation == "MUTATE": value = perform_mutation(request)
    elif operation == "RECOVER": value = perform_recovery(request)
    else: raise SecureError("INVALID_ARGUMENT", "Unknown helper operation")
    response = {"ok": True, "protocol": PROTOCOL, "result": value}
    encoded = (json.dumps(response, sort_keys=True, separators=(",", ":")) + "\n").encode()
    if len(encoded) > MAX_RESPONSE: raise SecureError("OUTPUT_LIMIT_EXCEEDED", "Helper response exceeds protocol limit")
    sys.stdout.buffer.write(encoded);sys.stdout.buffer.flush()


if __name__ == "__main__":
    try: main()
    except SecureError as error:
        sys.stdout.write(json.dumps({"ok": False, "protocol": PROTOCOL, "code": error.code, "detail": error.detail, "journal": error.journal}, sort_keys=True, separators=(",", ":")) + "\n")
    except BaseException as error:
        sys.stdout.write(json.dumps({"ok": False, "protocol": PROTOCOL, "code": "SECURE_WRITE_UNCERTAIN", "detail": f"Helper internal failure ({type(error).__name__})", "journal": None}, sort_keys=True, separators=(",", ":")) + "\n")
