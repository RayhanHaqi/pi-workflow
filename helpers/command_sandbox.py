#!/usr/bin/env python3
"""Landlock + seccomp execution helper for frozen M4 command specifications."""
from __future__ import annotations

import ctypes
import errno
import hashlib
import json
import os
import platform
import resource
import socket
import stat
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

PROTOCOL = "pi-gacw-command-sandbox-v1"
MAX_REQUEST = 1024 * 1024
libc = ctypes.CDLL(None, use_errno=True)
SYS_BY_ARCH = {
    "x86_64": {"landlock_create_ruleset": 444, "landlock_add_rule": 445, "landlock_restrict_self": 446, "execveat": 322, "audit": 0xC000003E,
               "network": [41,42,43,44,45,46,47,48,49,50,51,52,53,54,55,288,299,307],
               "dangerous": [62,86,90,91,92,93,94,101,109,112,129,132,133,165,166,175,176,188,189,190,197,198,199,200,234,235,246,259,260,261,265,268,272,280,297,298,300,304,308,313,321,424,425,426,427,428,429,430,431,432,433,438,440,442,452]},
    "aarch64": {"landlock_create_ruleset": 444, "landlock_add_rule": 445, "landlock_restrict_self": 446, "execveat": 281, "audit": 0xC00000B7,
                "network": [198,203,202,206,207,211,212,210,200,201,204,205,199,208,209,242,243,269],
                "dangerous": [5,6,7,14,15,16,33,37,39,40,52,53,54,55,88,96,97,104,105,106,117,129,130,131,138,154,157,240,265,268,273,280,424,425,426,427,428,429,430,431,432,433,438,440,442,452]},
}
PR_SET_NO_NEW_PRIVS = 38
PR_GET_NO_NEW_PRIVS = 39
PR_SET_SECCOMP = 22
SECCOMP_MODE_FILTER = 2
LANDLOCK_CREATE_RULESET_VERSION = 1
LANDLOCK_RULE_PATH_BENEATH = 1
ACCESS_EXECUTE = 1 << 0
ACCESS_WRITE_FILE = 1 << 1
ACCESS_READ_FILE = 1 << 2
ACCESS_READ_DIR = 1 << 3
ACCESS_REMOVE_DIR = 1 << 4
ACCESS_REMOVE_FILE = 1 << 5
ACCESS_MAKE_CHAR = 1 << 6
ACCESS_MAKE_DIR = 1 << 7
ACCESS_MAKE_REG = 1 << 8
ACCESS_MAKE_SOCK = 1 << 9
ACCESS_MAKE_FIFO = 1 << 10
ACCESS_MAKE_BLOCK = 1 << 11
ACCESS_MAKE_SYM = 1 << 12
ACCESS_REFER = 1 << 13
ACCESS_TRUNCATE = 1 << 14
READ_ACCESS = ACCESS_EXECUTE | ACCESS_READ_FILE | ACCESS_READ_DIR
WRITE_ACCESS = ACCESS_WRITE_FILE | ACCESS_REMOVE_DIR | ACCESS_REMOVE_FILE | ACCESS_MAKE_CHAR | ACCESS_MAKE_DIR | ACCESS_MAKE_REG | ACCESS_MAKE_SOCK | ACCESS_MAKE_FIFO | ACCESS_MAKE_BLOCK | ACCESS_MAKE_SYM | ACCESS_REFER | ACCESS_TRUNCATE
HANDLED_ACCESS = READ_ACCESS | WRITE_ACCESS


class Ruleset(ctypes.Structure):
    _fields_ = [("handled_access_fs", ctypes.c_uint64)]


class PathBeneath(ctypes.Structure):
    _fields_ = [("allowed_access", ctypes.c_uint64), ("parent_fd", ctypes.c_int), ("reserved", ctypes.c_uint32)]


class SockFilter(ctypes.Structure):
    _fields_ = [("code", ctypes.c_ushort), ("jt", ctypes.c_ubyte), ("jf", ctypes.c_ubyte), ("k", ctypes.c_uint32)]


class SockFprog(ctypes.Structure):
    _fields_ = [("len", ctypes.c_ushort), ("filter", ctypes.POINTER(SockFilter))]


class SandboxError(Exception):
    def __init__(self, code: str, detail: str):
        super().__init__(detail); self.code = code; self.detail = detail


def architecture() -> dict[str, Any]:
    result = SYS_BY_ARCH.get(platform.machine())
    if result is None: raise SandboxError("COMMAND_SANDBOX_UNAVAILABLE", "Unsupported sandbox architecture")
    return result


def syscall(number: int, *args: Any) -> int:
    value = libc.syscall(number, *args)
    if value < 0:
        code = ctypes.get_errno(); raise OSError(code, os.strerror(code))
    return int(value)


def set_no_new_privs() -> None:
    if libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
        raise OSError(ctypes.get_errno(), "PR_SET_NO_NEW_PRIVS")
    if libc.prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) != 1:
        raise OSError(errno.EPERM, "no_new_privs verification")


def landlock_abi() -> int:
    return syscall(architecture()["landlock_create_ruleset"], 0, 0, LANDLOCK_CREATE_RULESET_VERSION)


def open_rule(path: str) -> tuple[int, os.stat_result]:
    if not isinstance(path, str) or not os.path.isabs(path) or os.path.normpath(path) != path or "\x00" in path:
        raise SandboxError("COMMAND_SPEC_MISMATCH", "Sandbox path is not absolute normalized form")
    fd = os.open(path, os.O_PATH | os.O_CLOEXEC | os.O_NOFOLLOW)
    st = os.fstat(fd)
    if stat.S_ISLNK(st.st_mode): os.close(fd); raise SandboxError("COMMAND_SPEC_MISMATCH", "Sandbox rule path is a symlink")
    return fd, st


def assert_hardlink_safe_write_rules(write_rules: list[dict[str, str]]) -> None:
    inspected = 0
    for rule in write_rules:
        path = rule.get("path") if isinstance(rule, dict) else None
        kind = rule.get("kind") if isinstance(rule, dict) else None
        if not isinstance(path, str) or kind not in ("EXACT", "PREFIX"):
            raise SandboxError("COMMAND_SPEC_MISMATCH", "Write rule is malformed")
        if kind == "EXACT":
            fd, st = open_rule(path)
            try:
                if stat.S_ISREG(st.st_mode) and st.st_nlink > 1:
                    raise SandboxError("HARDLINK_WRITE_SCOPE_UNSAFE", "Exact command write target is multiply linked")
            finally: os.close(fd)
            continue
        root = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
        stack = [root]
        try:
            while stack:
                directory_fd = stack.pop()
                try:
                    for name in os.listdir(directory_fd):
                        inspected += 1
                        if inspected > 100_000: raise SandboxError("HARDLINK_WRITE_SCOPE_UNSAFE", "Command write-prefix audit exceeds its bound")
                        st = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                        if stat.S_ISREG(st.st_mode) and st.st_nlink > 1:
                            raise SandboxError("HARDLINK_WRITE_SCOPE_UNSAFE", "Command write prefix contains a multiply linked file")
                        if stat.S_ISDIR(st.st_mode):
                            stack.append(os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=directory_fd))
                finally: os.close(directory_fd)
        except BaseException:
            for fd in stack: os.close(fd)
            raise


def apply_landlock(read_paths: list[str], write_rules: list[dict[str, str]], path_identities: list[dict[str, int]] | None = None) -> int:
    abi = landlock_abi()
    if abi < 3: raise SandboxError("COMMAND_SANDBOX_UNAVAILABLE", "Landlock ABI lacks truncate mediation")
    ruleset = syscall(architecture()["landlock_create_ruleset"], ctypes.byref(Ruleset(HANDLED_ACCESS)), ctypes.sizeof(Ruleset), 0)
    opened: list[int] = []
    try:
        merged: dict[str, int] = {"/dev/null": ACCESS_READ_FILE | ACCESS_WRITE_FILE}
        for path in read_paths:
            merged[path] = merged.get(path, 0) | READ_ACCESS
        for rule in write_rules:
            if not isinstance(rule, dict) or set(rule) != {"path", "kind"} or rule["kind"] not in ("EXACT", "PREFIX"):
                raise SandboxError("COMMAND_SPEC_MISMATCH", "Write rule is malformed")
            access = ACCESS_WRITE_FILE | ACCESS_TRUNCATE | ACCESS_READ_FILE
            if rule["kind"] == "PREFIX": access = HANDLED_ACCESS & ~(ACCESS_MAKE_CHAR | ACCESS_MAKE_BLOCK | ACCESS_REFER)
            merged[rule["path"]] = merged.get(rule["path"], 0) | access
        expected: dict[str, tuple[int, int]] = {}
        if path_identities is not None:
            if not isinstance(path_identities,list): raise SandboxError("COMMAND_SPEC_MISMATCH","Sandbox path identities are malformed")
            for item in path_identities:
                if not isinstance(item,dict) or set(item)!={"path","device","inode"} or not isinstance(item["path"],str) or not isinstance(item["device"],int) or isinstance(item["device"],bool) or item["device"]<0 or not isinstance(item["inode"],int) or isinstance(item["inode"],bool) or item["inode"]<0 or item["path"] in expected:
                    raise SandboxError("COMMAND_SPEC_MISMATCH","Sandbox path identities are malformed")
                expected[item["path"]]=(item["device"],item["inode"])
            if set(expected)!=set(merged): raise SandboxError("COMMAND_SPEC_MISMATCH","Sandbox path identity set differs")
        for path, allowed in sorted(merged.items()):
            fd, st = open_rule(path); opened.append(fd)
            if path_identities is not None and expected[path] != (st.st_dev,st.st_ino): raise SandboxError("COMMAND_SPEC_MISMATCH","Sandbox authority path identity changed")
            if stat.S_ISREG(st.st_mode): allowed &= ~(ACCESS_READ_DIR | ACCESS_REMOVE_DIR | ACCESS_MAKE_CHAR | ACCESS_MAKE_DIR | ACCESS_MAKE_REG | ACCESS_MAKE_SOCK | ACCESS_MAKE_FIFO | ACCESS_MAKE_BLOCK | ACCESS_MAKE_SYM | ACCESS_REFER)
            elif not stat.S_ISDIR(st.st_mode): allowed &= ACCESS_READ_FILE | ACCESS_WRITE_FILE
            attr = PathBeneath(allowed, fd, 0)
            syscall(architecture()["landlock_add_rule"], ruleset, LANDLOCK_RULE_PATH_BENEATH, ctypes.byref(attr), 0)
        set_no_new_privs()
        syscall(architecture()["landlock_restrict_self"], ruleset, 0)
        return abi
    finally:
        for fd in opened: os.close(fd)
        os.close(ruleset)


def apply_seccomp(network_forbidden: bool) -> None:
    data = architecture()
    blocked = list(data["dangerous"]) + (list(data["network"]) if network_forbidden else [])
    instructions = [SockFilter(0x20, 0, 0, 4), SockFilter(0x15, 1, 0, data["audit"]), SockFilter(0x06, 0, 0, 0x80000000), SockFilter(0x20, 0, 0, 0)]
    for number in sorted(set(blocked)):
        instructions.extend([SockFilter(0x15, 0, 1, number), SockFilter(0x06, 0, 0, 0x00050000 | errno.EPERM)])
    instructions.append(SockFilter(0x06, 0, 0, 0x7FFF0000))
    array = (SockFilter * len(instructions))(*instructions); program = SockFprog(len(instructions), array)
    if libc.prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, ctypes.byref(program)) != 0:
        raise OSError(ctypes.get_errno(), "PR_SET_SECCOMP")


def sha256_fd(fd: int, maximum: int = 64 * 1024 * 1024) -> tuple[str, os.stat_result]:
    digest = hashlib.sha256();before = os.fstat(fd)
    if not stat.S_ISREG(before.st_mode) or before.st_size < 0 or before.st_size > maximum:
        raise SandboxError("COMMAND_SPEC_MISMATCH", "Executable exceeds its identity bound")
    offset = 0
    while offset < before.st_size:
        chunk = os.pread(fd, min(65536, before.st_size - offset), offset)
        if not chunk: raise SandboxError("COMMAND_SPEC_MISMATCH", "Executable changed while hashing")
        digest.update(chunk);offset += len(chunk)
    after = os.fstat(fd)
    if (before.st_dev,before.st_ino,before.st_mode,before.st_size,before.st_mtime_ns,before.st_ctime_ns) != (after.st_dev,after.st_ino,after.st_mode,after.st_size,after.st_mtime_ns,after.st_ctime_ns):
        raise SandboxError("COMMAND_SPEC_MISMATCH", "Executable changed while hashing")
    return "sha256:" + digest.hexdigest(), before


def verify_executable(request: dict[str, Any]) -> int:
    invocation = request.get("executable_invocation_path");physical = request.get("executable_realpath");digest = request.get("executable_sha256");identity=request.get("executable_identity")
    if not all(isinstance(x, str) for x in (invocation, physical, digest)) or not os.path.isabs(invocation) or not os.path.isabs(physical) or not isinstance(identity,dict) or set(identity)!={"device","inode","mode","size"}:
        raise SandboxError("COMMAND_SPEC_MISMATCH", "Executable authority is malformed")
    if any(not isinstance(identity[key],int) or isinstance(identity[key],bool) or identity[key]<0 for key in identity): raise SandboxError("COMMAND_SPEC_MISMATCH","Executable identity is malformed")
    actual=os.path.realpath(invocation);path_st=os.lstat(actual);held_digest,held_st=sha256_fd(4)
    expected=(identity["device"],identity["inode"],identity["mode"],identity["size"])
    observed=(held_st.st_dev,held_st.st_ino,stat.S_IMODE(held_st.st_mode),held_st.st_size)
    if actual!=physical or not stat.S_ISREG(path_st.st_mode) or (path_st.st_dev,path_st.st_ino)!=(held_st.st_dev,held_st.st_ino) or observed!=expected or held_digest!=digest:
        raise SandboxError("EXECUTION_INPUT_DRIFT", "Held executable identity changed")
    return 4


def verify_execution_inputs(value: Any) -> None:
    if not isinstance(value,list): raise SandboxError("EXECUTION_INPUT_DRIFT","Execution-input inventory is malformed")
    seen:set[str]=set()
    for item in value:
        if not isinstance(item,dict) or set(item)!={"path","realpath","device","inode","mode","size","digest"} or not isinstance(item["path"],str) or item["path"] in seen:
            raise SandboxError("EXECUTION_INPUT_DRIFT","Execution-input authority is malformed")
        seen.add(item["path"])
        try:
            physical=os.path.realpath(item["path"]);fd=os.open(item["path"],os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW)
            try: digest,st=sha256_fd(fd)
            finally: os.close(fd)
        except OSError as error: raise SandboxError("EXECUTION_INPUT_DRIFT","Execution input is absent or replaced") from error
        if physical!=item["realpath"] or (st.st_dev,st.st_ino,stat.S_IMODE(st.st_mode),st.st_size,digest)!=(item["device"],item["inode"],item["mode"],item["size"],item["digest"]):
            raise SandboxError("EXECUTION_INPUT_DRIFT","Execution input changed after immutable capture")


def execveat_fd(fd: int, argv: list[str], environment: dict[str, str]) -> None:
    encoded_argv=[os.fsencode(value) for value in argv];encoded_env=[os.fsencode(f"{key}={value}") for key,value in sorted(environment.items())]
    argv_array=(ctypes.c_char_p*(len(encoded_argv)+1))(*encoded_argv,None);env_array=(ctypes.c_char_p*(len(encoded_env)+1))(*encoded_env,None)
    result=libc.syscall(architecture()["execveat"],fd,ctypes.c_char_p(b""),argv_array,env_array,0x1000)
    code=ctypes.get_errno();raise OSError(code,os.strerror(code) if result<0 else "execveat unexpectedly returned")


def setup_status(value: dict[str, Any]) -> None:
    encoded = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()
    os.write(3, encoded)


def checkpoint(request: dict[str, Any], stage: str) -> None:
    if request.get("_checkpoint_stage") != stage or not isinstance(request.get("_checkpoint_socket"),str): return
    client=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
    try:
        client.connect(request["_checkpoint_socket"]);client.sendall((stage+"\n").encode())
        if client.recv(1)!=b"1": raise SandboxError("COMMAND_SANDBOX_UNAVAILABLE","Private checkpoint controller aborted")
    finally: client.close()


def execute(request: dict[str, Any]) -> None:
    # Keep a dedicated ordinary-timeout process group without creating a new
    # session: the productive invocation session remains the hard-stop boundary.
    try:
        os.setpgid(0, 0)
    except OSError as error:
        raise SandboxError("COMMAND_SANDBOX_UNAVAILABLE", "Sandbox process group setup failed") from error
    required = {"protocol","operation","executable_invocation_path","executable_realpath","executable_identity","executable_sha256","execution_inputs","argv","cwd","cwd_identity","environment","read_paths","write_rules","path_identities","network_policy"}
    optional = {"_checkpoint_socket","_checkpoint_stage"}
    if not required.issubset(request) or set(request)-required-optional: raise SandboxError("COMMAND_SPEC_MISMATCH", "Sandbox request has unexpected or missing fields")
    executable_fd=verify_executable(request)
    argv=request["argv"];environment=request["environment"];cwd=request["cwd"];cwd_identity=request["cwd_identity"];read_paths=request["read_paths"];write_rules=request["write_rules"];path_identities=request["path_identities"]
    if not isinstance(argv,list) or not argv or not all(isinstance(x,str) and x and "\x00" not in x for x in argv): raise SandboxError("COMMAND_SPEC_MISMATCH","argv is malformed")
    if not isinstance(environment,dict) or not all(isinstance(k,str) and isinstance(v,str) and "\x00" not in k+v for k,v in environment.items()): raise SandboxError("COMMAND_SPEC_MISMATCH","environment is malformed")
    if not isinstance(read_paths,list) or not all(isinstance(x,str) for x in read_paths) or not isinstance(write_rules,list): raise SandboxError("COMMAND_SPEC_MISMATCH","filesystem rules are malformed")
    if request["network_policy"] != "FORBIDDEN": raise SandboxError("NETWORK_SANDBOX_UNAVAILABLE","V0 command gateway requires denied network")
    checkpoint(request,"BEFORE_LANDLOCK")
    verify_execution_inputs(request["execution_inputs"])
    assert_hardlink_safe_write_rules(write_rules)
    resource.setrlimit(resource.RLIMIT_CORE,(0,0))
    if not isinstance(cwd,str) or not os.path.isabs(cwd) or os.path.normpath(cwd)!=cwd or not isinstance(cwd_identity,dict) or set(cwd_identity)!={"device","inode"} or any(not isinstance(cwd_identity.get(key),int) or isinstance(cwd_identity.get(key),bool) or cwd_identity[key]<0 for key in ("device","inode")): raise SandboxError("COMMAND_SPEC_MISMATCH","cwd is malformed")
    cwd_fd=os.open(cwd,os.O_PATH|os.O_DIRECTORY|os.O_CLOEXEC|os.O_NOFOLLOW)
    try:
        st=os.fstat(cwd_fd)
        if st.st_dev!=cwd_identity.get("device") or st.st_ino!=cwd_identity.get("inode"): raise SandboxError("COMMAND_CWD_IDENTITY_DRIFT","cwd identity changed")
        checkpoint(request,"CWD_OPENED")
        try: current_fd=os.open(cwd,os.O_PATH|os.O_DIRECTORY|os.O_CLOEXEC|os.O_NOFOLLOW)
        except OSError as error: raise SandboxError("COMMAND_CWD_IDENTITY_DRIFT","cwd path changed after open") from error
        try:
            current=os.fstat(current_fd)
            if current.st_dev!=st.st_dev or current.st_ino!=st.st_ino: raise SandboxError("COMMAND_CWD_IDENTITY_DRIFT","cwd path no longer names the frozen inode")
        finally: os.close(current_fd)
        os.fchdir(cwd_fd)
        abi=apply_landlock(read_paths,write_rules,path_identities)
    finally: os.close(cwd_fd)
    apply_seccomp(True)
    # Re-resolve only as a drift detector; execution is bound to the retained FD.
    current=os.lstat(os.path.realpath(request["executable_invocation_path"]));held_digest,held=sha256_fd(executable_fd)
    if (current.st_dev,current.st_ino)!=(held.st_dev,held.st_ino) or held_digest!=request["executable_sha256"]: raise SandboxError("EXECUTION_INPUT_DRIFT","Executable path or retained bytes changed after validation")
    setup_status({"ok":True,"protocol":PROTOCOL,"landlock_abi":abi,"no_new_privs":True,"network_denied":True})
    os.set_inheritable(3,False)
    execveat_fd(executable_fd,argv,environment)


def probe_landlock(root: str, outside: str) -> None:
    system_roots=sorted({os.path.realpath(path) for path in ["/usr","/lib","/lib64"] if os.path.exists(path)})
    apply_landlock([*system_roots,root], [{"path":root,"kind":"PREFIX"}])
    Path(root,"allowed").write_text("ok")
    try: Path(outside,"denied").write_text("bad"); os._exit(3)
    except PermissionError: pass
    child=subprocess.run(["/usr/bin/python3","-c",f"from pathlib import Path; Path({str(Path(outside,'child'))!r}).write_text('bad')"],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    if child.returncode==0: os._exit(4)


def probe_seccomp() -> None:
    set_no_new_privs();apply_seccomp(True)
    try: socket.socket();os._exit(3)
    except PermissionError: pass
    child=subprocess.run(["/usr/bin/python3","-c","import socket; socket.socket()"],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    if child.returncode==0:os._exit(4)


def fork_probe(fn: Any,*args: Any) -> None:
    pid=os.fork()
    if pid==0:
        try:fn(*args)
        except BaseException:os._exit(2)
        os._exit(0)
    _,status=os.waitpid(pid,0)
    if not os.WIFEXITED(status) or os.WEXITSTATUS(status)!=0:raise SandboxError("COMMAND_SANDBOX_UNAVAILABLE","Real sandbox probe failed")


def probe() -> dict[str, Any]:
    abi=landlock_abi()
    with tempfile.TemporaryDirectory(prefix="pi-gacw-m4-sandbox-") as td:
        allowed=Path(td,"allowed");outside=Path(td,"outside");allowed.mkdir();outside.mkdir();fork_probe(probe_landlock,str(allowed),str(outside))
    fork_probe(probe_seccomp)
    return {"landlock_available":True,"landlock_abi":abi,"filesystem_restrictions":True,"child_inheritance":True,"no_new_privs":True,"seccomp_available":True,"network_denial":True}


def main() -> None:
    raw=sys.stdin.buffer.read(MAX_REQUEST+1)
    if len(raw)>MAX_REQUEST:raise SandboxError("COMMAND_SPEC_MISMATCH","Sandbox request exceeds limit")
    try:request=json.loads(raw)
    except Exception as error:raise SandboxError("COMMAND_SPEC_MISMATCH","Sandbox request is invalid JSON") from error
    if not isinstance(request,dict) or request.get("protocol")!=PROTOCOL:raise SandboxError("COMMAND_SPEC_MISMATCH","Sandbox protocol identity is invalid")
    if request.get("operation")=="PROBE":
        print(json.dumps({"ok":True,"protocol":PROTOCOL,"result":probe()},sort_keys=True,separators=(",",":")));return
    if request.get("operation")!="EXECUTE":raise SandboxError("COMMAND_SPEC_MISMATCH","Unknown sandbox operation")
    execute(request)


if __name__=="__main__":
    try:main()
    except SandboxError as error:
        try:setup_status({"ok":False,"protocol":PROTOCOL,"code":error.code,"detail":error.detail})
        except OSError:print(json.dumps({"ok":False,"protocol":PROTOCOL,"code":error.code,"detail":error.detail},sort_keys=True,separators=(",",":")),file=sys.stderr)
        sys.exit(125)
    except BaseException as error:
        try:setup_status({"ok":False,"protocol":PROTOCOL,"code":"COMMAND_SANDBOX_UNAVAILABLE","detail":f"Sandbox setup failed ({type(error).__name__}:{getattr(error,'errno',None)})"})
        except OSError:pass
        sys.exit(125)
