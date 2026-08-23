import assert from "node:assert/strict";
import { chmod, mkdtemp, rm, writeFile } from "node:fs/promises";
import { createServer, type Server } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { resolveRepositoryIdentity } from "../src/repository/identity.js";
import { probeM4Capabilities } from "../src/secure-fs/capabilities.js";
import { runSandboxedCommand } from "../src/scoped-tools/sandbox.js";
import { freezeControllerVerificationCommandsForTests } from "../src/workflow-controller.js";
import { commandSpecification } from "./m4-helpers.js";

const ROOT = process.cwd();

async function listen(server: Server, endpoint: string): Promise<void> {
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(endpoint, () => { server.off("error", reject); resolve(); });
  });
}

async function close(server: Server): Promise<void> {
  await new Promise<void>((resolve) => server.close(() => resolve()));
}

test("production sandbox permits exact tsx verifier IPC while retaining truthful network denial", async () => {
  const repository = await resolveRepositoryIdentity({ requestedPath: ROOT, requireHead: true });
  const [specification] = await freezeControllerVerificationCommandsForTests(repository, [{
    command_id: "tsx-focused-production",
    executable: process.execPath,
    args: ["tsx/dist/cli.mjs", "--test", "--test-concurrency=1", "../tests/canonical-json.test.ts"],
    cwd: "node_modules",
    timeout_ms: 60_000,
    readable_paths: [
      { path: "node_modules", kind: "PREFIX" },
      { path: "package.json", kind: "EXACT" },
      { path: "src", kind: "PREFIX" },
      { path: "fixtures", kind: "PREFIX" },
      { path: "tests/canonical-json.test.ts", kind: "EXACT" },
      { path: "tsconfig.json", kind: "EXACT" },
    ],
  }], { readable_paths: [], editable_paths: [], frozen_paths: [] });
  const temporaryRoot = await mkdtemp(join(tmpdir(), "sandbox-tsx-ipc-")); await chmod(temporaryRoot, 0o700);
  try {
    const outcome = await runSandboxedCommand(repository, temporaryRoot, (await probeM4Capabilities()).sandbox, specification!);
    assert.equal(outcome.exitCode, 0, JSON.stringify({ stdout: outcome.stdout.toString(), stderr: outcome.stderr.toString() }));
    assert.match(outcome.stdout.toString(), /# pass 9\n/u);
    assert.equal(outcome.setup?.noNewPrivs, true); assert.equal(outcome.setup?.networkDenied, true); assert.ok((outcome.setup?.landlockAbi ?? 0) >= 3);
  } finally { await rm(temporaryRoot, { recursive: true, force: true }); }
});

test("production sandbox denies unrelated pathname, abstract, descriptor-transfer, and child IPC bridges", async () => {
  const repository = await resolveRepositoryIdentity({ requestedPath: ROOT, requireHead: true });
  const hostRoot = await mkdtemp(join(tmpdir(), "sandbox-host-ipc-"));
  const temporaryRoot = await mkdtemp(join(tmpdir(), "sandbox-command-ipc-")); await chmod(temporaryRoot, 0o700);
  const script = join(hostRoot, "probe.py"); const pathname = join(hostRoot, "unrelated.sock");
  const abstractName = `\0pi-gacw-unrelated-${process.pid}`;
  const source = `import json, os, socket, subprocess, sys\npathname, abstract = sys.argv[1:3]\ndef attempt(fn):\n try: return {"ok": True, "value": fn()}\n except BaseException as error: return {"ok": False, "errno": getattr(error, "errno", None), "type": type(error).__name__}\ndef create(family):\n value=socket.socket(family,socket.SOCK_STREAM);value.close();return "created"\ndef connect(endpoint):\n value=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);value.connect(endpoint);value.close();return "connected"\ndef local_pair():\n left,right=socket.socketpair();os.write(left.fileno(),b"x");value=os.read(right.fileno(),1).decode();left.close();right.close();return value\ndef blocked_recvmsg():\n left,right=socket.socketpair();os.write(left.fileno(),b"x");return right.recvmsg(1)\ndef blocked_accept():\n endpoint=os.path.join(os.environ["TMPDIR"],f"owned-{os.getpid()}.sock");server=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);server.bind(endpoint);server.listen(1);return server.accept()\ndef inherited():\n result=[]\n for fd in range(16):\n  try: os.fstat(fd);result.append(fd)\n  except OSError: pass\n return result\ndef probe():\n return {"af_inet":attempt(lambda:create(socket.AF_INET)),"af_inet6":attempt(lambda:create(socket.AF_INET6)),"pathname":attempt(lambda:connect(pathname)),"abstract":attempt(lambda:connect("\\0"+abstract)),"recvmsg":attempt(blocked_recvmsg),"accept":attempt(blocked_accept),"local_pair":attempt(local_pair),"inherited":inherited()}\nresult=probe()\nif os.environ.get("IPC_CHILD")!="1":\n environment=dict(os.environ);environment["IPC_CHILD"]="1";child=subprocess.run([sys.executable,__file__,pathname,abstract],capture_output=True,text=True,env=environment);result["child"]={"code":child.returncode,"value":json.loads(child.stdout)}\nprint(json.dumps(result,sort_keys=True))\n`;
  await writeFile(script, source);
  const pathnameServer = createServer(); const abstractServer = createServer();
  try {
    await listen(pathnameServer, pathname); await listen(abstractServer, abstractName);
    const specification = await commandSpecification("ipc-isolation", "VERIFICATION", "/usr/bin/python3", [script, pathname, abstractName.slice(1)], {
      repositoryRoot: ROOT, executionInputs: [script], timeoutMs: 30_000,
    });
    const outcome = await runSandboxedCommand(repository, temporaryRoot, (await probeM4Capabilities()).sandbox, specification);
    assert.equal(outcome.exitCode, 0, outcome.stderr.toString());
    assert.equal(outcome.setup?.noNewPrivs, true); assert.equal(outcome.setup?.networkDenied, true); assert.ok((outcome.setup?.landlockAbi ?? 0) >= 3);
    const result = JSON.parse(outcome.stdout.toString()) as any;
    const assertPolicy = (value: any): void => {
      for (const key of ["af_inet", "af_inet6", "pathname", "abstract", "recvmsg", "accept"]) assert.deepEqual(value[key], { ok: false, errno: 1, type: "PermissionError" }, key);
      assert.deepEqual(value.local_pair, { ok: true, value: "x" });
      assert.deepEqual(value.inherited, [0, 1, 2], "only standard controller channels survive exec");
    };
    assertPolicy(result); assert.equal(result.child.code, 0); assertPolicy(result.child.value);
  } finally {
    await Promise.all([close(pathnameServer), close(abstractServer)]);
    await Promise.all([rm(hostRoot, { recursive: true, force: true }), rm(temporaryRoot, { recursive: true, force: true })]);
  }
});
