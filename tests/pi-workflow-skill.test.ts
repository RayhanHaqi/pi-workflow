import assert from "node:assert/strict";
import { execFile as execFileCallback } from "node:child_process";
import { mkdir, mkdtemp, readFile, readdir, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import test from "node:test";

import workflowExtension from "../src/pi-extension/workflow.js";

const execFile = promisify(execFileCallback);
const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const SKILL_PATH = join(ROOT, "skills", "pi-workflow", "SKILL.md");
const EXTENSION_PATH = join(ROOT, "src", "pi-extension", "workflow.ts");

type PackageManifest = {
  readonly files?: readonly string[];
  readonly pi?: {
    readonly extensions?: readonly string[];
    readonly skills?: readonly string[];
  };
};

function parseFrontmatter(source: string): Record<string, string> {
  assert.match(source, /^---\n/u, "skill starts with frontmatter");
  const end = source.indexOf("\n---\n", 4);
  assert.notEqual(end, -1, "skill frontmatter closes");
  const fields: Record<string, string> = {};
  for (const line of source.slice(4, end).split("\n")) {
    const separator = line.indexOf(":");
    assert.ok(separator > 0, `frontmatter line is a key/value pair: ${line}`);
    fields[line.slice(0, separator)] = line.slice(separator + 1).trim();
  }
  return fields;
}

async function manifest(): Promise<PackageManifest> {
  return JSON.parse(await readFile(join(ROOT, "package.json"), "utf8")) as PackageManifest;
}

test("Pi package exposes the pi-workflow skill with valid metadata", async () => {
  const packageJson = await manifest();
  assert.deepEqual(packageJson.pi?.extensions, ["./dist/src/pi-extension/workflow.js"]);
  assert.deepEqual(packageJson.pi?.skills, ["./skills"]);
  assert.ok(packageJson.files?.includes("skills"), "npm files allowlist includes packaged skills");

  const source = await readFile(SKILL_PATH, "utf8");
  const frontmatter = parseFrontmatter(source);
  assert.equal(frontmatter["name"], "pi-workflow");
  assert.match(frontmatter["name"] ?? "", /^[a-z0-9-]+$/u);
  const description = frontmatter["description"] ?? "";
  assert.ok(description.length > 0 && description.length <= 1024);
  assert.match(description, /bounded/u);
  assert.match(description, /owner-approved/u);
  assert.match(description, /trusted Git repositories/u);
  assert.match(source, /existing workflow controller, CLI, and Pi extension are authoritative/u);
});

test("pi-workflow skill remains preparation-only until the existing owner handoff", async () => {
  const source = await readFile(SKILL_PATH, "utf8");

  assert.match(source, /preparation-only/u);
  assert.match(source, /`\/skill:pi-workflow \.\.\.`/u);
  assert.match(source, /`task authorization`/u);
  assert.match(source, /`pi-workflow engine approval`/u);
  for (const phrase of ["Authorized:", "execute the task", "you may modify files", "create a commit"]) {
    assert.ok(source.includes(phrase), `skill names natural-language authorization phrase: ${phrase}`);
  }
  assert.match(source, /must never treat .* as pi-workflow engine approval .* mutations directly/su);

  assert.match(source, /parent Pi agent must not directly:/u);
  for (const operation of [
    "write, edit, or delete project files",
    "create commits",
    "create or delete branches or worktrees",
    "create or remove environments",
    "run mutation-capable setup or install commands",
    "invoke implementation tools or provider/model calls",
    "start subagents",
    "execute the coding task itself",
  ]) {
    assert.ok(source.includes(operation), `skill forbids pre-handoff operation: ${operation}`);
  }
  assert.match(source, /`APPROVE <TaskDocument\.content_sha256>`/u);
  assert.match(source, /`\/workflow <goal\.json>`/u);
  assert.match(source, /`\/workflow mutate <goal\.json>`/u);
  assert.match(source, /must not invoke or simulate the owner's command/u);
  assert.match(source, /model-callable workflow-start tool/u);
});

test("pi-workflow skill resolves derivable workflow values before owner approval", async () => {
  const source = await readFile(SKILL_PATH, "utf8");

  for (const requiredContract of [
    "read-only repository inspection",
    "STATIC_APPROVED_DAG",
    "TERRA_EXECUTOR",
    "openai-codex",
    "gpt-5.6-terra",
    "static_max_attempts_per_leaf: 1",
    "smallest conservative values",
    "narrowest credible editable paths/globs",
    "documentation output paths",
    "branch, HEAD, HEAD tree, clean/dirty state",
    "controller-supported deterministic verification surfaces",
    "normalizeStaticApprovedDagLaunchSpec",
    "staticApprovedDagSpecSha256",
    "exact existing owner-start action",
    "normalized spec and generated approval/spec digest",
  ]) {
    assert.ok(source.includes(requiredContract), `skill resolves or presents: ${requiredContract}`);
  }
  assert.match(source, /The owner never invents or supplies a digest/u);
  assert.match(source, /READY_FOR_OWNER_APPROVAL[\s\S]*stop without mutation/u);
});

test("pi-workflow skill blocks unsupported engine capabilities rather than defaulting them", async () => {
  const source = await readFile(SKILL_PATH, "utf8");

  assert.match(source, /BLOCKED \(not started\)/u);
  assert.match(source, /Canonical defaults do not solve unsupported capabilities/u);
  for (const capability of ["Git worktree creation", "branch creation", "networked Conda environment creation", "commits"]) {
    assert.ok(source.includes(capability), `skill names unsupported capability boundary: ${capability}`);
  }
});

test("npm tarball includes the packaged pi-workflow skill", async () => {
  const packageRoot = await mkdtemp(join(tmpdir(), "pi-workflow-skill-pack-"));
  const extractRoot = join(packageRoot, "extract");
  try {
    await mkdir(extractRoot, { recursive: true });
    await execFile("npm", ["pack", "--ignore-scripts", "--pack-destination", packageRoot], { cwd: ROOT, maxBuffer: 4 * 1024 * 1024 });
    const archive = (await readdir(packageRoot)).find((name) => name.endsWith(".tgz"));
    assert.ok(archive, "npm pack produced a tarball");
    const tarball = join(packageRoot, archive);
    const listing = await execFile("tar", ["-tzf", tarball], { maxBuffer: 4 * 1024 * 1024 });
    assert.match(listing.stdout, /^package\/skills\/pi-workflow\/SKILL\.md$/mu);
    await execFile("tar", ["-xzf", tarball, "-C", extractRoot]);
    assert.equal(await readFile(join(extractRoot, "package", "skills", "pi-workflow", "SKILL.md"), "utf8"), await readFile(SKILL_PATH, "utf8"));
  } finally {
    await rm(packageRoot, { recursive: true, force: true });
  }
});

test("existing Pi extension remains the approval-gated workflow command without model-callable tools", async () => {
  const packageJson = await manifest();
  const extensionSource = await readFile(EXTENSION_PATH, "utf8");
  assert.match(extensionSource, /pi\.registerCommand\("workflow"/u);

  const commands: string[] = [];
  const tools: unknown[] = [];
  const providers: unknown[] = [];
  workflowExtension({
    registerCommand(name: string) {
      commands.push(name);
    },
    registerTool(definition: unknown) {
      tools.push(definition);
    },
    registerProvider(definition: unknown) {
      providers.push(definition);
    },
  } as unknown as Parameters<typeof workflowExtension>[0]);

  assert.deepEqual(packageJson.pi?.extensions, ["./dist/src/pi-extension/workflow.js"]);
  assert.deepEqual(commands, ["workflow"]);
  assert.deepEqual(tools, []);
  assert.deepEqual(providers, []);
});
