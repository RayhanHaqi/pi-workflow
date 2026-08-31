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
