import assert from "node:assert/strict";
import { chmod, readdir, unlink, writeFile } from "node:fs/promises";
import { join } from "node:path";
import test from "node:test";

import { sha256Canonical } from "../src/identity/index.js";
import { m3ScopeIdentity } from "../src/identity/m3-scope.js";
import { inspectRunStorage } from "../src/persistence/index.js";
import { m3FingerprintDirtyPaths, m3PorcelainIdentityProjection } from "../src/persistence/m3-authority.js";
import {
  acquireWorktreeLock,
  applyRetentionCleanup,
  captureBaseline,
  createBaselineApproval,
  inspectRetention,
  releaseWorktreeLock,
  resolveRepositoryIdentity,
  runFastPreflight,
  runFullPreflight,
  runPostflight,
} from "../src/repository/index.js";
import { canonicalJsonRecordBytes } from "../src/repository/storage.js";
import {
  identifyContractDocument,
  type M3BaselineRuntimeDocument,
  type M3PostflightDocument,
  type M3RepositoryStateTokenDocument,
  type M3RetentionResultDocument,
} from "../src/schemas/index.js";
import {
  createRepositoryFixture,
  git,
  instructionAuthorityInputs,
  removeRepositoryFixture,
  requiredEnvironment,
  scopeIdentity,
  type RepositoryFixture,
} from "./repository-helpers.js";
import {
  baselineInput,
  createCleanAdmission,
  createTerminalBlobFixture,
  pathDecision,
  releaseAdmission,
  retentionInput,
} from "./repository-matrix-helpers.js";

const directories = {
  baseline: "baselines",
  preflight: "preflights",
  token: "repository-state-tokens",
  postflight: "postflights",
  retention: "retention",
} as const;

async function persist(
  fixture: RepositoryFixture,
  directory: string,
  document: { readonly content_sha256: string },
): Promise<void> {
  const path = join(fixture.stateRoot, "runs", fixture.runId, "records", directory, `${document.content_sha256.slice(7)}.json`);
  await writeFile(path, canonicalJsonRecordBytes(document), { mode: 0o600 });
  await chmod(path, 0o600);
}

async function classification(fixture: RepositoryFixture, digest: string): Promise<string | undefined> {
  const inspection = await inspectRunStorage({ stateRoot: fixture.stateRoot, runId: fixture.runId });
  return inspection.managedRecordClassifications.find((entry) => entry.object.contentSha256 === digest)?.classification;
}

function refreshFingerprint(draft: Record<string, unknown>): void {
  const fingerprint = draft["git_fingerprint"] as Record<string, unknown>;
  fingerprint["staged_diff_sha256"] = sha256Canonical(fingerprint["staged"]);
  fingerprint["unstaged_diff_sha256"] = sha256Canonical(fingerprint["unstaged"]);
  fingerprint["untracked_inventory_sha256"] = sha256Canonical(fingerprint["untracked"]);
  fingerprint["porcelain_v2_sha256"] = sha256Canonical(m3PorcelainIdentityProjection(fingerprint as never));
  const identified = identifyContractDocument("pi_gacw_git_state_fingerprint_v0", fingerprint);
  draft["git_fingerprint"] = identified;
  const accepted = draft["accepted_baseline"] as Record<string, unknown>;
  accepted["git_state_sha256"] = identified.content_sha256;
  draft["accepted_baseline"] = identifyContractDocument("pi_gacw_baseline_v0", accepted);
}

function identifyBaseline(
  baseline: M3BaselineRuntimeDocument,
  mutate: (draft: Record<string, unknown>) => void,
  refresh = false,
): M3BaselineRuntimeDocument {
  const draft = structuredClone(baseline) as unknown as Record<string, unknown>;
  mutate(draft);
  if (refresh) refreshFingerprint(draft);
  return identifyContractDocument("pi_gacw_baseline_runtime_v0", draft) as unknown as M3BaselineRuntimeDocument;
}

async function tokenCount(fixture: RepositoryFixture): Promise<number> {
  return (await readdir(join(fixture.stateRoot, "runs", fixture.runId, "records", directories.token))).length;
}

async function assertInvalidDirtyBaseline(
  fixture: RepositoryFixture,
  lock: Awaited<ReturnType<typeof acquireWorktreeLock>>,
  baseline: M3BaselineRuntimeDocument,
): Promise<void> {
  await persist(fixture, directories.baseline, baseline);
  const before = await tokenCount(fixture);
  await assert.rejects(createBaselineApproval({
    stateRoot: fixture.stateRoot,
    runId: fixture.runId,
    baseline,
    approvedBy: "r4-owner",
    approvedAt: "2026-01-01T00:00:00.000Z",
  }));
  const selected = await instructionAuthorityInputs(fixture);
  await assert.rejects(runFullPreflight({
    stateRoot: fixture.stateRoot,
    runId: fixture.runId,
    expectedRepository: baseline.repository,
    expectedWorktreeKey: baseline.repository.worktree_key,
    expectedBranch: baseline.repository.branch,
    expectedHead: baseline.repository.head,
    expectedWorktreeListSha256: baseline.repository.worktree_list_sha256,
    baseline,
    approval: null,
    instructionFiles: selected.instructions,
    authorityFiles: selected.authorities,
    requiredEnvironment: await requiredEnvironment(fixture.repository),
    taskScopeIdentity: scopeIdentity(["tracked.txt"], ["AGENTS.md", "AUTHORITY.md"]),
    allowShallow: false,
    allowPartialClone: false,
    lock,
  }));
  assert.equal(await tokenCount(fixture), before);
  assert.equal(await classification(fixture, baseline.content_sha256), "INVALID_MANAGED_RECORD");
}

function updatePathStatus(draft: Record<string, unknown>, path: string): void {
  const fingerprint = draft["git_fingerprint"] as M3BaselineRuntimeDocument["git_fingerprint"];
  const entry = (draft["paths"] as Array<Record<string, unknown>>).find((candidate) => candidate["path"] === path)!;
  entry["status_sha256"] = sha256Canonical({
    staged: fingerprint.staged.filter((candidate) => candidate.path === path || candidate.old_path === path),
    unstaged: fingerprint.unstaged.filter((candidate) => candidate.path === path || candidate.old_path === path),
    untracked: fingerprint.untracked.filter((candidate) => candidate.path === path),
    conflicts: fingerprint.conflicts.filter((candidate) => candidate.path === path),
  });
}

test("R4 baseline-producer-semantics rejects staged deletion, fingerprint, blocker, inventory, and quota forgeries", async (t) => {
  const fixture = await createRepositoryFixture();
  await git(fixture.repository, "rm", "--", "tracked.txt");
  const repository = await resolveRepositoryIdentity({ requestedPath: fixture.repository, requireHead: true });
  const lock = await acquireWorktreeLock({ stateRoot: fixture.stateRoot, repository });
  try {
    const baseline = (await captureBaseline(await baselineInput(fixture, lock, "APPROVED_BASELINE_DIRTY", [pathDecision("tracked.txt")]))).baseline;
    const path = () => (baseline.paths[0]!);
    const staged = () => baseline.git_fingerprint.staged[0]!;
    const mutations: readonly [string, M3BaselineRuntimeDocument][] = [
      ["staged deletion represented as regular", identifyBaseline(baseline, (d) => {
        const p=(d["paths"] as Array<Record<string,unknown>>)[0]!;p["file_type"]="REGULAR";p["content_sha256"]=`sha256:${"d".repeat(64)}`;p["mode"]=420;p["size"]=1;
        ((d["accepted_baseline"] as Record<string,unknown>)["files"] as Array<Record<string,unknown>>)[0]!["content_sha256"]=p["content_sha256"];
        d["accepted_baseline"]=identifyContractDocument("pi_gacw_baseline_v0",d["accepted_baseline"] as Record<string, unknown>);
      })],
      ["wrong path content digest", identifyBaseline(baseline, (d) => {const p=(d["paths"] as Array<Record<string,unknown>>)[0]!;p["content_sha256"]=`sha256:${"c".repeat(64)}`;((d["accepted_baseline"] as Record<string,unknown>)["files"] as Array<Record<string,unknown>>)[0]!["content_sha256"]=p["content_sha256"];d["accepted_baseline"]=identifyContractDocument("pi_gacw_baseline_v0",d["accepted_baseline"] as Record<string, unknown>);})],
      ["wrong path size", identifyBaseline(baseline, (d) => {(d["paths"] as Array<Record<string,unknown>>)[0]!["size"]=1;})],
      ["wrong index object", identifyBaseline(baseline, (d) => {((d["git_fingerprint"] as Record<string,unknown>)["staged"] as Array<Record<string,unknown>>)[0]!["index_object"]=staged().head_object;}, true)],
      ["wrong HEAD object", identifyBaseline(baseline, (d) => {((d["git_fingerprint"] as Record<string,unknown>)["staged"] as Array<Record<string,unknown>>)[0]!["head_object"]="f".repeat(40);}, true)],
      ["wrong index identity", identifyBaseline(baseline, (d) => {(d["git_fingerprint"] as Record<string,unknown>)["index_sha256"]=`sha256:${"1".repeat(64)}`;}, true)],
      ["wrong staged-diff identity", identifyBaseline(baseline, (d) => {(d["git_fingerprint"] as Record<string,unknown>)["staged_diff_sha256"]=`sha256:${"2".repeat(64)}`;})],
      ["wrong physical requested path", identifyBaseline(baseline, (d) => {const r=d["repository"] as Record<string,unknown>;r["physical_requested_path"]=`${fixture.repository}/forged`;d["repository"]=identifyContractDocument("pi_gacw_repository_identity_v0",r);(d["git_fingerprint"] as Record<string,unknown>)["repository_identity_content_sha256"]=(d["repository"] as Record<string,unknown>)["content_sha256"];}, true)],
      ["active MERGE", identifyBaseline(baseline, (d) => {(d["git_fingerprint"] as Record<string,unknown>)["active_operations"]=["MERGE"];}, true)],
      ["active REBASE", identifyBaseline(baseline, (d) => {(d["git_fingerprint"] as Record<string,unknown>)["active_operations"]=["REBASE"];}, true)],
      ["index.lock present", identifyBaseline(baseline, (d) => {(d["git_fingerprint"] as Record<string,unknown>)["index_lock"]=true;}, true)],
      ["conflict present", identifyBaseline(baseline, (d) => {const f=d["git_fingerprint"] as Record<string,unknown>;f["conflicts"]=[{path:"tracked.txt",status:"UU",stage1_mode:"100644",stage2_mode:"100644",stage3_mode:"100644",worktree_mode:"100644",stage1_object:staged().head_object,stage2_object:staged().head_object,stage3_object:staged().head_object}];updatePathStatus(d,"tracked.txt");}, true)],
      ["extra dirty decision path", identifyBaseline(baseline, (d) => {const p=structuredClone((d["paths"] as Array<Record<string,unknown>>)[0]!);p["path"]="extra.txt";(d["paths"] as Array<Record<string,unknown>>).push(p);const a=d["accepted_baseline"] as Record<string,unknown>;const file=structuredClone((a["files"] as Array<Record<string,unknown>>)[0]!);file["path"]="extra.txt";(a["files"] as Array<Record<string,unknown>>).push(file);(a["files"] as Array<Record<string,unknown>>).sort((l,r)=>String(l["path"]).localeCompare(String(r["path"])));d["accepted_baseline"]=identifyContractDocument("pi_gacw_baseline_v0",a);})],
      ["missing dirty decision path", identifyBaseline(baseline, (d) => {(d["paths"] as unknown[]).length=0;const a=d["accepted_baseline"] as Record<string,unknown>;a["files"]=[];d["accepted_baseline"]=identifyContractDocument("pi_gacw_baseline_v0",a);})],
      ["no-blob baseline claims retained bytes", identifyBaseline(baseline, (d) => {const q=d["blob_quota"] as Record<string,unknown>;q["existing_physical_bytes"]=1;q["resulting_physical_bytes"]=1;})],
      ["wrong new unique bytes", identifyBaseline(baseline, (d) => {const q=d["blob_quota"] as Record<string,unknown>;q["new_unique_physical_bytes"]=1;q["resulting_physical_bytes"]=1;})],
      ["wrong resulting bytes", identifyBaseline(baseline, (d) => {(d["blob_quota"] as Record<string,unknown>)["resulting_physical_bytes"]=1;})],
      ["wrong deduplicated bytes", identifyBaseline(baseline, (d) => {(d["blob_quota"] as Record<string,unknown>)["deduplicated_bytes"]=1;})],
      ["wrong logical approved bytes", identifyBaseline(baseline, (d) => {(d["blob_quota"] as Record<string,unknown>)["logical_approved_bytes"]=1;})],
    ];
    assert.equal(path().file_type, "DELETED");
    for (const [name, altered] of mutations) await t.test(name, async () => assertInvalidDirtyBaseline(fixture, lock, altered));
    const approval = (await createBaselineApproval({stateRoot:fixture.stateRoot,runId:fixture.runId,baseline,approvedBy:"owner",approvedAt:"2026-01-01T00:00:00.000Z"})).approval;
    assert.equal(await classification(fixture, baseline.content_sha256), "AUTHORITATIVE_MANAGED_RECORD");
    assert.equal(await classification(fixture, approval.content_sha256), "AUTHORITATIVE_MANAGED_RECORD");
  } finally { await releaseWorktreeLock(lock).catch(() => undefined); await removeRepositoryFixture(fixture); }
});

async function scenarioBaseline(
  setup: (fixture: RepositoryFixture) => Promise<string>,
): Promise<{fixture:RepositoryFixture;lock:Awaited<ReturnType<typeof acquireWorktreeLock>>;baseline:M3BaselineRuntimeDocument}> {
  const fixture=await createRepositoryFixture();const path=await setup(fixture);const repository=await resolveRepositoryIdentity({requestedPath:fixture.repository,requireHead:true});const lock=await acquireWorktreeLock({stateRoot:fixture.stateRoot,repository});const baseline=(await captureBaseline(await baselineInput(fixture,lock,"APPROVED_BASELINE_DIRTY",[pathDecision(path)]))).baseline;return{fixture,lock,baseline};
}

test("R4 baseline-producer-semantics distinguishes deletion, addition, modification, rename, and mode state", async (t) => {
  const cases: readonly [string, () => Promise<{fixture:RepositoryFixture;lock:Awaited<ReturnType<typeof acquireWorktreeLock>>;baseline:M3BaselineRuntimeDocument}>, (baseline:M3BaselineRuntimeDocument)=>M3BaselineRuntimeDocument][] = [
    ["unstaged deletion represented as regular",()=>scenarioBaseline(async f=>{await unlink(f.trackedPath);return"tracked.txt";}),b=>identifyBaseline(b,d=>{const p=(d["paths"] as Array<Record<string,unknown>>)[0]!;p["file_type"]="REGULAR";p["content_sha256"]=`sha256:${"e".repeat(64)}`;p["mode"]=420;p["size"]=1;const a=d["accepted_baseline"] as Record<string,unknown>;(a["files"] as Array<Record<string,unknown>>)[0]!["content_sha256"]=p["content_sha256"];d["accepted_baseline"]=identifyContractDocument("pi_gacw_baseline_v0",a);})],
    ["untracked addition represented as modification",()=>scenarioBaseline(async f=>{await writeFile(join(f.repository,"new.txt"),"new\n");return"new.txt";}),b=>identifyBaseline(b,d=>{const f=d["git_fingerprint"] as Record<string,unknown>;const u=(f["untracked"] as Array<Record<string,unknown>>)[0]!;f["untracked"]=[];f["unstaged"]=[{path:u["path"],old_path:null,status:"M",state:"PRESENT",file_type:"REGULAR",mode:u["mode"],size:u["size"],content_sha256:u["content_sha256"]}];const a=d["accepted_baseline"] as Record<string,unknown>;a["untracked_paths"]=[];a["unstaged_paths"]=["new.txt"];d["accepted_baseline"]=identifyContractDocument("pi_gacw_baseline_v0",a);updatePathStatus(d,"new.txt");},true)],
    ["modified file represented as addition",()=>scenarioBaseline(async f=>{await writeFile(f.trackedPath,"modified\n");return"tracked.txt";}),b=>identifyBaseline(b,d=>{const f=d["git_fingerprint"] as Record<string,unknown>;const u=(f["unstaged"] as Array<Record<string,unknown>>)[0]!;f["unstaged"]=[];f["untracked"]=[{path:u["path"],file_type:"REGULAR",mode:u["mode"],size:u["size"],content_sha256:u["content_sha256"]}];const a=d["accepted_baseline"] as Record<string,unknown>;a["unstaged_paths"]=[];a["untracked_paths"]=["tracked.txt"];d["accepted_baseline"]=identifyContractDocument("pi_gacw_baseline_v0",a);updatePathStatus(d,"tracked.txt");},true)],
    ["rename with wrong old path",async()=>{const fixture=await createRepositoryFixture();await git(fixture.repository,"mv","tracked.txt","renamed.txt");const repository=await resolveRepositoryIdentity({requestedPath:fixture.repository,requireHead:true});const lock=await acquireWorktreeLock({stateRoot:fixture.stateRoot,repository});const baseline=(await captureBaseline(await baselineInput(fixture,lock,"APPROVED_BASELINE_DIRTY",[pathDecision("renamed.txt"),pathDecision("tracked.txt")]))).baseline;return{fixture,lock,baseline};},b=>identifyBaseline(b,d=>{const f=d["git_fingerprint"] as Record<string,unknown>;((f["staged"] as Array<Record<string,unknown>>)[0]!)["old_path"]="AUTHORITY.md";},true)],
    ["mode change with wrong before mode",()=>scenarioBaseline(async f=>{await chmod(f.trackedPath,0o755);await git(f.repository,"add","--","tracked.txt");return"tracked.txt";}),b=>identifyBaseline(b,d=>{const f=d["git_fingerprint"] as Record<string,unknown>;((f["staged"] as Array<Record<string,unknown>>)[0]!)["head_mode"]="100755";},true)],
    ["wrong unstaged-diff identity",()=>scenarioBaseline(async f=>{await writeFile(f.trackedPath,"modified\n");return"tracked.txt";}),b=>identifyBaseline(b,d=>{(d["git_fingerprint"] as Record<string,unknown>)["unstaged_diff_sha256"]=`sha256:${"3".repeat(64)}`;})],
    ["wrong untracked identity",()=>scenarioBaseline(async f=>{await writeFile(join(f.repository,"new.txt"),"new\n");return"new.txt";}),b=>identifyBaseline(b,d=>{(d["git_fingerprint"] as Record<string,unknown>)["untracked_inventory_sha256"]=`sha256:${"4".repeat(64)}`;})],
  ];
  for(const[name,create,mutate]of cases)await t.test(name,async()=>{const value=await create();try{await assertInvalidDirtyBaseline(value.fixture,value.lock,mutate(value.baseline));assert.equal(await classification(value.fixture,value.baseline.content_sha256),"AUTHORITATIVE_MANAGED_RECORD");}finally{await releaseWorktreeLock(value.lock).catch(()=>{});await removeRepositoryFixture(value.fixture);}});
});

function fullPair(sourceDraft: M3PostflightDocument | M3RepositoryStateTokenDocument, tokenDraft?: M3RepositoryStateTokenDocument) { return {sourceDraft,tokenDraft}; }

test("R4 environment-repository-binding rejects every forged full-preflight environment fact", async (t) => {
  const fixture=await createRepositoryFixture();let admission:Awaited<ReturnType<typeof createCleanAdmission>>|undefined;
  try{admission=await createCleanAdmission(fixture);const variants=new Map<string,{source:any;token:any}>();
    const add=(name:string,mutate:(s:Record<string,unknown>)=>void)=>{const s=structuredClone(admission!.full.preflight) as unknown as Record<string,unknown>;mutate(s);const source=identifyContractDocument("pi_gacw_preflight_v0",s);const td=structuredClone(admission!.full.acceptedState) as unknown as Record<string,unknown>;td["source_content_sha256"]=source.content_sha256;const token=identifyContractDocument("pi_gacw_repository_state_token_v0",td);variants.set(name,{source,token});};
    for(const field of ["git_version","node_version","python_version"] as const)add(field,s=>{const e=s["environment_fingerprint"] as Record<string,unknown>;e[field]=`${String(e[field])}-forged`;const{content_sha256:_,...p}=e;e["content_sha256"]=sha256Canonical(p);});
    for(const field of ["git_path","node_path","python_path"] as const)add(field,s=>{const e=s["environment_fingerprint"] as Record<string,unknown>;e[field]="/forged/impossible/executable";const{content_sha256:_,...p}=e;e["content_sha256"]=sha256Canonical(p);});
    add("environment fingerprint",s=>{(s["environment_fingerprint"] as Record<string,unknown>)["content_sha256"]=`sha256:${"5".repeat(64)}`;});
    add("repository Git version",s=>{const r=s["repository"] as Record<string,unknown>;r["git_version"]="git version forged";s["repository"]=identifyContractDocument("pi_gacw_repository_identity_v0",r);});
    await t.test("controller/package version is schema-fixed",()=>{const s=structuredClone(admission!.full.preflight) as unknown as Record<string,unknown>;const e=s["environment_fingerprint"] as Record<string,unknown>;e["controller_version"]="9.9.9";assert.throws(()=>identifyContractDocument("pi_gacw_preflight_v0",s));});
    for(const[name,pair]of variants){await persist(fixture,directories.preflight,pair.source);await persist(fixture,directories.token,pair.token);await t.test(name,async()=>{await assert.rejects(runFastPreflight({stateRoot:fixture.stateRoot,runId:fixture.runId,acceptedState:pair.token,baseline:admission!.baseline,instructionFiles:admission!.selected.instructions,authorityFiles:admission!.selected.authorities,taskScopeIdentity:admission!.taskScopeIdentity,lock:admission!.lock}));assert.equal(await classification(fixture,pair.source.content_sha256),"INVALID_MANAGED_RECORD");assert.equal(await classification(fixture,pair.token.content_sha256),"INVALID_MANAGED_RECORD");});}
    assert.equal(await classification(fixture,admission.full.preflight.content_sha256),"AUTHORITATIVE_MANAGED_RECORD");
  }finally{if(admission)await releaseAdmission(admission);await removeRepositoryFixture(fixture);}
});

interface PostflightPair { readonly source:M3PostflightDocument; readonly token:M3RepositoryStateTokenDocument }
function postflightPair(valid:PostflightPair,mutateSource?:(d:Record<string,unknown>)=>void,mutateToken?:(d:Record<string,unknown>)=>void):PostflightPair{const sd=structuredClone(valid.source) as unknown as Record<string,unknown>;mutateSource?.(sd);const source=identifyContractDocument("pi_gacw_postflight_v0",sd) as unknown as M3PostflightDocument;const td=structuredClone(valid.token) as unknown as Record<string,unknown>;td["source_content_sha256"]=source.content_sha256;td["workflow_owned_delta_sha256"]=sha256Canonical(source.workflow_owned_delta);td["changed_paths"]=source.workflow_owned_delta.map(e=>e.path);mutateToken?.(td);return{source,token:identifyContractDocument("pi_gacw_repository_state_token_v0",td) as unknown as M3RepositoryStateTokenDocument};}

test("R4 delta-preimage-semantics, change-kind-semantics, and scope domain reject forged successors",async(t)=>{const fixture=await createRepositoryFixture();await writeFile(join(fixture.repository,"delete.txt"),"delete\n");await writeFile(join(fixture.repository,"mode.txt"),"mode\n");await git(fixture.repository,"add","delete.txt","mode.txt");await git(fixture.repository,"commit","-m","mixed paths");let admission:Awaited<ReturnType<typeof createCleanAdmission>>|undefined;try{admission=await createCleanAdmission(fixture,{editable:["delete.txt","mode.txt","new.txt","tracked.txt"]});await writeFile(fixture.trackedPath,"modified\n");await writeFile(join(fixture.repository,"new.txt"),"new\n");await unlink(join(fixture.repository,"delete.txt"));await chmod(join(fixture.repository,"mode.txt"),0o755);const produced=await runPostflight({stateRoot:fixture.stateRoot,runId:fixture.runId,acceptedState:admission.full.acceptedState,baseline:admission.baseline,instructionFiles:admission.selected.instructions,authorityFiles:admission.selected.authorities,editablePaths:admission.editable,frozenPaths:admission.frozen,taskScopeIdentity:admission.taskScopeIdentity,claimedWorkflowPaths:["delete.txt","mode.txt","new.txt","tracked.txt"],lock:admission.lock});const valid={source:produced.postflight,token:produced.acceptedState};const index=(entries:readonly {path:string}[],path:string)=>entries.findIndex(e=>e.path===path);const rt=index(valid.source.repository_git_delta,"tracked.txt"),wt=index(valid.source.workflow_owned_delta,"tracked.txt"),rn=index(valid.source.repository_git_delta,"new.txt"),wn=index(valid.source.workflow_owned_delta,"new.txt"),rd=index(valid.source.repository_git_delta,"delete.txt"),wd=index(valid.source.workflow_owned_delta,"delete.txt"),rm=index(valid.source.repository_git_delta,"mode.txt"),wm=index(valid.source.workflow_owned_delta,"mode.txt");const other=`sha256:${"6".repeat(64)}`;const variants:readonly[string,PostflightPair][]=[
["repository before content",postflightPair(valid,d=>{(d["repository_git_delta"] as Array<Record<string,unknown>>)[rt]!["before_content_sha256"]=other;})],
["repository before mode",postflightPair(valid,d=>{(d["repository_git_delta"] as Array<Record<string,unknown>>)[rt]!["before_mode"]=493;})],
["repository before type",postflightPair(valid,d=>{(d["repository_git_delta"] as Array<Record<string,unknown>>)[rt]!["before_type"]="DELETED";})],
["workflow before content",postflightPair(valid,d=>{(d["workflow_owned_delta"] as Array<Record<string,unknown>>)[wt]!["before_content_sha256"]=other;})],
["workflow before mode",postflightPair(valid,d=>{(d["workflow_owned_delta"] as Array<Record<string,unknown>>)[wt]!["before_mode"]=493;})],
["workflow before type",postflightPair(valid,d=>{(d["workflow_owned_delta"] as Array<Record<string,unknown>>)[wt]!["before_type"]="DELETED";})],
["after content",postflightPair(valid,d=>{(d["repository_git_delta"] as Array<Record<string,unknown>>)[rt]!["after_content_sha256"]=other;})],
["after mode",postflightPair(valid,d=>{(d["repository_git_delta"] as Array<Record<string,unknown>>)[rt]!["after_mode"]=493;})],
["after type",postflightPair(valid,d=>{(d["repository_git_delta"] as Array<Record<string,unknown>>)[rt]!["after_type"]="DELETED";})],
["ADDED relabeled MODIFIED",postflightPair(valid,d=>{(d["repository_git_delta"] as Array<Record<string,unknown>>)[rn]!["change_kind"]="MODIFIED";(d["workflow_owned_delta"] as Array<Record<string,unknown>>)[wn]!["change_kind"]="MODIFIED";})],
["DELETED relabeled MODIFIED",postflightPair(valid,d=>{(d["repository_git_delta"] as Array<Record<string,unknown>>)[rd]!["change_kind"]="MODIFIED";(d["workflow_owned_delta"] as Array<Record<string,unknown>>)[wd]!["change_kind"]="MODIFIED";})],
["MODIFIED relabeled ADDED",postflightPair(valid,d=>{(d["repository_git_delta"] as Array<Record<string,unknown>>)[rt]!["change_kind"]="ADDED";(d["workflow_owned_delta"] as Array<Record<string,unknown>>)[wt]!["change_kind"]="ADDED";})],
["mode change relabeled modified",postflightPair(valid,d=>{(d["repository_git_delta"] as Array<Record<string,unknown>>)[rm]!["change_kind"]="MODIFIED";(d["workflow_owned_delta"] as Array<Record<string,unknown>>)[wm]!["change_kind"]="MODIFIED";})],
["missing delta path",postflightPair(valid,d=>{(d["workflow_owned_delta"] as unknown[]).splice(wt,1);})],
["extra unchanged delta path",postflightPair(valid,d=>{const e=structuredClone((d["workflow_owned_delta"] as Array<Record<string,unknown>>)[wt]!);e["path"]="AUTHORITY.md";e["before_content_sha256"]=e["after_content_sha256"];(d["workflow_owned_delta"] as Array<Record<string,unknown>>).push(e);(d["workflow_owned_delta"] as Array<Record<string,unknown>>).sort((a,b)=>String(a["path"]).localeCompare(String(b["path"])));})],
["wrong claimed path",postflightPair(valid,d=>{d["claimed_workflow_paths"]=["tracked.txt"];})],
["wrong changed-path inventory",postflightPair(valid,undefined,d=>{d["changed_paths"]=["tracked.txt"];})],
["wrong deletion inventory",postflightPair(valid,d=>{(d["workflow_owned_delta"] as Array<Record<string,unknown>>)[wd]!["after_type"]="REGULAR";})],
["wrong mode-change inventory",postflightPair(valid,d=>{(d["workflow_owned_delta"] as Array<Record<string,unknown>>)[wm]!["after_mode"]=420;})],
["editable paths",postflightPair(valid,d=>{(d["scope"] as Record<string,unknown>)["editable_paths"]=["tracked.txt"];})],
["frozen paths",postflightPair(valid,d=>{(d["scope"] as Record<string,unknown>)["frozen_paths"]=["AGENTS.md"];})],
["scope identity",postflightPair(valid,d=>{(d["scope"] as Record<string,unknown>)["scope_identity"]=other;})],
];for(const marker of ["schema_id","schema_version","scope_projection_id"] as const)await t.test(`scope ${marker} is schema-fixed`,()=>{const d=structuredClone(valid.source) as unknown as Record<string,unknown>;(d["scope"] as Record<string,unknown>)[marker]="forged";assert.throws(()=>identifyContractDocument("pi_gacw_postflight_v0",d));});for(const[name,pair]of variants){await persist(fixture,directories.postflight,pair.source);await persist(fixture,directories.token,pair.token);await t.test(name,async()=>{await assert.rejects(runFastPreflight({stateRoot:fixture.stateRoot,runId:fixture.runId,acceptedState:pair.token,baseline:admission!.baseline,instructionFiles:admission!.selected.instructions,authorityFiles:admission!.selected.authorities,taskScopeIdentity:admission!.taskScopeIdentity,lock:admission!.lock}));assert.equal(await classification(fixture,pair.source.content_sha256),name==="wrong changed-path inventory"?"AUTHORITATIVE_MANAGED_RECORD":"INVALID_MANAGED_RECORD");assert.equal(await classification(fixture,pair.token.content_sha256),"INVALID_MANAGED_RECORD");});}assert.equal(valid.source.scope.scope_identity,m3ScopeIdentity(valid.source.scope.editable_paths,valid.source.scope.frozen_paths));assert.equal(valid.source.scope.schema_id,"pi_gacw_task_scope_v0");assert.equal(valid.source.repository_git_delta.find(e=>e.path==="new.txt")!.change_kind,"ADDED");assert.equal(valid.source.repository_git_delta.find(e=>e.path==="delete.txt")!.change_kind,"DELETED");assert.equal(valid.source.repository_git_delta.find(e=>e.path==="mode.txt")!.change_kind,"MODE_CHANGED");assert.equal(await classification(fixture,valid.token.content_sha256),"AUTHORITATIVE_MANAGED_RECORD");}finally{if(admission)await releaseAdmission(admission);await removeRepositoryFixture(fixture);}});

function identifyRetention(base:M3RetentionResultDocument,mutate:(d:Record<string,unknown>)=>void):M3RetentionResultDocument{const d=structuredClone(base) as unknown as Record<string,unknown>;mutate(d);return identifyContractDocument("pi_gacw_retention_result_v0",d) as unknown as M3RetentionResultDocument;}

test("R4 retention-result-state-machine rejects impossible operation, outcome, detail, flags, counts, and proof states", async (t) => {
  const value = await createTerminalBlobFixture([
    { name: "one.txt", bytes: "one\n" },
    { name: "two.txt", bytes: "two\n" },
  ]);
  try {
    const inspection = await inspectRetention(retentionInput(value));
    const complete = await applyRetentionCleanup(retentionInput(value));
    const idempotent = await applyRetentionCleanup(retentionInput(value));
    const failed = identifyRetention(inspection, (draft) => {
      draft["operation"] = "CLEANUP";
      draft["outcome"] = "FAILED";
      for (const blob of draft["blobs"] as Array<Record<string, unknown>>) {
        blob["status"] = "ERROR";
        blob["result"] = "FAILED";
        blob["detail_code"] = "TARGET_UNLINK_FAILED";
        blob["prior_successful_result_content_sha256"] = null;
        blob["unlink_performed"] = false;
        blob["directory_fsync_performed"] = false;
      }
    });
    await persist(value.fixture, directories.retention, failed);
    const variants: readonly [string, M3RetentionResultDocument][] = [
      ["INSPECT to CLEANUP", identifyRetention(inspection, (d) => { d["operation"] = "CLEANUP"; })],
      ["CLEANUP to INSPECT", identifyRetention(complete, (d) => { d["operation"] = "INSPECT"; })],
      ["eligible inspection outcome FAILED", identifyRetention(inspection, (d) => { d["outcome"] = "FAILED"; })],
      ["eligible inspection forged detail", identifyRetention(inspection, (d) => {
        (d["blobs"] as Array<Record<string, unknown>>)[0]!["detail_code"] = "FORGED_DETAIL";
      })],
      ["complete cleanup outcome ELIGIBLE", identifyRetention(complete, (d) => { d["outcome"] = "ELIGIBLE"; })],
      ["complete cleanup forged detail", identifyRetention(complete, (d) => {
        (d["blobs"] as Array<Record<string, unknown>>)[0]!["detail_code"] = "FORGED_DETAIL";
      })],
      ["success target unlink false", identifyRetention(complete, (d) => {
        (d["blobs"] as Array<Record<string, unknown>>)[0]!["unlink_performed"] = false;
      })],
      ["failure target unlink true", identifyRetention(inspection, (d) => {
        d["operation"] = "CLEANUP"; d["outcome"] = "PARTIAL";
        const blob = (d["blobs"] as Array<Record<string, unknown>>)[0]!;
        blob["status"] = "ERROR"; blob["result"] = "FAILED";
        blob["detail_code"] = "TARGET_UNLINK_FAILED"; blob["unlink_performed"] = true;
      })],
      ["directory fsync without unlink", identifyRetention(inspection, (d) => {
        (d["blobs"] as Array<Record<string, unknown>>)[0]!["directory_fsync_performed"] = true;
      })],
      ["logical target count", identifyRetention(inspection, (d) => {
        d["logical_target_count"] = (d["logical_target_count"] as number) + 1;
      })],
      ["physical target count", identifyRetention(inspection, (d) => {
        d["physical_target_count"] = (d["physical_target_count"] as number) + 1;
      })],
      ["partial target set COMPLETE", identifyRetention(complete, (d) => {
        (d["blobs"] as unknown[]).pop(); d["physical_target_count"] = 1; d["logical_target_count"] = 1;
      })],
      ["complete target set PARTIAL", identifyRetention(complete, (d) => { d["outcome"] = "PARTIAL"; })],
      ["IDEMPOTENT without prior proof", identifyRetention(idempotent, (d) => {
        (d["blobs"] as Array<Record<string, unknown>>)[0]!["prior_successful_result_content_sha256"] = null;
      })],
      ["inspection used as deletion proof", identifyRetention(idempotent, (d) => {
        (d["blobs"] as Array<Record<string, unknown>>)[0]!["prior_successful_result_content_sha256"] = inspection.content_sha256;
      })],
      ["failed cleanup used as deletion proof", identifyRetention(idempotent, (d) => {
        (d["blobs"] as Array<Record<string, unknown>>)[0]!["prior_successful_result_content_sha256"] = failed.content_sha256;
      })],
    ];
    for (const [, record] of variants) await persist(value.fixture, directories.retention, record);
    const managed = await inspectRunStorage({ stateRoot: value.fixture.stateRoot, runId: value.fixture.runId });
    const classes: ReadonlyMap<string, string> = new Map(
      managed.managedRecordClassifications.map((entry) => [entry.object.contentSha256, entry.classification]),
    );
    for (const [name, record] of variants) {
      await t.test(name, () => assert.equal(classes.get(record.content_sha256), "INVALID_MANAGED_RECORD"));
    }
    await assert.rejects(applyRetentionCleanup(retentionInput(value)));
    assert.equal(classes.get(inspection.content_sha256), "AUTHORITATIVE_MANAGED_RECORD");
    assert.equal(classes.get(complete.content_sha256), "AUTHORITATIVE_MANAGED_RECORD");
    assert.equal(classes.get(idempotent.content_sha256), "AUTHORITATIVE_MANAGED_RECORD");
    assert.equal(classes.get(failed.content_sha256), "AUTHORITATIVE_MANAGED_RECORD");
  } finally {
    await removeRepositoryFixture(value.fixture);
  }
});
