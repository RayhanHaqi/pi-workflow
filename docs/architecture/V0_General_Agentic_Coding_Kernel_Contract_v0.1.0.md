# V0 General Agentic Coding Kernel Contract

```text
DOCUMENT_ID = PI-GACW-V0-CONTRACT
DOCUMENT_VERSION = 0.1.0
DESIGN_STATUS = REPLAN_READY_FOR_OWNER_REVIEW
IMPLEMENTATION_STATUS = NOT_STARTED
RUNTIME_SCOPE = ANY_TRUSTED_SINGLE_GIT_WORKTREE
```

## 1. V0 objective

Implement the smallest generally useful Pi workflow that can safely execute bounded coding objectives in arbitrary Git repositories.

V0 must support:

```text
feature implementation
bug fixing
behavior-preserving refactoring
test and CI repair
configuration and schema work with frozen semantics
documentation coupled to code
repository analysis followed by bounded mutation
```

V0 must not contain repository-specific business logic.

## 2. Package and installation contract

### 2.1 Package shape

```text
pi-bounded-coding-workflow/
├── package.json
├── bin/
│   └── pi-workflow
├── extensions/
│   └── workflow.ts
├── src/
│   ├── core/
│   ├── identity/
│   ├── state/
│   ├── contracts/
│   ├── routing/
│   ├── budget/
│   ├── progress/
│   ├── failures/
│   ├── repo-guard/
│   ├── secure-fs/
│   ├── pi-adapter/
│   └── cli/
├── schemas/
├── tests/
├── fixtures/
└── docs/
```

### 2.2 Pi package manifest

The package exposes only the thin extension:

```json
{
  "keywords": ["pi-package"],
  "bin": {
    "pi-workflow": "./bin/pi-workflow"
  },
  "pi": {
    "extensions": ["./extensions/workflow.ts"]
  }
}
```

### 2.3 Installation

Development source is a normal Git repository.

Global use:

```bash
pi install /absolute/path/to/pi-bounded-coding-workflow
```

Project-local installation is not the V0 default because the workflow is general and its controller must remain independent from the target repository.

### 2.4 Extension responsibility

The extension registers `/workflow` and may render status.

It must not:

```text
create worker sessions
own canonical run state
select transitions
select routes
modify budgets
expand tasks
run in the background after the command returns
expose a model-callable start tool
```

It launches the standalone controller as a child process without a shell and passes:

```text
current cwd
subcommand
run ID
explicit user arguments
```

## 3. State and configuration locations

```text
state:
${XDG_STATE_HOME:-~/.local/state}/pi-bounded-coding-workflow/

cache:
${XDG_CACHE_HOME:-~/.cache}/pi-bounded-coding-workflow/

optional user config:
${XDG_CONFIG_HOME:-~/.config}/pi-bounded-coding-workflow/
```

Pi credentials remain owned by Pi. The engine does not copy secrets from Pi authentication files into run records.

## 4. General run contract

Required top-level records:

```text
run.json
objective.json
owner-decisions.json
route-map.json
route-map-approval.json
baseline.json
baseline-approval.json
authority-lock.json
contract.json
routing.json
budget.json
task-graph.json
plan-approval.json
state.json
final-report.json
```

### 4.1 Objective

The objective binds:

```text
target repository root
requested mode: AUTO | DIRECT_LUNA_HIGH | SINGLE_OWNER_SOL | ROUTED_DAG
objective statement
primary failure domain
allowed path envelope
forbidden path envelope
repository authority paths
frozen invariants
required outputs
acceptance criteria
verification commands
declared owner-acceptance criteria
command and network policy
baseline mode
configured maximum leaves
```

### 4.2 Authority

Generic authority roles:

```text
OWNER_DECISION
REPOSITORY_INSTRUCTION
PUBLIC_API
SCHEMA
PROTOCOL
SECURITY_POLICY
BUILD_MANIFEST
TEST_CONTRACT
DOCUMENTATION_NORMATIVE
IMPLEMENTATION_CONTEXT
```

The controller records paths, roles, and hashes. It does not infer domain truth from prose.

## 5. Non-circular identities

All JSON identities use:

```text
canonicalization = RFC 8785/JCS-compatible canonical-json-v1
hash = SHA-256
digest = sha256:<64 lowercase hex>
encoding = UTF-8
```

General rule:

```text
content_sha256 =
sha256(canonical_json(document excluding /content_sha256))
```

Domain identities exclude their own digest and `/content_sha256`.

Required projection identities:

```text
objective-freeze-v1
route-map-v1
route-map-approval-v1
baseline-snapshot-v1
baseline-approval-v1
authority-lock-v1
contract-freeze-v1
task-packet-v1
task-graph-freeze-v1
routing-freeze-v1
budget-freeze-v1
plan-approval-v1
transition-commit-v1
final-report-v1
```

Every projection has:

```text
projection ID
included fields
excluded fields
normalization
ordering
canonical serialization
```

The plan approval binds transitively:

```text
objective
baseline
authority
mode
DAG
all task packets
scope
outputs
acceptance
commands
exact routes
tool policy
attempt and replan limits
usage budgets
```

## 6. Multi-file transition commit protocol

V0 uses immutable content-addressed evidence and a commit pointer.

Order:

```text
1. write immutable evidence
2. fsync evidence
3. rename evidence to content-addressed names
4. fsync evidence directories
5. write immutable attempt/verification/failure records
6. fsync and rename records
7. write immutable transition commit record
8. fsync and rename commit record
9. update state.json last to reference the transition commit
10. fsync state.json and run directory
```

Only records reachable from `state.json` are committed.

After a crash:

```text
unreferenced valid files → ORPHANED_UNCOMMITTED_EVIDENCE
missing referenced evidence → BLOCKED_STATE_COMMIT_INCOMPLETE
run → BLOCKED_PROCESS_CRASH
```

V0 never resumes.

## 7. Baseline contract

### 7.1 Modes

```text
CLEAN_REQUIRED
APPROVED_BASELINE_DIRTY
```

### 7.2 Dirty baseline

Capture:

```text
branch and HEAD
staged inventory
unstaged inventory
untracked inventory
per-path content hashes
index identities
file type and size
ownership class
data sensitivity class
baseline Git-state hash
```

Ownership classes:

```text
OWNER_AUTHORITY
OWNER_ACCEPTED_MUTABLE
PREEXISTING_UNRELATED
GENERATED_ACCEPTED_BASELINE
```

Data classes:

```text
PUBLIC_SOURCE
PRIVATE_SOURCE
SENSITIVE
SECRET
LARGE_BINARY
HASH_ONLY
```

Rules:

```text
SECRET → block baseline approval
SENSITIVE → hash-only unless explicit per-path approval
LARGE_BINARY → hash and metadata only
unknown untracked → hash-only
symlink or special file → reject
```

The final report separates:

```text
pre-existing baseline delta
workflow-owned delta
unexpected drift
```

## 8. Execution modes and state paths

## 8.1 Common states

```text
CREATED
OBJECTIVE_FROZEN
LOCK_ACQUIRED
BASELINE_CAPTURED
AWAITING_BASELINE_APPROVAL
BASELINE_APPROVED
FULL_PREFLIGHT_PASSED
CONTRACT_VALIDATED
ROUTE_SELECTED
PASS
BLOCKED
```

## 8.2 Direct Luna path

```text
DIRECT_CONTRACT_VALIDATED
AWAITING_DIRECT_APPROVAL
DIRECT_TASK_FROZEN
DIRECT_FAST_PREFLIGHT
DIRECT_ATTEMPT_RUNNING
DIRECT_POSTFLIGHT
DIRECT_VERIFYING
DIRECT_RETRY_READY
PASS
BLOCKED
```

Limits:

```text
one task
Luna High only
maximum two fresh invocations
no Sol call
```

## 8.3 Single-owner Sol path

```text
SINGLE_OWNER_CONTRACT_VALIDATED
AWAITING_SINGLE_OWNER_APPROVAL
SINGLE_OWNER_TASK_FROZEN
SINGLE_OWNER_FAST_PREFLIGHT
SINGLE_OWNER_RUNNING
SINGLE_OWNER_POSTFLIGHT
SINGLE_OWNER_VERIFYING
AWAITING_DECLARED_OWNER_ACCEPTANCE
PASS
BLOCKED
```

Limits:

```text
one fresh Sol invocation
maximum two controller-admitted mutation cycles
no separate planner
no closeout worker
```

`AWAITING_DECLARED_OWNER_ACCEPTANCE` exists only when the frozen contract contains an `OWNER_ACCEPTANCE` criterion.

## 8.4 Routed DAG path

```text
PLAN_RUNNING
PLAN_VALIDATED
AWAITING_PLAN_APPROVAL
DAG_FROZEN
READY
LEAF_FAST_PREFLIGHT
LEAF_RUNNING
LEAF_POSTFLIGHT
LEAF_VERIFYING
LEAF_RETRY_READY
REPLAN_REQUIRED
CLOSEOUT_RUNNING
CLOSEOUT_VERIFYING
PASS
BLOCKED
```

Limits:

```text
default maximum leaves = 8
maximum two fresh Luna High attempts per leaf
maximum two constrained Sol replans
one verification-only Sol closeout
```

Closeout has no mutation tools.

Any ordinary defect first discovered at closeout becomes:

```text
BLOCKED_CLOSEOUT_DEFECT
```

## 9. Deterministic routing

### 9.1 Hard Sol rules

Select or require `SINGLE_OWNER_SOL` for:

```text
unresolved authority meaning
architecture or public interface decisions
security and permission boundaries
lifecycle, concurrency, cleanup, or provenance ownership
migration semantics not fully frozen
judgment acceptance not declared as owner acceptance
inseparable high-coupling objective
```

### 9.2 Direct Luna eligibility

All required:

```text
one coherent task
one primary failure domain
deterministic acceptance
frozen scope and semantics
no hard Sol rule
no ambiguous write ownership
```

### 9.3 Routed DAG eligibility

All required:

```text
two to configured maximum leaves
acyclic dependencies
unique write ownership
machine-checkable acceptance per leaf
no hard Sol rule
no full-context dependency between every leaf
```

### 9.4 Shadow routing telemetry

Numeric heuristics do not control V0 route selection until calibrated:

```text
context-packet share
planned closeout reread share
subsystem count
consumer count
context-window saturation
```

They are logged for later policy calibration.

## 10. Contract-satisfiability gate

Before any worker invocation, V0 detects:

```text
MISSING_DEPENDENCY
CYCLIC_DEPENDENCY
MISSING_PRODUCER
AMBIGUOUS_PRODUCER
FUTURE_STAGE_DEPENDENCY
REQUIRED_OUTPUT_UNAVAILABLE
IDENTITY_FORMAT_MISMATCH
OVERLAPPING_WRITE_OWNERSHIP
ACCEPTANCE_WITHOUT_EVIDENCE
VERIFICATION_COMMAND_UNAVAILABLE
ROUTE_UNAVAILABLE
BUDGET_ENVELOPE_INFEASIBLE
UNSUPPORTED_CONTRACT_CONSTRUCT
```

V0 supports a deliberately small identity grammar:

```text
HEX
UUID
INTEGER
LITERAL
PREFIXED_LITERAL
PATH
```

Unsupported constructs fail closed.

## 11. Pi worker isolation

### OA-M6-01 — M6 Lower-Level Pi Agent Runtime Boundary

```text
STATUS = OWNER_APPROVED
DECISION = Replace implementation-specific mandatory AgentSession,
           resource-loader, and unconditional dispose mechanics with
           a behaviorally equivalent lower-level Agent isolation contract.
```

This amendment does not authorize Pi dependency mutation or M6 implementation.

The M6 V0 positive slice uses `@earendil-works/pi-agent-core` `Agent` at the exact owner-approved Pi version. Each invocation constructs one fresh in-memory `Agent` with:

```text
a controller-generated system prompt
the exact provider, model, and effort derived from authoritative M5 state
only controller-owned custom tools
built-in tools disabled
no persistent worker conversation
no model-callable workflow-start or agent-spawn capability
```

The controller directly assembles only:

```text
approved system prompt
approved user/task prompt
approved instruction resources
approved authority resources
approved task-readable target
```

Every resource is explicit, hash-verified, bounded, controller-selected, non-secret, and within M3/M4 authority. Approved `AGENTS.md` or equivalent instructions are injected explicitly with hashes. Repository cwd and filesystem authority remain enforced through the repository-bound M3/M4 scoped gateway. The `Agent` receives no raw cwd-based filesystem capability.

No discovery-capable session, settings, extension, prompt-template, skill, project-context, or resource-loader layer is instantiated. A custom resource loader is not instantiated. In particular, the worker does not discover:

```text
target .pi/extensions
target .pi/skills
target .pi/prompts
target .pi/settings.json
unapproved ancestor context files
```

This is stricter than configuring a discovery-capable loader to return nothing.

Automatic controller retry, SDK retry, and provider retry are disabled. No compaction transform is installed. Provider and model fallback are forbidden.

Lifecycle closure requires:

```text
abort when active
await prompt settlement
await Agent idle settlement
remove subscriptions
clear queues
reset Agent state
release controller-owned references
invoke dispose() only when exposed by the selected public runtime
```

Cleanup uncertainty remains fail-closed as `BLOCKED_CLEANUP_UNCERTAIN`.

`AgentSession` is rejected only for the approved M6 V0 positive slice because it adds unneeded session, settings, extension, resource, compaction, retry, and event-forwarding machinery. This is not a claim that `AgentSession` is universally invalid.

The M5 reservation is authoritative before provider work, and one active writer remains mandatory. OA-M6-01 changes no M1–M5 identity, schema, route, reservation, repository, scoped-tool, budget, failure, V0/V1, or milestone authority. It does not alter `DIRECT_LUNA_HIGH`, the `LUNA_EXECUTOR` role, provider/model/effort derivation, secure read authority, terminal `PASS` or `BLOCKED` behavior, or the prohibition on caller route selection and Slice A mutation tools. It does not add resume, a journal, fallback, recursive agents, M7 work, or V1 promotion. V0 process crashes continue to fail closed as `BLOCKED_PROCESS_CRASH`.

### OA-M6-02 — Verified Dynamic Pi Runtime Boundary

```text
STATUS = OWNER_APPROVED
DECISION = Replace mandatory static Pi declaration imports with a strict
           repository-owned dynamic ESM runtime boundary, verified against
           exact official Pi packages before provider work.
```

OA-M6-01 remains authoritative for M6 behavior. Its clause selecting `@earendil-works/pi-agent-core` `Agent` at the exact owner-approved Pi version selects the official low-level runtime and does not require a static TypeScript import. OA-M6-02 replaces only the compile-time and runtime-package trust mechanism used to realize that behavior. It does not restore `AgentSession` or change worker, tool, persistence, replay, cleanup, retry, fallback, route, or failure behavior.

Direct static imports of the supported Pi root declarations produced eight upstream declaration diagnostics under each of TypeScript 5.8.3, 6.0.3, and 7.0.2 with `moduleResolution = NodeNext`, strict checking, and `skipLibCheck = false`. OA-M6-02 does not claim those upstream declarations were repaired. It replaces reliance on them as the sole SDK authority with:

```text
strict repository-owned boundary
+ exact package identity
+ pre-import integrity verification
+ runtime capability guards
+ bounded behavioral evidence
```

#### Dynamic module boundary

M6 uses the official low-level Pi `Agent` runtime through a strict, controller-owned dynamic ESM boundary. The controller loads only these fixed public package specifiers:

```text
@earendil-works/pi-agent-core
@earendil-works/pi-ai
@earendil-works/pi-ai/providers/all
```

The specifiers are controller constants. They must not originate from the caller, task packet, route map, model output, environment, configuration discovery, fallback list, or a runtime-generated package name.

Canonical source must not statically import Pi runtime declarations while the supported official declaration graph remains incompatible with the required strict NodeNext build. Every dynamically imported value begins as `unknown` and may enter a repository-owned narrow interface only after runtime guards establish every capability M6 actually uses. That interface may model only the used `Agent`, model/provider, catalogue, tool, event, and lifecycle capabilities. It must not reproduce the complete Pi SDK declarations, provider SDK types, transcript implementation, or unused event union.

The canonical repository remains compiled with strict TypeScript and `skipLibCheck = false`. This boundary does not authorize a declaration shim, ambient declaration, unchecked cast from `unknown`, `any`-based SDK facade, `ts-ignore`, `ts-nocheck`, `node_modules` patch, postinstall patch, unsupported internal import, or CommonJS resolution fallback through `createRequire` or `require.resolve`.

#### Package identity boundary

Before executing Pi package code, the controller must verify exact owner-approved package identities through Node ESM semantics. The identity gate must:

- use `import.meta.resolve` for each fixed public specifier;
- require a file URL with no authority, query, or fragment;
- require an existing, regular, non-symlinked canonical target;
- require containment within the approved `node_modules` root;
- discover the nearest package root through a bounded upward walk;
- require the exact package name and version;
- verify the exact committed lockfile entry and registry integrity;
- verify the owner-approved installed-tree digest;
- reject duplicate package roots;
- require `providers/all` to share the verified Pi AI root;
- require the validated URL to equal the URL resolved immediately before and after dynamic import; and
- revalidate package, lockfile, and tree identity after import.

Any identity failure must occur before provider work or model-callable tool execution. The initially proven package graph is:

```text
@earendil-works/pi-agent-core@0.83.0
@earendil-works/pi-ai@0.83.0
```

A future version change requires explicit owner approval and fresh strict compile and runtime evidence. Canonical authority must not depend on a temporary fixture path.

#### Runtime capability boundary

After identity verification, the controller guards only the runtime capabilities required by the approved M6 positive slice. The guard must establish:

- a constructible `Agent`;
- `prompt`, `abort`, `waitForIdle`, `subscribe`, queue-clear, queue-state, `reset`, and guarded state capabilities;
- model/provider collection construction and exact lookup;
- provider catalogue enumeration and exact selection;
- stream-function capability;
- supported thinking-level inspection;
- exactly the two fixed tools; and
- lifecycle cleanup capabilities.

A method name alone is insufficient when an inert behavioral check can be performed without provider work. Malformed, substituted, incomplete, duplicated, or identity-mismatched capabilities must fail before provider work. This amendment authorizes neither a general capability registry nor a new durable capability record.

#### Provider and credential authority

Authority remains separated as follows:

```text
provider authority source:
  owner-approved M5 route map

provider implementation source:
  verified official Pi provider catalogue
  or separately owner-approved controller-owned provider implementation

credential source:
  controller/Pi credential boundary
  never the route map, task packet, caller, or model

test provider:
  controller-owned faux provider
```

Catalogue capability proof is not M5 production-route acceptance. A synthetic test route is not official production provider/model identity, and synthetic identifiers are not required to exist in the official catalogue. Production provider, model, and effort still derive exactly from immutable M5 authority. Provider or model fallback, substitution, and caller selection remain forbidden.

The `Agent` may invoke an explicitly supplied, controller-owned credential callback such as `getApiKey` before each provider turn. This is not ambient credential discovery when the callback receives the exact M5-derived provider ID, uses only the approved credential boundary, and does not inspect arbitrary environment or project files. Its output must never be persisted, logged, placed in prompts, copied into M6 records, or exposed to model-callable tools. Tests may return a fixed non-secret sentinel through this callback. Production credentials remain private to the approved controller/Pi credential boundary. Ambient environment credential discovery, ambient credential-file discovery, and credential copying into M6 records are forbidden.

#### Preserved worker protocol and cleanup

OA-M6-02 preserves all OA-M6-01 worker requirements, including:

```text
one fresh low-level Agent
one tool-loop owner
exactly read_scoped and submit_worker_report
two provider turns
one genuine M4 read
one structured terminal report
terminate after the report
no third provider turn
exactly M6_WORKER_INVOCATION and M6_WORKER_RESULT
persist invocation before provider work
reuse a completed result
refuse an incomplete invocation
no resume
no retry
no fallback
no compaction
no event bridge
no AgentSession
```

All runtime protocol assertions and failures must pass through `finally` or an equivalent structured cleanup owner. Cleanup must abort when active; await prompt settlement and `Agent` idle; unsubscribe; clear queues; verify no queued messages; reset the `Agent`; clear timers and provider collections; and release module, `Agent`, provider, model, tool, prompt, and credential-callback references. The controller preserves the first chronological operational failure separately from any cleanup failure. Cleanup uncertainty remains fail-closed as `BLOCKED_CLEANUP_UNCERTAIN`.

#### Security, package, and proof boundary

The M6 boundary forbids caller- or model-controlled module specifiers, generic plugin or package loading, module/provider/model fallback, runtime `eval`, `Function` constructor invocation, unsupported package internals, static Pi type imports, unchecked `unknown` casts, an `any`-based SDK facade, declaration shims, package patches, ambient credential discovery, and real provider execution during capability guarding.

Package identity failure, runtime capability-guard failure, M5 authority failure, provider/model identity failure, unsupported thinking level, malformed tool registration, or inability to establish cleanup ownership must result in zero provider work.

The canonical public package surface remains nine subpaths, with zero new M6 public subpaths. The dynamic Pi loader and runtime boundary remain package-internal, and internal M6 paths remain blocked by the package exports map. The package must not expose Pi module handles, the provider catalogue, credential callbacks, runtime-guard internals, or M6 invocation or execution APIs until M7 defines an explicitly approved public surface.

A controlled Pi fork is `REJECTED FOR CURRENT M6 SLICE`. The verified official dynamic boundary satisfies strict compilation, package identity, catalogue access, the two-turn protocol, credential isolation, negative guards, and cleanup without fork ownership, vendored release machinery, or parallel SDK authority. Forks are not universally forbidden; a later owner may reconsider one only if an official runtime loses a required supported public capability and no bounded official dynamic boundary remains.

Accepted proof authority:

```text
archive = /home/tilakoid/archives/pi-bounded-coding-workflow/m6-credential-corrected-dynamic-proof-pass-20260806T075326Z
manifest = f4ce15f60049966c74dff50a000f3ecc884ef9340863bbaf8ac8807d376b774b
classification = M6_DYNAMIC_BOUNDARY_CAPABILITY_EVIDENCE
not = PRODUCTION_IMPLEMENTATION | MILESTONE_ACCEPTANCE
```

This amendment authorizes architecture only. This invocation does not authorize `package.json` mutation, `package-lock.json` mutation, production dependency installation, or M6 source implementation. A later Luna Max implementation authorization may approve exactly `@earendil-works/pi-agent-core@0.83.0` and `@earendil-works/pi-ai@0.83.0` and the resulting reviewed lockfile mutation.

## 12. Scoped tools

### 12.1 Read-only tools

```text
read_scoped
search_scoped
list_scoped
inspect_git_scoped
read_evidence
```

### 12.2 Mutation tool

```text
apply_patch_scoped
```

Requirements:

```text
writer token held
path under target root
path in editable scope
path not frozen
baseline ownership permits mutation
expected preimage matches
patch size within budget
FD-relative secure write
post-write hash and containment verification
```

### 12.3 Commands

```text
run_inspection_command
run_task_command
run_verification_command
```

Commands are approved structured `argv`, not arbitrary shell strings.

Default forbidden:

```text
package installation
network access
git commit
git push
git tag
git merge
git rebase
git reset
git restore
git clean
branch switching
remote modification
```

## 13. Secure filesystem helper

Linux V0 requires file-descriptor-relative resolution and mutation, preferably using `openat2` with:

```text
RESOLVE_BENEATH
RESOLVE_NO_SYMLINKS
RESOLVE_NO_MAGICLINKS
```

Write sequence:

```text
verify root FD
open verified parent
reject symlink/special target
verify preimage
create temporary file in same directory
write and fsync
revalidate parent
atomic rename via directory FD
fsync directory
verify final inode and content
run immediate Git drift check
```

If the primitive is unavailable:

```text
BLOCKED_SECURE_WRITE_PRIMITIVE_UNAVAILABLE
```

## 14. Preflight and postflight

### Full preflight

```text
target path and Git identity
branch and HEAD
worktree/common-dir identity
upstream divergence
Git operation state
staged/unstaged/untracked/conflict state
exclusive lock
baseline mode
instruction and authority hashes
required commands
Node and Pi compatibility
exact route availability
worker retry/compaction policy
state-root capacity
```

### Fast preflight

Before every mutation cycle:

```text
lock held
repo identity unchanged
branch and HEAD expected
current state = approved baseline + owned delta
authority unchanged
scope unchanged
route map unchanged
budget reservation valid
no unexpected files
```

### Postflight

```text
exact workflow-owned diff
forbidden path check
staged state
commands and exit codes
test evidence
test-integrity audit
temporary files
cleanup ownership
failure signature
progress events
```

## 15. Usage ontology and budgets

Separate:

```text
worker_invocation
model_turn
provider_request
tool_call
```

Classification:

```text
HARD_ENFORCEABLE
SOFT_ENFORCEABLE
OBSERVABLE_ONLY
ESTIMATED_ONLY
UNAVAILABLE
```

Default:

```text
worker invocation → hard enforceable
tool call → hard enforceable
model turn → soft enforceable unless a pre-generation seam is proven
provider request → observable only or unavailable
```

Unavailable values are `null`, never zero.

### Invocation caps

```text
DIRECT_LUNA_HIGH:
  maximum 2

SINGLE_OWNER_SOL:
  maximum 1

ROUTED_DAG:
  1 planner
  + 2 × leaf count
  + 2 replans
  + 1 closeout
```

At eight leaves:

```text
20 invocations
```

### Budget behavior

Before an invocation, reserve its conservative envelope.

At soft limit:

```text
do not start a new task
finish only an already-admitted invocation
run pre-reserved required closeout only
otherwise block
```

At hard limit:

```text
admit no new invocation
admit no new tool call
abort locally where possible
postflight
BLOCKED_BUDGET_EXHAUSTED
```

## 16. Progress and failure routing

Valid progress:

```text
state transition
approved plan revision
valid repository delta
new test evidence
new evidence-backed diagnosis
failure reclassification
context restoration
terminal result
```

No progress:

```text
identical report
same normalized failure with no delta
repeated test with no new evidence
out-of-scope patch
prose without evidence
```

A `NO_PROGRESS_CALL` forbids automatic continuation.

Core failure actions:

| Failure | Action |
|---|---|
| `TRANSIENT_TOOL_FAILURE` | One bounded retry when confirmed |
| `LOCAL_IMPLEMENTATION_DEFECT` | One coherent second Luna attempt |
| `COMMAND_CONTRACT_ERROR` | Correct command if semantics unchanged |
| `CONTEXT_MISSING` | Restore exact context |
| `PLAN_INCORRECT` | Constrained Sol replan |
| `AUTHORITY_CONTRADICTION` | Owner decision/block |
| `SCOPE_EXPANSION_REQUIRED` | Block |
| `STATE_DRIFT` | Block |
| `CONCURRENT_WRITER` | Block |
| `TEST_INTEGRITY_VIOLATION` | Block |
| `CLEANUP_UNCERTAIN` | Block |
| `SAME_FAILURE_TWICE` | Replan once if eligible, otherwise block |
| `CLOSEOUT_DEFECT` | Block; no repair |
| `PROCESS_CRASH` | Block; no resume |
| `MODEL_UNAVAILABLE` | Block; no fallback |

## 17. CLI and Pi commands

Standalone:

```text
pi-workflow init [objective.json]
pi-workflow capture-baseline <run-id>
pi-workflow approve-baseline <run-id> <hash>
pi-workflow plan <run-id>
pi-workflow approve <run-id> <hash>
pi-workflow start <run-id>
pi-workflow status <run-id>
pi-workflow inspect <run-id>
pi-workflow abort <run-id>
```

Global Pi command:

```text
/workflow init
/workflow baseline
/workflow plan
/workflow approve <hash>
/workflow start
/workflow status
/workflow inspect
/workflow abort
```

There is no V0 `resume`.

## 18. Test strategy

### Pure tests

```text
canonical serialization
all identity projections
plan-binding mutation matrix
schema validation
all legal and illegal state transitions
terminal immutability
attempt/replan/invocation caps
route rules
contract contradiction fixtures
progress and failure signatures
```

### Repository fixtures

```text
clean repository
approved dirty repository
wrong repository
branch drift
external writer
lock collision
symlink race
special files
unknown untracked files
test weakening
cleanup uncertainty
```

### Fake Pi adapter

```text
valid plan
invalid report
direct Luna PASS
Luna defect then repair
single-owner two-cycle PASS
third-cycle request
same failure twice
closeout defect
model unavailable
retry event
compaction event
provider usage unavailable
process crash
```

### Generic coding pilot fixtures

```text
mechanical edit
bug fix
multi-file feature
refactor
schema/config task
CI repair
docs plus code
dirty baseline
budget exhaustion
scope expansion
```

No paid-model calls in unit or integration tests.

## 19. V0 implementation milestones

Each implementation milestone:

```text
Sol Max single-owner implementation
→ fresh Sol Max independent verification
→ PASS required before next milestone
```

### M1 — Package skeleton, canonical identities, schemas, pure state machines

### M2 — Immutable evidence, transition commit pointer, state store

### M3 — Baseline capture, lock guardian, Git preflight/postflight

### M4 — Secure filesystem helper and scoped tool gateway

#### OA-M4-01 — V0 M4 bounded-admission refusal authority

> **V0 M4 bounded-admission refusal authority.** V0 defines one immutable
> `M4_ADMISSION_REFUSAL` record. Pi runtime `beforeToolCall` admission is
> limited to cancellation and runtime sequencing; it does not decide accepted
> M4 budget or active-task mutation scope, and started-tool telemetry is not
> accepted M4 usage. Only the trusted bounded-worker M4 admission boundary owns
> those bounded M4 budget/task-scope decisions and may create the record, after
> publication of the exact bounded invocation and before forwarding the refused
> operation to the M4 gateway. The record binds the exact invocation, current
> authoritative M3 execution state, exact attempted-operation identity,
> `REFUSED` disposition, and refusal code. Invocation identity transitively
> binds the M5 operation/reservation and Task/Plan authority.
>
> A controller hard mutation-admission cap applies only to accepted mutations;
> it is distinct from total accepted M4 tool-call accounting, which is derived
> only from authoritative accepted M4 result or receipt evidence.
>
> A bounded result claiming terminal M4-admission refusal is authoritative only
> when its M4 evidence references exactly one matching authoritative refusal
> record and the sole bounded-execution resolver validates the complete
> invocation, reservation, route, active task, M3, accepted-M4-evidence,
> refusal-code, fixed-stage, and cleanup joins. Absence or mismatch of producer
> refusal evidence leaves the result unresolved.
>
> Accepted/admitted M4 result or receipt evidence contributes accepted tool
> usage. `M4_ADMISSION_REFUSAL` contributes refusal authority and zero accepted
> tool usage. A resolved refusal is eligible only for M5 `BLOCK`, excludes
> `PASS` and continuation, and cannot be suppressed by caller-provided source
> arrays. Historical records remain readable; historical BLOCKED results lacking
> this producer evidence do not retroactively acquire terminal-refusal
> authority.

### M5 — Usage budgets, progress, failures, contract gate, route selection

### M6 — Pi SDK adapter and fresh isolated workers

### M7 — Standalone CLI and global thin Pi extension

### M8 — Synthetic and generic coding pilot

### M9 — Matched economic evaluation and V0 closeout

M9 verdict:

```text
V0_PASS
V0_PARTIAL
V0_BLOCKED
ROUTED_MODE_ECONOMICALLY_SUSPENDED
```

## 20. V0 product acceptance

V0 passes only if:

```text
global /workflow command works from unrelated Git repositories
no hard-coded target project
all three execution modes work
no recursive spawning path
no model-callable workflow start
no third attempt or replan
no silent fallback
one writer enforced for cooperating controllers
external drift detected
clean and dirty baselines proven
secure scoped writes proven
Pi child resource discovery isolated
usage nulls reported honestly
crash becomes BLOCKED_PROCESS_CRASH
all mandatory tests pass
no test weakening
final Git state and cleanup known
```
