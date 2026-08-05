# Pi General Agentic Coding Workflow — Architecture Replan

```text
DOCUMENT_ID = PI-GACW-ARCHITECTURE
DOCUMENT_VERSION = 0.1.0
DESIGN_STATUS = GENERAL_USAGE_REPLAN_READY_FOR_OWNER_REVIEW
IMPLEMENTATION_STATUS = NOT_STARTED
SCOPE = GENERAL_AGENTIC_CODING
PROJECT_SPECIFIC_LOGIC = FORBIDDEN
```

## 1. Executive recommendation

Build a **general-purpose bounded agentic-coding workflow for Pi**, usable from any trusted Git repository.

The selected shape is:

```text
installable global Pi package
+ thin human-invoked /workflow extension
+ standalone deterministic TypeScript controller
+ Pi SDK worker adapter
+ fresh bounded model sessions
+ controller-owned scoped tools
+ one active writer per worktree
+ machine-readable run contracts
+ PASS or BLOCKED terminal outcomes
```

The system is not a repository-specific workflow and must not contain hard-coded knowledge about:

```text
project names
repository paths
programming languages
frameworks
datasets
scientific semantics
product domains
test commands
build systems
```

All project-specific meaning enters through a versioned run contract supplied for the current repository.

## 2. Why the architecture is Pi-native without storing the source inside `.pi`

The engine is developed as a normal Git repository and installed globally into Pi as a local package.

Recommended development location:

```text
~/src/pi-bounded-coding-workflow/
```

Recommended global installation:

```bash
pi install /absolute/path/to/pi-bounded-coding-workflow
```

The package exposes:

```text
extensions/workflow.ts
bin/pi-workflow
```

Pi records the global package source in its user settings, making `/workflow` available across repositories. The source path remains a normal development repository and is not copied into a dynamic extension-discovery folder.

Runtime state is separate:

```text
${XDG_STATE_HOME:-~/.local/state}/pi-bounded-coding-workflow/
```

Cache is separate:

```text
${XDG_CACHE_HOME:-~/.cache}/pi-bounded-coding-workflow/
```

This separation gives:

```text
source code      → normal Git repository
Pi integration   → globally installed Pi package
run state        → XDG state directory
target project   → current trusted Git worktree
```

The source may physically live under an owner-selected directory, including a non-discovered development folder under `~/.pi`, but the architecture does not depend on that location.

## 3. M6 Pi worker capability boundary

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

Every resource is explicit, hash-verified, bounded, controller-selected, non-secret, and within M3/M4 authority. Repository cwd and filesystem authority remain enforced through the repository-bound M3/M4 scoped gateway. The `Agent` receives no raw cwd-based filesystem capability.

No discovery-capable session, settings, extension, prompt-template, skill, project-context, or resource-loader layer is instantiated. A custom resource loader is not instantiated. This is stricter than configuring a discovery-capable loader to return nothing.

Automatic controller retry, SDK retry, and provider retry are disabled. No compaction transform is installed. Provider and model fallback are forbidden. The worker adapter must not rely on Pi defaults for model selection, tools, retry, compaction, resource loading, or project-local extensions.

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

The M5 reservation is authoritative before provider work, and one active writer remains mandatory. OA-M6-01 changes no M1–M5 identity, schema, route, reservation, repository, scoped-tool, budget, failure, V0/V1, or milestone authority. It does not add resume, a journal, fallback, recursive agents, M7 work, or V1 promotion.

The global Pi package and extension continue to rely on global extensions, `registerCommand()`, and installable local Pi packages; OA-M6-01 changes only the M6 worker runtime mechanism.

## 4. User experience

From any trusted Git repository:

```text
cd <repository>
pi
/workflow init
/workflow plan
/workflow approve <hash>
/workflow start
/workflow status
/workflow inspect
/workflow abort
```

The global extension is a thin adapter. It:

```text
registers commands
passes current cwd and user arguments
launches the standalone controller without a shell
renders structured status
never creates a worker itself
never changes state transitions
never selects a model
never expands a DAG
```

No LLM-callable V0 tool may start a workflow. Starting a workflow is a human command, preventing recursive orchestration.

## 5. General runtime contract

Each run binds:

```text
target Git worktree identity
objective
requested or automatic execution mode
clean or approved-dirty baseline
repository authority files
global and repository instructions
readable paths
editable paths
frozen paths
semantic and operational invariants
required outputs
acceptance criteria
verification commands
command policy
route map
tool policy
attempt and replan limits
token, cost, turn, tool, and wall-time budgets
```

The controller understands contracts and evidence. It does not interpret business or domain truth.

## 6. Execution modes

### 6.1 `DIRECT_LUNA_HIGH`

For one fully bounded task with deterministic acceptance.

```text
owner-approved one-task packet
→ Luna High attempt 1
→ deterministic postflight and verification
→ optional coherent Luna High attempt 2
→ PASS or BLOCKED
```

No Sol planning or closeout.

### 6.2 `SINGLE_OWNER_SOL`

For tightly coupled, architecture-heavy, security-sensitive, lifecycle-sensitive, or judgment-heavy objectives.

```text
owner-approved one-task milestone packet
→ one fresh Sol invocation
   audit
   → internal non-authoritative plan
   → mutation cycle 1
   → verification
   → optional mutation cycle 2
   → final report
→ deterministic postflight
→ declared owner-acceptance gate when required
→ PASS or BLOCKED
```

No separate model planning call and no routed closeout.

### 6.3 `ROUTED_DAG`

For two to eight coherent leaves with frozen, machine-checkable acceptance.

```text
Sol planner
→ controller validates candidate DAG
→ owner approves exact plan hash
→ fresh Luna High session per ready leaf
→ one writer at a time
→ maximum two attempts per leaf
→ maximum two constrained Sol replans
→ verification-only Sol closeout
→ PASS or BLOCKED
```

A closeout defect blocks the run. Closeout cannot mutate or reopen leaves.

## 7. Route selection

Hard rules select `SINGLE_OWNER_SOL` when any applies:

```text
unresolved authority semantics
public API or schema semantics are being decided
security boundary or permission model changes
lifecycle, concurrency, cleanup, or provenance ownership changes
acceptance requires unstructured judgment not frozen as owner acceptance
task cannot be separated without full-context rereading
```

`DIRECT_LUNA_HIGH` requires:

```text
exactly one coherent task
fully frozen scope
fully deterministic acceptance
no hard Sol rule
one primary failure domain
```

`ROUTED_DAG` requires:

```text
two to configured_max_leaf_tasks coherent leaves
dependency graph is acyclic
write ownership is unambiguous
acceptance is machine-checkable per leaf
no hard Sol rule
```

When evidence is insufficient, route conservatively to `SINGLE_OWNER_SOL` or block for an owner decision.

Numeric coupling heuristics run in shadow mode until calibrated.

## 8. Model policy

Logical roles are separate from exact provider/model IDs:

```text
SOL_OWNER
SOL_PLANNER
SOL_REPLAN
SOL_CLOSEOUT
LUNA_EXECUTOR
BENCHMARK_VERIFIER
BENCHMARK_SELECTOR
```

All Luna execution uses high effort:

```text
LUNA_EXECUTOR = LUNA_HIGH
LUNA_MEDIUM = FORBIDDEN
```

Provider-managed multi-agent or hidden-subagent modes are forbidden because the controller cannot own their spawning and accounting.

The exact route map is versioned, owner-approved, and bound into every plan identity.

## 9. Anti-runaway invariants

```text
no recursive spawning
no model-started workflow
no autonomous DAG growth
no third executor attempt
no third constrained replan
no provider fallback
no model substitution
no concurrent mutating workers
no unrestricted built-in write/bash tools
no call beyond admitted invocation budget
no continuation after no-progress without a typed route
```

Guarantee:

> Recursive and unbounded workflow expansion is prevented by construction. The controller never admits a new worker invocation beyond the frozen budget. One already-admitted provider request may still produce a bounded usage overshoot when final provider telemetry is available only after completion.

## 10. Repository safety

Default:

```text
CLEAN_REQUIRED
```

Supported first-class mode:

```text
APPROVED_BASELINE_DIRTY
```

The baseline snapshot separates:

```text
pre-existing owner changes
workflow-owned changes
unexpected external drift
```

Writes go through a file-descriptor-relative secure helper with no-follow and beneath-root semantics. A model never receives raw unrestricted shell or filesystem mutation.

Commands are explicit `argv` records. Package installation, network use, Git history mutation, commit, push, branch switching, and destructive cleanup are forbidden unless a future separately approved capability allows them.

## 11. V0/V1 boundary

### V0 — General Agentic Coding Kernel

V0 proves:

```text
global Pi command availability
general repository contracts
three execution modes
bounded model routing
one active writer
baseline ownership
secure scoped tools
identity and commit correctness
honest usage accounting
terminal completion
economic comparison
```

V0 has no resume. A process crash becomes `BLOCKED_PROCESS_CRASH`.

### V1 — Durable Agentic Coding Engine

V1 adds capabilities only after V0 evidence:

```text
journal
crash recovery
resume
advanced provider telemetry
project policy packs
isolated worktree backend
broader contract satisfiability
read-only scouts
advanced progress and analytics
richer Pi UX
```

Parallel writers, recursive agents, provider fallback, autonomous task creation, and automatic publication remain outside V1.

## 12. Build workflow

The engine itself is implemented milestone by milestone:

```text
Sol Max single-owner implements one milestone
→ fresh Sol Max independently verifies it
→ PASS, PARTIAL, or BLOCKED
→ next milestone only after PASS
```

No Ultra or provider-managed multi-agent mode. No giant M1–M8 invocation.

## 13. Generic pilot

The pilot uses synthetic and disposable coding repositories, not a specific production project.

Required task classes:

```text
single-file mechanical edit
bounded bug fix
multi-file feature
behavior-preserving refactor
schema/config migration with frozen semantics
test/CI repair without weakening tests
documentation plus directly coupled code
approved dirty-baseline task
failure and budget scenarios
```

Matched arms:

```text
A. SINGLE_OWNER_SOL
B. ROUTED_DAG
C. DIRECT_LUNA_HIGH where the task qualifies
```

Every arm starts from an identical isolated snapshot and receives the same frozen contract and blind independent verifier.

## 14. Decisions still requiring owner approval

Before paid-model execution:

```text
OD-01 exact logical-route → provider/model/effort map
OD-02 soft and hard usage/cost/time budgets
OD-03 final source repository path
```

Recommended defaults:

```text
OD-01:
  Sol roles → owner-selected GPT-5.6 Sol effort
  Luna executor → Luna High
  no fallback

OD-02:
  derive from measured single-owner baseline
  soft = 80% of hard
  routed hard estimated cost <= min(1.25 × baseline, owner ceiling)

OD-03:
  ~/src/pi-bounded-coding-workflow
  installed globally using pi install <absolute-path>
```

These decisions do not block deterministic implementation with fake adapters.
