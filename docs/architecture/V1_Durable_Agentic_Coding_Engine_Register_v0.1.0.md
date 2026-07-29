# V1 Durable Agentic Coding Engine — Deferred Capability Register

```text
DOCUMENT_ID = PI-GACW-V1-REGISTER
DOCUMENT_VERSION = 0.1.0
V1_STATUS = DEFERRED_PENDING_V0_EVIDENCE
IMPLEMENTATION_STATUS = NOT_STARTED
SCOPE = GENERAL_AGENTIC_CODING
```

## 1. Promotion principle

V1 is not “more agents.” V1 makes the proven V0 kernel durable, easier to use, and better measured.

V1 preserves:

```text
human-started workflows
deterministic orchestration
one active writer
frozen contracts
fresh bounded sessions
no recursive spawning
no provider fallback
terminal PASS or BLOCKED
```

Promotion is per capability:

```text
PROMOTE
DEFER
REJECT
REQUIRES_V0_REPAIR
```

## 2. Common V0 evidence gate

Every V1 capability requires:

```text
V0 deterministic suite PASS
all three execution modes tested
identity projections stable
transition commit protocol proven
secure tool gateway proven
synthetic pilot PASS
generic coding pilot PASS
no invocation-cap breach
no scope leak
no hidden fallback
truthful usage null handling
no cleanup uncertainty
```

Capabilities increasing model coordination also require the economic gate.

## 3. Deferred capabilities

## V1-C01 — Append-only event journal

Adds:

```text
JSONL journal
monotonic sequence
event hashes
snapshot reconstruction
```

Depends on:

```text
stable V0 transition commit record
stable state pointer
stable evidence identities
```

Promotion requires deterministic reconciliation. Journal and state cannot become competing authorities.

## V1-C02 — Crash recovery

Adds recovery from:

```text
controller crash
worker crash
partial lifecycle interruption
```

Promotion requires:

```text
crash injection at every commit boundary
no adoption of orphan evidence
no duplicate model invocation
unknown provider outcome fails closed
one exact recovery point
```

## V1-C03 — Resume

Adds:

```text
pi-workflow resume
/workflow resume
```

Resume verifies:

```text
same worktree
same branch and expected HEAD
same baseline approval
same authority
same route map
same plan
same workflow-owned delta
no unknown in-flight invocation
```

Otherwise:

```text
RESUME_REFUSED_STATE_DRIFT
```

## V1-C04 — Advanced provider-request accounting

Adds request-level metrics where provider/Pi observability supports them.

Potential sources:

```text
before-provider-request hooks
after-provider-response hooks
transport events
provider response metadata
```

A hard provider-request cap may be claimed only when pre-send admission and all retries are observable.

Otherwise the value remains:

```text
OBSERVABLE_ONLY
or
UNAVAILABLE
```

## V1-C05 — Repository policy packs

Adds deterministic, owner-approved profiles for common ecosystems:

```text
Node/TypeScript
Python
Rust
Go
Java
C/C++
```

A policy pack may propose:

```text
common authority files
build manifests
read-only inspection commands
focused test conventions
generated-output patterns
temporary-file patterns
```

It may not silently choose acceptance semantics or mutate the repository.

Every detected profile requires owner approval before it affects a frozen contract.

## V1-C06 — Isolated worktree backend

Adds optional controller-created isolated worktrees for disposable runs and matched benchmarks.

Requirements:

```text
explicit owner approval
known source commit and baseline
separate lock
no automatic merge
no commit or push
deterministic cleanup
promotion only after output selection
```

This does not permit parallel writers in V1.

## V1-C07 — Broader contract satisfiability

Adds:

```text
minimum-valid-fixture generation
broader JSON Schema subset
producer/consumer schema intersection
additional identity grammars
command-output contracts
```

Unsupported constructs remain fail closed.

No model judgment may be labeled a proof of satisfiability.

## V1-C08 — Read-only scouts

Adds at most:

```text
two scouts
one wave
before plan approval
read-only tools
distinct frozen questions
```

Scouts cannot:

```text
mutate
spawn
add tasks
request follow-up agents
change routes
```

Promotion requires stable routed-mode economics and evidence that scouts reduce total cost per PASS.

## V1-C09 — Advanced progress classifier

Adds:

```text
criterion coverage graph
cross-attempt evidence lineage
diagnosis-delta assistance
duplicate-read detection
```

Deterministic rules remain authoritative. An LLM score cannot admit a new invocation.

## V1-C10 — Rich Pi workflow UX

Adds:

```text
run picker
approval dialogs
status widgets
evidence viewer
budget dashboard
terminal report viewer
```

The extension remains non-authoritative and cannot create workers itself.

## V1-C11 — Cost and routing analytics

Adds:

```text
route comparison
cache-aware accounting
confidence intervals
task-class metrics
coordination-cost attribution
economic kill-switch dashboard
```

Primary metric remains:

```text
total cost per verified terminal PASS
```

Failed and blocked runs remain included.

## V1-C12 — Optional sandbox backend

Adds a separately approved execution backend that runs commands and writes in an isolated environment.

Requirements:

```text
same scoped tool protocol
same evidence schema
same exit-code preservation
same one-writer invariant
no silent network access
explicit artifact import
```

Host secure tools remain the reference backend until sandbox equivalence is proven.

## 4. Economic promotion gate

Required for scouts, richer automatic routing, and other coordination-increasing features:

```text
routed PASS rate not materially lower than single-owner
escaped defects not higher
manual intervention not higher
context restoration within threshold
coordination cost below implementation cost dominance threshold
full-milestone reread rate below threshold
cost per PASS not worse than configured kill threshold
```

Initial kill threshold:

```text
routed cost per PASS > 1.20 × single-owner
after the minimum matched sample
→ suspend routed expansion
```

Zero verified PASS is represented as positive infinity, not undefined or zero.

## 5. Generic benchmark protocol

Benchmark corpus contains independent coding tasks across:

```text
languages
repository sizes
task shapes
test systems
clean and dirty baselines
```

For each task:

```text
one frozen contract
identical isolated snapshots
blind independent verifier
same verification policy
cost/model/arm identity hidden from correctness selection
```

Arms:

```text
A SINGLE_OWNER_SOL
B ROUTED_DAG
C DIRECT_LUNA_HIGH when eligible
D ROUTED_DAG_WITH_SCOUTS only after V1-C08 promotion
```

For chained milestones:

```text
verify both candidates blindly
select canonical output only by frozen correctness criteria
hide cost and model identity
freeze canonical snapshot
start the next pair from that snapshot
```

## 6. Capabilities outside approved V1

The following require a new architecture review:

```text
parallel mutating workers
recursive subagents
autonomous DAG growth
provider or account fallback
automatic model substitution
multi-repository objectives
automatic commit
automatic push
automatic merge
self-modifying routing rules
continuous advisors
continuous reviewer fleets
background unattended workflow start
```

## 7. V1 implementation order

Recommended:

```text
V1-M1 event journal
V1-M2 crash recovery
V1-M3 resume
V1-M4 isolated worktree backend
V1-M5 provider telemetry
V1-M6 repository policy packs
V1-M7 broader satisfiability
V1-M8 rich Pi UX
V1-M9 advanced progress and analytics
V1-M10 optional scouts
V1-M11 optional sandbox backend
```

Scouts are deliberately late because they add model coordination rather than safety or durability.

Every V1 milestone uses:

```text
Sol Max single-owner implementation
→ fresh Sol Max independent verification
```

## 8. V0-to-V1 promotion verdict

Required packet:

```text
V0 final verification
synthetic pilot
generic coding pilot
identity and crash-boundary evidence
scope and test-integrity audits
usage observability matrix
matched economic results
known limitations
final repository state
cleanup report
```

Possible verdicts:

```text
PROMOTE_SELECTED_V1_CAPABILITIES
V0_REPAIR_REQUIRED
V1_DEFERRED
V0_REJECTED
```

## 9. Owner decisions

No V1 capability is automatically approved.

Owner approval is requested only after a capability satisfies its V0 evidence dependencies and has a bounded implementation contract.
