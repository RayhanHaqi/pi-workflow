# V1 Static Approved Terra DAG — Authority Amendment

```text
DOCUMENT_ID = PI-GACW-V1-STATIC-APPROVED-TERRA-DAG-AMENDMENT
DOCUMENT_VERSION = 0.1.0
STATUS = PROSPECTIVE_NARROW_AUTHORITY
SCOPE = ONE_V1_STATIC_APPROVED_DAG_CANDIDATE
IMPLEMENTATION_STATUS = NOT_STARTED
```

## 1. Purpose and relationship

This amendment prospectively authorizes only the first V1 candidate needed to answer:

> Can a human start one pre-approved bounded coding DAG once and let it complete meaningful multi-step work with near-zero owner attention, using Terra High as the ordinary implementation worker, while preserving existing V0 safety and authority invariants?

This is an authority amendment, not runtime implementation authority, a rewritten V1 register, or autonomy-pilot authorization.

It references and preserves:

- [V0 General Agentic Coding Kernel Contract v0.1.0](V0_General_Agentic_Coding_Kernel_Contract_v0.1.0.md);
- [Pi General Agentic Coding Workflow Architecture v0.1.0](Pi_General_Agentic_Coding_Workflow_Architecture_v0.1.0.md); and
- [V1 Durable Agentic Coding Engine Register v0.1.0](V1_Durable_Agentic_Coding_Engine_Register_v0.1.0.md).

The V1 register remains v0.1.0 and remains the deferred-capability inventory. This amendment preserves V0/M8/M9 evidence and takes precedence only where older V1 authority lacks Terra or conflicts with this specifically approved `STATIC_APPROVED_DAG` candidate. It does not rewrite historical architecture documents, including the engine-build constitution or historical statements about V0/V1 milestone review.

Canonical recorded facts:

```text
M8 = PASS
M9 = ROUTED_MODE_ECONOMICALLY_SUSPENDED
SOL_PLANNER → LUNA_EXECUTOR → SOL_CLOSEOUT = existing routed sequence
ROUTED_DAG = SUSPENDED
```

This amendment does not reopen M8 or M9. The existing `ROUTED_DAG` remains suspended.

## 2. Static unattended-control distinction

A human-started deterministic progression through an already-approved static DAG is permitted. This is not autonomous DAG creation or growth.

The following remain forbidden:

```text
model-created tasks
model-created dependency changes
background/model-started workflow creation
background or detached workflow start
```

The owner supplies and approves the complete frozen DAG before execution. The controller may only progress through that already-approved DAG deterministically.

## 3. New logical role and exact route

The following logical role is prospectively added:

```text
TERRA_EXECUTOR
```

Its initial exact route is:

```yaml
provider_id: openai-codex
model_id: gpt-5.6-terra
effort: high
```

`TERRA_EXECUTOR` is a distinct role. Terra is not aliased under `LUNA_EXECUTOR` or `SOL_OWNER`.

## 4. V1-only topology: `STATIC_APPROVED_DAG`

`STATIC_APPROVED_DAG` is authorized only as the first V1 candidate topology. Before execution, the owner approves:

- DAG nodes;
- node objectives;
- dependencies;
- read/edit/frozen scope;
- exact route;
- budgets;
- acceptance;
- deterministic verification; and
- an optional frozen repair edge.

Runtime progression is:

```text
human starts once
→ deterministic controller selects ready node
→ TERRA_EXECUTOR
→ deterministic postflight and verification
```

If verification succeeds:

```text
mark node complete
→ automatically advance to the next ready node
```

If verification identifies a clear local implementation defect and that node has an already-approved repair edge:

```text
allow exactly one additional Terra High attempt for that node
```

Otherwise:

```text
BLOCK
```

The controller continues deterministically until one of:

```text
DAG PASS/completion
BLOCK
genuine owner-controlled boundary
budget/time exhaustion
process/provider failure
```

## 5. No model on the normal coordination path

For the first candidate, the normal coordination path contains no:

```text
live Sol planner
Sol closeout
replan model
Luna reviewer
higher-Terra effort
model-selected routing
```

The owner-supplied frozen DAG replaces live planning. This amendment does not promote Sol or Luna functionality. If a future DAG requires a Sol diagnosis node or a Luna independent-review node, that exact optional node and route require separate explicit authority.

## 6. Terra repair rule

The initial candidate permits:

```text
Terra High initial attempt
+ at most one Terra High repair attempt per node
```

A repair attempt is permitted only when all are true:

- deterministic verification failed;
- the failure is a clear local implementation defect;
- a repair edge was frozen before execution;
- objective, scope, DAG, and acceptance remain unchanged; and
- no unknown provider request is in flight.

No Terra XHigh or Max escalation is authorized by this amendment.

## 7. Owner interruption boundary

Routine successful progression must not interrupt the owner. A clear local defect with its frozen repair edge must not require owner input.

Owner interaction is permitted only for:

- a genuine authority or scope decision;
- a destructive or publication decision;
- an unrecoverable or unknown failure;
- budget or time exhaustion; or
- completion notification, if requested.

The absence of a frozen repair edge means `BLOCK`, not creation of a new approval ritual.

## 8. Preserved V0 invariants

This amendment explicitly preserves accepted V0 invariants, including:

```text
one active writer
frozen scope
secure scoped writes
deterministic postflight/verification
no recursive/model-started workflows
no silent provider/model fallback
no automatic task creation
no DAG growth
no parallel mutating writers
no automatic commit, merge, or push
Git/external-drift protection
bounded attempts
immutable evidence
unknown provider outcomes fail closed
```

It does not authorize Git publication, history mutation, branch switching, merge, commit, or push.

## 9. First-candidate crash semantics

Crash recovery and resume are not promoted. For this candidate:

```text
process/controller crash
→ fail closed / BLOCK under existing semantics
```

Alive-process unattended execution and process-death durability are separate properties. Detached or background workflow start is not authorized.

## 10. Non-promotions

This amendment does not promote:

```text
V1-C01 event journal
V1-C02 crash recovery
V1-C03 resume
V1-C04 advanced provider accounting
V1-C05 through V1-C12
scouts
advanced classifier
rich UX/dashboard
sandbox backend
isolated-worktree backend
dynamic DAG growth
higher Terra effort
```

These capabilities remain deferred unless separately authorized later; they are not rejected permanently.

## 11. Initial autonomy pilot gate

The first candidate pilot uses one real pre-frozen multi-step workflow. It requires at least:

- 3 useful DAG nodes;
- explicit dependencies;
- unique or compatible write ownership preserving one active writer;
- machine-checkable acceptance;
- verified terminal `PASS`;
- all required nodes verified;
- zero incorrect `PASS`;
- zero scope escape;
- zero unauthorized mutation;
- zero fallback;
- zero post-start owner interactions on the `PASS` run;
- zero Sol/Luna requests in the initial candidate; and
- requests and wall time within owner-approved budgets.

Observe and report:

```text
useful nodes completed
owner interactions
useful nodes per owner interaction
longest autonomous interval
total wall time
Terra worker/provider requests
repair attempts
incorrect PASS count
unauthorized mutation count
token/cost values when truthfully available; otherwise null
```

The pilot does not require an artificial two-hour runtime. A fast multi-node zero-intervention `PASS` is valid evidence. One pilot does not prove universal reliability.

## 12. Durability sequencing

Prospective sequencing is:

```text
architecture amendment
→ STATIC_APPROVED_DAG implementation
→ alive-process autonomy pilot
```

Only if the candidate proves useful should durability promotion be considered:

```text
event journal
→ crash recovery
→ resume
→ longer-horizon durability evaluation
```

This ordering does not automatically approve any later capability.

## 13. Authority boundary

`STATIC_APPROVED_DAG` authorized by this amendment is limited to the defined initial candidate, exact Terra route, frozen topology, deterministic controller progression, and pilot gate. Implementation, pilot execution, durability, dynamic planning, model coordination, higher Terra effort, background start, automatic commit/merge/push, and any broader V1 promotion require separate explicit authority.
