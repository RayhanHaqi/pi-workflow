# V1 Build Routing — Authority Amendment

```text
DOCUMENT_ID = PI-GACW-V1-BUILD-ROUTING-AMENDMENT
DOCUMENT_VERSION = 0.1.0
STATUS = PROSPECTIVE_NARROW_AUTHORITY
SCOPE = V1_ENGINE_BUILD_MODEL_ROUTING_ONLY
IMPLEMENTATION_STATUS = DOCUMENTATION_ONLY
```

## 1. Purpose and boundary

This amendment prospectively changes only V1 engine-build and model-routing authority. For ordinary V1 milestone work, it replaces the older default:

```text
Sol Max implements
→ Sol Max verifies
```

with Terra High as the default bounded implementation executor and proportional verification. Sol and Luna remain selective roles only where their different reasoning or independent-review value is material.

This amendment does not change runtime safety invariants, historical V0 implementation or evidence, M8, M9, or `STATIC_APPROVED_DAG` runtime semantics. It does not rewrite historical documents, implement `STATIC_APPROVED_DAG`, authorize source or test changes, or begin an autonomy pilot.

## 2. Default bounded implementation

The canonical default V1 bounded implementation route is:

```text
TERRA_EXECUTOR
```

```yaml
provider_id: openai-codex
model_id: gpt-5.6-terra
effort: high
```

Terra High is the default executor for:

- ordinary implementation;
- known-root-cause fixes;
- tests;
- refactors;
- packaging;
- mechanical canonicalization;
- Git-aware validation; and
- implementation of an already-approved architecture contract.

No prior Sol planning step is required when the objective, scope, authority, and acceptance are already clear. Sol High is not a mandatory planner before Terra High.

## 3. Sol High reasoning role

Use Sol High only for genuine unresolved reasoning, including:

- architecture ambiguity;
- an unclear root cause;
- conflicting authority;
- simplification decisions;
- milestone or promotion decisions; and
- definition of a bounded candidate contract where authority is not yet clear.

After Sol High resolves the ambiguity and the bounded authority is clear, ordinary implementation returns to Terra High. Sol High is neither a routine implementation executor nor a required planning or closeout step.

## 4. Terra High repair and bounded diagnosis

When Terra High fails and the root cause is clear:

```text
one bounded Terra High repair under the unchanged contract
```

Do not increase model effort merely as a recovery strategy.

When Terra High fails and the root cause is unclear:

```text
stop execution
→ one bounded Sol High diagnosis
→ one bounded Terra High implementation or repair attempt
```

A failed bounded repair does not create another diagnosis, repair, or effort-escalation loop. The next action must stop at the applicable authority boundary.

## 5. Higher Terra effort

Terra XHigh, Terra Max, and any other higher-effort Terra tier are not defaults. A higher Terra tier requires a concrete, pre-approved technical predicate showing why Terra High is insufficient, such as several difficult interacting lifecycle, concurrency, cancellation, persistence, or security invariants.

Importance, task size, or the word “critical” alone is insufficient. No failure automatically escalates Terra effort.

The current `STATIC_APPROVED_DAG` first candidate continues to authorize only Terra High.

## 6. Luna review roles

Use Luna High selectively for independent review when model independence has real value. Ordinary implementation, test-only work, and mechanical changes do not require Luna review merely because work occurred.

Reserve Luna Max for serious independent-review boundaries, including:

- lifecycle;
- security;
- persistence;
- provenance;
- authority; and
- final milestone evidence.

Luna Max is not a routine verifier. Neither Luna tier is a continuous reviewer or a mandatory verifier for every V1 change.

## 7. Sol Max exception

Sol Max is exceptional. Reserve it for:

- a fundamental architecture reset;
- an immutable-authority dispute; or
- a similarly exceptional architecture boundary where Sol High is demonstrably insufficient.

Sol Max is not the default V1 implementer or verifier.

## 8. Verification proportionality

Verification remains proportional:

- small deterministic changes receive small deterministic verification;
- test-only or mechanical changes do not automatically require independent review; and
- full regression and independent review are reserved for load-bearing boundaries.

Do not create verifier-on-verifier loops. Independent review must have a concrete boundary and stop condition rather than becoming a routine chain.

## 9. Owner authority

Owner approval is required only when the next action changes genuine owner-controlled authority, including:

- architecture authority;
- scope;
- destructive state;
- provider or model execution authority when not already frozen;
- Git publication; or
- another explicit owner-controlled boundary.

Routine deterministic work under already-approved authority proceeds without an additional owner approval gate. Any selective Sol or Luna invocation still requires its exact provider/model route to be frozen when existing authority has not already frozen it; no route is inferred as a fallback.

## 10. Session policy

The prospective execution preference is:

```text
CONTINUE CURRENT SESSION
```

when it is genuinely the same implementation or debugging task with the same candidate, authority, and failure context.

Use:

```text
START NEW SESSION
```

for:

- an architecture reset;
- independent review;
- a role change; or
- a materially different candidate or authority context.

A fresh bounded executor session receives only the canonical repository state, exact objective, authorized scope, acceptance criteria, and stop conditions necessary for its task.

## 11. Relationship to the Static Terra DAG amendment

[`docs/architecture/V1_Static_Approved_Terra_DAG_Amendment_v0.1.0.md`](V1_Static_Approved_Terra_DAG_Amendment_v0.1.0.md) remains fully authoritative.

Its first runtime candidate remains exactly:

```text
TERRA_EXECUTOR
openai-codex / gpt-5.6-terra / high
```

That candidate has no automatic higher-Terra escalation and no Sol or Luna normal path. This build-routing amendment governs prospective V1 engine-build work only; it does not enlarge `STATIC_APPROVED_DAG` runtime authority. Implementation of that candidate and execution of its autonomy pilot remain separately controlled boundaries.

## 12. Precedence and preserved decisions

The following remain unchanged:

- historical V0 implementation and evidence;
- M8 `PASS`;
- M9 `ROUTED_MODE_ECONOMICALLY_SUSPENDED` and the existing `ROUTED_DAG = SUSPENDED` decision;
- [V1 Durable Agentic Coding Engine Register v0.1.0](V1_Durable_Agentic_Coding_Engine_Register_v0.1.0.md) as the deferred capability inventory; and
- the Static Terra DAG amendment as authority for its runtime candidate.

This amendment prospectively supersedes older V1 instructions only where they require Sol Max as the default implementer or verifier for ordinary V1 milestone work. Historical documents and evidence are not rewritten or reinterpreted.

## 13. Non-authorizations

This amendment does not authorize:

- dynamic DAG growth;
- scouts;
- recursive agents;
- parallel writers;
- automatic model fallback or substitution;
- automatic higher Terra effort;
- a Sol planner or Sol closeout on `STATIC_APPROVED_DAG`;
- continuous Luna review;
- crash recovery or resume;
- new V1 capabilities;
- `STATIC_APPROVED_DAG` implementation or an autonomy pilot; or
- automatic commit, merge, or push.

All existing bounded scope, one-active-writer, deterministic verification, fail-closed, and publication controls remain in force.
