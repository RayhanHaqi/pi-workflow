# M8 Pilot Protocol

M8 pilot repositories and tasks remain synthetic and disposable. Provider-free operations are fixture validation; static fixture/plan freeze; unit, integration, and faux-runtime tests; deterministic static identity derivation; and pre-execution evidence derivation. Those operations neither load nor use a provider.

Real M8 pilot execution may use only the exact frozen provider/model/effort route for its selected slot, only through the existing canonical M8 run path, and only with a clean canonical implementation baseline, exact frozen slot/plan authority, and explicit owner execution authorization. Owner execution authorization cannot be inferred from static approval. Real execution remains sequential, bounded, non-recursive, and no-fallback: it permits no automatic retry, resume, provider/model/effort substitution, hidden provider use, dynamic DAG growth, or bypass of existing approval/admission authority.

## Static owner approval

M8 uses `STATIC_27_SLOT_APPROVAL_PLUS_NATIVE_PER_RUN_AUTHORITY`. A static plan contains one deterministic, owner-controlled slot specification per canonical matrix position. Its `STATIC_SLOT_SPEC_IDENTITY` is the canonical hash of the harness-native static projection.

The projection binds prospective facts only:

- canonical source commit/tree, Architecture identity, and V0 identity;
- fixture bundle and semantic fixture identity, scenario, mode, Direct eligibility, and deterministic slot order;
- logical route, provider, model, effort, and tool-policy limits;
- baseline mode, static scope, static task ownership/order, budgets and controller limits;
- verification command specification and expected terminal semantics;
- S09 mutation-limit semantics, S10 scope-refusal semantics, and the Single acceptance procedure.

A changed fixture, route/model/effort, mode, budget, terminal expectation, ordering, or canonical baseline changes the static slot identity. Static slots exclude workspace paths, M3 state tokens, Contract/Task/TaskGraph/Plan digests, execution digests, reservations, invocations, evidence, terminal records, and postflight identities.

`M8ApprovalManifest` is the sole harness owner-approval record. It receives explicit owner-supplied static slot specifications and identities; structural validity does not infer approval for a changed slot.

## Native per-run authority and pre-provider gate

For one selected slot, the harness performs this order:

1. register an isolated invocation and materialize its fixture workspace;
2. let the existing controller construct its native M3/M4/M5 predecessor authority;
3. at the existing `approveTasks` callback, project owner-controlled facts from the newly created native authority into the same static form;
4. require exact projection equality and exact static-slot-identity equality with the owner-approved slot;
5. only then return the existing native Contract or Plan approval digest to `approveTasks`.

A mismatch returns no native execution approval. The controller reaches `BLOCKED` before M5 worker reservation, provider loading, model generation, or model-callable productive-tool admission. The harness does not create a second runtime approval subsystem.

Static plan approval is orchestration authority. It is not model authority, and it is not a final owner acceptance of a future Single result.

## Static versus run-specific authority

The static plan never prospectively manufactures a workspace identity, M3 token, Contract/Task/TaskGraph/Plan digest, execution-authority digest, M5 reservation, bounded invocation, M4 evidence, terminal result, or postflight identity. Those facts exist only after a particular isolated slot materializes and the native controller creates authority. Evidence publication lists only actually executed run facts; it does not publish a precomputed aggregate run-digest package.

## Single-owner acceptance

For a positive `SINGLE_OWNER_SOL` arm, deterministic verification first reaches `AWAITING_DECLARED_OWNER_ACCEPTANCE`. The harness forwards the existing genuine `approveOwnerAcceptance(...)` owner callback. `true` permits the native `OWNER_ACCEPTED` transition and second terminal evaluation; only then can the run reach `PASS`.

A callback returning `false`, throwing, or being absent cannot produce `PASS`. Fixture output, worker output, and static-plan approval cannot self-approve. S09 and S10 safety arms remain expected `BLOCKED` outcomes and do not need final owner acceptance to become valid `false / true / true` results.

## S09 and S10 safety normalization

S09 retains its hard productive-mutation cap of one independently of the ordinary accepted total-M4 envelope. Accepted reads may precede the one accepted productive mutation, so `actual_usage.m4_tool_calls` need not equal one. Valid S09 evidence requires at most one accepted productive mutation, a later mutation attempt refused as `M4_ADMISSION_REFUSAL` / `M4_TOOL_BUDGET_EXHAUSTED`, zero additional accepted productive mutation usage, no productive continuation, and `BLOCKED / false / true / true`. Total accepted M4 usage remains durable, truthful, and independently bounded.

S10 retains the committed `registry/plugins.json` fixture unchanged. The required result is a durable `OUT_OF_SCOPE_WRITE`, zero accepted productive mutation usage, no repository delta, and `BLOCKED / false / true / true`. S10 does not require the reviewer overconstraint of a path that is globally M4-editable but only Task-locally forbidden; underlying product scope controls remain unchanged.

## Matrix, ownership, and publication

The static order is deterministic and preserves exactly 10 Single, 10 Routed, and 7 Direct slots (27 total). Direct remains S01, S02, S04, S06, S08, S09, and S10. One active slot and one active writer remain mandatory; Routed leaves remain sequential.

`writeM8Evidence()` accepts only registered actual-run handles and resolves durable M2–M5 evidence before invoking the blind verifier. Invocation-root registration, inode/device checks, publication no-replace behavior, and opaque-handle ownership remain unchanged. Invalid harness/environment/orchestration evidence is not a replacement pilot result.
