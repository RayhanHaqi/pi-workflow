# pi-bounded-coding-workflow

Deterministic **V0 M1–M5** foundations for a general-purpose bounded agentic-coding workflow for Pi.

The package contains:

- RFC 8785/JCS-compatible `canonical-json-v1` serialization;
- SHA-256 content and domain identities;
- a versioned projection registry and transitive plan-approval binding;
- strict versioned JSON Schemas with aligned TypeScript types and semantic validators;
- one pure reducer for `DIRECT_LUNA_HIGH`, `SINGLE_OWNER_SOL`, and `ROUTED_DAG`;
- an M2 state store with immutable evidence, reducer-derived transition commits, a `state.json` commit pointer, reachability inspection, and bounded process-crash terminalization;
- an M3 repository guard with deterministic Git/worktree identity, exact clean or approved-dirty baselines, bounded baseline blobs and retention, a Linux `flock` guardian, and full/fast preflight plus postflight ownership accounting; and
- an M4 descriptor-relative secure filesystem and scoped tool gateway with exact-byte mutation, frozen structured commands, Landlock filesystem confinement, `no_new_privs`, seccomp network denial, and immutable operation evidence; and
- an M5 deterministic control-decision kernel for typed usage budgets, evidence-backed progress, fixed failure actions, contract satisfiability, finite route eligibility/selection, and M2-bound immutable decision authority.

M7 adds one approval-gated, ephemeral, read-only/report-only workflow surface: `pi-workflow <goal.json>` and the human-confirmed `/workflow <goal.json>` Pi command. It compiles the Goal into the existing canonical TaskDocument, revalidates the approved content identity, reuses M3/M4/M5, and invokes only the existing bounded M6 worker. It does not add Goal identity or persistence, a Goal schema/record, mutation, resume/recovery, retries, fallback, provider/model selection, or another worker.

## Package foundation

The package uses TypeScript, Node 22, npm, and ESM (`NodeNext`). Top-level dependencies are exactly pinned. Tests use Node's deterministic test runner through `tsx`, with test concurrency fixed to one.

```bash
npm ci
npm run schema:check
npm run typecheck
npm test
npm run build
```

Generated JavaScript and declarations are written to ignored `dist/`. The package advertises its Pi extension through `pi.extensions` and its CLI through `bin.pi-workflow`; installation into active Pi configuration remains an explicit consumer action. The M7 controller remains private and no additional package export subpath is added.

## Canonical JSON

`src/canonical-json/index.ts` accepts already-parsed JSON-domain values and emits compact JCS-compatible JSON:

- object keys use raw UTF-16 code-unit ordering;
- ordinary arrays preserve order;
- finite numbers use ECMAScript JSON number serialization;
- strings are encoded as UTF-8 without BOM and are not Unicode-normalized; and
- non-finite numbers, unsupported JavaScript values, cycles, sparse arrays, symbol/extra properties, accessors, non-enumerable properties, and unpaired surrogates are rejected.

The value-level API cannot detect duplicate object names already discarded by an earlier ordinary `JSON.parse`. A caller requiring duplicate-name proof must enforce it at its parser boundary.

Schema-declared set-like arrays reject duplicate canonical members before hashing and are then normalized by canonical UTF-8 byte order in the identity projection layer. Baseline files and authority entries additionally require unique canonical repository-relative paths.

## Identity model

All digests use:

```text
canonicalization: canonical-json-v1
hash:             SHA-256
format:           sha256:<64 lowercase hexadecimal characters>
text:             UTF-8 without BOM
```

`document-content-v1` includes all fields except top-level `/content_sha256`; `content_projection_id` remains bound.

Domain identity order is non-circular:

1. validate/normalize the input boundary;
2. project out the domain digest and `/content_sha256`;
3. compute and insert the domain digest;
4. compute `/content_sha256`, excluding only itself.

Public contract construction uses `identifyContractDocument(schemaId, value)`, which performs structural and semantic validation before invoking internal projection primitives and validates the identified result again. Public verification uses `assertDocumentValid` or `verifyContractDocument`; both validate structure and semantics before checking identities. Unvalidated projection/hash constructors are internal and are not exported by the package identity entry point.

Canonical projection definitions live in a module-private registry and are deeply immutable. Public introspection is limited to `listProjectionDefinitions()` and `getProjectionDefinition(projectionId)`, which return independent, deeply frozen snapshots. No backing `Map` or canonical definition reference is exported, so callers cannot alter identity exclusions, normalization, ordering, digest fields, or the projection inventory.

The private registry in `src/identity/projections.ts` contains:

| Projection | Domain kind | Declared set-like arrays |
| --- | --- | --- |
| `objective-freeze-v1` | objective | scope paths, authority paths |
| `route-map-v1` | route map | routes |
| `route-map-approval-v1` | route-map approval | none |
| `baseline-snapshot-v1` | baseline | files |
| `baseline-approval-v1` | baseline approval | none |
| `authority-lock-v1` | authority lock | authorities |
| `contract-freeze-v1` | contract | scope paths, required inputs/outputs |
| `task-packet-v1` | task | dependencies, scope paths, required inputs/outputs |
| `task-graph-freeze-v1` | task graph | tasks, edges |
| `routing-freeze-v1` | routing | reasons |
| `budget-freeze-v1` | budget | none |
| `plan-approval-v1` | plan approval | DAG edges, scope paths, required inputs/outputs, logical routes |
| `transition-commit-v1` | transition-commit boundary only | none |
| `final-report-v1` | final report | none |
| `document-content-v1` | any versioned document | none |

`plan-approval-v1` includes the objective, repository identity, execution mode, baseline, authority, contract, DAG, ordered task identities, scope, inputs/outputs, acceptance, commands, route/provider/model/effort/tool policy, all limits and budgets, and stopping conditions.

## Schemas and types

`src/schemas/definitions.ts` is the single TypeBox source of truth. It produces both static TypeScript types and the JSON Schemas under `schemas/`; `npm run schema:check` fails if an emitted file differs. Every object boundary has `additionalProperties: false`.

Canonical runtime schemas are held in a package-private, deeply frozen registry. Ajv compiles exact serialized clones of that authority, so neither compilation nor public inspection can change it. The supported `./schemas` entrypoint exposes the frozen primitive `SCHEMA_VERSION`, the frozen schema-ID list `SCHEMA_IDS`, and `getSchemaSnapshot(schemaId)` / `listSchemaSnapshots()` for runtime inspection. Each schema snapshot is a fresh, detached, deeply frozen, serializable copy; snapshots inspect but never configure validation. Direct TypeBox objects, shared enum arrays, and the backing registry are not public runtime exports. Document and policy types remain available as compile-time-only TypeScript exports.

The 17 required core schemas are present, plus the pure-reducer policy, five additive M2 persistence schemas, twelve M3 repository schemas, nine M4 secure-tool schemas, and three M5 control schemas (46 emitted schemas total). Ajv enforces structural constraints. Deterministic semantic validators enforce cross-field rules such as canonical scope separation, route-role completeness and effort, verification-only closeout, owner-acceptance placement, graph consistency and caps, unambiguous write ownership, mode/state isolation, counter consistency, frozen identities, and null-only unavailable usage.

Scope and write-ownership paths use a rejecting repository-relative grammar: no absolute or drive-rooted paths, backslashes, NUL, empty segments, `.`/`..` segments, root aliases, or trailing slash. Paths are already canonical when accepted; no glob interpretation or silent path normalization occurs.

`AUTO` exists only as a requested mode. Concrete execution modes are exactly the three reducer modes. `LUNA_MEDIUM` is not a logical role, mode, or effort value.

## Pure state reducer

`src/state-machine/reducer.ts` reads only validated state, event, policy, counters, and identities. It performs no filesystem, Git, clock, environment, network, Pi-runtime, or model-prose access.

Each state binds `frozen_policy_content_sha256`, the complete independently verified policy content identity. Task lifecycle evidence records postflight, verification, and retry-progress admission; mode gates record planner, owner-acceptance, and closeout completion. Explicit phase invariants reject counter, task, active-writer, or completion evidence that is incompatible with the phase.

- **Direct:** one task, Luna executor only, at most two fresh attempts, evidence-backed progress before retry, mandatory postflight and verification.
- **Single owner:** one Sol owner invocation, no planner/closeout, one or two controller-admitted mutation cycles, mandatory postflight and verification, and an owner gate only when frozen as required.
- **Routed:** one planner, deterministic ready-leaf ordering, one active writer, two attempts per leaf, two constrained replans, frozen full-policy/DAG/scope/acceptance/budget identities, and one verification-only closeout.

Ready leaves sort by dependency satisfaction, topological rank, integer priority, then lexicographic `task_id`. The unchecked ordering helper is private to the reducer and runs only after `reduceState` has validated the state, event, policy, frozen policy binding, mode, and phase. The public state-machine subpath exports only `TransitionError`, `createInitialState`, and `reduceState`; it exposes no standalone workflow-decision helper. `PASS` and `BLOCKED` are immutable. An ordinary defect discovered at closeout becomes `BLOCKED_CLOSEOUT_DEFECT`; closeout cannot mutate or reopen a leaf.

## M5 control decisions

The supported `./control` entrypoint exports only `ControlDecisionError` and `createControlDecisionKernel`. A kernel validates one immutable policy, reconstructs committed M2 state and managed evidence, aggregates strict operation usage, applies exact integer budget arithmetic, classifies progress and failures, evaluates the bounded contract gate, and selects one finite mode/action or BLOCK. It publishes content-addressed policy, usage, and aggregate decision records. If the decision admits an existing M1 transition, its exact canonical bytes become M2 transition evidence and `commitTransition` remains the only state publication path.

Route facts and production route-map/budget values are external owner authority. M5 never infers them from objective prose, chooses provider/model values, invokes a worker, dispatches a tool, adds a phase, or creates another mutable pointer. `PASS` and `BLOCKED` remain the only terminal phases. Unavailable telemetry remains `null`; estimates never become actual usage; unknown outcomes retain reservations. Public results are detached and recursively frozen, while evaluators, classifiers, publishers, and interruption seams remain package-private.

## Durable state-commit foundation

The supported `./persistence` entrypoint exports only `StateStoreError`, `initializeRunStorage`, `putEvidence`, `commitTransition`, `inspectRunStorage`, and `terminalizeProcessCrash`. Internal atomic primitives, path derivation, checkpoint hooks, and object registries are blocked package subpaths.

A run uses this fixed private layout beneath a caller-supplied absolute state root and strict ASCII run ID:

```text
<state-root>/runs/<run-id>/
  state.json
  evidence/sha256/<raw-byte-sha256>
  records/evidence-metadata/<content-sha256>.json
  records/evidence-manifests/<content-sha256>.json
  records/workflow-states/<content-sha256>.json
  records/transition-events/<content-sha256>.json
  records/reducer-policies/<content-sha256>.json
  records/process-assessments/<content-sha256>.json
  records/baselines/<content-sha256>.json
  records/baseline-approvals/<content-sha256>.json
  records/lock-diagnostics/<content-sha256>.json
  records/preflights/<content-sha256>.json
  records/repository-state-tokens/<content-sha256>.json
  records/postflights/<content-sha256>.json
  records/retention/<content-sha256>.json
  records/secure-fs-capabilities/<content-sha256>.json
  records/sandbox-capabilities/<content-sha256>.json
  records/tool-policies/<content-sha256>.json
  records/command-catalogs/<content-sha256>.json
  records/tool-requests/<content-sha256>.json
  records/patch-requests/<content-sha256>.json
  records/tool-results/<content-sha256>.json
  records/mutation-receipts/<content-sha256>.json
  records/command-results/<content-sha256>.json
  records/m5-control-policies/<content-sha256>.json
  records/m5-usage-evidence/<content-sha256>.json
  records/m5-control-decisions/<content-sha256>.json
  baseline-blobs/sha256/<raw-byte-sha256>
  commits/<content-sha256>.json
```

Every immutable JSON object is strictly schema- and identity-validated, encoded as canonical JSON, and stored under its content identity. Raw evidence is binary-safe, bounded to 16 MiB per object, addressed by the SHA-256 of exact bytes, and bound to byte-count metadata. Files are mode `0600`; owned state/run directories are mode `0700`. Existing immutable objects are reused only when their exact bytes match.

Atomic publication uses an exclusive same-directory temporary file, complete writes, file `fsync`, close, atomic rename, and parent-directory `fsync`. A transition publishes all evidence first, then records, then its M2 transition-commit companion, verifies every reference from disk, rechecks the prior pointer/state identities, and replaces `state.json` last through the same fsync/rename discipline. The accepted M1 `pi_gacw_transition_commit_v0` meaning is unchanged; `pi_gacw_state_transition_commit_v0` is the additive M2 record binding run, exact revisions, reconstructed prior pointer, prior commit/state, event, complete reducer policy, reducer-produced state, evidence manifest, process metadata, and optional process assessment.

`state.json` is the sole mutable commit authority. Inspection reconstructs all historical pointers from the immutable commit chain, replays each non-genesis transition through the public M1 `reduceState` boundary, verifies all object hashes/schemas/identities, and reports `HEALTHY`, `ORPHANED_UNCOMMITTED_EVIDENCE`, `BLOCKED_STATE_COMMIT_INCOMPLETE`, or `BLOCKED_UNEXPECTED_STATE_STORE_ENTRY`. Orphans and temporary files are never adopted or silently removed.

V0 has no resume. With explicit interruption evidence and exact expected revision/pointer/state identities, a valid nonterminal run may commit a process-assessment record and an M1 `BLOCK` event whose reducer result is `BLOCKED_PROCESS_CRASH`. Existing orphans are inventoried but remain uncommitted. Terminal state remains immutable.

M2 guarantees process-interruption consistency under supported local-filesystem file/directory-fsync and rename semantics. It does not claim complete power-loss, hardware-controller, storage-device, distributed-filesystem, or concurrent-writer durability. **One-writer ownership is a caller precondition.** Expected-identity rereads detect sequentially observed drift but do not replace the M3 exclusive lock.

## Repository guard

The supported `./repository` entrypoint exposes only validated repository-guard operations. Production Git commands are inspection-only, use explicit argument vectors with `shell: false`, deterministic locale and pager settings, disabled optional Git locks, bounded binary output, and real exit/signal checks. Git status and index inventories are NUL-safe; paths outside the UTF-8 canonical repository-relative grammar fail closed.

A worktree key is `sha256(realpath(git-common-dir) || NUL || realpath(worktree-root))`. One packaged Python standard-library guardian owns a nonblocking Linux kernel `flock` at `<state-root>/locks/<key>.lock`, keeps its descriptor open, monitors its controller, and responds to bounded health and release messages. Owner markers are diagnostic and never override the kernel lock.

`CLEAN_REQUIRED` rejects every staged, unstaged, untracked, conflict, operation, or index-lock state. `APPROVED_BASELINE_DIRTY` requires one decision for every dirty path and binds bytes/status, ownership, data class, capture policy, retention, repository, instructions, authority, and Git fingerprint. Durable authority reconstructs the historical index from the stored HEAD tree and staged inventory, checks exact HEAD/index objects, exact porcelain HEAD/index/worktree mode layers, and rename relationships, and binds each path to its staged, unstaged, untracked, or deletion producer state without comparing historical branch/HEAD to current live state. The supported local Git 2.43 copy fixture reports a staged copy as `A`, so destination addition modes are enforced and no unavailable `C` source-mode claim is invented. Missing classification defaults only to `HASH_ONLY`; `SECRET` blocks, and symlink/special paths are never followed. Optional blobs are SHA-256 addressed, mode `0600`, atomically published through the M2 primitive, limited to 1 MiB each, and admitted under both a 64 MiB cumulative retained-physical-byte limit per run and a 2 GiB state-root ceiling. Admission enumerates and verifies every retained object and counts only new unique physical bytes; durable quota authority must be a possible one-writer transition over the complete retained-blob history, with all convergent populations explored deterministically under a 4096-state fail-closed bound, and every selected predecessor population must remain complete through a currently verified blob or exact cleanup-rooted deletion proof; an incomplete predecessor makes every dependent baseline, approval, source, and token incomplete. If baseline-record publication fails, it rolls back only blobs first created by that invocation and fsyncs each affected directory; cleanup uncertainty is typed separately. An interrupted blob without a durable baseline record is classified as `UNCOMMITTED_BASELINE_PUBLICATION`, remains capacity-accounted, and is never silently adopted.

Full preflight loads and compares the exact durable baseline and, for dirty mode, the exact durable approval before it can publish authority. The approval semantic validator compares the complete M1 accepted-repository projection and binds all additional runtime repository, worktree, HEAD-tree, upstream/divergence, fingerprint, and path-policy facts through the exact durable baseline-runtime identity. After guardian `READY`, lock acquisition atomically publishes a strict content-addressed producer root directly from private held-handle facts under `locks/`; it binds the state root, worktree and lock paths, controller/guardian PIDs, timestamp, protocol, random acquisition nonce and READY identity, Python invocation/real paths and version, and helper invocation/real paths and digest. Full preflight publishes an exact per-run copy, then a diagnostic referencing that root, then the successful source and root token. Managed classification independently requires the per-run root to match its global producer file, eliminating the former diagnostic/source/token authority cycle; a missing producer file is incomplete and a mismatched diagnostic is invalid. The environment reprobes Node and Git, while Python and helper authority come from this immutable acquisition chain rather than a later `PATH` lookup; the environment Git version must equal the exact repository-inspection Git version.

Fast preflight and postflight use one common loader and semantic graph evaluator that verifies the exact token, successful source, prior chain, baseline/approval root, durable lock, repository, worktree, fingerprints, instructions, authority, scope, claims, and deltas; chains terminate at a successful full preflight and are loop/depth bounded. The M3 scope identity hashes a versioned domain (`pi_gacw_task_scope_v0`, `0.1.0`, `m3-task-scope-v1`) plus canonical sorted editable/frozen sets; overlap is rejected. Historical postflight validation reconstructs repository before-states from the stored HEAD objects, workflow before-states from the approved baseline, and after-states from the resulting fingerprint, then derives exact `ADDED`, `DELETED`, `MODIFIED`, `MODE_CHANGED`, type-change, and baseline-reversion transitions. An absent baseline/result state uses `null` content/mode while retaining any deletion sentinel only as baseline-document identity, so exact restoration of deleted, modified, mode-changed, or added paths to stored HEAD is an authoritative `BASELINE_REVERTED` workflow delta. Git-only executable class is reconciled with exact approved physical permission bits when that class is unchanged. Staged rename reversion remains unsupported because restoring its HEAD layout would mutate the frozen accepted index. Claimed paths are derived from the exact prior-to-resulting fingerprint change set. A failed source/token pair publication never returns authority, and any retained standalone valid source is classified as unreferenced. Postflight keeps current-versus-HEAD `repository_git_delta` separate from current-versus-baseline `workflow_owned_delta`, rejects index changes, and admits only an exact caller claim inside the versioned editable scope.

Retention requires exact durable baseline/approval records and terminal-timestamp authorities committed as terminal-transition evidence. The strict `pi_gacw_terminal_retention_authority_v0` and `pi_gacw_retention_result_v0` documents have additive R2 provenance/group fields; weaker pre-R2 documents are intentionally rejected rather than reinterpreted as deletion proof. It builds a reverse index from each physical digest to every logical reference across durable snapshots. A physical blob is validated, unlinked, and parent-fsynced at most once, and only after every live reference has compatible authority and has reached its deadline. One deterministic aggregate state machine derives and validates operation, outcome, per-target status/result/detail, counts, unlink/fsync flags, and deletion-proof eligibility; `COMPLETE` permits no residual eligible, pending, failed, or unproved target, inspection and failed/partial cleanup cannot masquerade as success, and idempotence requires an exact cleanup-rooted successful prior proof. An inspection may report an already-removed observation but carries no prior-proof edge and is rejected anywhere in a deletion-proof chain. Results also bind the complete sorted logical-reference group, baseline/approval, repository/worktree, terminal state and authority, digest, size, path, classification, and deadline. Missing bytes are reconciled only by this shared exact proof validator. Inspection and failed cleanup subtract no target bytes from capacity; successful cleanup relies only on physical bytes already removed, and exact canonical result bytes are rechecked immediately before publication. The documented unlink/fsync-to-result interruption window remains: a missing blob is unproved until an exact durable success result exists. It does not claim secure physical erasure.

For cooperating controllers, M3 guarantees one active lock owner per worktree key and detects guardian loss. A process that ignores advisory locking can still write; unexplained file, index, ref, instruction, authority, worktree-list, or lock drift is detected at guard boundaries. Until M4, model-controlled path containment, `openat2` repository writes, preimage-checked mutation, and a repository write API are explicitly not guaranteed.

## Secure filesystem and scoped tool gateway

The supported `./secure-fs` entrypoint exports only `SecureFilesystemError`, `probeSecureFilesystemCapabilities`, and `createSecureFilesystem`. Reads and listings use the packaged Python guardian through a verified helper identity. Every path is rejecting canonical repository-relative form; `.git`, symlinks, magic links, special files, root changes, and scope escapes fail closed. The helper opens the exact M3 physical worktree root and resolves descendants with Linux `openat2(2)` using `RESOLVE_BENEATH`, `RESOLVE_NO_SYMLINKS`, and `RESOLVE_NO_MAGICLINKS`.

Mutation is available only through the supported `./scoped-tools` gateway. `CREATE` uses same-directory temporary-file publication with `RENAME_NOREPLACE`; `REPLACE` uses `RENAME_EXCHANGE` and validates the displaced inode before unlink; `DELETE` uses a no-replace tombstone. Each protocol checks exact digest/size/mode preimages, rejects multiply linked targets, fsyncs file and directory boundaries, verifies parent and installed-inode identity, runs M3 fast preflight immediately before the helper, and advances authority only through M3 postflight. M4 publishes capability, policy, request, result, receipt, and command records as private content-addressed objects and never writes `state.json`.

The gateway exposes only `read_scoped`, `search_scoped`, `list_scoped`, `inspect_git_scoped`, `read_evidence`, `apply_patch_scoped`, `run_inspection_command`, `run_task_command`, and `run_verification_command`. Read policy supports raw, metadata-only, and forbidden data classes. Search is literal and bounded. Git inspection has a fixed catalog and hides paths outside readable scope. The caller supplies only a frozen command ID and current M3 token—never an executable, shell, argument vector, environment, cwd, or sandbox rule.

Commands revalidate catalog, executable, and helper identities at execution. The packaged sandbox applies Landlock before `execve`, sets `no_new_privs`, denies network and dangerous metadata/namespace syscalls with seccomp, supplies a minimal environment, enforces timeout and stdout/stderr bounds, kills the complete process group, and runs M3 postflight over exact declared effects. Missing secure-write, filesystem-sandbox, or network-denial primitives are distinct blocking outcomes; no weaker fallback exists.

## Authority and milestone boundary

The frozen architecture documents are byte-for-byte copies in `docs/architecture/`. M1 reducer, schema, and identity projections remain frozen dependencies. M2 commit-graph semantics remain unchanged: M3 records/blobs are validated immutable managed objects, `state.json` is still the sole mutable commit pointer, and no managed object is silently adopted into the graph. Read-only inspection uses the same semantic baseline, approval, source/token, terminal-authority, and retention-proof validators as operational consumers. It classifies managed objects as authoritative, unreferenced, incomplete-chain, invalid, or uncommitted-baseline publication without creating a second mutable pointer. `HEALTHY` describes intact foundational M2 layout and bytes; a semantic-invalid managed object is still reported by an `INVALID_MANAGED_RECORD` issue and classification, is never authoritative, and is rejected by any operational authority path. M4 records remain managed immutable evidence rather than a second mutable controller pointer; a future controller may reference them in a transition. M5 usage budgets, routing, progress/failure orchestration, Pi worker integration, CLI/extension behavior, resume, and all later capabilities remain unimplemented.
