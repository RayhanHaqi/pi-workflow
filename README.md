# pi-bounded-coding-workflow

Deterministic **V0 M1** foundations for a general-purpose bounded agentic-coding workflow for Pi.

This milestone contains only:

- RFC 8785/JCS-compatible `canonical-json-v1` serialization;
- SHA-256 content and domain identities;
- a versioned projection registry and transitive plan-approval binding;
- strict versioned JSON Schemas with aligned TypeScript types and semantic validators; and
- one pure reducer for `DIRECT_LUNA_HIGH`, `SINGLE_OWNER_SOL`, and `ROUTED_DAG`.

It does **not** register a Pi extension or implement a CLI, persistence, transition commits, Git/baseline operations, locking, secure filesystem access, command execution, worker sessions, runtime budgets, resume, or any M2-or-later subsystem.

## Package foundation

The package uses TypeScript, Node 22, npm, and ESM (`NodeNext`). Top-level dependencies are exactly pinned. Tests use Node's deterministic test runner through `tsx`, with test concurrency fixed to one.

```bash
npm ci
npm run schema:check
npm run typecheck
npm test
npm run build
```

Generated JavaScript and declarations are written to ignored `dist/`. The package has no `pi.extensions` entry and installation into active Pi configuration is outside M1.

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

The 17 required core schemas are present, plus the internal pure-reducer policy schema. Ajv enforces structural constraints. Deterministic semantic validators enforce cross-field rules such as canonical scope separation, route-role completeness and effort, verification-only closeout, owner-acceptance placement, graph consistency and caps, unambiguous write ownership, mode/state isolation, counter consistency, frozen identities, and null-only unavailable usage.

Scope and write-ownership paths use a rejecting repository-relative grammar: no absolute or drive-rooted paths, backslashes, NUL, empty segments, `.`/`..` segments, root aliases, or trailing slash. Paths are already canonical when accepted; no glob interpretation or silent path normalization occurs.

`AUTO` exists only as a requested mode. Concrete execution modes are exactly the three reducer modes. `LUNA_MEDIUM` is not a logical role, mode, or effort value.

## Pure state reducer

`src/state-machine/reducer.ts` reads only validated state, event, policy, counters, and identities. It performs no filesystem, Git, clock, environment, network, Pi-runtime, or model-prose access.

Each state binds `frozen_policy_content_sha256`, the complete independently verified policy content identity. Task lifecycle evidence records postflight, verification, and retry-progress admission; mode gates record planner, owner-acceptance, and closeout completion. Explicit phase invariants reject counter, task, active-writer, or completion evidence that is incompatible with the phase.

- **Direct:** one task, Luna executor only, at most two fresh attempts, evidence-backed progress before retry, mandatory postflight and verification.
- **Single owner:** one Sol owner invocation, no planner/closeout, one or two controller-admitted mutation cycles, mandatory postflight and verification, and an owner gate only when frozen as required.
- **Routed:** one planner, deterministic ready-leaf ordering, one active writer, two attempts per leaf, two constrained replans, frozen full-policy/DAG/scope/acceptance/budget identities, and one verification-only closeout.

Ready leaves sort by dependency satisfaction, topological rank, integer priority, then lexicographic `task_id`. The unchecked ordering helper is private to the reducer and runs only after `reduceState` has validated the state, event, policy, frozen policy binding, mode, and phase. The public state-machine subpath exports only `TransitionError`, `createInitialState`, and `reduceState`; it exposes no standalone workflow-decision helper. `PASS` and `BLOCKED` are immutable. An ordinary defect discovered at closeout becomes `BLOCKED_CLOSEOUT_DEFECT`; closeout cannot mutate or reopen a leaf.

## Authority and milestone boundary

The frozen architecture documents are byte-for-byte copies in `docs/architecture/`. M1 defines transition-commit schemas and identities only; durable evidence and commit-pointer behavior begin at M2 and are intentionally not implemented here.
