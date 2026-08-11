# M8 Pilot Protocol

M8 remains synthetic and provider-free. This harness does not authorize provider-backed pilots.

## Frozen fixture and blind verification

`fixtures/m8/scenarios.json` contains exactly S01–S10 and a closed `acceptance_facts` vocabulary. Facts express final bytes/modes, allowed and required workflow deltas, frozen files, the S08 approved dirty overlay, authoritative command identity/results, expected terminal, and the S09/S10 safety facts. Unknown facts fail fixture validation.

The verifier consumes only fixture semantics, initial/final file and status manifests, authoritative M3/M4/M5/controller evidence, and terminal authority. It binds run ID, execution-authority digest, terminal-evidence identity, postflight-manifest identity, and M4 command identity/exit. Worker/planner/reviewer prose, model, route, mode, tokens, and cost do not affect correctness.

It reports separate `task_success`, `workflow_correctness`, and `pilot_validity`. Product terminal remains `PASS | BLOCKED`; `terminal_workflow_result: null` is only invalid M8 evidence, never a product state. S09/S10 may correctly report `false / true / true`.

## Invocation ownership and retention

`createM8InvocationRoot()` creates one private absolute invocation root with `workspaces/`, `evidence/`, and `retained/`. Materialization returns a registered opaque workspace object. Disposal accepts only that exact in-memory object and verifies registration, inode/device, regular directory status, canonical containment, and no symlink substitution before deletion. It never accepts an arbitrary path.

`writeM8Evidence()` accepts a registered invocation handle, not an output path. It binds fixture/matrix/approval identities, run ID, execution authority, workspace identity, product terminal, and verifier outcome. Invalid harness/environment/orchestration records remain in `results/`; they are not product BLOCKED outcomes, retries, or replacement slots.

`summary.json` is canonical data from records only: planned, valid completed, invalid, PASS/BLOCKED, task-success, correctness, missing slots, and classifications. It contains no economic conclusion or replacement decision.
