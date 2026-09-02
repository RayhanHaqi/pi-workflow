---
name: pi-workflow
description: Use for bounded, owner-approved coding workflows in trusted Git repositories; prepare the existing pi-workflow CLI or Pi /workflow surface without granting execution authority to the parent agent.
---

# pi-workflow

This skill is **preparation-only**. Invoking `/skill:pi-workflow ...` never starts, approves, resumes, or executes a workflow and never grants the parent Pi agent mutation authority.

## Task authorization is not engine approval

`task authorization` is the user's natural-language description of the requested work. It may define the objective and desired result, but it is not execution authority for the parent Pi agent.

`pi-workflow engine approval` is the exact controller-owned approval input accepted by the existing CLI or Pi extension at its documented approval boundary. It is a separate event and must remain separate from task authorization.

The skill must never treat `Authorized:`, `execute the task`, `you may modify files`, `create a commit`, or any similar natural-language statement as pi-workflow engine approval or as permission for the parent agent to perform mutations directly.

## Fail-closed preparation

Until the owner explicitly starts the existing workflow engine, the parent Pi agent may only:

- inspect repository state and authority read-only;
- read relevant files, maintained-file layout, nearby usage, and supported verification surfaces;
- resolve canonical defaults and derive a proposed bounded Goal, exact existing launch spec, or exact existing DAG representation;
- normalize the proposed spec and derive its existing approval/spec digest; and
- present the exact next owner action.

Read-only shell inspection is allowed only when it has no side effects. Before handoff, the parent Pi agent must not directly:

- write, edit, or delete project files;
- create commits;
- create or delete branches or worktrees;
- create or remove environments;
- run mutation-capable setup or install commands;
- invoke implementation tools or provider/model calls;
- start subagents; or
- execute the coding task itself.

## Resolve before asking

Do not ask the owner to fill a schema field merely because it exists. First use read-only repository inspection and current controller/repository authority to resolve or propose every derivable value; the owner approves the resulting exact workflow, not a collection of manually supplied defaults.

### Derivable or proposable values

- **Execution mode:** Select the existing supported bounded mode that fits the task. For ordinary V1 bounded coding work that meets its static constraints, prefer `STATIC_APPROVED_DAG`; do not require a mode identifier unless multiple materially different valid modes remain.
- **Provider/model/effort:** Use the canonical route supplied by current authority. For a current V1 static candidate, preserve the authoritative no-fallback Terra route: `TERRA_EXECUTOR`, `openai-codex`, `gpt-5.6-terra`, and the controller's default `high` effort. Do not introduce fallback, automatic escalation, or a new route.
- **Attempts and budgets:** Apply existing bounded defaults. Prefer `static_max_attempts_per_leaf: 1`; propose `2` only for an existing, explicitly frozen repair edge. Use current controller limits and time-budget defaults when defined. Where a required task-specific time budget has no current default, derive the smallest conservative values consistent with the existing bounds, display every value, and leave it for approval; never add a retry loop.
- **Scopes and outputs:** Derive the narrowest credible editable paths/globs, required outputs, and documentation output paths from the task, repository layout, and maintained files. Reuse the existing documentation hierarchy; do not invent a parallel one. Give each output one task owner and expose exact paths before approval.
- **Repository identity:** Capture the actual repository root, branch, HEAD, HEAD tree, clean/dirty state, and read-only baseline during preparation. Present those frozen facts; never demand that the owner type hashes. A dirty baseline remains subject to the existing controller baseline-approval boundary and must never be discarded or silently accepted.
- **Verification:** Select the smallest sufficient commands only from existing controller-supported deterministic verification surfaces. Present the exact command/check identifiers, arguments, working directories, and timeouts. If required verification cannot be represented by the existing engine, report that capability gap instead of asking the owner to invent commands.
- **Digest:** Normalize the exact proposed spec and generate its approval/spec digest with the existing mechanism (for a static spec, `normalizeStaticApprovedDagLaunchSpec` and `staticApprovedDagSpecSha256`, or the provider-free inspection result). The owner never invents or supplies a digest.

### Genuine owner decisions

Ask only when no safe current default or read-only derivation exists, or when the unresolved choice materially changes scope, authority, destructive operations, external side effects, frozen architecture, provider/model policy, unusually high budget/cost, or another existing owner-controlled boundary. Report the concrete alternatives and remain blocked; do not substitute a default in those cases.

## Existing owner-start surfaces

The existing implementation, not this skill, owns the handoff:

- `pi-workflow <goal.json>` is the existing CLI read-only/report-only surface. The owner supplies the exact `APPROVE <TaskDocument.content_sha256>` input after reviewing its preview.
- `/workflow <goal.json>` is the existing Pi UI read-only/report-only command. The owner invokes it and confirms the exact TaskDocument in the UI.
- `/workflow mutate <goal.json>` is the existing Pi UI mutation command. The owner invokes it; the extension requires human UI confirmation and the existing controller owns baseline, execution, and owner-acceptance authority.
- `pi-workflow mutate <goal.json>` remains conditional on an existing host supplying controller-owned verification authority; it is not a skill-created fallback or a command for the parent to invoke.
- The existing `static-approved-dag` launcher is only for an already frozen launch spec and its generated exact approval digest.
- `pi-workflow status <retained-run-root>` and `pi-workflow resume-inspect <retained-run-root>` are only existing provider-free post-run inspection surfaces.

The skill may describe exactly one applicable owner action, but must not invoke or simulate the owner's command. No new workflow-start mechanism is permitted.

## Required preparation stop

After read-only preparation, present a concise exact proposal containing:

- objective, non-goals, deliverable, and stop condition;
- execution mode and exact provider/model/effort route;
- DAG tasks, dependencies, editable scopes, write ownership, required outputs, and documentation paths;
- exact controller-supported verification;
- attempt limits, every budget, and stopping conditions;
- frozen repository root, branch, HEAD, tree, clean/dirty state, and baseline facts;
- prohibited actions and any genuine owner decision or concrete engine capability gap;
- the exact existing owner-start action; and
- the normalized spec and generated approval/spec digest when the existing mechanism produces them.

Then emit exactly:

```text
READY_FOR_OWNER_APPROVAL
```

and stop without mutation. `READY_FOR_OWNER_APPROVAL` is never approval, engine start, or permission for the parent to act.

If the existing engine cannot represent a required operation, emit `BLOCKED (not started)` with that concrete capability boundary. Canonical defaults do not solve unsupported capabilities. Examples include Git worktree creation, branch creation, networked Conda environment creation, and commits when the current controller cannot authorize them.

After the owner starts the real engine through the existing supported path, execution authority belongs to the existing controller. The parent must not replace it with direct tools, reimplement its decisions, or reinterpret notification/UI state as authority.

## Boundaries

The existing workflow controller, CLI, and Pi extension are authoritative. This skill does not define state, execute a DAG, choose a non-canonical provider/model, add fallback or retries, create subagents, widen scope, invent verification commands, alter persistence, or bypass approval. It adds no controller, approval record, state machine, event bus, orchestration, model-routing change, fallback, or model-callable workflow-start tool.
