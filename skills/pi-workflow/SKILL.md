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

## Fail-closed before owner handoff

Until the owner explicitly starts the existing workflow engine, the parent Pi agent may only:

- inspect repository state read-only;
- read relevant files and nearby usage;
- prepare the bounded Goal, exact existing launch spec, or exact existing DAG representation;
- explain the objective, dependencies, budgets, route, provider/model/effort, editable scopes, required inputs/outputs, and deterministic verification already defined by the Goal/spec/controller; and
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

## Existing owner-start surfaces

The existing implementation, not this skill, owns the handoff:

- `pi-workflow <goal.json>` is the existing CLI read-only/report-only surface. The owner supplies the exact `APPROVE <TaskDocument.content_sha256>` input after reviewing its preview.
- `/workflow <goal.json>` is the existing Pi UI read-only/report-only command. The owner invokes it and confirms the exact TaskDocument in the UI.
- `/workflow mutate <goal.json>` is the existing Pi UI mutation command. The owner invokes it; the extension requires human UI confirmation and the existing controller owns baseline, execution, and owner-acceptance authority.
- `pi-workflow mutate <goal.json>` remains conditional on an existing host supplying controller-owned verification authority; it is not a skill-created fallback or a command for the parent to invoke.
- The existing `static-approved-dag` launcher is only for an already frozen launch spec and its exact approval digest.
- `pi-workflow status <retained-run-root>` and `pi-workflow resume-inspect <retained-run-root>` are only existing provider-free post-run inspection surfaces.

The skill may describe these actions, but must not invoke or simulate the owner's command. No new workflow-start mechanism is permitted.

## Required preparation stop

After read-only preparation, stop and begin the response with:

```text
READY_FOR_OWNER_APPROVAL
```

Follow it with the exact proposed bounded workflow:

- objective, non-goals, deliverable, and stop condition;
- exact route/provider/model/effort from the authoritative Goal, frozen spec, or controller output (never infer or choose them);
- exact editable scopes and write ownership;
- exact required inputs, outputs, and deterministic verification;
- exact budgets, attempt limits, and stopping conditions; and
- the exact existing owner-start action: `/workflow <goal.json>`, `/workflow mutate <goal.json>`, or the applicable CLI surface above.

If any scope, route, provider/model/effort, verification, budget, or approval identity is absent or ambiguous, report `BLOCKED (not started)` and ask the owner rather than filling it from prose.

After the owner starts the real engine through the existing supported path, execution authority belongs to the existing controller. The parent must not replace it with direct tools, reimplement its decisions, or reinterpret notification/UI state as authority.

## Boundaries

The existing workflow controller, CLI, and Pi extension are authoritative. This skill does not define state, execute a DAG, choose a provider/model, add fallback or retries, create subagents, widen scope, invent verification commands, alter persistence, or bypass approval. It adds no controller, approval record, state machine, event bus, orchestration, model-routing change, fallback, or model-callable workflow-start tool.
