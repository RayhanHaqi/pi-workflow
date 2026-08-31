---
name: pi-workflow
description: Use for bounded, owner-approved coding workflows in trusted Git repositories; helps choose and prepare the existing pi-workflow CLI or Pi /workflow surface without changing execution authority.
---

# pi-workflow

Use this skill when a user asks to inspect, prepare, approve, run, or check a bounded coding workflow in a trusted Git repository.

## Choose the existing surface

- `pi-workflow <goal.json>` for the existing approval-gated read-only/report-only workflow.
- `/workflow <goal.json>` for the existing Pi UI approval boundary.
- `pi-workflow mutate <goal.json>` only when an existing host supplies controller-owned verification authority; never invent that authority.
- The existing `static-approved-dag` launcher only for an already frozen launch spec and its exact approval digest.
- `pi-workflow status <retained-run-root>` and `pi-workflow resume-inspect <retained-run-root>` for provider-free post-run inspection.

## Operating steps

1. Confirm the repository is trusted and identify the smallest relevant existing entrypoint. Inspect only the repository status, relevant goal/spec, and nearby usage needed to choose it.
2. Preserve the exact objective, scope, required outputs, verification authority, budgets, route, and approval identity supplied by the owner or controller.
3. Explain or prepare the exact existing command and approval input. Do not start a mutating workflow merely because this skill was invoked; wait for the existing owner approval.
4. After an owner-authorized run, use the existing report, status, or inspection surface and copy its classification and reason exactly.

## Boundaries

The existing workflow controller, CLI, and Pi extension are authoritative. This skill does not define state, execute a DAG, choose a provider/model, add fallback or retries, create subagents, widen scope, invent verification commands, alter persistence, or bypass approval. Notification or UI state is never execution authority.
