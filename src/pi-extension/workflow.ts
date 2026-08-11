import { readFile } from "node:fs/promises";
import { resolve } from "node:path";

import { runBoundedMutationWorkflow } from "../workflow-controller.js";
import { prepareWorkflow, renderTaskPreview, runApprovedWorkflow } from "../workflow.js";

interface ExtensionUI {
  readonly setWidget: (key: string, content: string[] | undefined, options?: { readonly placement?: "aboveEditor" | "belowEditor" }) => void;
  readonly setStatus: (key: string, text: string | undefined) => void;
  readonly notify: (message: string, type?: "info" | "warning" | "error") => void;
  readonly confirm: (title: string, message: string, options?: { readonly signal?: AbortSignal }) => Promise<boolean>;
  readonly input: (title: string, placeholder?: string) => Promise<string | undefined>;
}

interface ExtensionCommandContext {
  readonly cwd: string;
  readonly hasUI: boolean;
  readonly signal: AbortSignal | undefined;
  readonly ui: ExtensionUI;
}

interface ExtensionAPI {
  readonly registerCommand: (name: string, options: { readonly description?: string; readonly handler: (args: string, ctx: ExtensionCommandContext) => Promise<void> }) => void;
}

const WIDGET_KEY = "pi-workflow-preview";

async function handleMutation(fileArgument: string, ctx: ExtensionCommandContext): Promise<void> {
  if (fileArgument.length === 0 || fileArgument.includes("\n") || fileArgument.includes("\r")) {
    ctx.ui.notify("BLOCKED (not started): usage is /workflow mutate <goal.json>", "error");
    return;
  }
  try {
    const goal = JSON.parse(await readFile(resolve(ctx.cwd, fileArgument), "utf8")) as unknown;
    // The extension is a human surface, not a command authority. A host that
    // owns verification authority invokes the controller API directly.
    const result = await runBoundedMutationWorkflow(goal, {
      cwd: ctx.cwd,
      ...(ctx.signal === undefined ? {} : { signal: ctx.signal }),
      onControlCapability: ({ path }) => { ctx.ui.notify(`FORCE_STOP_CAPABILITY ${path}`, "info"); },
      approveBaseline: async (baseline) => {
        const inventory = JSON.stringify(baseline.paths.map((entry) => ({ path: entry.path, ownership_class: entry.ownership_class, data_class: entry.data_class, capture_mode: entry.capture_mode, retention_days_after_terminal: entry.retention_days_after_terminal })));
        const confirmed = ctx.signal === undefined
          ? await ctx.ui.confirm("Approve exact dirty baseline", `${baseline.content_sha256}\n${inventory}`)
          : await ctx.ui.confirm("Approve exact dirty baseline", `${baseline.content_sha256}\n${inventory}`, { signal: ctx.signal });
        if (!confirmed) return null;
        const approvedBy = (await ctx.ui.input("Baseline approval identity", "your explicit approval identity"))?.trim();
        const approvedAt = (await ctx.ui.input("Baseline approval UTC timestamp", "YYYY-MM-DDTHH:MM:SS.sssZ"))?.trim();
        return approvedBy === undefined || approvedBy.length === 0 || approvedAt === undefined || approvedAt.length === 0
          ? null : { baseline_content_sha256: baseline.content_sha256 as `sha256:${string}`, approved_by: approvedBy, approved_at: approvedAt };
      },
      approveTasks: async ({ contract, plan }) => {
        const target = plan?.content_sha256 ?? contract.content_sha256;
        const kind = plan === null ? "final Contract-bound execution authority" : "exact routed PlanApproval";
        const confirmed = ctx.signal === undefined
          ? await ctx.ui.confirm(`Approve ${kind}`, target)
          : await ctx.ui.confirm(`Approve ${kind}`, target, { signal: ctx.signal });
        return confirmed ? target as `sha256:${string}` : null;
      },
      approveOwnerAcceptance: async ({ finalState }) => ctx.signal === undefined
        ? ctx.ui.confirm("Declared owner acceptance", finalState.content_sha256)
        : ctx.ui.confirm("Declared owner acceptance", finalState.content_sha256, { signal: ctx.signal }),
    });
    ctx.ui.notify(`${result.outcome}: ${result.reason}`, result.outcome === "PASS" ? "info" : "warning");
  } catch (error: unknown) {
    ctx.ui.notify(`BLOCKED: ${error instanceof Error ? error.message : String(error)}`, "error");
  }
}

async function handleWorkflow(args: string, ctx: ExtensionCommandContext): Promise<void> {
  const fileArgument = args.trim();
  if (fileArgument.startsWith("mutate ")) {
    if (!ctx.hasUI) { ctx.ui.notify("BLOCKED (not started): /workflow mutate requires human UI confirmation", "error"); return; }
    await handleMutation(fileArgument.slice("mutate ".length).trim(), ctx);
    return;
  }
  if (fileArgument.length === 0 || fileArgument.includes("\n") || fileArgument.includes("\r")) {
    ctx.ui.notify("BLOCKED (not started): usage is /workflow <goal.json>", "error");
    return;
  }
  if (!ctx.hasUI) {
    ctx.ui.notify("BLOCKED (not started): /workflow requires human UI confirmation", "error");
    return;
  }

  let prepared;
  try {
    const source = await readFile(resolve(ctx.cwd, fileArgument), "utf8");
    prepared = prepareWorkflow(JSON.parse(source) as unknown);
  } catch (error: unknown) {
    ctx.ui.notify(`BLOCKED (not started): ${error instanceof Error ? error.message : String(error)}`, "error");
    return;
  }

  ctx.ui.setWidget(WIDGET_KEY, renderTaskPreview(prepared).split("\n"), { placement: "aboveEditor" });
  ctx.ui.setStatus(WIDGET_KEY, `Approval required: ${prepared.task.content_sha256}`);
  try {
    const approved = ctx.signal === undefined
      ? await ctx.ui.confirm("Approve bounded read-only workflow", `Approve the exact TaskDocument content_sha256 ${prepared.task.content_sha256}?`)
      : await ctx.ui.confirm("Approve bounded read-only workflow", `Approve the exact TaskDocument content_sha256 ${prepared.task.content_sha256}?`, { signal: ctx.signal });
    if (!approved) {
      ctx.ui.notify("BLOCKED (not started): workflow approval was rejected", "warning");
      return;
    }
    const result = await runApprovedWorkflow(prepared, prepared.task.content_sha256, {
      cwd: ctx.cwd,
      ...(ctx.signal === undefined ? {} : { signal: ctx.signal }),
    });
    ctx.ui.notify(`${result.outcome}: ${result.reason}`, result.outcome === "PASS" ? "info" : "warning");
  } catch (error: unknown) {
    ctx.ui.notify(`BLOCKED: ${error instanceof Error ? error.message : String(error)}`, "error");
  } finally {
    ctx.ui.setStatus(WIDGET_KEY, undefined);
    ctx.ui.setWidget(WIDGET_KEY, undefined);
  }
}

export default function workflowExtension(pi: ExtensionAPI): void {
  pi.registerCommand("workflow", {
    description: "Preview and explicitly approve one bounded read-only workflow",
    handler: handleWorkflow,
  });
}
