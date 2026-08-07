import { readFile } from "node:fs/promises";
import { resolve } from "node:path";

import { prepareWorkflow, renderTaskPreview, runApprovedWorkflow } from "../workflow.js";

interface ExtensionUI {
  readonly setWidget: (key: string, content: string[] | undefined, options?: { readonly placement?: "aboveEditor" | "belowEditor" }) => void;
  readonly setStatus: (key: string, text: string | undefined) => void;
  readonly notify: (message: string, type?: "info" | "warning" | "error") => void;
  readonly confirm: (title: string, message: string, options?: { readonly signal?: AbortSignal }) => Promise<boolean>;
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

async function handleWorkflow(args: string, ctx: ExtensionCommandContext): Promise<void> {
  const fileArgument = args.trim();
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
