import { activateDeterministicResumeAdmission, acquireDeterministicResumeAdmission } from "../src/resume-admission.js";

const root = process.argv[2];
if (root === undefined || process.send === undefined) throw new Error("resume-activation-child requires retained root and IPC");
const retainedRunRoot = root;

async function main(): Promise<void> {
  const admission = await acquireDeterministicResumeAdmission({ retainedRunRoot });
  const activation = await activateDeterministicResumeAdmission(admission);
  process.send?.({ type: "ACTIVATED", binding: activation.binding });
  await new Promise<void>(() => {});
}

main().catch((error: unknown) => { process.send?.({ type: "ERROR", error: error instanceof Error ? error.message : String(error) }); process.exitCode = 1; });
