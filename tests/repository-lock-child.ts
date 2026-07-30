import {
  acquireWorktreeLock,
  releaseWorktreeLock,
  resolveRepositoryIdentity,
} from "../src/repository/index.js";

const stateRoot = process.argv[2];
const repositoryPath = process.argv[3];
if (stateRoot === undefined || repositoryPath === undefined || process.send === undefined) {
  throw new Error("repository-lock-child requires state root, repository, and IPC");
}

try {
  const repository = await resolveRepositoryIdentity({ requestedPath: repositoryPath, requireHead: true });
  const lock = await acquireWorktreeLock({ stateRoot, repository });
  process.send({ type: "ACQUIRED", diagnostics: lock.diagnostics });
  process.on("message", async (message: unknown) => {
    if (message !== null && typeof message === "object" && (message as { type?: unknown }).type === "RELEASE") {
      try {
        await releaseWorktreeLock(lock);
        process.send?.({ type: "RELEASED" });
        process.exitCode = 0;
        process.disconnect?.();
      } catch (error: unknown) {
        process.send?.({ type: "ERROR", code: (error as { code?: unknown }).code ?? "UNKNOWN" });
        process.exitCode = 2;
        process.disconnect?.();
      }
    }
  });
} catch (error: unknown) {
  process.send({ type: "ERROR", code: (error as { code?: unknown }).code ?? "UNKNOWN" });
  process.exitCode = 1;
  process.disconnect();
}
