export class StateStoreError extends Error {
  public readonly code: string;

  public constructor(code: string, message: string, options: ErrorOptions = {}) {
    super(`${code}: ${message}`, options);
    this.name = "StateStoreError";
    this.code = code;
  }
}

export function stateStoreError(code: string, message: string, cause?: unknown): StateStoreError {
  return cause === undefined
    ? new StateStoreError(code, message)
    : new StateStoreError(code, message, { cause });
}
