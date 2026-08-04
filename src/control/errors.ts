export const CONTROL_DECISION_ERROR_CODES = [
  "M5_POLICY_INVALID",
  "USAGE_EVIDENCE_INVALID",
  "BUDGET_EVALUATION_INVALID",
  "BUDGET_EXHAUSTED",
  "PROGRESS_EVIDENCE_INVALID",
  "PROGRESS_CLASSIFICATION_INVALID",
  "FAILURE_CLASSIFICATION_INVALID",
  "CONTRACT_GATE_INVALID",
  "CONTRACT_GATE_BLOCKED",
  "ROUTE_INVENTORY_INVALID",
  "ROUTE_NOT_ELIGIBLE",
  "NO_ELIGIBLE_ROUTE",
  "ROUTE_LIMIT_EXHAUSTED",
  "M5_DECISION_INVALID",
  "M5_AUTHORITY_INCOMPLETE",
  "M5_EVIDENCE_PUBLICATION_FAILED",
  "M5_STATE_PUBLICATION_FAILED",
  "TERMINAL_STATE_IMMUTABLE",
] as const;

export type ControlDecisionErrorCode = (typeof CONTROL_DECISION_ERROR_CODES)[number];

export interface ControlDecisionErrorContext {
  readonly sourceLayer?: "M1" | "M2" | "M3" | "M4" | "M5" | "CONTROLLER";
  readonly sourceCode?: string;
  readonly sourceRecordContentSha256?: string;
  readonly authorityRelevant?: boolean;
}

export class ControlDecisionError extends Error {
  public readonly code: ControlDecisionErrorCode;
  public readonly sourceLayer: ControlDecisionErrorContext["sourceLayer"];
  public readonly sourceCode: ControlDecisionErrorContext["sourceCode"];
  public readonly sourceRecordContentSha256: ControlDecisionErrorContext["sourceRecordContentSha256"];
  public readonly authorityRelevant: boolean;

  public constructor(code: ControlDecisionErrorCode, message: string, context: ControlDecisionErrorContext = {}, cause?: unknown) {
    super(`${code}: ${message}`, cause === undefined ? undefined : { cause });
    this.name = "ControlDecisionError";
    this.code = code;
    this.sourceLayer = context.sourceLayer;
    this.sourceCode = context.sourceCode;
    this.sourceRecordContentSha256 = context.sourceRecordContentSha256;
    this.authorityRelevant = context.authorityRelevant ?? false;
  }
}

export function controlError(
  code: ControlDecisionErrorCode,
  message: string,
  cause?: unknown,
  context: ControlDecisionErrorContext = {},
): ControlDecisionError {
  return new ControlDecisionError(code, message, context, cause);
}
