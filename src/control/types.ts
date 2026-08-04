import type { Sha256Digest } from "../identity/index.js";
import type {
  BudgetDocument,
  ContractDocument,
  LogicalModelRole,
  M3PostflightDocument,
  M3RepositoryIdentityDocument,
  M3RepositoryStateTokenDocument,
  M4CommandCatalogDocument,
  M4CommandResultDocument,
  M4ScopedToolPolicyDocument,
  M5ControlDecisionDocument,
  M5ControlPolicyDocument,
  M5UsageEvidenceDocument,
  PlanApprovalDocument,
  ProcessMetadata,
  ReducerPolicy,
  RouteMapApprovalDocument,
  StateTransitionCommitDocument,
  RouteMapDocument,
  TaskDocument,
  TaskGraphDocument,
  TransitionEvent,
  WorkflowState,
} from "../schemas/index.js";

export type ControlDecisionIntent =
  | "VALIDATE_CONTRACT"
  | "SELECT_ROUTE"
  | "AUTHORIZE_WORK"
  | "AUTHORIZE_CONTINUATION"
  | "EVALUATE_TERMINAL"
  | "BLOCK";

export interface M5ProgressEvidenceInput {
  readonly claimedKind?: M5ControlDecisionDocument["progress"]["kind"];
  readonly noProgressReason?: M5ControlDecisionDocument["progress"]["no_progress_reason"];
  readonly evidenceContentSha256: readonly Sha256Digest[];
  readonly priorStateOrDecisionContentSha256?: Sha256Digest;
  readonly priorFailureSignature?: Sha256Digest;
  readonly currentFailureSignature?: Sha256Digest;
}

export interface M5FailureInput {
  readonly sourceLayer: "M1" | "M2" | "M3" | "M4" | "M5" | "CONTROLLER";
  readonly sourceErrorCode: string;
  readonly sourceRecordContentSha256: Sha256Digest;
  readonly normalizedSignature: Sha256Digest;
  readonly operationId?: string;
  readonly scopeIdentity?: Sha256Digest;
  readonly pathIdentity?: Sha256Digest;
  readonly repositoryIdentity?: Sha256Digest;
  readonly worktreeKey?: Sha256Digest;
  readonly resolutionEvidenceContentSha256?: Sha256Digest;
}

export interface M5ObligationEvidenceInput {
  readonly descriptorSha256: Sha256Digest;
  readonly value: string;
  readonly evidenceContentSha256: Sha256Digest;
}

export interface M5GateDetectionInput {
  readonly code: M5ControlDecisionDocument["contract_gate"]["detections"][number]["code"];
  readonly evidenceContentSha256?: Sha256Digest;
}

export interface M5ImmutableRunAuthoritySources {
  readonly repositoryIdentity: M3RepositoryIdentityDocument;
  readonly contract: ContractDocument;
  readonly routeMap: RouteMapDocument;
  readonly routeMapApproval: RouteMapApprovalDocument;
}

export interface M5AuthoritativeSources {
  readonly contract?: ContractDocument;
  readonly budget?: BudgetDocument;
  readonly m4ToolPolicy?: M4ScopedToolPolicyDocument;
  readonly m4CommandCatalog?: M4CommandCatalogDocument;
  readonly routeMap?: RouteMapDocument;
  readonly routeMapApproval?: RouteMapApprovalDocument;
  readonly m4CommandResults?: readonly M4CommandResultDocument[];
  readonly m3StateTokens?: readonly M3RepositoryStateTokenDocument[];
  readonly m3Postflights?: readonly M3PostflightDocument[];
  readonly workflowStates?: readonly WorkflowState[];
  readonly transitionEvents?: readonly TransitionEvent[];
  readonly transitionCommits?: readonly StateTransitionCommitDocument[];
  readonly planApprovals?: readonly PlanApprovalDocument[];
  readonly taskGraphs?: readonly TaskGraphDocument[];
  readonly tasks?: readonly TaskDocument[];
}

export interface EvaluateControlDecisionInput {
  readonly intent: ControlDecisionIntent;
  readonly expectedRevision: number;
  readonly expectedStatePointerContentSha256: Sha256Digest;
  readonly expectedWorkflowStateContentSha256: Sha256Digest;
  readonly transitionId?: string;
  readonly operationId?: string;
  readonly processMetadata?: ProcessMetadata;
  readonly authoritativeSources?: M5AuthoritativeSources;
  readonly usageEvidence?: readonly M5UsageEvidenceDocument[];
  readonly progressEvidence?: M5ProgressEvidenceInput;
  readonly failures?: readonly M5FailureInput[];
  readonly obligationEvidence?: readonly M5ObligationEvidenceInput[];
  readonly gateDetections?: readonly M5GateDetectionInput[];
  readonly availableLogicalRoles?: readonly LogicalModelRole[];
  readonly requiredLogicalRole?: LogicalModelRole;
  readonly blockReason?: string;
}

export interface ControlDecisionKernelOptions {
  readonly stateRoot: string;
  readonly runId: string;
  readonly policy: M5ControlPolicyDocument;
  readonly reducerPolicy: ReducerPolicy;
  readonly runAuthority?: M5ImmutableRunAuthoritySources;
  readonly authoritativeSources?: M5AuthoritativeSources;
  readonly production?: boolean;
}

export interface ControlDecisionResult {
  readonly decision: M5ControlDecisionDocument;
  readonly workflowState: WorkflowState;
  readonly committed: boolean;
  readonly reusedDecision: boolean;
}

export interface ControlDecisionInspection {
  readonly currentState: WorkflowState;
  readonly decisions: readonly M5ControlDecisionDocument[];
  readonly usageEvidence: readonly M5UsageEvidenceDocument[];
  readonly policyClassification: string;
}

export interface ControlDecisionKernel {
  evaluateControlDecision(input: EvaluateControlDecisionInput): Promise<ControlDecisionResult>;
  inspectControlDecision(): Promise<ControlDecisionInspection>;
}
