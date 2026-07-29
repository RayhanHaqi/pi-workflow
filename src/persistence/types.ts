import type { Sha256Digest } from "../identity/index.js";
import type {
  PersistedStatePointerDocument,
  ProcessMetadata,
  ReducerPolicy,
  StateTransitionCommitDocument,
  TransitionEvent,
  WorkflowState,
} from "../schemas/index.js";

export interface RunStorageLocation {
  readonly stateRoot: string;
  readonly runId: string;
}

export interface EvidenceInput {
  readonly bytes: Uint8Array;
  readonly mediaType: string;
}

export interface EvidenceReceipt {
  readonly evidenceSha256: Sha256Digest;
  readonly metadataContentSha256: Sha256Digest;
  readonly byteLength: number;
  readonly mediaType: string;
  readonly reusedEvidence: boolean;
  readonly reusedMetadata: boolean;
}

export interface InitializeRunStorageInput extends RunStorageLocation {
  readonly policy: ReducerPolicy;
  readonly initialState: WorkflowState;
  readonly processMetadata: ProcessMetadata;
}

export interface CommitTransitionInput extends RunStorageLocation {
  readonly expectedRevision: number;
  readonly expectedStatePointerContentSha256: Sha256Digest;
  readonly expectedWorkflowStateContentSha256: Sha256Digest;
  readonly expectedNextWorkflowStateContentSha256?: Sha256Digest;
  readonly transitionId: string;
  readonly policy: ReducerPolicy;
  readonly event: TransitionEvent;
  readonly evidence?: readonly EvidenceInput[];
  readonly processMetadata: ProcessMetadata;
}

export interface CommittedRunState {
  readonly statePointer: PersistedStatePointerDocument;
  readonly workflowState: WorkflowState;
  readonly transitionCommit: StateTransitionCommitDocument;
  readonly evidence: readonly EvidenceReceipt[];
}

export type StoredObjectKind =
  | "RAW_EVIDENCE"
  | "EVIDENCE_METADATA"
  | "EVIDENCE_MANIFEST"
  | "WORKFLOW_STATE"
  | "TRANSITION_EVENT"
  | "REDUCER_POLICY"
  | "PROCESS_ASSESSMENT"
  | "TRANSITION_COMMIT";

export interface InspectedObject {
  readonly kind: StoredObjectKind;
  readonly contentSha256: Sha256Digest;
  readonly relativePath: string;
}

export interface InspectionIssue {
  readonly code: string;
  readonly relativePath: string;
  readonly detail: string;
}

export type RunStorageInspectionStatus =
  | "HEALTHY"
  | "ORPHANED_UNCOMMITTED_EVIDENCE"
  | "BLOCKED_STATE_COMMIT_INCOMPLETE"
  | "BLOCKED_UNEXPECTED_STATE_STORE_ENTRY";

export interface RunStorageInspection {
  readonly status: RunStorageInspectionStatus;
  readonly runId: string;
  readonly revision: number | null;
  readonly statePointer: PersistedStatePointerDocument | null;
  readonly workflowState: WorkflowState | null;
  readonly transitionCommit: StateTransitionCommitDocument | null;
  readonly reachableObjects: readonly InspectedObject[];
  readonly orphanedObjects: readonly InspectedObject[];
  readonly temporaryFiles: readonly string[];
  readonly issues: readonly InspectionIssue[];
}

export interface ProcessInterruptionEvidence {
  readonly controller_instance_id: string;
  readonly process_id: number;
  readonly invocation_id: string;
  readonly exit_kind: "UNEXPECTED_TERMINATION";
  readonly detail: string;
}

export interface TerminalizeProcessCrashInput extends RunStorageLocation {
  readonly expectedRevision: number;
  readonly expectedStatePointerContentSha256: Sha256Digest;
  readonly expectedWorkflowStateContentSha256: Sha256Digest;
  readonly transitionId: string;
  readonly policy: ReducerPolicy;
  readonly processMetadata: ProcessMetadata;
  readonly interruptionEvidence: ProcessInterruptionEvidence;
}
