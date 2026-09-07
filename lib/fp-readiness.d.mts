import type { NetworkSchemaStatus } from "./fp-schema.mjs";

export interface ControlEngineRequirement {
  readonly id: string;
  readonly version: string | RegExp;
}

export interface PersistedCaptureRecord {
  readonly context: string;
  readonly measurements: Record<string, unknown>;
  readonly identity: CaptureIdentity;
}

export interface CaptureIdentity {
  readonly environment: "plain" | "anti";
  readonly pairKey: string;
  readonly captureKey: string;
  readonly collectorBuild: string;
  /** SHA-256 of the exact collector JavaScript bytes executed by every realm. */
  readonly collectorArtifactSha256: string;
  /** Browser-echoed binding only; raw renderer process IDs stay server-side. */
  readonly oopif: OopifRecordBinding;
  readonly serviceWorkerChallenge: string;
}

export interface OopifRecordBinding {
  readonly parentOrigin: string;
  readonly childOrigin: string;
  /** Server-resolved registrable domains; never derived from browser claims. */
  readonly registrableParentSite: string;
  readonly registrableChildSite: string;
  /** @deprecated Not trusted for readiness; retained for source compatibility. */
  readonly parentSite?: string;
  /** @deprecated Not trusted for readiness; retained for source compatibility. */
  readonly childSite?: string;
  readonly configurationId: string;
  readonly processEvidenceSha256: string;
  readonly processEvidenceBuild: string;
}

/** Server-owned build/deployment evidence; never embedded in browser records. */
export interface OopifEvidence extends OopifRecordBinding {
  readonly processEvidence: OopifProcessEvidence;
}

export interface OopifProcessEvidence {
  readonly collectorBuild: string;
  readonly configurationId: string;
  readonly parentOrigin: string;
  readonly childOrigin: string;
  readonly registrableParentSite: string;
  readonly registrableChildSite: string;
  readonly parentProcessId: string;
  readonly childProcessId: string;
  readonly [key: string]: unknown;
}

export interface SideCaptureInput {
  readonly environment: "plain" | "anti";
  readonly pairKey: string;
  readonly captureKey: string;
  readonly collectorBuild: string;
  /** Server-owned SHA-256 returned with the immutable collector descriptor. */
  readonly collectorArtifactSha256: string;
  /** Server-owned build ID of the deployed direct TLS capture component. */
  readonly expectedNetworkBuild: string;
  readonly oopif: OopifEvidence;
  /** One-time server-owned challenge echoed and hashed by the SW response. */
  readonly serviceWorkerChallenge: string;
  readonly serverExpectedContexts: readonly string[];
  readonly records: readonly PersistedCaptureRecord[];
  readonly unreadableLines?: number;
  /** Durable, server-owned inventory for refs sealed into this capture. */
  readonly storedBlobLocators?: readonly string[];
  /** Preferred full sidecars; hashes and metadata are re-verified at readiness. */
  readonly storedBlobInventory?: readonly import("./fp-blob.mjs").FingerprintBlobSidecar[];
  readonly requiredControls?: readonly ControlEngineRequirement[];
}

export interface ReadinessIssue {
  readonly code: string;
  readonly blocking: boolean;
  readonly context?: string;
  readonly path?: string;
  readonly status?: string | NetworkSchemaStatus;
  readonly [key: string]: unknown;
}

export interface SideReadinessResult {
  readonly ready: boolean;
  readonly overall: "READY" | "NOT_READY";
  /**
   * The run finished and persisted: every server-expected context has a
   * record, the run-manifest is terminal for each of them and no line was
   * unreadable. Independent of `ready` — a typed getUserMedia failure
   * (`device-start-failure` / `aborted` / `not-supported`) is a complete
   * capture that is still NOT_READY.
   */
  readonly captureComplete: boolean;
  readonly expected: readonly string[];
  readonly present: readonly string[];
  readonly issues: readonly ReadinessIssue[];
}

export interface PairedReadinessResult {
  readonly ready: boolean;
  readonly overall: "READY" | "NOT_READY";
  /** Both sides' `captureComplete`. */
  readonly captureComplete: boolean;
  readonly plain: SideReadinessResult;
  readonly anti: SideReadinessResult;
  readonly issues: readonly ReadinessIssue[];
}

export const DEFAULT_CONTROL_ENGINES: readonly ControlEngineRequirement[];
export const DEFAULT_EXPECTED_CONTEXTS: readonly string[];
export const DEFAULT_COLLECTOR_JOBS: readonly string[];
export interface RequiredJobEvidenceAlternative {
  readonly path: string;
  readonly statuses: readonly string[];
}
export const DEFAULT_REQUIRED_JOB_EVIDENCE: Readonly<Record<string, readonly RequiredJobEvidenceAlternative[]>>;
/** Build-owned fixed leaf sets; browser-provided manifests cannot weaken them. */
export const DEFAULT_REQUIRED_PATH_CONTRACT: Readonly<Record<string, readonly string[]>>;
export function validateSideCapture(input: SideCaptureInput): SideReadinessResult;
export function validatePairedCapture(input: {
  readonly plain: SideCaptureInput;
  readonly anti: SideCaptureInput;
}): PairedReadinessResult;
