// Compile-only consumer contract. This catches drift between the runtime .mjs
// readiness API and the declaration file used by the private TypeScript panel.
import {
  DEFAULT_COLLECTOR_JOBS,
  DEFAULT_EXPECTED_CONTEXTS,
  validatePairedCapture,
  validateSideCapture,
  type PersistedCaptureRecord,
  type CaptureIdentity,
  type OopifEvidence,
  type SideCaptureInput,
} from "../lib/fp-readiness.mjs";
import {
  auditStoredBlobReferences,
  blobLocatorForAddress,
  verifyAndSealBlobSidecars,
} from "../lib/fp-blob.mjs";

const oopifBinding = {
  parentOrigin: "https://panel.example.test",
  childOrigin: "https://probe.other.test",
  registrableParentSite: "example.test",
  registrableChildSite: "other.test",
  configurationId: "oopif-1",
  processEvidenceSha256: "b".repeat(64),
  processEvidenceBuild: "a".repeat(64),
};
const identity: CaptureIdentity = {
  environment: "plain" as const,
  pairKey: "pair-1",
  captureKey: "pair-1:plain",
  collectorBuild: "a".repeat(64),
  collectorArtifactSha256: "c".repeat(64),
  serviceWorkerChallenge: "S".repeat(22),
  oopif: oopifBinding,
};
const oopifEvidence: OopifEvidence = {
    ...oopifBinding,
    processEvidence: {
      collectorBuild: "a".repeat(64),
      configurationId: "oopif-1",
      parentOrigin: "https://panel.example.test",
      childOrigin: "https://probe.other.test",
      registrableParentSite: "example.test",
      registrableChildSite: "other.test",
      parentProcessId: "browser-1",
      childProcessId: "renderer-2",
    },
};
const record: PersistedCaptureRecord = {
  context: "main-frame",
  measurements: {},
  identity,
};
const side: SideCaptureInput = {
  ...identity,
  expectedNetworkBuild: "d".repeat(64),
  serverExpectedContexts: DEFAULT_EXPECTED_CONTEXTS,
  records: [record],
  unreadableLines: 0,
  oopif: oopifEvidence,
  storedBlobLocators: [],
};

const one = validateSideCapture(side);
const pair = validatePairedCapture({
  plain: side,
  anti: {
    ...side,
    environment: "anti",
    captureKey: "pair-1:anti",
  },
});

void one.issues;
void pair.issues;
void DEFAULT_COLLECTOR_JOBS;
void blobLocatorForAddress("a".repeat(64));
void auditStoredBlobReferences({}, []);
void verifyAndSealBlobSidecars({}, []);
