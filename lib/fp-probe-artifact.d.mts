export interface RenderedFingerprintProbe {
  readonly html: string;
  readonly artifactSha256: string;
  readonly collectorSource: string;
  readonly collectorArtifactSha256: string;
  readonly browserCollectorBuild: string;
}

export function renderFingerprintProbe(input: {
  readonly template: string;
  readonly encoderSource: string;
  readonly browserCollectorBuild: string;
}): RenderedFingerprintProbe;

export interface BoundChildBinding {
  readonly protocol: "fingerprint-bound-child";
  readonly handshakeVersion: 1;
  readonly context: "iframe-url" | "cross-origin-iframe";
  readonly collectorBuild: string;
  readonly collectorArtifactSha256: string;
  readonly captureKey: string;
  readonly requestId: string;
  readonly parentOrigin: string;
  readonly acknowledgementSha256: string;
}

export interface RenderedBoundChildProbe {
  readonly html: string;
  readonly artifactSha256: string;
  readonly collectorArtifactSha256: string;
  readonly browserCollectorBuild: string;
  readonly captureKey: string;
  readonly requestId: string;
  readonly context: "iframe-url" | "cross-origin-iframe";
  readonly parentOrigin: string;
  readonly acknowledgementSha256: string;
  readonly binding: BoundChildBinding;
}

export function renderBoundChildProbe(input: {
  readonly collectorSource: string;
  readonly browserCollectorBuild: string;
  readonly collectorArtifactSha256: string;
  readonly captureKey: string;
  readonly requestId: string;
  readonly context: "iframe-url" | "cross-origin-iframe";
  readonly parentOrigin: string;
}): RenderedBoundChildProbe;

export interface RenderedServiceWorkerProbe {
  readonly source: string;
  readonly artifactSha256: string;
  readonly collectorArtifactSha256: string;
  readonly browserCollectorBuild: string;
  readonly captureKey: string;
  readonly challenge: string;
  readonly acknowledgementSha256: string;
}

export function renderServiceWorkerProbe(input: {
  readonly collectorSource: string;
  readonly browserCollectorBuild: string;
  readonly collectorArtifactSha256: string;
  readonly captureKey: string;
  readonly challenge: string;
}): RenderedServiceWorkerProbe;
