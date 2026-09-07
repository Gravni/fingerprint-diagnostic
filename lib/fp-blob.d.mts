export const FP_BLOB_ADDRESS_VERSION: "fp-blob-address-v1";
export const FP_BLOB_LOCATOR_PREFIX: "fpblob:v1:";

export interface BlobReferenceIssue {
  readonly code: string;
  readonly path?: string;
  readonly locator?: unknown;
  readonly count?: number;
}

export interface FingerprintBlobSidecar {
  readonly kind: string;
  readonly length: number;
  readonly lengthUnit: string;
  readonly sha256: string;
  readonly fnv: string;
  readonly addressSha256: string;
  readonly addressFnv: string;
  readonly reason: string;
  readonly encoding: string;
  readonly addressVersion: "fp-blob-address-v1";
  readonly complete: true;
  readonly hashScope: "content";
  readonly locator: string;
  readonly payload: string;
}

export function blobLocatorForAddress(addressSha256: string): string;
export function isBlobLocatorForAddress(locator: unknown, addressSha256: unknown): boolean;
export function verifyAndSealBlobSidecars(measurements: unknown, sidecars: unknown): {
  readonly ok: boolean;
  readonly measurements: unknown | null;
  readonly blobs: readonly FingerprintBlobSidecar[];
  readonly issues: readonly BlobReferenceIssue[];
};
export function auditStoredBlobReferences(measurements: unknown, storedBlobInventory?: unknown): {
  readonly ok: boolean;
  readonly issues: readonly BlobReferenceIssue[];
  readonly referencedLocators: readonly string[];
};
