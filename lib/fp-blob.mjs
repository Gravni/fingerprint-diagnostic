// Pure, framework-independent blob sidecar verification. Browser records carry
// content-addressed refs with `stored:false`; only a server that verifies the
// exact sidecar and persists it may seal a cloned record as `stored:true`.

import { fnv1a, sha256hex } from "./fp-encode.mjs";

export const FP_BLOB_ADDRESS_VERSION = "fp-blob-address-v1";
export const FP_BLOB_LOCATOR_PREFIX = "fpblob:v1:";
const HEX64 = /^[0-9a-f]{64}$/;
const HEX8 = /^[0-9a-f]{8}$/;
const MAX_SCAN_NODES = 50_000;
const MAX_SIDECARS = 512;
const MAX_PAYLOAD_UNITS = 1_048_576;

export function blobLocatorForAddress(addressSha256) {
  if (typeof addressSha256 !== "string" || !HEX64.test(addressSha256)) {
    throw new TypeError("addressSha256 must be 64 lowercase hex characters");
  }
  return FP_BLOB_LOCATOR_PREFIX + addressSha256;
}

export function isBlobLocatorForAddress(locator, addressSha256) {
  return typeof locator === "string" && HEX64.test(addressSha256 || "")
    && locator === FP_BLOB_LOCATOR_PREFIX + addressSha256;
}

function looksLikeBlobRef(value) {
  return !!(value && typeof value === "object" && !Array.isArray(value)
    && Object.prototype.hasOwnProperty.call(value, "kind")
    && Object.prototype.hasOwnProperty.call(value, "length")
    && Object.prototype.hasOwnProperty.call(value, "sha256")
    && Object.prototype.hasOwnProperty.call(value, "complete")
    && Object.prototype.hasOwnProperty.call(value, "hashScope")
    && Object.prototype.hasOwnProperty.call(value, "stored"));
}

function scanBlobRefs(root) {
  const refs = [];
  const stack = [{ value: root, path: "$" }];
  const seen = new WeakSet();
  let nodes = 0;
  while (stack.length) {
    const { value, path } = stack.pop();
    if (!value || typeof value !== "object") continue;
    if (seen.has(value)) continue;
    seen.add(value);
    if (++nodes > MAX_SCAN_NODES) return { refs, issue: { code: "blob-scan-limit", path } };
    if (!Array.isArray(value) && Object.prototype.hasOwnProperty.call(value, "__blobRef")
        && looksLikeBlobRef(value.__blobRef)) {
      refs.push({ ref: value.__blobRef, path: path + ".__blobRef" });
      continue;
    }
    // Error name/message/stack refs and function signature refs are deliberately
    // stored bare beside their bounded display value. Recognise the contract,
    // not merely a property name, so an observed ordinary key called
    // `__blobRef` cannot become a false marker.
    if (looksLikeBlobRef(value)) {
      refs.push({ ref: value, path });
      continue;
    }
    if (Array.isArray(value)) {
      for (let index = value.length - 1; index >= 0; index--) {
        stack.push({ value: value[index], path: `${path}[${index}]` });
      }
    } else {
      const keys = Object.keys(value);
      for (let index = keys.length - 1; index >= 0; index--) {
        const key = keys[index];
        stack.push({ value: value[key], path: `${path}.${key}` });
      }
    }
  }
  return { refs, issue: null };
}

function completeRefContract(ref, expectedStored) {
  return !!(ref && typeof ref === "object" && !Array.isArray(ref)
    && ref.complete === true && ref.hashScope === "content" && ref.stored === expectedStored
    && ref.addressVersion === FP_BLOB_ADDRESS_VERSION
    && typeof ref.kind === "string" && ref.kind.length > 0
    && Number.isInteger(ref.length) && ref.length >= 0
    && typeof ref.lengthUnit === "string" && ref.lengthUnit.length > 0
    && typeof ref.reason === "string" && ref.reason.length > 0
    && typeof ref.encoding === "string" && ref.encoding.length > 0
    && typeof ref.sha256 === "string" && HEX64.test(ref.sha256)
    && typeof ref.fnv === "string" && HEX8.test(ref.fnv)
    && typeof ref.addressSha256 === "string" && HEX64.test(ref.addressSha256)
    && typeof ref.addressFnv === "string" && HEX8.test(ref.addressFnv)
    && isBlobLocatorForAddress(ref.locator, ref.addressSha256));
}

function sidecarContract(blob) {
  return !!(blob && typeof blob === "object" && !Array.isArray(blob)
    && blob.complete === true && blob.hashScope === "content"
    && blob.addressVersion === FP_BLOB_ADDRESS_VERSION
    && typeof blob.payload === "string" && blob.payload.length <= MAX_PAYLOAD_UNITS
    && typeof blob.kind === "string" && blob.kind.length > 0
    && Number.isInteger(blob.length) && blob.length >= 0
    && typeof blob.lengthUnit === "string" && blob.lengthUnit.length > 0
    && typeof blob.reason === "string" && blob.reason.length > 0
    && typeof blob.encoding === "string" && blob.encoding.length > 0
    && typeof blob.sha256 === "string" && HEX64.test(blob.sha256)
    && typeof blob.fnv === "string" && HEX8.test(blob.fnv)
    && typeof blob.addressSha256 === "string" && HEX64.test(blob.addressSha256)
    && typeof blob.addressFnv === "string" && HEX8.test(blob.addressFnv)
    && isBlobLocatorForAddress(blob.locator, blob.addressSha256));
}

function sameBlobMetadata(ref, blob) {
  return ["kind", "length", "lengthUnit", "sha256", "fnv", "addressSha256",
    "addressFnv", "reason", "encoding", "addressVersion", "complete", "hashScope",
    "locator"].every((key) => ref[key] === blob[key]);
}

function computedBlobMetadata(blob) {
  const addressPayload = FP_BLOB_ADDRESS_VERSION + "\u0000" + blob.encoding + "\u0000" + blob.payload;
  return {
    sha256: sha256hex(blob.payload),
    fnv: fnv1a(blob.payload),
    addressSha256: sha256hex(addressPayload),
    addressFnv: fnv1a(addressPayload),
  };
}

function payloadLengthMatches(blob) {
  if (blob.lengthUnit === "utf16-code-units"
      || blob.lengthUnit === "encoded-json-utf16-code-units") {
    return blob.length === blob.payload.length;
  }
  if (blob.encoding === "fp-canonical-v1" && blob.kind === "array" && blob.lengthUnit === "elements") {
    const match = /^array#0:(\d+)\[/.exec(blob.payload);
    return !!match && Number(match[1]) === blob.length;
  }
  return true;
}

function uniqueIssues(issues) {
  const seen = new Set();
  return issues.filter((entry) => {
    const key = JSON.stringify(entry);
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

/**
 * Verify one browser envelope's sidecars, then return a cloned measurement tree
 * whose verified complete refs are sealed as stored. Persistence itself remains
 * the caller's responsibility and must be atomic with storing this clone.
 */
export function verifyAndSealBlobSidecars(measurements, sidecars) {
  const issues = [];
  const scanned = scanBlobRefs(measurements);
  if (scanned.issue) issues.push(scanned.issue);
  const blobs = Array.isArray(sidecars) ? sidecars : [];
  if (!Array.isArray(sidecars)) issues.push({ code: "blob-sidecars-invalid" });
  if (blobs.length > MAX_SIDECARS) issues.push({ code: "blob-sidecars-limit", count: blobs.length });

  const byLocator = new Map();
  for (const blob of blobs.slice(0, MAX_SIDECARS + 1)) {
    if (!sidecarContract(blob)) {
      issues.push({ code: "blob-sidecar-invalid", locator: blob?.locator ?? null });
      continue;
    }
    if (byLocator.has(blob.locator)) {
      issues.push({ code: "blob-sidecar-duplicate", locator: blob.locator });
      continue;
    }
    const computed = computedBlobMetadata(blob);
    if (computed.sha256 !== blob.sha256 || computed.fnv !== blob.fnv
        || computed.addressSha256 !== blob.addressSha256 || computed.addressFnv !== blob.addressFnv) {
      issues.push({ code: "blob-sidecar-hash-mismatch", locator: blob.locator });
      continue;
    }
    if (!payloadLengthMatches(blob)) {
      issues.push({ code: "blob-sidecar-length-mismatch", locator: blob.locator });
      continue;
    }
    byLocator.set(blob.locator, blob);
  }

  const referenced = new Set();
  for (const { ref, path } of scanned.refs) {
    if (!ref || typeof ref !== "object" || ref.complete !== true || ref.hashScope !== "content") continue;
    if (ref.stored !== false) {
      issues.push({ code: "blob-client-stored-claim", path, locator: ref.locator ?? null });
      continue;
    }
    if (!completeRefContract(ref, false)) {
      issues.push({ code: "blob-ref-contract-invalid", path, locator: ref.locator ?? null });
      continue;
    }
    referenced.add(ref.locator);
    const blob = byLocator.get(ref.locator);
    if (!blob) issues.push({ code: "blob-sidecar-missing", path, locator: ref.locator });
    else if (!sameBlobMetadata(ref, blob)) {
      issues.push({ code: "blob-sidecar-metadata-mismatch", path, locator: ref.locator });
    }
  }
  for (const locator of byLocator.keys()) {
    if (!referenced.has(locator)) issues.push({ code: "blob-sidecar-extra", locator });
  }

  const finalIssues = uniqueIssues(issues);
  if (finalIssues.length) return { ok: false, measurements: null, blobs: [], issues: finalIssues };

  const sealed = structuredClone(measurements);
  const sealedScan = scanBlobRefs(sealed);
  for (const { ref } of sealedScan.refs) {
    if (ref && ref.complete === true && ref.hashScope === "content") ref.stored = true;
  }
  return {
    ok: true,
    measurements: sealed,
    blobs: [...byLocator.values()].map((blob) => ({ ...blob })),
    issues: [],
  };
}

/** Grade already-persisted refs against the durable blob inventory. Inventory
 * entries may be trusted locator strings (legacy adapter) or full persisted
 * sidecars. Full sidecars are re-hashed and metadata-matched on every audit. */
export function auditStoredBlobReferences(measurements, storedBlobInventory = []) {
  const issues = [];
  const inventory = new Map();
  if (!Array.isArray(storedBlobInventory)) {
    issues.push({ code: "blob-inventory-invalid" });
  } else {
    for (const entry of storedBlobInventory) {
      if (typeof entry === "string") {
        if (!entry.startsWith(FP_BLOB_LOCATOR_PREFIX)
            || !HEX64.test(entry.slice(FP_BLOB_LOCATOR_PREFIX.length))) {
          issues.push({ code: "blob-inventory-invalid", locator: entry });
        } else inventory.set(entry, null);
        continue;
      }
      if (!sidecarContract(entry)) {
        issues.push({ code: "blob-inventory-invalid", locator: entry?.locator ?? null });
        continue;
      }
      const computed = computedBlobMetadata(entry);
      if (computed.sha256 !== entry.sha256 || computed.fnv !== entry.fnv
          || computed.addressSha256 !== entry.addressSha256 || computed.addressFnv !== entry.addressFnv) {
        issues.push({ code: "blob-payload-hash-mismatch", locator: entry.locator });
        continue;
      }
      if (!payloadLengthMatches(entry)) {
        issues.push({ code: "blob-payload-length-mismatch", locator: entry.locator });
        continue;
      }
      const prior = inventory.get(entry.locator);
      if (prior && JSON.stringify(prior) !== JSON.stringify(entry)) {
        issues.push({ code: "blob-inventory-conflict", locator: entry.locator });
        continue;
      }
      inventory.set(entry.locator, entry);
    }
  }
  const scanned = scanBlobRefs(measurements);
  if (scanned.issue) issues.push(scanned.issue);
  const referenced = new Set();
  for (const { ref, path } of scanned.refs) {
    if (ref && ref.stored === false && completeRefContract(ref, false)) {
      issues.push({ code: "blob-ref-unsealed", path, locator: ref.locator });
      continue;
    }
    if (!completeRefContract(ref, true)) {
      issues.push({ code: "blob-ref-incomplete", path });
      continue;
    }
    referenced.add(ref.locator);
    if (!inventory.has(ref.locator)) {
      issues.push({ code: "blob-payload-missing", path, locator: ref.locator });
      continue;
    }
    const blob = inventory.get(ref.locator);
    if (blob && !sameBlobMetadata(ref, blob)) {
      issues.push({ code: "blob-persisted-metadata-mismatch", path, locator: ref.locator });
    }
  }
  for (const [locator, blob] of inventory) {
    if (blob && !referenced.has(locator)) issues.push({ code: "blob-payload-extra", locator });
  }
  const finalIssues = uniqueIssues(issues);
  return { ok: finalIssues.length === 0, issues: finalIssues,
    referencedLocators: [...referenced].sort() };
}
