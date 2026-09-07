import { encodeValue } from "../lib/fp-encode.mjs";

let pass = 0, fail = 0;
function ok(label, cond) { if (cond) pass++; else { fail++; console.log("  \u2717 " + label); } }

let blobApi = null;
try { blobApi = await import("../lib/fp-blob.mjs"); } catch (_) {}
ok("blob verification module is part of the public core", !!blobApi);

if (blobApi) {
  const {
    auditStoredBlobReferences,
    blobLocatorForAddress,
    verifyAndSealBlobSidecars,
  } = blobApi;
  const payload = "fingerprint-payload:\ud83e\uddea".repeat(1000);
  const sidecars = [];
  const encoded = encodeValue(payload, { blobSink(blob) {
    const locator = blobLocatorForAddress(blob.addressSha256);
    sidecars.push({ ...blob, locator });
    return { locator, stored: false };
  } });
  const measurements = { _schema: "typed-v4", _measurements: [{
    path: "diagnostic.large", context: "main-frame", phase: "passive", status: "ok",
    valueType: encoded.valueType, value: encoded.value, error: null, meta: {},
  }] };
  const ref = encoded.value.__blobRef;

  ok("20KB+ client ref is addressed but never claims server persistence",
    payload.length > 20_000 && ref.complete === true && ref.stored === false
      && ref.locator === `fpblob:v1:${ref.addressSha256}` && sidecars[0]?.payload === payload);

  const verified = verifyAndSealBlobSidecars(measurements, sidecars);
  const sealedRef = verified.measurements?._measurements?.[0]?.value?.__blobRef;
  ok("exact sidecar verifies and produces a non-mutating sealed measurement clone",
    verified.ok === true && sealedRef?.stored === true && ref.stored === false
      && verified.blobs?.[0]?.payload === payload);
  ok("stored inventory audit accepts only the sealed exact locator",
    auditStoredBlobReferences(verified.measurements, [ref.locator]).ok === true);
  ok("stored inventory audit re-hashes a full durable sidecar",
    auditStoredBlobReferences(verified.measurements, verified.blobs).ok === true);
  const corruptedStored = structuredClone(verified.blobs); corruptedStored[0].payload += "corrupt";
  ok("stored inventory audit detects payload corruption, not only locator presence",
    auditStoredBlobReferences(verified.measurements, corruptedStored).issues
      .some((x) => x.code === "blob-payload-hash-mismatch"));

  const tampered = structuredClone(sidecars);
  tampered[0].payload += "tamper";
  ok("payload tampering is rejected before sealing",
    verifyAndSealBlobSidecars(measurements, tampered).issues.some((x) => x.code === "blob-sidecar-hash-mismatch"));
  const forgedLengthSidecars = structuredClone(sidecars);
  const forgedLengthMeasurements = structuredClone(measurements);
  forgedLengthSidecars[0].length = 1;
  forgedLengthMeasurements._measurements[0].value.__blobRef.length = 1;
  ok("matching forged ref+sidecar length is rejected against the exact payload",
    verifyAndSealBlobSidecars(forgedLengthMeasurements, forgedLengthSidecars).issues
      .some((x) => x.code === "blob-sidecar-length-mismatch"));
  ok("a missing sidecar is rejected before sealing",
    verifyAndSealBlobSidecars(measurements, []).issues.some((x) => x.code === "blob-sidecar-missing"));
  ok("an unreferenced sidecar is rejected rather than silently retained",
    verifyAndSealBlobSidecars({ _measurements: [] }, sidecars).issues.some((x) => x.code === "blob-sidecar-extra"));

  const forgedStored = structuredClone(measurements);
  forgedStored._measurements[0].value.__blobRef.stored = true;
  ok("a browser cannot self-assert stored:true",
    verifyAndSealBlobSidecars(forgedStored, sidecars).issues.some((x) => x.code === "blob-client-stored-claim"));
  ok("readiness audit rejects a sealed reference absent from durable inventory",
    auditStoredBlobReferences(verified.measurements, []).issues.some((x) => x.code === "blob-payload-missing"));
  ok("readiness audit rejects an unsealed browser reference even if inventory contains its locator",
    auditStoredBlobReferences(measurements, [ref.locator]).issues.some((x) => x.code === "blob-ref-unsealed"));

  const errorSidecars = [];
  const longError = new Error("e".repeat(20_000));
  const encodedError = encodeValue(longError, { blobSink(blob) {
    const locator = blobLocatorForAddress(blob.addressSha256);
    errorSidecars.push({ ...blob, locator }); return { locator, stored: false };
  } });
  const errorMeasurements = { _measurements: [{ valueType: encodedError.valueType,
    value: encodedError.value, meta: {} }] };
  ok("nested bare refs from long Error fields are discovered and sealed",
    errorSidecars.length > 0 && verifyAndSealBlobSidecars(errorMeasurements, errorSidecars).ok === true);

  const fnSidecars = [];
  const longNamedFunction = function () {};
  Object.defineProperty(longNamedFunction, "name", { value: "f".repeat(20_000) });
  const encodedFunction = encodeValue(longNamedFunction, { blobSink(blob) {
    const locator = blobLocatorForAddress(blob.addressSha256);
    fnSidecars.push({ ...blob, locator }); return { locator, stored: false };
  } });
  const fnMeasurements = { _measurements: [{ valueType: encodedFunction.valueType,
    value: encodedFunction.value, meta: { signatureRef: encodedFunction.signatureRef } }] };
  ok("bare signatureRef is discovered and sealed",
    fnSidecars.length === 1 && verifyAndSealBlobSidecars(fnMeasurements, fnSidecars).ok === true);

  const ordinary = encodeValue({ __blobRef: "ordinary observed property", keep: 1 });
  ok("an ordinary observed key named __blobRef is not misclassified as a marker",
    verifyAndSealBlobSidecars({ _measurements: [{ valueType: ordinary.valueType, value: ordinary.value }] }, []).ok === true);
}

console.log(`\nfp-blob: ${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
