// Ambient types for the pure schema module (lib/fp-schema.mjs), so the Next
// server (TS) can import it. Kept in sync with the .mjs by scripts/fp-schema.test.mjs.
export const STATUS_ENUM: string[];
export const VALUETYPE_ENUM: string[];
export function validateMeasurement(rec: unknown): string[];
export function classifySessionSchema(session: unknown): "CURRENT" | "MIXED" | "LEGACY_LOSSY" | "INVALID";
