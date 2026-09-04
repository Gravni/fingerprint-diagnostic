// Public declarations for the pure schema module used by a TypeScript server.
export type BrowserSchemaStatus = "CURRENT" | "MIXED" | "LEGACY_LOSSY" | "INVALID";
export type NetworkSchemaStatus = "CURRENT" | "PARTIAL" | "MISSING" | "LEGACY" | "INVALID";
export const STATUS_ENUM: readonly string[];
export const VALUETYPE_ENUM: readonly string[];
export const NET_REQUIRED: readonly string[];
export function validateMeasurement(rec: unknown): string[];
export function classifySessionSchema(session: unknown): BrowserSchemaStatus;
export function classifyNetworkSchema(measurements: unknown): NetworkSchemaStatus;
export function nonOkAllowed(path: string, context: string, status: string): boolean;
export function scanUnexpected(session: unknown, context?: string): Array<{
  path?: string;
  status: string;
  recordContext?: string;
}>;
export function findDuplicatePaths(session: unknown): Array<{
  context: string;
  path: string;
  count: number;
}>;
