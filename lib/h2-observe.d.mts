import type { Buffer } from "node:buffer";

export interface H2Setting {
  readonly id: number;
  readonly name: string | null;
  readonly value: number;
  readonly wireIndex: number;
}

export type H2InitialResult =
  | { readonly status: "incomplete"; readonly needed: number | null }
  | { readonly status: "invalid"; readonly error: string }
  | {
      readonly status: "complete";
      readonly consumed: number;
      readonly settings: readonly H2Setting[];
      readonly settingsOrder: readonly number[];
      readonly effective: Readonly<Record<string, number>>;
      readonly payloadSha256: string;
    };

export const H2_CLIENT_PREFACE: Buffer;
export const H2_DEFAULT_MAX_FRAME_SIZE: number;
export function parseInitialH2Settings(input: Uint8Array | ArrayBuffer): H2InitialResult;
export class H2PrefaceObserver {
  constructor(maxBytes?: number);
  push(chunk: Uint8Array | ArrayBuffer): H2InitialResult;
}
export function analyzeH2RawHeaders(rawHeaders: readonly string[]):
  | { readonly status: "invalid"; readonly error: string }
  | {
      readonly status: "valid" | "invalid";
      readonly errors: readonly string[];
      readonly pseudoHeaderOrder: readonly string[];
      readonly headersTyped: readonly Array<{
        readonly name: string;
        readonly value: string;
        readonly wireIndex: number;
        readonly pseudo: boolean;
      }>;
    };
