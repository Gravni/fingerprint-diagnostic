import type { Vector } from "./fp-vectors";
export declare const EXPECT_TARGETS: Record<Vector, RegExp>;
export declare const EXCLUDE_META: Record<Vector, RegExp>;
export declare function isExpectedTarget(path: string, vector: Vector, mode?: string): boolean;
export declare function vectorForPath(path: string): Vector | null;
export declare function classifyPath(path: string): string;
