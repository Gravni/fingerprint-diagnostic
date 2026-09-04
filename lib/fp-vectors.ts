// Anti-detect vectors and their per-vector modes, mirroring Linken Sphere, plus
// hardware presets. Pure data (no fs/db) so BOTH the client form and the server
// verdict logic import it without pulling Node built-ins into the browser bundle.

export type Vector =
  | "canvas" | "webgl" | "clientRects" | "audio"
  | "webgpu" | "mediaDevices" | "fonts" | "timezone" | "geolocation";

export interface VecOption { value: string; label: string }

/** Options per vector, matching what Sphere actually offers. The FIRST option
 *  of each is the pass-through / no-protection default. */
export const VECTOR_OPTIONS: Record<Vector, VecOption[]> = {
  canvas:       [{ value: "direct", label: "Direct" }, { value: "noise", label: "Шум" }],
  webgl:        [{ value: "direct", label: "Direct" }, { value: "noise", label: "Шум" }],
  clientRects:  [{ value: "direct", label: "Direct" }, { value: "noise", label: "Шум" }],
  audio:        [{ value: "direct", label: "Direct" }, { value: "noise", label: "Шум" }],
  webgpu:       [{ value: "direct", label: "Direct" }, { value: "fake", label: "Fake" }],
  mediaDevices: [{ value: "direct", label: "Direct" }, { value: "fake", label: "Fake" }],
  fonts:        [{ value: "real", label: "Real" }, { value: "masked", label: "Маскировка" }],
  timezone:     [{ value: "off", label: "Выкл" }, { value: "auto", label: "Авто по IP" }, { value: "manual", label: "Вручную" }],
  geolocation:  [{ value: "off", label: "Выкл" }, { value: "auto", label: "Авто по IP" }, { value: "manual", label: "Вручную" }, { value: "prompt", label: "Запрос" }],
};

export const VECTORS: { id: Vector; label: string }[] = [
  { id: "canvas",       label: "Canvas" },
  { id: "webgl",        label: "WebGL" },
  { id: "clientRects",  label: "ClientRects" },
  { id: "audio",        label: "Audio" },
  { id: "webgpu",       label: "WebGPU" },
  { id: "mediaDevices", label: "MediaDevices" },
  { id: "fonts",        label: "Шрифты" },
  { id: "timezone",     label: "Таймзона" },
  { id: "geolocation",  label: "Геолокация" },
];

/** Default (pass-through) mode for a vector = its first option. */
export function defaultMode(v: Vector): string { return VECTOR_OPTIONS[v][0].value; }

/** Is a value one of a vector's valid modes? */
export function isValidMode(v: Vector, mode: string): boolean {
  return VECTOR_OPTIONS[v].some((o) => o.value === mode);
}

/** Human label for a stored mode value. */
export function modeLabel(v: Vector, mode: string): string {
  return VECTOR_OPTIONS[v].find((o) => o.value === mode)?.label ?? mode;
}

// Modes that mean "no protection / pass real value through". Anything else means
// the vector was actively spoofed, so an identical value is a real leak.
const NOT_PROTECTED = new Set(["", "direct", "off", "real"]);
export function isProtected(mode: string | undefined | null): boolean {
  return !!mode && !NOT_PROTECTED.has(mode);
}

// Per-vector EXPECTATION registry (Codex v4.2 #16) lives in the importable
// fp-expect.mjs (single source, so the unit test runs the exact regexes). A path
// earns leaked/masked ONLY if it is an expected target of a spoofed vector.
export { EXPECT_TARGETS, EXCLUDE_META, isExpectedTarget, vectorForPath, classifyPath } from "./fp-expect.mjs";

/** Editable-dropdown suggestions for the hardware fields (type-your-own too).
 *  Kept broad, Sphere-style; the field still accepts anything typed by hand. */
export const HW_PRESETS: Record<"os" | "resolution" | "cores" | "memory", string[]> = {
  os: [
    "Windows 11", "Windows 10", "Windows 8.1", "Windows 7",
    "macOS 26 (Tahoe)", "macOS 15 (Sequoia)", "macOS 14 (Sonoma)", "macOS 13 (Ventura)",
    "macOS 12 (Monterey)", "macOS 11 (Big Sur)", "macOS 10.15 (Catalina)",
    "Linux", "Ubuntu", "Fedora", "Debian", "ChromeOS",
    "Android 16", "Android 15", "Android 14", "Android 13",
    "iOS 26", "iOS 18", "iOS 17", "iPadOS 26",
  ],
  resolution: [
    "1920×1080", "1366×768", "1536×864", "1280×720", "1600×900", "1440×900", "1680×1050",
    "1920×1200", "2560×1440", "2560×1600", "3440×1440", "3840×2160", "1280×800", "1024×768",
    "1728×1117", "1512×982", "1470×956", "1710×1112", "1512×944",
    "2880×1800", "3024×1964", "3456×2234",
    "390×844", "393×852", "430×932", "414×896", "360×800", "412×915",
  ],
  cores: ["2", "4", "6", "8", "10", "12", "14", "16", "20", "24", "32"],
  memory: ["2", "4", "6", "8", "12", "16", "24", "32", "48", "64", "128"],
};
