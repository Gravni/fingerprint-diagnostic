// Framework-independent readiness gate for a single browser-fingerprint side
// and for a paired plain/anti capture. The server, UI and exporter should all
// call this module instead of inventing their own weaker notion of "complete".

import {
  classifyNetworkSchema,
  classifySessionSchema,
  findDuplicatePaths,
  scanUnexpected,
} from "./fp-schema.mjs";
import { sha256hex } from "./fp-encode.mjs";

export const DEFAULT_CONTROL_ENGINES = Object.freeze([
  { id: "thumbmark", version: /^1\.11\./ },
  { id: "fingerprintjs", version: /^5\./ },
  { id: "fpscanner", version: /^0\.1\.5(?:\b|$)/ },
  { id: "clientjs", version: /^0\.2\./ },
]);

function sameControlRequirement(actual, expected) {
  if (!actual || actual.id !== expected.id) return false;
  if (actual.version instanceof RegExp && expected.version instanceof RegExp) {
    return actual.version.source === expected.version.source && actual.version.flags === expected.version.flags;
  }
  return actual.version === expected.version;
}

function isCanonicalControlMatrix(value) {
  return Array.isArray(value) && value.length === DEFAULT_CONTROL_ENGINES.length
    && value.every((entry, index) => sameControlRequirement(entry, DEFAULT_CONTROL_ENGINES[index]));
}

export const DEFAULT_EXPECTED_CONTEXTS = Object.freeze([
  "main-frame", "dedicated-worker", "dedicated-worker-module",
  "shared-worker", "shared-worker-module", "audio-worklet", "iframe",
  "iframe-url", "sandboxed-iframe", "credentialless-iframe",
  "service-worker", "cross-origin-iframe", "network", "permissioned",
]);
export const DEFAULT_COLLECTOR_JOBS = Object.freeze([
  "locale", "canvas", "webgl", "webgpu", "audio", "fonts", "css",
  "math", "codecs", "speech", "webrtc", "misc", "uach", "hooks",
  "cssSupports", "mediaDevices", "keyboard", "storage", "env",
  "clientRects", "wasm", "mediaCaps", "device", "intlx", "errors",
  "control",
]);

// Server-owned evidence for every non-control collector job. A browser manifest
// can name a job as completed, but READY requires at least one typed terminal
// output that the reviewed collector actually emits for that job. Alternative
// paths cover capability-unavailable branches without accepting arbitrary rows.
const output = (path) => Object.freeze({ path, statuses: Object.freeze(["ok"]) });
const fallback = (path, ...statuses) => Object.freeze({ path, statuses: Object.freeze(statuses) });
const jobEvidence = (...entries) => Object.freeze(entries);

export const DEFAULT_REQUIRED_JOB_EVIDENCE = Object.freeze({
  locale: jobEvidence(output("locale.resolvedTZ")),
  canvas: jobEvidence(output("canvas.pixelSha256"), fallback("canvas.status", "unsupported", "unavailable-in-context")),
  webgl: jobEvidence(output("webgl.webgl.status"), fallback("webgl.webgl.status", "unsupported", "unavailable-in-context")),
  webgpu: jobEvidence(output("webgpu.status"), fallback("webgpu.available", "unsupported"), fallback("webgpu.status", "unavailable-in-context", "blocked")),
  audio: jobEvidence(output("audio.status"), fallback("audio.available", "unsupported", "unavailable-in-context")),
  fonts: jobEvidence(output("fonts.hash"), fallback("fonts.available", "unavailable-in-context")),
  css: jobEvidence(output("css.deviceAspect"), fallback("css.available", "unavailable-in-context")),
  math: jobEvidence(output("math.powPI")),
  codecs: jobEvidence(
    output('codecs.canPlay[video/mp4; codecs="avc1.42E01E"]'),
    fallback('codecs.canPlay[video/mp4; codecs="avc1.42E01E"]', "unavailable-in-context"),
  ),
  speech: jobEvidence(output("speech.count"), fallback("speech.available", "unsupported", "unavailable-in-context")),
  webrtc: jobEvidence(output("webrtc.offerStable"), fallback("webrtc.status", "unsupported", "unavailable-in-context", "blocked")),
  misc: jobEvidence(output("misc.webdriver")),
  uach: jobEvidence(output("uach.mobile"), fallback("uach.available", "unsupported", "unavailable-in-context")),
  hooks: jobEvidence(output("hooks.native.toString")),
  cssSupports: jobEvidence(output("cssSupports[display:grid]"), fallback("cssSupports.available", "unsupported", "unavailable-in-context")),
  mediaDevices: jobEvidence(output("mediaDevices.total"), fallback("mediaDevices.available", "unsupported", "unavailable-in-context", "blocked")),
  keyboard: jobEvidence(output("keyboard.size"), fallback("keyboard.available", "unsupported", "unavailable-in-context", "blocked")),
  storage: jobEvidence(output("storage.localStorage"), fallback("storage.localStorage", "blocked")),
  env: jobEvidence(output("env.devicePixelRatio")),
  clientRects: jobEvidence(output("clientRects.bcr"), fallback("clientRects.status", "unsupported", "unavailable-in-context")),
  wasm: jobEvidence(output("wasm.streaming"), fallback("wasm.status", "unsupported", "unavailable-in-context")),
  mediaCaps: Object.freeze([
    output('mediaCaps.dec[video/mp4; codecs="avc1.42E01E"]'),
    fallback("mediaCaps.mediaCapabilities", "unsupported", "unavailable-in-context"),
  ]),
  device: jobEvidence(output("device.gamepads"), fallback("device.gamepads", "unsupported", "unavailable-in-context")),
  intlx: jobEvidence(output("intlx.tzCount"), fallback("intlx.tzCount", "unsupported", "unavailable-in-context"), fallback("intlx.status", "unsupported", "unavailable-in-context")),
  errors: jobEvidence(output("errors.syncFrames")),
});

const freezePaths = (values) => Object.freeze(values);
const LOCALE_PATHS = freezePaths([
  "locale.resolvedTZ", "locale.resolvedLocale", "locale.calendar", "locale.numberingSystem",
  "locale.tzOffset", "locale.dtfWinter", "locale.dtfSummer", "locale.dateToLocale",
  "locale.numberToLocale", "locale.relativeTime", "locale.collator", "locale.listFormat",
  "locale.pluralRules", "locale.firstWeekday",
]);
const CANVAS_PATHS = freezePaths([
  "canvas.winding", "canvas.width", "canvas.height", "canvas.pixelBytes", "canvas.pixelFnv",
  "canvas.pixelSha256", "canvas.encFmt", "canvas.encLen", "canvas.repeats", "canvas.stable",
]);
const WEBGL_CORE_PARAMS = freezePaths([
  "ACTIVE_TEXTURE", "ALIASED_LINE_WIDTH_RANGE", "ALIASED_POINT_SIZE_RANGE", "ALPHA_BITS",
  "BLUE_BITS", "DEPTH_BITS", "GREEN_BITS", "RED_BITS", "STENCIL_BITS",
  "MAX_COMBINED_TEXTURE_IMAGE_UNITS", "MAX_CUBE_MAP_TEXTURE_SIZE",
  "MAX_FRAGMENT_UNIFORM_VECTORS", "MAX_RENDERBUFFER_SIZE", "MAX_TEXTURE_IMAGE_UNITS",
  "MAX_TEXTURE_SIZE", "MAX_VARYING_VECTORS", "MAX_VERTEX_ATTRIBS",
  "MAX_VERTEX_TEXTURE_IMAGE_UNITS", "MAX_VERTEX_UNIFORM_VECTORS", "MAX_VIEWPORT_DIMS",
  "RENDERER", "SHADING_LANGUAGE_VERSION", "VENDOR", "VERSION",
]);
const WEBGL2_PARAMS = freezePaths([
  "MAX_3D_TEXTURE_SIZE", "MAX_ARRAY_TEXTURE_LAYERS", "MAX_COLOR_ATTACHMENTS",
  "MAX_COMBINED_FRAGMENT_UNIFORM_COMPONENTS", "MAX_COMBINED_UNIFORM_BLOCKS",
  "MAX_COMBINED_VERTEX_UNIFORM_COMPONENTS", "MAX_DRAW_BUFFERS", "MAX_ELEMENT_INDEX",
  "MAX_ELEMENTS_INDICES", "MAX_ELEMENTS_VERTICES", "MAX_FRAGMENT_INPUT_COMPONENTS",
  "MAX_FRAGMENT_UNIFORM_BLOCKS", "MAX_FRAGMENT_UNIFORM_COMPONENTS", "MAX_PROGRAM_TEXEL_OFFSET",
  "MAX_SAMPLES", "MAX_TEXTURE_LOD_BIAS", "MAX_TRANSFORM_FEEDBACK_SEPARATE_ATTRIBS",
  "MAX_UNIFORM_BLOCK_SIZE", "MAX_UNIFORM_BUFFER_BINDINGS", "MAX_VARYING_COMPONENTS",
  "MAX_VERTEX_OUTPUT_COMPONENTS", "MAX_VERTEX_UNIFORM_BLOCKS", "MAX_VERTEX_UNIFORM_COMPONENTS",
]);
const WEBGL_PRECISION = freezePaths(["VERTEX_SHADER", "FRAGMENT_SHADER"].flatMap((stage) =>
  ["HIGH_FLOAT", "MEDIUM_FLOAT", "LOW_FLOAT", "HIGH_INT", "MEDIUM_INT", "LOW_INT"]
    .map((precision) => `${stage}.${precision}`)));
const WEBGL_RENDER_LEAVES = freezePaths([
  "status", "fnv", "sha256", "compile", "link", "glError", "width", "height",
  "pixelBytes", "stable", "repeats", "sha256Repeats", "fnvRepeats",
]);
const CSS_MEDIA = freezePaths([
  "prefers-color-scheme: dark", "prefers-color-scheme: light", "prefers-reduced-motion: reduce",
  "prefers-reduced-transparency: reduce", "prefers-contrast: more", "prefers-contrast: less",
  "inverted-colors: inverted", "forced-colors: active", "dynamic-range: high",
  "video-dynamic-range: high", "any-hover: hover", "any-pointer: fine", "any-pointer: coarse",
  "hover: hover", "pointer: fine", "pointer: coarse", "color-gamut: srgb", "color-gamut: p3",
  "color-gamut: rec2020", "monochrome: 0", "orientation: landscape", "display-mode: browser",
  "display-mode: standalone", "scripting: enabled", "update: fast", "overflow-block: scroll",
]);
const MATH_PATHS = freezePaths([
  "acos", "acosh", "asin", "asinh", "atan", "atanh", "cbrt", "cos", "cosh", "exp",
  "expm1", "log", "log1p", "log10", "sin", "sinh", "sqrt", "tan", "tanh", "tan1e300",
  "powPI",
].map((name) => `math.${name}`));
const CODEC_TYPES = freezePaths([
  'video/mp4; codecs="avc1.42E01E"', 'video/mp4; codecs="hev1.1.6.L93.B0"',
  'video/webm; codecs="vp8"', 'video/webm; codecs="vp9"',
  'video/mp4; codecs="av01.0.05M.08"', 'video/ogg; codecs="theora"', "audio/mpeg",
  'audio/mp4; codecs="mp4a.40.2"', 'audio/ogg; codecs="vorbis"',
  'audio/ogg; codecs="opus"', 'audio/webm; codecs="opus"', "audio/flac", "audio/wav",
]);
const MISC_PATHS = freezePaths([
  "misc.errorStack", "misc.perfMemory", "misc.timerRes", "misc.chromeObj", "misc.webdriver",
  "misc.notifPermission", "misc.pluginsLen", "misc.mimeTypesLen",
  ...["geolocation", "notifications", "camera", "microphone", "midi", "background-sync",
    "persistent-storage", "clipboard-read", "clipboard-write", "accelerometer", "gyroscope",
    "magnetometer"].map((name) => `misc.perm.${name}`),
]);
const HOOK_PATHS = freezePaths([
  "toString", "bind", "canvas.toDataURL", "canvas.toBlob", "canvas.getContext",
  "gl.getParameter", "gl.readPixels", "audio.getChannelData", "audio.getFloatFrequencyData",
  "perm.query", "rtc.createOffer", "enumerateDevices", "getHighEntropyValues",
].map((name) => `hooks.native.${name}`).concat(
  "hooks.native.toStringOfToString",
  ...["userAgent", "platform", "languages", "hardwareConcurrency", "deviceMemory", "webdriver",
    "plugins", "vendor"].map((name) => `hooks.navDesc.${name}`),
  "hooks.navigator.webdriverOwnProp", "hooks.navigator.pluginsOwnProp",
));
const CSS_SUPPORTS = freezePaths([
  "display:grid", "display:flow-root", "gap:1px", "aspect-ratio:1/1",
  "backdrop-filter:blur(1px)", "-webkit-backdrop-filter:blur(1px)",
  "color:color(display-p3 1 1 1)", "width:min(1px,2px)", "width:clamp(1px,2px,3px)",
  "inset:0", "position:sticky", "overscroll-behavior:none", "scroll-snap-align:start",
  "contain:paint", "content-visibility:auto", "accent-color:red", "text-decoration-thickness:1px",
  "-webkit-touch-callout:none", "-moz-appearance:none", "-webkit-appearance:none",
  "font-palette:dark", "container-type:inline-size", "text-wrap:balance", "color:lab(50 0 0)",
  "color:oklch(0 0 0)", "width:100dvh", "width:100svh", "width:100lvh",
  "field-sizing:content", "animation-timeline:scroll()", "hyphenate-character:auto", "zoom:1",
  "-webkit-line-clamp:2", "image-rendering:pixelated", "mix-blend-mode:multiply",
  "paint-order:stroke", "shape-outside:circle()", "offset-path:circle()", "clip-path:circle()",
  "initial-letter:2", "math-style:compact", "scrollbar-width:thin", "scrollbar-color:red blue",
  "text-emphasis:none", "-webkit-text-security:disc", "selector(:has(a))",
  "selector(:focus-visible)", "selector(:modal)", "selector(::backdrop)",
]);
const ENV_PATHS = freezePaths([
  "env.devicePixelRatio", "env.maxTouchPoints", "env.colorDepth", "env.innerWidth",
  "env.innerHeight", "env.outerWidth", "env.outerHeight", "env.screenX", "env.screenY",
  "env.historyLength", "env.timeOrigin", "env.vvScale", "env.vvWidth",
]);
const CLIENT_RECTS_PATHS = freezePaths([
  "clientRects.bcr", "clientRects.rangeRects", "clientRects.rangeRectCount",
  ...["width", "actualBoundingBoxAscent", "actualBoundingBoxDescent", "actualBoundingBoxLeft",
    "actualBoundingBoxRight", "fontBoundingBoxAscent", "fontBoundingBoxDescent", "emHeightAscent",
    "emHeightDescent", "hangingBaseline", "alphabeticBaseline", "ideographicBaseline"]
    .map((name) => `clientRects.tm.${name}`),
  "clientRects.svgBBox", "clientRects.svgTextLen",
]);
const WASM_PATHS = freezePaths(["core", "simd", "memory64", "multiValue", "refTypes", "streaming", "exceptions"]
  .map((name) => `wasm.${name}`));
const INTLX_PATHS = freezePaths([
  "intlx.tzCount", "intlx.calendars", "intlx.currencyCount", "intlx.dtfParts", "intlx.nfParts",
  "intlx.displayRegion", "intlx.displayLang", "intlx.segmenter",
]);
const ERROR_PATHS = freezePaths([
  "errors.syncFrames", "errors.typeErrorFrames", "errors.nestedFrames", "errors.domException",
  "errors.evalFrames", "errors.prepareStackTrace", "errors.stackTraceLimit", "errors.asyncFrames",
]);
const DEEP_CORE_PATHS = freezePaths([
  "navigator.userAgent", "navigator.platform", "navigator.language", "navigator.languages",
  "navigator.hardwareConcurrency", "window.globals",
]);
const DOCUMENT_DEEP_PATHS = freezePaths([
  "screen.width", "screen.height", "screen.availWidth", "screen.availHeight", "screen.colorDepth",
  "screen.pixelDepth", "document.characterSet", "document.compatMode", "document.referrer",
  "document.visibilityState",
]);
const UACH_SUCCESS_PATHS = freezePaths([
  "uach.mobile", "uach.brands", "uach.platform", "uach.platformVersion", "uach.architecture",
  "uach.bitness", "uach.model", "uach.uaFullVersion", "uach.fullVersionList", "uach.wow64",
  "uach.formFactors",
]);
const WEBGPU_SUCCESS_PATHS = freezePaths([
  "webgpu.available", "webgpu.status", "webgpu.features", "webgpu.isFallback", "webgpu.vendor",
  "webgpu.architecture", "webgpu.device", "webgpu.description", "webgpu.wgslFeatures",
  "webgpu.preferredFormat", "webgpu.compute.status", "webgpu.compute.hash",
  "webgpu.compute.sha256", "webgpu.compute.hashAlgorithm", "webgpu.compute.byteLength",
  "webgpu.compute.valueCount", "webgpu.compute.compilationMessages",
  "webgpu.compute.compilationErrors", "webgpu.compute.deviceLost", "webgpu.render.status",
  "webgpu.render.hash", "webgpu.render.sha256", "webgpu.render.hashAlgorithm",
  "webgpu.render.byteLength", "webgpu.render.pixelBytes", "webgpu.render.width",
  "webgpu.render.height", "webgpu.render.bytesPerRow", "webgpu.render.compilationMessages",
  "webgpu.render.compilationErrors", "webgpu.render.deviceLost",
]);
const WEBRTC_SUCCESS_PATHS = freezePaths([
  "webrtc.status", "webrtc.audio.codecs", "webrtc.audio.exts", "webrtc.video.codecs",
  "webrtc.video.exts", "webrtc.iceGatheringComplete", "webrtc.iceCandidateCount",
  "webrtc.iceCandidates", "webrtc.iceCandidateTypes", "webrtc.iceCandidateProtocols",
  "webrtc.iceCandidateComponents", "webrtc.iceCandidateFamilies", "webrtc.offerStable",
  "webrtc.codecs", "webrtc.codecsHash", "webrtc.fmtpHash", "webrtc.extmap",
  "webrtc.fingerprintAlgo",
]);
const WORKLET_PATHS = freezePaths([
  "navigator.userAgent", "navigator.platform", "navigator.hardwareConcurrency", "navigator.deviceMemory",
  "locale.tz", "locale.locale", "math.tanPI", "math.sinh1", "worklet.sampleRate",
  "worklet.currentTime", "worklet.currentFrame", "worklet.hasNavigator", "worklet.dsp.sum",
  "worklet.dsp.hash", "worklet.dsp.len", "worklet.globals", "worklet.__manifest",
]);
const FPSCANNER_TEST_KEYS = freezePaths([
  "CHR_BATTERY", "CHR_DEBUG_TOOLS", "CHR_MEMORY", "HEADCHR_CHROME_OBJ", "HEADCHR_IFRAME",
  "HEADCHR_PERMISSIONS", "HEADCHR_PLUGINS", "HEADCHR_UA", "MQ_SCREEN", "PHANTOM_ETSL",
  "PHANTOM_LANGUAGE", "PHANTOM_OVERFLOW", "PHANTOM_PROPERTIES", "PHANTOM_UA",
  "PHANTOM_WEBSOCKET", "PHANTOM_WINDOW_HEIGHT", "SELENIUM_DRIVER", "SEQUENTUM",
  "TRANSPARENT_PIXEL", "VIDEO_CODECS", "WEBDRIVER",
]);
const CLIENTJS_COMPONENT_KEYS = freezePaths([
  "getFingerprint", "getUserAgent", "getBrowser", "getBrowserVersion", "getOS", "getOSVersion",
  "getDevice", "getCPU", "getEngine", "getScreenPrint", "getColorDepth",
  "getCurrentResolution", "getAvailableResolution", "getTimeZone", "getLanguage",
  "getSystemLanguage", "getCanvasPrint", "getPlugins", "getFonts",
].sort());
const CONTROL_SANITY_PATHS = freezePaths([
  "control.sanity.headless.webdriver", "control.sanity.headless.headlessUA",
  "control.sanity.headless.chromeObject", "control.sanity.headless.chromeRuntime",
  "control.sanity.headless.pluginsZero", "control.sanity.headless.languagesEmpty",
  "control.sanity.headless.notifVsPerm", "control.sanity.headless.appVersionInUA",
  "control.sanity.consistency.uaPlatformMatch", "control.sanity.consistency.toStringNative",
  "control.sanity.consistency.languagesVsLanguage", "control.sanity.consistency.hardwareConcurrency",
  "control.sanity.consistency.deviceMemory", "control.sanity.consistency.productSub",
  "control.sanity.consistency.vendorMatch",
]);

const REQUIRED_ROLES = ["main-frame", "permissioned", "network"];
const SPECIAL_CONTEXTS = new Set(["network", "run-manifest"]);
const FULL_COLLECTOR_CONTEXTS = new Set(DEFAULT_EXPECTED_CONTEXTS.filter((x) =>
  !["audio-worklet", "network", "permissioned"].includes(x)));
const DOCUMENT_CONTEXTS = new Set([
  "main-frame", "iframe", "iframe-url", "sandboxed-iframe", "credentialless-iframe",
  "cross-origin-iframe",
]);
const AUDIO_OFFLINE_PATHS = freezePaths([
  "audio.status", "audio.offline.sum", "audio.offline.sha256", "audio.offline.fnv",
  "audio.offline.sampleCount", "audio.offline.byteLength", "audio.offline.sampleRate",
  "audio.offline.stable", "audio.offline.sha256Repeats",
]);
const AUDIO_REALTIME_PATHS = freezePaths([
  "audio.realtime.status", "audio.realtime.baseLatency", "audio.realtime.outputLatency",
  "audio.realtime.sampleRate", "audio.realtime.state",
]);
const FONT_PATHS = freezePaths(["fonts.count", "fonts.list", "fonts.hash"]);
const CSS_PATHS = freezePaths([...CSS_MEDIA.map((query) => `css[${query}]`), "css.deviceAspect"]);
const SPEECH_PATHS = freezePaths(["speech.voices", "speech.count"]);
const MEDIA_DEVICE_PATHS = freezePaths([
  "mediaDevices.total", "mediaDevices.audioinput", "mediaDevices.audiooutput",
  "mediaDevices.videoinput", "mediaDevices.groups", "mediaDevices.supportedConstraints",
]);
const KEYBOARD_PATHS = freezePaths(["keyboard.size", "keyboard.hash"]);
const STORAGE_COMMON_PATHS = freezePaths([
  "storage.localStorage", "storage.sessionStorage", "storage.indexedDB", "storage.caches",
  "storage.opfs", "storage.storageBuckets",
]);
const STORAGE_ESTIMATE_PATHS = freezePaths([
  "storage.quotaRoundedGB", "storage.hasQuota", "storage.usageDetails", "storage.persisted",
]);
const MEDIA_CAPABILITY_PATHS = freezePaths([
  'mediaCaps.dec[video/mp4; codecs="avc1.42E01E"]',
  'mediaCaps.dec[video/webm; codecs="vp9"]',
  'mediaCaps.dec[video/mp4; codecs="av01.0.05M.08"]',
]);
const WEBCODECS_PATHS = freezePaths([
  "mediaCaps.webcodecs[avc1.42E01E]", "mediaCaps.webcodecs[vp09.00.10.08]",
  "mediaCaps.webcodecs[av01.0.05M.08]",
]);
const EME_PATHS = freezePaths([
  "mediaCaps.eme[com.widevine.alpha]", "mediaCaps.eme[com.microsoft.playready]",
  "mediaCaps.eme[org.w3.clearkey]",
]);
const DEVICE_COMMON_PATHS = freezePaths([
  "device.gamepads", "device.hasBluetooth", "device.hasUSB", "device.hasHID", "device.hasSerial",
]);
const BATTERY_PATHS = freezePaths([
  "device.batteryCharging", "device.batteryLevel", "device.batteryChargingTimeFinite",
]);

// This table is owned by the collector build, not by browser manifests. It is
// intentionally explicit: dropping a reviewed leaf from persisted evidence must
// change this contract and its deletion tests in the same reviewed change.
export const DEFAULT_REQUIRED_PATH_CONTRACT = Object.freeze({
  locale: LOCALE_PATHS,
  canvas: CANVAS_PATHS,
  webglCoreParams: WEBGL_CORE_PARAMS,
  webgl2Params: WEBGL2_PARAMS,
  webglPrecision: WEBGL_PRECISION,
  webglRender: WEBGL_RENDER_LEAVES,
  webglMetadata: freezePaths(["unmaskedVendor", "unmaskedRenderer", "extensions", "contextAttrs"]),
  webgpuSuccess: WEBGPU_SUCCESS_PATHS,
  audioOffline: AUDIO_OFFLINE_PATHS,
  audioRealtime: AUDIO_REALTIME_PATHS,
  fonts: FONT_PATHS,
  cssMedia: CSS_MEDIA,
  math: MATH_PATHS,
  codecs: freezePaths(CODEC_TYPES.flatMap((type) => [`codecs.canPlay[${type}]`, `codecs.mse[${type}]`])),
  speech: SPEECH_PATHS,
  misc: MISC_PATHS,
  hooks: HOOK_PATHS,
  cssSupports: freezePaths(CSS_SUPPORTS.map((query) => `cssSupports[${query}]`)),
  mediaDevices: MEDIA_DEVICE_PATHS,
  keyboard: KEYBOARD_PATHS,
  storageCommon: STORAGE_COMMON_PATHS,
  storageEstimate: STORAGE_ESTIMATE_PATHS,
  env: ENV_PATHS,
  clientRects: CLIENT_RECTS_PATHS,
  wasm: WASM_PATHS,
  mediaCapabilities: MEDIA_CAPABILITY_PATHS,
  webcodecs: WEBCODECS_PATHS,
  eme: EME_PATHS,
  deviceCommon: DEVICE_COMMON_PATHS,
  battery: BATTERY_PATHS,
  intlx: INTLX_PATHS,
  errors: ERROR_PATHS,
  deepCore: DEEP_CORE_PATHS,
  documentDeep: DOCUMENT_DEEP_PATHS,
  uachSuccess: UACH_SUCCESS_PATHS,
  webrtcSuccess: WEBRTC_SUCCESS_PATHS,
  audioWorklet: WORKLET_PATHS,
  fpscannerTests: FPSCANNER_TEST_KEYS,
  clientjsComponents: CLIENTJS_COMPONENT_KEYS,
  controlSanity: CONTROL_SANITY_PATHS,
});

function issue(code, detail = {}, blocking = true) {
  return { code, blocking, ...detail };
}

function encodedField(value, name) {
  const props = value && typeof value === "object" && value.props;
  const node = props && props[name];
  return node && typeof node === "object" ? node.value : undefined;
}

function decodedField(value, name) {
  const props = value && typeof value === "object" && value.props;
  return decodeNode(props && props[name]);
}

function decodeNode(node) {
  if (!node || typeof node !== "object" || Array.isArray(node)) return undefined;
  const type = node.valueType;
  if (type === "array") {
    if (!Array.isArray(node.value)) return undefined;
    return node.value.map(decodeNode);
  }
  if (type === "object") {
    const props = node.value && typeof node.value === "object" && node.value.props;
    if (!props || typeof props !== "object" || Array.isArray(props)) return undefined;
    return Object.fromEntries(Object.entries(props).map(([key, child]) => [key, decodeNode(child)]));
  }
  return node.value;
}

function decodedRecord(row) {
  return decodeNode({ valueType: row?.valueType, value: row?.value, special: row?.meta?.special, count: row?.meta?.count });
}

function sameList(a, b) {
  return Array.isArray(a) && Array.isArray(b) && a.length === b.length && a.every((x, i) => x === b[i]);
}

function canonical(value) {
  if (Array.isArray(value)) return value.map(canonical);
  if (value && typeof value === "object") {
    const out = Object.create(null);
    for (const key of Object.keys(value).sort()) out[key] = canonical(value[key]);
    return out;
  }
  return value;
}

function canonicalSha256(value) {
  try { return sha256hex(JSON.stringify(canonical(value))); }
  catch { return null; }
}

function validOrigin(originText) {
  try { return new URL(originText).origin === originText; }
  catch { return false; }
}

function validRegistrableSite(site) {
  return typeof site === "string" && site.length > 0 && site.length <= 253
    && site === site.toLowerCase() && /^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$/.test(site)
    && !site.includes("..");
}

function expectedServiceWorkerBinding(identity) {
  try {
    const script = new URL("/fingerprint/sw", identity?.oopif?.parentOrigin);
    script.searchParams.set("build", identity.collectorBuild);
    script.searchParams.set("artifact", identity.collectorArtifactSha256);
    script.searchParams.set("capture", identity.captureKey);
    script.searchParams.set("challenge", identity.serviceWorkerChallenge);
    return {
      scriptURL: script.href,
      scope: new URL(`/fingerprint/sw-scope/${identity.serviceWorkerChallenge}/`, identity.oopif.parentOrigin).href,
    };
  } catch {
    return null;
  }
}

function sameCanonical(a, b) {
  try { return JSON.stringify(canonical(a)) === JSON.stringify(canonical(b)); }
  catch { return false; }
}

function sameIdentity(value, expected) {
  return value && typeof value === "object" && !Array.isArray(value)
    && value.environment === expected.environment
    && value.pairKey === expected.pairKey
    && value.captureKey === expected.captureKey
    && value.collectorBuild === expected.collectorBuild
    && value.collectorArtifactSha256 === expected.collectorArtifactSha256
    && value.oopif && expected.oopif
    && !("processEvidence" in value.oopif)
    && value.oopif.parentOrigin === expected.oopif.parentOrigin
    && value.oopif.childOrigin === expected.oopif.childOrigin
    && value.oopif.registrableParentSite === expected.oopif.registrableParentSite
    && value.oopif.registrableChildSite === expected.oopif.registrableChildSite
    && value.oopif.configurationId === expected.oopif.configurationId
    && value.oopif.processEvidenceSha256 === expected.oopif.processEvidenceSha256
    && value.oopif.processEvidenceBuild === expected.oopif.processEvidenceBuild
    && value.serviceWorkerChallenge === expected.serviceWorkerChallenge;
}

const BOUND_CHILD_KEYS = Object.freeze([
  "acknowledgementSha256", "captureKey", "collectorArtifactSha256", "collectorBuild",
  "context", "handshakeVersion", "parentOrigin", "protocol", "requestId",
]);

function validateBoundChildEvidence(context, payload, identity) {
  const binding = payload?._boundChild;
  const exactKeys = binding && typeof binding === "object" && !Array.isArray(binding)
    && sameList(Object.keys(binding).sort(), BOUND_CHILD_KEYS);
  if (!exactKeys || binding.protocol !== "fingerprint-bound-child"
      || binding.handshakeVersion !== 1 || binding.context !== context
      || binding.collectorBuild !== identity?.collectorBuild
      || binding.collectorArtifactSha256 !== identity?.collectorArtifactSha256
      || binding.captureKey !== identity?.captureKey
      || typeof binding.requestId !== "string" || !/^[A-Za-z0-9_-]{22,240}$/.test(binding.requestId)
      || binding.parentOrigin !== identity?.oopif?.parentOrigin) {
    return issue("bound-child-evidence-invalid", { context });
  }
  const core = {
    protocol: binding.protocol,
    handshakeVersion: binding.handshakeVersion,
    context: binding.context,
    collectorBuild: binding.collectorBuild,
    collectorArtifactSha256: binding.collectorArtifactSha256,
    captureKey: binding.captureKey,
    requestId: binding.requestId,
    parentOrigin: binding.parentOrigin,
  };
  return binding.acknowledgementSha256 === canonicalSha256(core)
    ? null : issue("bound-child-evidence-invalid", { context });
}

function validateCollectorJobEvidence(context, byPath) {
  const out = [];
  for (const [job, alternatives] of Object.entries(DEFAULT_REQUIRED_JOB_EVIDENCE)) {
    if (!alternatives.some(({ path, statuses }) => statuses.includes(byPath.get(path)?.status))) {
      out.push(issue("required-job-evidence-missing", { context, job, paths: alternatives.map((x) => x.path) }));
    }
  }
  return out;
}

function requireContractPaths(context, byPath, paths, code = "collector-contract-missing", detail = {}) {
  const out = [];
  for (const path of paths) {
    if (!byPath.has(path)) out.push(issue(code, { context, path, ...detail }));
  }
  return out;
}

function familyPaths(byPath, matches) {
  return [...byPath.keys()].filter((path) => typeof path === "string" && matches(path));
}

function validateTerminalOrSuccess(context, byPath, {
  name, markerPath, terminalStatuses, successPaths, matches, commonPaths = [],
}) {
  const out = [];
  const marker = byPath.get(markerPath);
  const terminal = marker && terminalStatuses.includes(marker.status);
  if (terminal) {
    const allowed = new Set([...commonPaths, markerPath]);
    const contradictions = familyPaths(byPath, matches).filter((path) => !allowed.has(path));
    if (contradictions.length) {
      out.push(issue("collector-capability-branch-invalid", {
        context, family: name, marker: markerPath, contradictoryPaths: contradictions.sort(),
      }));
    }
    return { terminal: true, issues: out };
  }
  out.push(...requireContractPaths(context, byPath, successPaths));
  if (marker && !successPaths.includes(markerPath)) {
    out.push(issue("collector-capability-branch-invalid", {
      context, family: name, marker: markerPath, detail: "non-terminal marker mixed with success branch",
    }));
  }
  return { terminal: false, issues: out };
}

function validateCollectorPathContract(context, byPath) {
  const out = [];
  out.push(...requireContractPaths(context, byPath, [
    ...LOCALE_PATHS, ...MATH_PATHS,
    ...CODEC_TYPES.flatMap((type) => [`codecs.canPlay[${type}]`, `codecs.mse[${type}]`]),
    ...MISC_PATHS, ...HOOK_PATHS, ...STORAGE_COMMON_PATHS, ...ENV_PATHS,
    ...DEVICE_COMMON_PATHS, ...ERROR_PATHS, ...DEEP_CORE_PATHS,
  ]));
  if (DOCUMENT_CONTEXTS.has(context)) {
    out.push(...requireContractPaths(context, byPath, DOCUMENT_DEEP_PATHS));
  }

  const branches = [
    {
      name: "fonts", markerPath: "fonts.available",
      terminalStatuses: ["unsupported", "unavailable-in-context"], successPaths: FONT_PATHS,
      matches: (path) => path.startsWith("fonts."),
    },
    {
      name: "css", markerPath: "css.available",
      terminalStatuses: ["unsupported", "unavailable-in-context"], successPaths: CSS_PATHS,
      matches: (path) => path.startsWith("css.") || path.startsWith("css["),
    },
    {
      name: "speech", markerPath: "speech.available",
      terminalStatuses: ["unsupported", "unavailable-in-context"], successPaths: SPEECH_PATHS,
      matches: (path) => path.startsWith("speech."),
    },
    {
      name: "uach", markerPath: "uach.available",
      terminalStatuses: ["unsupported", "unavailable-in-context"], successPaths: UACH_SUCCESS_PATHS,
      matches: (path) => path.startsWith("uach."),
    },
    {
      name: "cssSupports", markerPath: "cssSupports.available",
      terminalStatuses: ["unsupported", "unavailable-in-context"],
      successPaths: CSS_SUPPORTS.map((query) => `cssSupports[${query}]`),
      matches: (path) => path.startsWith("cssSupports.") || path.startsWith("cssSupports["),
    },
    {
      name: "mediaDevices", markerPath: "mediaDevices.available",
      terminalStatuses: ["unsupported", "unavailable-in-context", "blocked"],
      successPaths: MEDIA_DEVICE_PATHS, matches: (path) => path.startsWith("mediaDevices."),
    },
    {
      name: "keyboard", markerPath: "keyboard.available",
      terminalStatuses: ["unsupported", "unavailable-in-context", "blocked"],
      successPaths: KEYBOARD_PATHS, matches: (path) => path.startsWith("keyboard."),
    },
    {
      name: "clientRects", markerPath: "clientRects.status",
      terminalStatuses: ["unsupported", "unavailable-in-context"],
      successPaths: CLIENT_RECTS_PATHS, matches: (path) => path.startsWith("clientRects."),
    },
    {
      name: "wasm", markerPath: "wasm.status",
      terminalStatuses: ["unsupported", "unavailable-in-context"],
      successPaths: WASM_PATHS, matches: (path) => path.startsWith("wasm."),
    },
    {
      name: "intlx", markerPath: "intlx.status",
      terminalStatuses: ["unsupported", "unavailable-in-context"],
      successPaths: INTLX_PATHS, matches: (path) => path.startsWith("intlx."),
    },
  ];
  for (const branch of branches) out.push(...validateTerminalOrSuccess(context, byPath, branch).issues);

  const independent = [
    {
      name: "storage.estimate", markerPath: "storage.estimate",
      terminalStatuses: ["unsupported", "unavailable-in-context", "blocked"],
      successPaths: STORAGE_ESTIMATE_PATHS, commonPaths: STORAGE_COMMON_PATHS,
      matches: (path) => path.startsWith("storage."),
    },
    {
      name: "device.battery", markerPath: "device.battery",
      terminalStatuses: ["unsupported", "unavailable-in-context"],
      successPaths: BATTERY_PATHS, commonPaths: DEVICE_COMMON_PATHS,
      matches: (path) => path.startsWith("device."),
    },
    {
      name: "mediaCaps.mediaCapabilities", markerPath: "mediaCaps.mediaCapabilities",
      terminalStatuses: ["unsupported", "unavailable-in-context"], successPaths: MEDIA_CAPABILITY_PATHS,
      matches: (path) => path === "mediaCaps.mediaCapabilities" || path.startsWith("mediaCaps.dec["),
    },
    {
      name: "mediaCaps.webcodecs", markerPath: "mediaCaps.webcodecs",
      terminalStatuses: ["unsupported", "unavailable-in-context"], successPaths: WEBCODECS_PATHS,
      matches: (path) => path === "mediaCaps.webcodecs" || path.startsWith("mediaCaps.webcodecs["),
    },
    {
      name: "mediaCaps.eme", markerPath: "mediaCaps.eme",
      terminalStatuses: ["unsupported", "unavailable-in-context"], successPaths: EME_PATHS,
      matches: (path) => path === "mediaCaps.eme" || path.startsWith("mediaCaps.eme["),
    },
  ];
  for (const branch of independent) out.push(...validateTerminalOrSuccess(context, byPath, branch).issues);
  return out;
}

function validateCanvasEvidence(context, byPath) {
  const statusRow = byPath.get("canvas.status");
  const evidenceRows = [...byPath.keys()].filter((path) => path.startsWith("canvas.") && path !== "canvas.status");
  if (statusRow && ["unsupported", "unavailable-in-context"].includes(statusRow.status)) {
    return evidenceRows.length
      ? [
        issue("collector-capability-branch-invalid", { context, family: "canvas", contradictoryPaths: evidenceRows }),
        issue("canvas-evidence-invalid", { context, detail: "pixel rows contradict unavailable canvas" }),
      ] : [];
  }
  const out = requireContractPaths(context, byPath, CANVAS_PATHS);
  if (statusRow) out.push(issue("collector-capability-branch-invalid", {
    context, family: "canvas", detail: "unexpected non-terminal canvas marker",
  }));
  const value = (path) => decodedRecord(byPath.get(path));
  const sha = value("canvas.pixelSha256"), repeats = value("canvas.repeats");
  const width = value("canvas.width"), height = value("canvas.height"), pixelBytes = value("canvas.pixelBytes");
  const valid = typeof sha === "string" && /^[0-9a-f]{64}$/.test(sha)
    && typeof value("canvas.pixelFnv") === "string" && /^[0-9a-f]{8}$/.test(value("canvas.pixelFnv"))
    && Array.isArray(repeats) && repeats.length === 3 && repeats.every((digest) => digest === sha)
    && value("canvas.stable") === true
    && Number.isInteger(width) && width > 0 && Number.isInteger(height) && height > 0
    && Number.isInteger(pixelBytes) && pixelBytes === width * height * 4;
  if (!valid) out.push(issue("canvas-evidence-invalid", { context, detail: "semantic full-readback contract failed" }));
  return out;
}

function validateWebglEvidence(context, byPath) {
  const out = [];
  for (const api of ["webgl", "webgl2"]) {
    const prefix = `webgl.${api}`;
    const statusRow = byPath.get(`${prefix}.status`);
    const unavailable = statusRow
      && ["unsupported", "unavailable-in-context"].includes(statusRow.status);
    const familyRows = [...byPath.keys()].filter((path) => path.startsWith(`${prefix}.`) && path !== `${prefix}.status`);
    if (unavailable) {
      if (familyRows.length) {
        out.push(issue("collector-capability-branch-invalid", {
          context, family: prefix, marker: `${prefix}.status`, contradictoryPaths: familyRows.sort(),
        }));
        out.push(issue("webgl-evidence-invalid", { context, api, detail: "rows contradict unavailable API" }));
      }
      continue;
    }
    const required = [
      `${prefix}.status`,
      ...WEBGL_CORE_PARAMS.map((name) => `${prefix}.params.${name}`),
      ...(api === "webgl2" ? WEBGL2_PARAMS.map((name) => `${prefix}.params.${name}`) : []),
      ...WEBGL_PRECISION.map((name) => `${prefix}.precision.${name}`),
      ...WEBGL_RENDER_LEAVES.map((name) => `${prefix}.render.${name}`),
      `${prefix}.unmaskedVendor`, `${prefix}.unmaskedRenderer`, `${prefix}.extensions`,
      `${prefix}.contextAttrs`,
    ];
    out.push(...requireContractPaths(context, byPath, required));
    const value = (path) => decodedRecord(byPath.get(`${prefix}.${path}`));
    const sha = value("render.sha256");
    const repeats = value("render.sha256Repeats");
    const width = value("render.width"), height = value("render.height");
    const pixelBytes = value("render.pixelBytes");
    const valid = statusRow?.status === "ok" && decodedRecord(statusRow) === "ok"
      && byPath.get(`${prefix}.render.status`)?.status === "ok" && value("render.status") === "ok"
      && value("render.compile") === true && value("render.link") === true
      && value("render.glError") === 0 && value("render.stable") === true
      && typeof sha === "string" && /^[0-9a-f]{64}$/.test(sha)
      && Array.isArray(repeats) && repeats.length === 3 && repeats.every((digest) => digest === sha)
      && Number.isInteger(width) && width > 0 && Number.isInteger(height) && height > 0
      && Number.isInteger(pixelBytes) && pixelBytes === width * height * 4;
    const fnv = value("render.fnv"), fnvRepeats = value("render.fnvRepeats");
    const renderRepeats = value("render.repeats");
    const strengthened = valid
      && typeof fnv === "string" && /^[0-9a-f]{8}$/.test(fnv)
      && Array.isArray(fnvRepeats) && fnvRepeats.length === 3 && fnvRepeats.every((digest) => digest === fnv)
      && Array.isArray(renderRepeats) && sameList(renderRepeats, repeats);
    if (!strengthened) out.push(issue("webgl-evidence-invalid", { context, api, detail: "semantic render contract failed" }));
  }
  return out;
}

function validateWebgpuEvidence(context, byPath) {
  const out = [];
  const availableRow = byPath.get("webgpu.available");
  const statusRow = byPath.get("webgpu.status");
  const apiMissing = availableRow && availableRow.status === "unsupported";
  const adapterMissing = statusRow && ["unavailable-in-context", "blocked"].includes(statusRow.status);
  const unavailable = apiMissing || adapterMissing;
  const stageRows = [...byPath.keys()].filter((path) => /^webgpu\.(?:compute|render)\./.test(path));
  if (unavailable) {
    const allowed = apiMissing ? new Set(["webgpu.available"]) : new Set(["webgpu.available", "webgpu.status"]);
    const contradictory = [...byPath.keys()].filter((path) => path.startsWith("webgpu.") && !allowed.has(path));
    const availableValue = decodedRecord(availableRow);
    if (stageRows.length || contradictory.length
        || (apiMissing && statusRow)
        || (adapterMissing && (availableRow?.status !== "ok" || availableValue !== true))) {
      out.push(issue("collector-capability-branch-invalid", {
        context, family: "webgpu", contradictoryPaths: contradictory.sort(),
      }));
      out.push(issue("webgpu-evidence-invalid", { context, detail: "rows contradict unavailable branch" }));
    }
    return out;
  }
  const missing = WEBGPU_SUCCESS_PATHS.filter((path) => !byPath.has(path));
  const limitRows = [...byPath.entries()].filter(([path, row]) => path.startsWith("webgpu.limits.")
    && row?.status === "ok" && Number.isFinite(decodedRecord(row)) && decodedRecord(row) >= 0);
  if (missing.length || limitRows.length === 0) {
    out.push(issue("webgpu-evidence-invalid", {
      context, detail: "incomplete success path set", missingPaths: missing, adapterLimitCount: limitRows.length,
    }));
  }
  const value = (path) => decodedRecord(byPath.get(path));
  const computeSha = value("webgpu.compute.sha256");
  const renderSha = value("webgpu.render.sha256");
  const width = value("webgpu.render.width"), height = value("webgpu.render.height");
  const bytesPerRow = value("webgpu.render.bytesPerRow"), pixelBytes = value("webgpu.render.pixelBytes");
  const valid = availableRow?.status === "ok" && value("webgpu.available") === true
    && statusRow?.status === "ok" && value("webgpu.status") === "ok"
    && typeof value("webgpu.features") === "string"
    && byPath.get("webgpu.compute.status")?.status === "ok" && value("webgpu.compute.status") === "ok"
    && value("webgpu.compute.hash") === computeSha
    && typeof computeSha === "string" && /^[0-9a-f]{64}$/.test(computeSha)
    && value("webgpu.compute.hashAlgorithm") === "sha256"
    && value("webgpu.compute.byteLength") === 256
    && value("webgpu.compute.valueCount") === 64
    && Number.isInteger(value("webgpu.compute.compilationMessages"))
    && value("webgpu.compute.compilationMessages") >= 0
    && value("webgpu.compute.compilationErrors") === 0
    && value("webgpu.compute.deviceLost") === false
    && byPath.get("webgpu.render.status")?.status === "ok" && value("webgpu.render.status") === "ok"
    && value("webgpu.render.hash") === renderSha
    && typeof renderSha === "string" && /^[0-9a-f]{64}$/.test(renderSha)
    && value("webgpu.render.hashAlgorithm") === "sha256"
    && Number.isInteger(width) && width > 0 && Number.isInteger(height) && height > 0
    && Number.isInteger(bytesPerRow) && bytesPerRow >= width * 4
    && Number.isInteger(pixelBytes) && pixelBytes === bytesPerRow * height
    && value("webgpu.render.byteLength") === pixelBytes
    && Number.isInteger(value("webgpu.render.compilationMessages"))
    && value("webgpu.render.compilationMessages") >= 0
    && value("webgpu.render.compilationErrors") === 0
    && value("webgpu.render.deviceLost") === false;
  if (!valid) out.push(issue("webgpu-evidence-invalid", { context, detail: "semantic compute/render contract failed" }));
  return out;
}

function validateAudioEvidence(context, byPath) {
  const out = [];
  const availableRow = byPath.get("audio.available");
  const offlineRows = [...byPath.keys()].filter((path) => path.startsWith("audio.offline."));
  if (availableRow && ["unsupported", "unavailable-in-context"].includes(availableRow.status)) {
    const contradictory = [...byPath.keys()].filter((path) => path.startsWith("audio.") && path !== "audio.available");
    if (offlineRows.length || contradictory.length) {
      out.push(issue("collector-capability-branch-invalid", {
        context, family: "audio", marker: "audio.available", contradictoryPaths: contradictory.sort(),
      }));
      out.push(issue("audio-evidence-invalid", { context, detail: "rows contradict unavailable API" }));
    }
    return out;
  }
  out.push(...requireContractPaths(context, byPath, AUDIO_OFFLINE_PATHS));
  if (availableRow) out.push(issue("collector-capability-branch-invalid", {
    context, family: "audio", detail: "unexpected non-terminal audio marker",
  }));

  const realtimeMarker = byPath.get("audio.realtime.available");
  if (realtimeMarker && ["unsupported", "unavailable-in-context"].includes(realtimeMarker.status)) {
    const contradictory = [...byPath.keys()].filter((path) => path.startsWith("audio.realtime.")
      && path !== "audio.realtime.available");
    if (contradictory.length) {
      out.push(issue("collector-capability-branch-invalid", {
        context, family: "audio.realtime", contradictoryPaths: contradictory.sort(),
      }));
      out.push(issue("audio-evidence-invalid", { context, detail: "realtime rows contradict unavailable branch" }));
    }
  } else {
    out.push(...requireContractPaths(context, byPath, AUDIO_REALTIME_PATHS));
    if (realtimeMarker) out.push(issue("collector-capability-branch-invalid", {
      context, family: "audio.realtime", detail: "unexpected non-terminal marker",
    }));
  }
  const value = (path) => decodedRecord(byPath.get(path));
  const sha = value("audio.offline.sha256"), repeats = value("audio.offline.sha256Repeats");
  const sampleCount = value("audio.offline.sampleCount"), byteLength = value("audio.offline.byteLength");
  const valid = byPath.get("audio.status")?.status === "ok" && value("audio.status") === "ok"
    && typeof sha === "string" && /^[0-9a-f]{64}$/.test(sha)
    && Array.isArray(repeats) && repeats.length === 3 && repeats.every((digest) => digest === sha)
    && value("audio.offline.stable") === true
    && Number.isInteger(sampleCount) && sampleCount > 0
    && Number.isInteger(byteLength) && byteLength === sampleCount * 4
    && typeof value("audio.offline.sampleRate") === "number" && value("audio.offline.sampleRate") > 0
    && typeof value("audio.offline.sum") === "number" && Number.isFinite(value("audio.offline.sum"))
    && typeof value("audio.offline.fnv") === "string" && /^[0-9a-f]{8}$/.test(value("audio.offline.fnv"));
  if (!valid) out.push(issue("audio-evidence-invalid", { context, detail: "semantic DSP contract failed" }));
  if (!realtimeMarker) {
    const realtimeValid = value("audio.realtime.status") === "ok"
      && Number.isFinite(value("audio.realtime.baseLatency")) && value("audio.realtime.baseLatency") >= 0
      && Number.isFinite(value("audio.realtime.outputLatency")) && value("audio.realtime.outputLatency") >= 0
      && Number.isFinite(value("audio.realtime.sampleRate")) && value("audio.realtime.sampleRate") > 0
      && typeof value("audio.realtime.state") === "string" && value("audio.realtime.state").length > 0;
    if (!realtimeValid) out.push(issue("audio-evidence-invalid", { context, detail: "semantic realtime contract failed" }));
  }
  return out;
}

function validateWebrtcEvidence(context, byPath) {
  const out = [];
  const statusRow = byPath.get("webrtc.status");
  const evidenceRows = [...byPath.keys()].filter((path) => path.startsWith("webrtc.") && path !== "webrtc.status");
  if (statusRow && ["unsupported", "unavailable-in-context", "blocked"].includes(statusRow.status)) {
    if (evidenceRows.length) {
      out.push(issue("collector-capability-branch-invalid", {
        context, family: "webrtc", marker: "webrtc.status", contradictoryPaths: evidenceRows.sort(),
      }));
      out.push(issue("webrtc-evidence-invalid", { context, detail: "offer rows contradict unavailable WebRTC" }));
    }
    return out;
  }
  const missing = WEBRTC_SUCCESS_PATHS.filter((path) => !byPath.has(path));
  if (missing.length) out.push(issue("webrtc-evidence-invalid", {
    context, detail: "incomplete WebRTC success path set", missingPaths: missing,
  }));
  const value = (path) => decodedRecord(byPath.get(path));
  const candidates = value("webrtc.iceCandidates"), count = value("webrtc.iceCandidateCount");
  const candidateShapeOk = Array.isArray(candidates) && candidates.every((candidate) =>
    candidate && typeof candidate === "object"
      && typeof candidate.candidate === "string" && candidate.candidate.length > 0
      && typeof candidate.foundation === "string" && candidate.foundation.length > 0
      && typeof candidate.component === "string" && candidate.component.length > 0
      && typeof candidate.protocol === "string" && candidate.protocol.length > 0
      && typeof candidate.address === "string"
      && Number.isFinite(candidate.priority) && Number.isFinite(candidate.port)
      && typeof candidate.type === "string" && candidate.type.length > 0
      && ["mdns", "ipv4", "ipv6", "?"].includes(candidate.family));
  const summarize = (field) => {
    const counts = Object.create(null);
    for (const candidate of candidates || []) {
      const key = String(candidate?.[field] ?? "?");
      counts[key] = (counts[key] || 0) + 1;
    }
    return Object.keys(counts).sort().map((key) => `${key}:${counts[key]}`).join(",");
  };
  const valid = statusRow?.status === "ok" && value("webrtc.status") === "ok"
    && value("webrtc.iceGatheringComplete") === true
    && value("webrtc.offerStable") === true
    && Number.isInteger(count) && count >= 0
    && candidateShapeOk && candidates.length === count
    && value("webrtc.iceCandidateTypes") === summarize("type")
    && value("webrtc.iceCandidateProtocols") === summarize("protocol")
    && value("webrtc.iceCandidateComponents") === summarize("component")
    && value("webrtc.iceCandidateFamilies") === summarize("family")
    && typeof value("webrtc.audio.codecs") === "string"
    && typeof value("webrtc.audio.exts") === "string"
    && typeof value("webrtc.video.codecs") === "string"
    && typeof value("webrtc.video.exts") === "string"
    && typeof value("webrtc.codecs") === "string"
    && typeof value("webrtc.codecsHash") === "string" && /^[0-9a-f]{8}$/.test(value("webrtc.codecsHash"))
    && typeof value("webrtc.fmtpHash") === "string" && /^[0-9a-f]{8}$/.test(value("webrtc.fmtpHash"))
    && typeof value("webrtc.extmap") === "string"
    && typeof value("webrtc.fingerprintAlgo") === "string" && value("webrtc.fingerprintAlgo").length > 0;
  if (!valid) out.push(issue("webrtc-evidence-invalid", { context, detail: "semantic ICE/repeated-offer contract failed" }));
  return out;
}

function validateAudioWorkletContract(context, rows, byPath) {
  const actualPaths = rows.map((row) => row?.path).sort();
  const expectedPaths = [...WORKLET_PATHS].sort();
  const value = (path) => decodedRecord(byPath.get(path));
  const unavailablePaths = [
    "navigator.userAgent", "navigator.platform", "navigator.hardwareConcurrency",
    "navigator.deviceMemory", "worklet.hasNavigator",
  ];
  const unavailableOk = unavailablePaths.every((path) => byPath.get(path)?.status === "unavailable-in-context"
    && value(path) === null);
  const normalPaths = WORKLET_PATHS.filter((path) => !unavailablePaths.includes(path));
  const statusesOk = normalPaths.every((path) => byPath.get(path)?.status === "ok");
  const digest = value("worklet.dsp.hash");
  const manifest = value("worklet.__manifest");
  const valid = sameList(actualPaths, expectedPaths)
    && rows.length === WORKLET_PATHS.length
    && unavailableOk && statusesOk
    && typeof value("locale.tz") === "string" && value("locale.tz").length > 0
    && typeof value("locale.locale") === "string" && value("locale.locale").length > 0
    && Number.isFinite(value("math.tanPI")) && Number.isFinite(value("math.sinh1"))
    && Number.isFinite(value("worklet.sampleRate")) && value("worklet.sampleRate") > 0
    && Number.isFinite(value("worklet.currentTime")) && value("worklet.currentTime") >= 0
    && Number.isFinite(value("worklet.currentFrame")) && value("worklet.currentFrame") >= 0
    && Number.isFinite(value("worklet.dsp.sum"))
    && typeof digest === "string" && /^[0-9a-f]{64}$/.test(digest)
    && value("worklet.dsp.len") === 256
    && typeof value("worklet.globals") === "string" && value("worklet.globals").length > 0
    && manifest && manifest.version === "4.4.0" && manifest.status === "ok"
    && manifest.probeCount === WORKLET_PATHS.length - 1;
  return valid ? [] : [issue("worklet-contract-invalid", {
    context,
    missingPaths: expectedPaths.filter((path) => !byPath.has(path)),
    unexpectedPaths: actualPaths.filter((path) => !WORKLET_PATHS.includes(path)),
  })];
}

function fnv1aText(text) {
  let hash = 0x811c9dc5;
  for (let i = 0; i < text.length; i++) {
    hash ^= text.charCodeAt(i);
    hash = (hash + ((hash << 1) + (hash << 4) + (hash << 7) + (hash << 8) + (hash << 24))) >>> 0;
  }
  return (`00000000${hash.toString(16)}`).slice(-8);
}

function sameStringSet(actual, expected) {
  return Array.isArray(actual) && actual.every((value) => typeof value === "string")
    && new Set(actual).size === actual.length
    && sameList([...actual].sort(), [...expected].sort());
}

function validatePermissionedContract(context, payload, rows, byPath) {
  const out = [];
  const value = (path) => decodedRecord(byPath.get(path));
  const permissionNames = ["geolocation", "camera", "microphone", "notifications"];
  const requested = [
    "perm.geolocation", "perm.camera", "perm.microphone", "perm.notifications",
    "enumerateDevices", "getUserMedia", "geolocation",
  ];
  const baseRequired = [
    ...permissionNames.flatMap((name) => [
      `permissioned.perm.${name}.before`, `permissioned.perm.${name}.after`,
    ]),
    "permissioned.devices.before.count", "permissioned.devices.before.withLabels",
    "permissioned.devices.after.count", "permissioned.devices.after.withLabels",
    "permissioned.devices.labelsRevealed", "permissioned.getUserMedia.result",
    "permissioned.phase.complete",
  ];
  const missingBase = baseRequired.filter((path) => !byPath.has(path));
  for (const path of missingBase) out.push(issue("required-path-missing", { context, path }));

  let devicesValid = missingBase.every((path) => !path.startsWith("permissioned.devices."));
  const deviceStats = Object.create(null);
  for (const phase of ["before", "after"]) {
    const count = value(`permissioned.devices.${phase}.count`);
    const withLabels = value(`permissioned.devices.${phase}.withLabels`);
    const groups = new Map();
    let malformed = false;
    for (const row of rows) {
      if (!row?.path?.startsWith(`permissioned.devices.${phase}[`)) continue;
      const match = new RegExp(`^permissioned\\.devices\\.${phase}\\[(\\d+)\\]\\.(kind|label|deviceId|groupId)$`).exec(row.path);
      if (!match || row.status !== "ok") { malformed = true; continue; }
      const index = Number(match[1]);
      const group = groups.get(index) || {};
      group[match[2]] = decodedRecord(row);
      groups.set(index, group);
    }
    const expectedIndices = Number.isInteger(count) && count >= 0
      ? Array.from({ length: count }, (_, index) => index) : [];
    const actualIndices = [...groups.keys()].sort((a, b) => a - b);
    let labelled = 0;
    let shapeOk = expectedIndices.length >= 2 && sameList(actualIndices, expectedIndices);
    for (const index of expectedIndices) {
      const group = groups.get(index) || {};
      if (!["audioinput", "audiooutput", "videoinput"].includes(group.kind)
          || typeof group.label !== "string" || typeof group.deviceId !== "string"
          || typeof group.groupId !== "string") shapeOk = false;
      if (typeof group.label === "string" && group.label.length > 0) labelled++;
    }
    if (!Number.isInteger(withLabels) || withLabels < 0 || withLabels > count || labelled !== withLabels) shapeOk = false;
    if (malformed || !shapeOk) devicesValid = false;
    deviceStats[phase] = { count, withLabels };
  }
  const labelsRevealed = value("permissioned.devices.labelsRevealed");
  if (typeof labelsRevealed !== "boolean"
      || labelsRevealed !== (deviceStats.after?.withLabels > deviceStats.before?.withLabels)) devicesValid = false;
  if (!devicesValid) out.push(issue("permissioned-device-evidence-invalid", { context }));

  const trackGroups = new Map();
  let tracksMalformed = false;
  for (const row of rows) {
    if (!row?.path?.startsWith("permissioned.track[")) continue;
    const match = /^permissioned\.track\[(\d+)\]\.(kind|label|settings|capabilities|constraints)$/.exec(row.path);
    if (!match || row.status !== "ok") { tracksMalformed = true; continue; }
    const index = Number(match[1]);
    const track = trackGroups.get(index) || {};
    track[match[2]] = decodedRecord(row);
    trackGroups.set(index, track);
  }
  const trackIndices = [...trackGroups.keys()].sort((a, b) => a - b);
  const validObject = (entry, nonEmpty) => entry && typeof entry === "object" && !Array.isArray(entry)
    && (!nonEmpty || Object.keys(entry).length > 0);
  const trackKinds = [];
  let tracksValid = !tracksMalformed && sameList(trackIndices, [0, 1]);
  for (const index of trackIndices) {
    const track = trackGroups.get(index);
    trackKinds.push(track.kind);
    if (!["audio", "video"].includes(track.kind) || typeof track.label !== "string"
        || !validObject(track.settings, true) || !validObject(track.capabilities, true)
        || !validObject(track.constraints, false)) tracksValid = false;
  }
  if (!sameStringSet(trackKinds, ["audio", "video"])) tracksValid = false;
  if (!tracksValid) out.push(issue("permissioned-track-evidence-invalid", { context }));

  const geoPaths = ["latitude", "longitude", "accuracy", "altitude", "altitudeAccuracy", "heading",
    "speed", "timestamp", "coarseBucket"].map((leaf) => `permissioned.geo.${leaf}`);
  const missingGeo = geoPaths.filter((path) => !byPath.has(path));
  let geoValid = missingGeo.length === 0;
  const latitude = value("permissioned.geo.latitude");
  const longitude = value("permissioned.geo.longitude");
  const accuracy = value("permissioned.geo.accuracy");
  const timestamp = value("permissioned.geo.timestamp");
  const requiredNumbers = [
    ["permissioned.geo.latitude", latitude, (number) => number >= -90 && number <= 90],
    ["permissioned.geo.longitude", longitude, (number) => number >= -180 && number <= 180],
    ["permissioned.geo.accuracy", accuracy, (number) => number >= 0],
    ["permissioned.geo.timestamp", timestamp, (number) => number >= 0],
  ];
  for (const [path, number, inRange] of requiredNumbers) {
    if (byPath.get(path)?.status !== "ok" || !Number.isFinite(number) || !inRange(number)) geoValid = false;
  }
  const optionalNumbers = [
    ["permissioned.geo.altitude", () => true],
    ["permissioned.geo.altitudeAccuracy", (number) => number >= 0],
    ["permissioned.geo.heading", (number) => number >= 0 && number <= 360],
    ["permissioned.geo.speed", (number) => number >= 0],
  ];
  for (const [path, inRange] of optionalNumbers) {
    const row = byPath.get(path), number = value(path);
    const validUnavailable = row?.status === "unavailable-in-context" && number === null;
    const validNumber = row?.status === "ok" && Number.isFinite(number) && inRange(number);
    if (!validUnavailable && !validNumber) geoValid = false;
  }
  const coarse = value("permissioned.geo.coarseBucket");
  const roundOne = (number) => Math.round(number * 10) / 10;
  if (typeof coarse !== "string" || !/^[0-9a-f]{8}$/.test(coarse)
      || !Number.isFinite(latitude) || !Number.isFinite(longitude)
      || coarse !== fnv1aText(`${roundOne(latitude)},${roundOne(longitude)}`)) geoValid = false;
  if (!geoValid) out.push(issue("permissioned-geo-evidence-invalid", { context, missingPaths: missingGeo }));

  const manifest = payload?._phaseManifest;
  const permissionStates = new Set(["granted", "denied", "prompt", "unsupported"]);
  const expectedOutcomes = { granted: ["getUserMedia", "geolocation"], denied: [], prompt: [], unsupported: [] };
  let permissionStatesValid = true;
  for (const name of permissionNames) {
    const before = value(`permissioned.perm.${name}.before`);
    const after = value(`permissioned.perm.${name}.after`);
    if (!permissionStates.has(before) || !permissionStates.has(after)) permissionStatesValid = false;
    if (permissionStates.has(after)) expectedOutcomes[after].push(`perm.${name}`);
  }
  const manifestValid = manifest && manifest.phase === "permissioned" && manifest.complete === true
    && sameList(manifest.requested, requested)
    && sameStringSet(manifest.granted, expectedOutcomes.granted)
    && sameStringSet(manifest.denied, expectedOutcomes.denied)
    && sameStringSet(manifest.prompt, expectedOutcomes.prompt)
    && sameStringSet(manifest.unsupported, expectedOutcomes.unsupported)
    && sameStringSet(manifest.timeout, [])
    && manifest.steps && manifest.steps.enumerateBefore === true && manifest.steps.enumerateAfter === true
    && manifest.steps.getUserMedia === "granted" && manifest.steps.geolocation === "granted"
    && value("permissioned.getUserMedia.result") === "granted"
    && value("permissioned.phase.complete") === true
    && permissionStatesValid;
  if (!manifestValid) out.push(issue("permissioned-manifest-invalid", { context }));
  return out;
}

function validateRequiredPaths(context, payload, identity) {
  const out = [];
  const rows = Array.isArray(payload?._measurements) ? payload._measurements : [];
  const byPath = new Map(rows.map((r) => [r?.path, r]));
  const requirePath = (path) => {
    if (!byPath.has(path)) out.push(issue("required-path-missing", { context, path }));
  };

  if (FULL_COLLECTOR_CONTEXTS.has(context)) {
    requirePath("collector.__manifest");
    out.push(...validateCollectorJobEvidence(context, byPath));
    out.push(...validateCollectorPathContract(context, byPath));
    out.push(...validateCanvasEvidence(context, byPath));
    out.push(...validateWebglEvidence(context, byPath));
    out.push(...validateWebgpuEvidence(context, byPath));
    out.push(...validateAudioEvidence(context, byPath));
    out.push(...validateWebrtcEvidence(context, byPath));

    const manifestRow = byPath.get("collector.__manifest");
    const manifest = decodedRecord(manifestRow);
    if (!manifest || manifest.collectorVersion !== "4.4.0" || manifest.context !== context
        || !sameList(manifest.expectedJobs, DEFAULT_COLLECTOR_JOBS)
        || !sameList(manifest.completedJobs, DEFAULT_COLLECTOR_JOBS)
        || !Array.isArray(manifest.failedJobs) || manifest.failedJobs.length !== 0
        || manifest.measurementCount !== rows.length) {
      out.push(issue("collector-manifest-invalid", { context }));
    }
    if (context === "cross-origin-iframe") {
      const evidence = payload?._crossOrigin, expected = identity?.oopif;
      const bound = payload?._boundChild;
      if (!evidence || !expected || evidence.parentOrigin !== expected.parentOrigin
          || evidence.childOrigin !== expected.childOrigin || evidence.eventOriginVerified !== true
          || evidence.crossSiteConfigured !== true || evidence.configurationId !== expected.configurationId
          || evidence.collectorBuild !== identity?.collectorBuild
          || evidence.collectorArtifactSha256 !== identity?.collectorArtifactSha256
          || evidence.captureKey !== identity?.captureKey
          || evidence.requestId !== bound?.requestId
          || evidence.acknowledgementSha256 !== bound?.acknowledgementSha256
          || evidence.registrableParentSite !== expected.registrableParentSite
          || evidence.registrableChildSite !== expected.registrableChildSite
          || evidence.processEvidenceSha256 !== expected.processEvidenceSha256
          || evidence.processEvidenceBuild !== expected.processEvidenceBuild) {
        out.push(issue("cross-origin-evidence-invalid", { context }));
      }
    }
    if (context === "iframe-url" || context === "cross-origin-iframe") {
      const boundIssue = validateBoundChildEvidence(context, payload, identity);
      if (boundIssue) out.push(boundIssue);
    }
    if (context === "service-worker") {
      const sw = payload?._serviceWorker;
      const expectedBinding = expectedServiceWorkerBinding(identity);
      const expectedAck = canonicalSha256({
        context: "service-worker",
        collectorBuild: identity?.collectorBuild,
        collectorArtifactSha256: identity?.collectorArtifactSha256,
        captureKey: identity?.captureKey,
        challenge: identity?.serviceWorkerChallenge,
      });
      if (!sw || sw.context !== "service-worker"
          || sw.collectorBuild !== identity?.collectorBuild
          || sw.collectorArtifactSha256 !== identity?.collectorArtifactSha256
          || sw.captureKey !== identity?.captureKey
          || sw.challenge !== identity?.serviceWorkerChallenge
          || sw.handshakeVersion !== 1
          || typeof sw.requestId !== "string" || !/^[A-Za-z0-9_-]{22,240}$/.test(sw.requestId)
          || !expectedBinding || sw.scriptURL !== expectedBinding.scriptURL
          || sw.scope !== expectedBinding.scope
          || sw.acknowledgementSha256 !== expectedAck) {
        out.push(issue("service-worker-evidence-invalid", { context }));
      }
    }
  } else if (context === "audio-worklet") {
    out.push(...validateAudioWorkletContract(context, rows, byPath));
  } else if (context === "permissioned") {
    out.push(...validatePermissionedContract(context, payload, rows, byPath));
  }
  return out;
}

function validateControls(mainPayload, required) {
  const out = [];
  const rows = mainPayload && mainPayload._measurements;
  if (!Array.isArray(required) || required.length === 0) {
    return [issue("control-matrix-empty")];
  }
  if (!Array.isArray(rows)) return [issue("control-incomplete", { detail: "main-frame has no typed measurements" })];

  for (const path of CONTROL_SANITY_PATHS) {
    const matches = rows.filter((candidate) => candidate?.path === path);
    if (matches.length !== 1 || matches[0].status !== "ok") {
      out.push(issue("control-sanity-incomplete", {
        path,
        detail: matches.length === 0 ? "missing" : matches.length > 1 ? "duplicate" : "non-ok",
      }));
    }
  }

  for (const engine of required) {
    const matches = rows.filter((r) => r && r.path === `control.${engine.id}.__manifest`);
    if (matches.length !== 1) {
      out.push(issue("control-incomplete", { engine: engine.id, detail: matches.length ? "duplicate manifest" : "missing manifest" }));
      continue;
    }
    const row = matches[0];
    const status = encodedField(row.value, "status");
    const version = String(encodedField(row.value, "version") ?? "");
    const componentCount = encodedField(row.value, "componentCount");
    const errorCount = encodedField(row.value, "errorCount");
    const hash = encodedField(row.value, "hash");
    const hashAlgorithm = encodedField(row.value, "hashAlgorithm");
    const componentKeys = decodedField(row.value, "componentKeys");
    const manifest = decodedRecord(row);
    const versionOk = engine.version instanceof RegExp ? engine.version.test(version) : version === engine.version;
    const expectedEngineName = engine.id === "thumbmark" ? "thumbmarkjs" : engine.id;
    const prefix = `control.${engine.id}.`;
    const knownDerived = (suffix) => (engine.id === "thumbmark" && suffix === "hash")
      || (engine.id === "fingerprintjs" && suffix === "visitorId")
      || (engine.id === "fpscanner" && suffix.startsWith("test."));
    const componentRows = rows.filter((r) => r && r.path?.startsWith(prefix)
      && r.path !== `${prefix}__manifest` && !knownDerived(r.path.slice(prefix.length)));
    const actualKeys = componentRows.map((r) => r.path.slice(prefix.length)).sort();
    const declaredKeys = Array.isArray(componentKeys) ? componentKeys : [];
    const declaredShapeOk = declaredKeys.every((key) => typeof key === "string" && key
      && key !== "__manifest" && !knownDerived(key))
      && sameList(declaredKeys, [...new Set(declaredKeys)].sort())
      && sameList(declaredKeys, actualKeys);
    const componentMap = Object.create(null);
    for (const key of actualKeys) {
      const component = componentRows.find((candidate) => candidate.path === `${prefix}${key}`);
      const meta = {};
      if (component?.meta?.special != null) meta.special = component.meta.special;
      if (component?.meta?.count != null) meta.count = component.meta.count;
      componentMap[key] = { valueType: component?.valueType, value: component?.value, meta };
    }
    const computedHash = canonicalSha256(componentMap);
    let engineSpecificOk = true;
    if (engine.id === "clientjs") {
      engineSpecificOk = sameList(actualKeys, CLIENTJS_COMPONENT_KEYS);
    }
    if (engine.id === "thumbmark" || engine.id === "fingerprintjs") {
      const derivedPath = engine.id === "thumbmark"
        ? "control.thumbmark.hash" : "control.fingerprintjs.visitorId";
      const derivedRows = rows.filter((candidate) => candidate?.path === derivedPath);
      const derivedValue = derivedRows.length === 1 ? decodedRecord(derivedRows[0]) : null;
      engineSpecificOk = derivedRows.length === 1 && derivedRows[0].status === "ok"
        && typeof derivedValue === "string" && derivedValue.length > 0;
    }
    if (engine.id === "fpscanner") {
      const testPrefix = "control.fpscanner.test.";
      const testRows = rows.filter((candidate) => candidate?.path?.startsWith(testPrefix));
      const actualTestKeys = testRows.map((candidate) => candidate.path.slice(testPrefix.length)).sort();
      const testMap = Object.create(null);
      const verdictByConsistency = { 1: "INCONSISTENT", 2: "UNSURE", 3: "CONSISTENT" };
      let inconsistentCount = 0;
      let testsValid = sameList(actualTestKeys, FPSCANNER_TEST_KEYS)
        && testRows.length === FPSCANNER_TEST_KEYS.length;
      for (const key of actualTestKeys) {
        const testRow = testRows.find((candidate) => candidate.path === `${testPrefix}${key}`);
        const decoded = decodedRecord(testRow);
        if (testRow?.status !== "ok" || !decoded || typeof decoded !== "object" || Array.isArray(decoded)
            || ![1, 2, 3].includes(decoded.consistent)
            || decoded.verdict !== verdictByConsistency[decoded.consistent]
            || !Object.prototype.hasOwnProperty.call(decoded, "data")) testsValid = false;
        if (decoded?.consistent === 1) inconsistentCount++;
        const meta = {};
        if (testRow?.meta?.special != null) meta.special = testRow.meta.special;
        if (testRow?.meta?.count != null) meta.count = testRow.meta.count;
        testMap[key] = { valueType: testRow?.valueType, value: testRow?.value, meta };
      }
      engineSpecificOk = testsValid
        && manifest?.testCount === FPSCANNER_TEST_KEYS.length
        && sameList(manifest?.testKeys, FPSCANNER_TEST_KEYS)
        && manifest?.testKeySetHash === canonicalSha256(FPSCANNER_TEST_KEYS)
        && manifest?.testSetHash === canonicalSha256(testMap)
        && manifest?.testHashAlgorithm === "sha256"
        && sameList(manifest?.expectedTestKeys, FPSCANNER_TEST_KEYS)
        && manifest?.expectedTestKeySetHash === canonicalSha256(FPSCANNER_TEST_KEYS)
        && manifest?.inconsistentCount === inconsistentCount
        && manifest?.invalidTestCount === 0;
    }
    if (row.status !== "ok" || status !== "ok" || !versionOk
        || manifest?.engine !== expectedEngineName
        || !Number.isFinite(manifest?.durationMs) || manifest.durationMs < 0
        || !Number.isInteger(componentCount) || componentCount <= 0
        || componentCount !== componentRows.length || !declaredShapeOk || errorCount !== 0
        || hashAlgorithm !== "sha256" || hash !== computedHash || !engineSpecificOk) {
      out.push(issue("control-incomplete", { engine: engine.id, detail: "manifest contract failed" }));
    }
  }
  return out;
}

/**
 * Validate one side (`plain` or `anti`) from already parsed JSONL records.
 *
 * Input records have the persisted outer shape `{context, measurements}`.
 * `serverExpectedContexts` MUST be a non-empty server-owned canonical matrix;
 * the browser's terminal manifest is only evidence and never defines coverage.
 */
export function validateSideCapture(input = {}) {
  const issues = [];
  const expected = input.serverExpectedContexts;
  const records = Array.isArray(input.records) ? input.records : [];
  // This collector build always ships four fixed control engines. A caller
  // override is accepted only as an exact restatement of that build contract;
  // a subset/broader regex must never lower READY requirements.
  const suppliedControls = input.requiredControls;
  if (suppliedControls !== undefined && !isCanonicalControlMatrix(suppliedControls)) {
    issues.push(issue("control-matrix-contract-mismatch"));
  }
  const controls = DEFAULT_CONTROL_ENGINES;
  const processEvidence = input.oopif?.processEvidence;
  const expectedNetworkBuild = input.expectedNetworkBuild;

  const metadataOk = (input.environment === "plain" || input.environment === "anti")
    && typeof input.pairKey === "string" && input.pairKey.length > 0 && input.pairKey.length <= 200
    && typeof input.captureKey === "string" && input.captureKey.length > 0 && input.captureKey.length <= 240
    && input.captureKey === `${input.pairKey}:${input.environment}`
    && typeof input.collectorBuild === "string" && /^[0-9a-f]{64}$/.test(input.collectorBuild)
    && input.oopif && typeof input.oopif === "object"
    && typeof input.oopif.parentOrigin === "string" && typeof input.oopif.childOrigin === "string"
    && input.oopif.parentOrigin !== input.oopif.childOrigin
    && validOrigin(input.oopif.parentOrigin) && validOrigin(input.oopif.childOrigin)
    && validRegistrableSite(input.oopif.registrableParentSite)
    && validRegistrableSite(input.oopif.registrableChildSite)
    && input.oopif.registrableParentSite !== input.oopif.registrableChildSite
    && typeof input.oopif.configurationId === "string" && input.oopif.configurationId.length > 0
    && processEvidence && typeof processEvidence === "object" && !Array.isArray(processEvidence)
    && !("captureKey" in processEvidence)
    && processEvidence.collectorBuild === input.collectorBuild
    && processEvidence.configurationId === input.oopif.configurationId
    && processEvidence.parentOrigin === input.oopif.parentOrigin
    && processEvidence.childOrigin === input.oopif.childOrigin
    && processEvidence.registrableParentSite === input.oopif.registrableParentSite
    && processEvidence.registrableChildSite === input.oopif.registrableChildSite
    && typeof processEvidence.parentProcessId === "string" && processEvidence.parentProcessId.length > 0
    && typeof processEvidence.childProcessId === "string" && processEvidence.childProcessId.length > 0
    && processEvidence.parentProcessId !== processEvidence.childProcessId
    && typeof input.oopif.processEvidenceSha256 === "string"
    && input.oopif.processEvidenceSha256 === canonicalSha256(processEvidence)
    && input.oopif.processEvidenceBuild === input.collectorBuild;
  if (!metadataOk) issues.push(issue("capture-metadata-invalid"));
  if (typeof input.collectorArtifactSha256 !== "string"
      || !/^[0-9a-f]{64}$/.test(input.collectorArtifactSha256)) {
    issues.push(issue("collector-artifact-invalid"));
  }
  if (typeof input.serviceWorkerChallenge !== "string"
      || !/^[A-Za-z0-9_-]{22,240}$/.test(input.serviceWorkerChallenge)) {
    issues.push(issue("service-worker-challenge-invalid"));
  }
  if (typeof expectedNetworkBuild !== "string" || !/^[0-9a-f]{64}$/.test(expectedNetworkBuild)) {
    issues.push(issue("expected-network-build-invalid"));
  }
  const expectedIdentity = {
    environment: input.environment,
    pairKey: input.pairKey,
    captureKey: input.captureKey,
    collectorBuild: input.collectorBuild,
    collectorArtifactSha256: input.collectorArtifactSha256,
    oopif: input.oopif,
    serviceWorkerChallenge: input.serviceWorkerChallenge,
  };

  if (!Array.isArray(expected) || expected.length === 0) {
    issues.push(issue("expected-matrix-empty"));
  }
  const canonical = Array.isArray(expected) ? expected.filter((x) => typeof x === "string" && x) : [];
  if (new Set(canonical).size !== canonical.length || canonical.length !== (Array.isArray(expected) ? expected.length : 0)) {
    issues.push(issue("expected-matrix-invalid"));
  }
  if (canonical.includes("run-manifest")) issues.push(issue("expected-matrix-terminal-context"));
  if (!sameList(canonical, DEFAULT_EXPECTED_CONTEXTS)) {
    issues.push(issue("expected-matrix-contract-mismatch"));
  }
  for (const role of REQUIRED_ROLES) {
    if (!canonical.includes(role)) issues.push(issue("expected-matrix-missing-required", { context: role }));
  }
  if (!Number.isInteger(input.unreadableLines ?? 0) || (input.unreadableLines ?? 0) < 0) {
    issues.push(issue("unreadable-count-invalid"));
  } else if ((input.unreadableLines ?? 0) > 0) {
    issues.push(issue("unreadable-jsonl", { count: input.unreadableLines }));
  }

  const grouped = new Map();
  for (const row of records) {
    if (!row || typeof row !== "object" || typeof row.context !== "string"
        || !row.measurements || typeof row.measurements !== "object" || Array.isArray(row.measurements)) {
      issues.push(issue("outer-record-invalid"));
      continue;
    }
    if (!sameIdentity(row.identity, expectedIdentity)) {
      issues.push(issue("record-identity-mismatch", { context: row.context }));
    }
    const list = grouped.get(row.context) || [];
    list.push(row);
    grouped.set(row.context, list);
  }

  const allowedContexts = new Set([...canonical, "run-manifest"]);
  for (const [context, list] of grouped) {
    if (!allowedContexts.has(context)) issues.push(issue("unexpected-context", { context }));
    if (list.length > 1) issues.push(issue("duplicate-context", { context, count: list.length }));
  }
  for (const context of canonical) {
    const count = (grouped.get(context) || []).length;
    if (count === 0) issues.push(issue("missing-context", { context }));
  }

  // Browser-owned terminal manifest is required exactly once, but never trusted
  // to shrink the server's canonical matrix.
  const manifests = grouped.get("run-manifest") || [];
  if (manifests.length === 0) issues.push(issue("manifest-missing"));
  else if (manifests.length === 1) {
    const m = manifests[0].measurements;
    if (!sameIdentity(m.identity, expectedIdentity)) issues.push(issue("manifest-identity-mismatch"));
    if (!Array.isArray(m.expected) || m.expected.length === 0) {
      issues.push(issue("manifest-expected-empty"));
    } else if (!sameList(m.expected, canonical)) {
      issues.push(issue("manifest-expected-mismatch"));
    }
    if (!m.realms || typeof m.realms !== "object") {
      issues.push(issue("manifest-realms-missing"));
    } else {
      const realmKeys = Object.keys(m.realms);
      if (!sameList(realmKeys, canonical)) issues.push(issue("manifest-realms-mismatch"));
      for (const context of canonical) {
        if (!m.realms[context] || m.realms[context].status !== "finished") {
          issues.push(issue("manifest-realm-incomplete", { context, status: m.realms[context]?.status ?? "missing" }));
        }
      }
    }
  }

  // Grade every persisted browser context against the same strict schema and
  // non-ok policy. With duplicate outer contexts, inspect all copies rather than
  // silently selecting the last one.
  for (const [context, list] of grouped) {
    if (SPECIAL_CONTEXTS.has(context)) continue;
    for (const row of list) {
      const payload = row.measurements;
      if (payload._context !== context) issues.push(issue("context-mismatch", { context, embedded: payload._context }));
      const schema = classifySessionSchema(payload);
      if (schema !== "CURRENT") issues.push(issue("browser-schema", { context, status: schema }));
      for (const dup of findDuplicatePaths(payload)) {
        issues.push(issue("duplicate-measurement", { context: dup.context, path: dup.path, count: dup.count }));
      }
      for (const bad of scanUnexpected(payload, context)) {
        issues.push(issue("unexpected-non-ok", { context, path: bad.path, status: bad.status }));
      }
      issues.push(...validateRequiredPaths(context, payload, expectedIdentity));
    }
  }

  const permissioned = grouped.get("permissioned") || [];
  if (permissioned.length === 1 && permissioned[0].measurements._phaseManifest?.complete !== true) {
    issues.push(issue("permissioned-incomplete"));
  }

  const network = grouped.get("network") || [];
  if (network.length === 1) {
    const status = classifyNetworkSchema(network[0].measurements);
    if (status !== "CURRENT") issues.push(issue("network-schema", { status }));
    if (network[0].measurements.captureBuild !== expectedNetworkBuild) {
      issues.push(issue("network-build-mismatch", {
        expected: expectedNetworkBuild,
        actual: network[0].measurements.captureBuild,
      }));
    }
  }

  const main = grouped.get("main-frame") || [];
  if (main.length === 1) issues.push(...validateControls(main[0].measurements, controls));
  else if (main.length === 0) issues.push(issue("control-incomplete", { detail: "main-frame missing" }));

  const blocking = issues.filter((x) => x.blocking);
  return {
    ready: blocking.length === 0,
    overall: blocking.length === 0 ? "READY" : "NOT_READY",
    expected: canonical,
    present: [...grouped.keys()].sort(),
    issues,
  };
}

export function validatePairedCapture({ plain, anti } = {}) {
  const p = validateSideCapture(plain || {});
  const a = validateSideCapture(anti || {});
  const issues = [];
  if (plain?.environment !== "plain" || anti?.environment !== "anti") {
    issues.push(issue("pair-environments-invalid"));
  }
  if (!plain?.captureKey || !anti?.captureKey || plain.captureKey === anti.captureKey) {
    issues.push(issue("pair-capture-not-distinct"));
  }
  if (!plain?.pairKey || plain.pairKey !== anti?.pairKey) issues.push(issue("pair-key-mismatch"));
  if (!plain?.collectorBuild || plain.collectorBuild !== anti?.collectorBuild) issues.push(issue("pair-build-mismatch"));
  if (!plain?.collectorArtifactSha256
      || plain.collectorArtifactSha256 !== anti?.collectorArtifactSha256) {
    issues.push(issue("pair-collector-artifact-mismatch"));
  }
  if (!plain?.expectedNetworkBuild || plain.expectedNetworkBuild !== anti?.expectedNetworkBuild) {
    issues.push(issue("pair-expected-network-build-mismatch"));
  }
  if (!plain?.oopif || !anti?.oopif
      || plain.oopif.parentOrigin !== anti.oopif.parentOrigin
      || plain.oopif.childOrigin !== anti.oopif.childOrigin
      || plain.oopif.registrableParentSite !== anti.oopif.registrableParentSite
      || plain.oopif.registrableChildSite !== anti.oopif.registrableChildSite
      || plain.oopif.configurationId !== anti.oopif.configurationId
      || plain.oopif.processEvidenceSha256 !== anti.oopif.processEvidenceSha256
      || plain.oopif.processEvidenceBuild !== anti.oopif.processEvidenceBuild) {
    issues.push(issue("pair-oopif-mismatch"));
  }
  if (!sameList(plain?.serverExpectedContexts, anti?.serverExpectedContexts)) issues.push(issue("pair-matrix-mismatch"));
  const networkBuild = (side) => side?.records?.find((row) => row?.context === "network")?.measurements?.captureBuild;
  const plainNetworkBuild = networkBuild(plain), antiNetworkBuild = networkBuild(anti);
  if (!plainNetworkBuild || plainNetworkBuild !== antiNetworkBuild) issues.push(issue("pair-network-build-mismatch"));
  const ready = p.ready && a.ready && issues.length === 0;
  return { ready, overall: ready ? "READY" : "NOT_READY", plain: p, anti: a, issues };
}
