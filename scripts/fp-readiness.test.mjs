import { createHash } from "node:crypto";
import {
  DEFAULT_REQUIRED_JOB_EVIDENCE,
  validateSideCapture,
  validatePairedCapture,
} from "../lib/fp-readiness.mjs";
import { encodeValue } from "../lib/fp-encode.mjs";

let pass = 0, fail = 0;
function ok(label, cond) { if (cond) pass++; else { fail++; console.log("  ✗ " + label); } }

const rec = (path, value = "x", extra = {}) => {
  const enc = encodeValue(value);
  const meta = {};
  if (enc.special != null) meta.special = enc.special;
  if (enc.count != null) meta.count = enc.count;
  return {
    path, context: extra.context || "main-frame", phase: extra.phase || "passive",
    status: extra.status || "ok", valueType: enc.valueType, value: enc.value,
    error: extra.error || null, meta,
  };
};

function canonical(value) {
  if (Array.isArray(value)) return value.map(canonical);
  if (value && typeof value === "object") {
    return Object.fromEntries(Object.keys(value).sort().map((key) => [key, canonical(value[key])]));
  }
  return value;
}
const canonicalSha256 = (value) => createHash("sha256")
  .update(JSON.stringify(canonical(value)), "utf8").digest("hex");

function decodedTestValue(row) {
  function decode(node) {
    if (!node || typeof node !== "object") return undefined;
    if (node.valueType === "array") return node.value.map(decode);
    if (node.valueType === "object") {
      return Object.fromEntries(Object.entries(node.value.props).map(([key, child]) => [key, decode(child)]));
    }
    return node.value;
  }
  return decode(row);
}
function replaceEncodedTestValue(row, value) {
  const encoded = encodeValue(value);
  row.valueType = encoded.valueType;
  row.value = encoded.value;
  row.meta = {};
  if (encoded.special != null) row.meta.special = encoded.special;
  if (encoded.count != null) row.meta.count = encoded.count;
}
function encodedIdentity(row) {
  const meta = {};
  if (row.meta?.special != null) meta.special = row.meta.special;
  if (row.meta?.count != null) meta.count = row.meta.count;
  return { valueType: row.valueType, value: row.value, meta };
}

const CONTROL_COMPONENTS = Object.freeze({ component0: 0, component1: 1, component2: Object.freeze([1, 2]) });
const CONTROL_COMPONENT_KEYS = Object.freeze(Object.keys(CONTROL_COMPONENTS));
const FPSCANNER_TEST_KEYS = Object.freeze([
  "CHR_BATTERY", "CHR_DEBUG_TOOLS", "CHR_MEMORY", "HEADCHR_CHROME_OBJ", "HEADCHR_IFRAME",
  "HEADCHR_PERMISSIONS", "HEADCHR_PLUGINS", "HEADCHR_UA", "MQ_SCREEN", "PHANTOM_ETSL",
  "PHANTOM_LANGUAGE", "PHANTOM_OVERFLOW", "PHANTOM_PROPERTIES", "PHANTOM_UA",
  "PHANTOM_WEBSOCKET", "PHANTOM_WINDOW_HEIGHT", "SELENIUM_DRIVER", "SEQUENTUM",
  "TRANSPARENT_PIXEL", "VIDEO_CODECS", "WEBDRIVER",
]);
const CLIENTJS_COMPONENT_KEYS = Object.freeze([
  "getFingerprint", "getUserAgent", "getBrowser", "getBrowserVersion", "getOS", "getOSVersion",
  "getDevice", "getCPU", "getEngine", "getScreenPrint", "getColorDepth",
  "getCurrentResolution", "getAvailableResolution", "getTimeZone", "getLanguage",
  "getSystemLanguage", "getCanvasPrint", "getPlugins", "getFonts",
].sort());
const CONTROL_SANITY_PATHS = Object.freeze([
  "control.sanity.headless.webdriver", "control.sanity.headless.headlessUA",
  "control.sanity.headless.chromeObject", "control.sanity.headless.chromeRuntime",
  "control.sanity.headless.pluginsZero", "control.sanity.headless.languagesEmpty",
  "control.sanity.headless.notifVsPerm", "control.sanity.headless.appVersionInUA",
  "control.sanity.consistency.uaPlatformMatch", "control.sanity.consistency.toStringNative",
  "control.sanity.consistency.languagesVsLanguage", "control.sanity.consistency.hardwareConcurrency",
  "control.sanity.consistency.deviceMemory", "control.sanity.consistency.productSub",
  "control.sanity.consistency.vendorMatch",
]);
function controlRows(id, version) {
  const componentKeys = id === "clientjs" ? CLIENTJS_COMPONENT_KEYS : CONTROL_COMPONENT_KEYS;
  const rows = componentKeys.map((key, index) => rec(`control.${id}.${key}`,
    id === "clientjs" ? `value-${index}` : CONTROL_COMPONENTS[key]));
  const componentMap = Object.fromEntries(rows.map((row, index) => [componentKeys[index], encodedIdentity(row)]));
  if (id === "fpscanner") {
    for (const key of FPSCANNER_TEST_KEYS) {
      rows.push(rec(`control.fpscanner.test.${key}`, {
        consistent: key === "VIDEO_CODECS" ? 2 : 3,
        verdict: key === "VIDEO_CODECS" ? "UNSURE" : "CONSISTENT",
        data: { test: key },
      }));
    }
  }
  const testRows = id === "fpscanner"
    ? rows.filter((row) => row.path.startsWith("control.fpscanner.test.")) : [];
  const testMap = Object.fromEntries(testRows.map((row) => [
    row.path.slice("control.fpscanner.test.".length), encodedIdentity(row),
  ]));
  if (id === "thumbmark") rows.push(rec("control.thumbmark.hash", "thumbmark-hash"));
  if (id === "fingerprintjs") rows.push(rec("control.fingerprintjs.visitorId", "fingerprint-visitor-id"));
  rows.push(rec(`control.${id}.__manifest`, {
    engine: id === "thumbmark" ? "thumbmarkjs" : id,
    version, status: "ok", durationMs: 1, componentCount: componentKeys.length,
    componentKeys, errorCount: 0,
    hash: canonicalSha256(componentMap), hashAlgorithm: "sha256",
    ...(id === "fpscanner" ? {
      testCount: FPSCANNER_TEST_KEYS.length, testKeys: FPSCANNER_TEST_KEYS,
      testKeySetHash: canonicalSha256(FPSCANNER_TEST_KEYS), testSetHash: canonicalSha256(testMap),
      testHashAlgorithm: "sha256", expectedTestKeys: FPSCANNER_TEST_KEYS,
      expectedTestKeySetHash: canonicalSha256(FPSCANNER_TEST_KEYS),
      inconsistentCount: 0, invalidTestCount: 0,
    } : {}),
  }));
  return rows;
}

const CONTROLS = [
  ["thumbmark", "1.11.0"], ["fingerprintjs", "5.0.0"],
  ["fpscanner", "0.1.5+fpcollect1.0.5"], ["clientjs", "0.2.1"],
];
const EXPECTED = [
  "main-frame", "dedicated-worker", "dedicated-worker-module",
  "shared-worker", "shared-worker-module", "audio-worklet", "iframe",
  "iframe-url", "sandboxed-iframe", "credentialless-iframe",
  "service-worker", "cross-origin-iframe", "network", "permissioned",
];
const COLLECTOR_JOBS = [
  "locale", "canvas", "webgl", "webgpu", "audio", "fonts", "css",
  "math", "codecs", "speech", "webrtc", "misc", "uach", "hooks",
  "cssSupports", "mediaDevices", "keyboard", "storage", "env",
  "clientRects", "wasm", "mediaCaps", "device", "intlx", "errors",
  "control",
];
const OOPIF = {
  parentOrigin: "https://panel.example.test",
  childOrigin: "https://probe.other.test",
  registrableParentSite: "example.test",
  registrableChildSite: "other.test",
  configurationId: "oopif-config-1",
};

const REQUIRED_JOB_ROWS = Object.freeze({
  locale: ["locale.resolvedTZ", "UTC"],
  canvas: ["canvas.pixelSha256", "a".repeat(64)],
  webgl: ["webgl.webgl.status", "ok"],
  webgpu: ["webgpu.available", null, { status: "unsupported" }],
  audio: ["audio.status", "ok"],
  fonts: ["fonts.hash", "fonts-hash"],
  css: ["css.deviceAspect", false],
  math: ["math.powPI", 1.2],
  codecs: ['codecs.canPlay[video/mp4; codecs="avc1.42E01E"]', "probably"],
  speech: ["speech.count", 1],
  webrtc: ["webrtc.status", null, { status: "unsupported" }],
  misc: ["misc.webdriver", false],
  uach: ["uach.available", null, { status: "unsupported" }],
  hooks: ["hooks.native.toString", "native"],
  cssSupports: ["cssSupports.available", null, { status: "unsupported" }],
  mediaDevices: ["mediaDevices.available", null, { status: "unavailable-in-context" }],
  keyboard: ["keyboard.available", null, { status: "unavailable-in-context" }],
  storage: ["storage.localStorage", "object"],
  env: ["env.devicePixelRatio", 2],
  clientRects: ["clientRects.bcr", "100,20"],
  wasm: ["wasm.streaming", true],
  mediaCaps: ["mediaCaps.mediaCapabilities", null, { status: "unavailable-in-context" }],
  device: ["device.gamepads", null, { status: "unavailable-in-context" }],
  intlx: ["intlx.tzCount", 400],
  errors: ["errors.syncFrames", 2],
});

// Literal, hand-checked path contract from assets/fingerprint-probe.html.  The
// test fixture deliberately does not import the validator's contract table: if
// production accidentally drops a path from its table, these deletion tests
// must still fail.
const LOCALE_PATHS = [
  "locale.resolvedTZ", "locale.resolvedLocale", "locale.calendar", "locale.numberingSystem",
  "locale.tzOffset", "locale.dtfWinter", "locale.dtfSummer", "locale.dateToLocale",
  "locale.numberToLocale", "locale.relativeTime", "locale.collator", "locale.listFormat",
  "locale.pluralRules", "locale.firstWeekday",
];
const CANVAS_PATHS = [
  "canvas.winding", "canvas.width", "canvas.height", "canvas.pixelBytes", "canvas.pixelFnv",
  "canvas.pixelSha256", "canvas.encFmt", "canvas.encLen", "canvas.repeats", "canvas.stable",
];
const WEBGL_CORE_PARAMS = [
  "ACTIVE_TEXTURE", "ALIASED_LINE_WIDTH_RANGE", "ALIASED_POINT_SIZE_RANGE", "ALPHA_BITS",
  "BLUE_BITS", "DEPTH_BITS", "GREEN_BITS", "RED_BITS", "STENCIL_BITS",
  "MAX_COMBINED_TEXTURE_IMAGE_UNITS", "MAX_CUBE_MAP_TEXTURE_SIZE",
  "MAX_FRAGMENT_UNIFORM_VECTORS", "MAX_RENDERBUFFER_SIZE", "MAX_TEXTURE_IMAGE_UNITS",
  "MAX_TEXTURE_SIZE", "MAX_VARYING_VECTORS", "MAX_VERTEX_ATTRIBS",
  "MAX_VERTEX_TEXTURE_IMAGE_UNITS", "MAX_VERTEX_UNIFORM_VECTORS", "MAX_VIEWPORT_DIMS",
  "RENDERER", "SHADING_LANGUAGE_VERSION", "VENDOR", "VERSION",
];
const WEBGL2_PARAMS = [
  "MAX_3D_TEXTURE_SIZE", "MAX_ARRAY_TEXTURE_LAYERS", "MAX_COLOR_ATTACHMENTS",
  "MAX_COMBINED_FRAGMENT_UNIFORM_COMPONENTS", "MAX_COMBINED_UNIFORM_BLOCKS",
  "MAX_COMBINED_VERTEX_UNIFORM_COMPONENTS", "MAX_DRAW_BUFFERS", "MAX_ELEMENT_INDEX",
  "MAX_ELEMENTS_INDICES", "MAX_ELEMENTS_VERTICES", "MAX_FRAGMENT_INPUT_COMPONENTS",
  "MAX_FRAGMENT_UNIFORM_BLOCKS", "MAX_FRAGMENT_UNIFORM_COMPONENTS", "MAX_PROGRAM_TEXEL_OFFSET",
  "MAX_SAMPLES", "MAX_TEXTURE_LOD_BIAS", "MAX_TRANSFORM_FEEDBACK_SEPARATE_ATTRIBS",
  "MAX_UNIFORM_BLOCK_SIZE", "MAX_UNIFORM_BUFFER_BINDINGS", "MAX_VARYING_COMPONENTS",
  "MAX_VERTEX_OUTPUT_COMPONENTS", "MAX_VERTEX_UNIFORM_BLOCKS", "MAX_VERTEX_UNIFORM_COMPONENTS",
];
const WEBGL_PRECISION = ["VERTEX_SHADER", "FRAGMENT_SHADER"].flatMap((stage) =>
  ["HIGH_FLOAT", "MEDIUM_FLOAT", "LOW_FLOAT", "HIGH_INT", "MEDIUM_INT", "LOW_INT"]
    .map((precision) => `${stage}.${precision}`));
const WEBGL_RENDER_LEAVES = [
  "status", "fnv", "sha256", "compile", "link", "glError", "width", "height",
  "pixelBytes", "stable", "repeats", "sha256Repeats", "fnvRepeats",
];
const CSS_MEDIA = [
  "prefers-color-scheme: dark", "prefers-color-scheme: light", "prefers-reduced-motion: reduce",
  "prefers-reduced-transparency: reduce", "prefers-contrast: more", "prefers-contrast: less",
  "inverted-colors: inverted", "forced-colors: active", "dynamic-range: high",
  "video-dynamic-range: high", "any-hover: hover", "any-pointer: fine", "any-pointer: coarse",
  "hover: hover", "pointer: fine", "pointer: coarse", "color-gamut: srgb", "color-gamut: p3",
  "color-gamut: rec2020", "monochrome: 0", "orientation: landscape", "display-mode: browser",
  "display-mode: standalone", "scripting: enabled", "update: fast", "overflow-block: scroll",
];
const MATH_PATHS = [
  "acos", "acosh", "asin", "asinh", "atan", "atanh", "cbrt", "cos", "cosh", "exp",
  "expm1", "log", "log1p", "log10", "sin", "sinh", "sqrt", "tan", "tanh", "tan1e300",
  "powPI",
].map((name) => `math.${name}`);
const CODEC_TYPES = [
  'video/mp4; codecs="avc1.42E01E"', 'video/mp4; codecs="hev1.1.6.L93.B0"',
  'video/webm; codecs="vp8"', 'video/webm; codecs="vp9"',
  'video/mp4; codecs="av01.0.05M.08"', 'video/ogg; codecs="theora"', "audio/mpeg",
  'audio/mp4; codecs="mp4a.40.2"', 'audio/ogg; codecs="vorbis"',
  'audio/ogg; codecs="opus"', 'audio/webm; codecs="opus"', "audio/flac", "audio/wav",
];
const MISC_PATHS = [
  "misc.errorStack", "misc.perfMemory", "misc.timerRes", "misc.chromeObj", "misc.webdriver",
  "misc.notifPermission", "misc.pluginsLen", "misc.mimeTypesLen",
  ...["geolocation", "notifications", "camera", "microphone", "midi", "background-sync",
    "persistent-storage", "clipboard-read", "clipboard-write", "accelerometer", "gyroscope",
    "magnetometer"].map((name) => `misc.perm.${name}`),
];
const HOOK_PATHS = [
  "toString", "bind", "canvas.toDataURL", "canvas.toBlob", "canvas.getContext",
  "gl.getParameter", "gl.readPixels", "audio.getChannelData", "audio.getFloatFrequencyData",
  "perm.query", "rtc.createOffer", "enumerateDevices", "getHighEntropyValues",
].map((name) => `hooks.native.${name}`).concat(
  "hooks.native.toStringOfToString",
  ...["userAgent", "platform", "languages", "hardwareConcurrency", "deviceMemory", "webdriver",
    "plugins", "vendor"].map((name) => `hooks.navDesc.${name}`),
  "hooks.navigator.webdriverOwnProp", "hooks.navigator.pluginsOwnProp",
);
const CSS_SUPPORTS = [
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
];
const ENV_PATHS = [
  "env.devicePixelRatio", "env.maxTouchPoints", "env.colorDepth", "env.innerWidth",
  "env.innerHeight", "env.outerWidth", "env.outerHeight", "env.screenX", "env.screenY",
  "env.historyLength", "env.timeOrigin", "env.vvScale", "env.vvWidth",
];
const CLIENT_RECTS_PATHS = [
  "clientRects.bcr", "clientRects.rangeRects", "clientRects.rangeRectCount",
  ...["width", "actualBoundingBoxAscent", "actualBoundingBoxDescent", "actualBoundingBoxLeft",
    "actualBoundingBoxRight", "fontBoundingBoxAscent", "fontBoundingBoxDescent", "emHeightAscent",
    "emHeightDescent", "hangingBaseline", "alphabeticBaseline", "ideographicBaseline"]
    .map((name) => `clientRects.tm.${name}`),
  "clientRects.svgBBox", "clientRects.svgTextLen",
];
const WASM_PATHS = ["core", "simd", "memory64", "multiValue", "refTypes", "streaming", "exceptions"]
  .map((name) => `wasm.${name}`);
const INTLX_PATHS = [
  "intlx.tzCount", "intlx.calendars", "intlx.currencyCount", "intlx.dtfParts", "intlx.nfParts",
  "intlx.displayRegion", "intlx.displayLang", "intlx.segmenter",
];
const ERROR_PATHS = [
  "errors.syncFrames", "errors.typeErrorFrames", "errors.nestedFrames", "errors.domException",
  "errors.evalFrames", "errors.prepareStackTrace", "errors.stackTraceLimit", "errors.asyncFrames",
];
const DEEP_CORE_PATHS = [
  "navigator.userAgent", "navigator.platform", "navigator.language", "navigator.languages",
  "navigator.hardwareConcurrency", "window.globals",
];
const DOCUMENT_CONTEXTS = new Set([
  "main-frame", "iframe", "iframe-url", "sandboxed-iframe", "credentialless-iframe",
  "cross-origin-iframe",
]);
const DOCUMENT_DEEP_PATHS = [
  "screen.width", "screen.height", "screen.availWidth", "screen.availHeight", "screen.colorDepth",
  "screen.pixelDepth", "document.characterSet", "document.compatMode", "document.referrer",
  "document.visibilityState",
];
const UACH_SUCCESS_PATHS = [
  "uach.mobile", "uach.brands", "uach.platform", "uach.platformVersion", "uach.architecture",
  "uach.bitness", "uach.model", "uach.uaFullVersion", "uach.fullVersionList", "uach.wow64",
  "uach.formFactors",
];
const WEBGPU_SUCCESS_PATHS = [
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
];
const WEBRTC_SUCCESS_PATHS = [
  "webrtc.status", "webrtc.audio.codecs", "webrtc.audio.exts", "webrtc.video.codecs",
  "webrtc.video.exts", "webrtc.iceGatheringComplete", "webrtc.iceCandidateCount",
  "webrtc.iceCandidates", "webrtc.iceCandidateTypes", "webrtc.iceCandidateProtocols",
  "webrtc.iceCandidateComponents", "webrtc.iceCandidateFamilies", "webrtc.offerStable",
  "webrtc.codecs", "webrtc.codecsHash", "webrtc.fmtpHash", "webrtc.extmap",
  "webrtc.fingerprintAlgo",
];
const WORKLET_PATHS = [
  "navigator.userAgent", "navigator.platform", "navigator.hardwareConcurrency", "navigator.deviceMemory",
  "locale.tz", "locale.locale", "math.tanPI", "math.sinh1", "worklet.sampleRate",
  "worklet.currentTime", "worklet.currentFrame", "worklet.hasNavigator", "worklet.dsp.sum",
  "worklet.dsp.hash", "worklet.dsp.len", "worklet.globals", "worklet.__manifest",
];

const STRICT_STATIC_PATHS = Object.freeze([
  ...LOCALE_PATHS, ...CANVAS_PATHS,
  ...["webgl", "webgl2"].flatMap((api) => [
    `webgl.${api}.status`, ...WEBGL_CORE_PARAMS.map((name) => `webgl.${api}.params.${name}`),
    ...(api === "webgl2" ? WEBGL2_PARAMS.map((name) => `webgl.${api}.params.${name}`) : []),
    ...WEBGL_PRECISION.map((name) => `webgl.${api}.precision.${name}`),
    ...WEBGL_RENDER_LEAVES.map((name) => `webgl.${api}.render.${name}`),
    `webgl.${api}.unmaskedVendor`, `webgl.${api}.unmaskedRenderer`,
    `webgl.${api}.extensions`, `webgl.${api}.contextAttrs`,
  ]),
  "audio.status", "audio.offline.sum", "audio.offline.sha256", "audio.offline.fnv",
  "audio.offline.sampleCount", "audio.offline.byteLength", "audio.offline.sampleRate",
  "audio.offline.stable", "audio.offline.sha256Repeats", "audio.realtime.status",
  "audio.realtime.baseLatency", "audio.realtime.outputLatency", "audio.realtime.sampleRate",
  "audio.realtime.state",
  "fonts.count", "fonts.list", "fonts.hash", ...CSS_MEDIA.map((query) => `css[${query}]`),
  "css.deviceAspect", ...MATH_PATHS,
  ...CODEC_TYPES.flatMap((type) => [`codecs.canPlay[${type}]`, `codecs.mse[${type}]`]),
  "speech.voices", "speech.count", ...MISC_PATHS, ...HOOK_PATHS,
  ...CSS_SUPPORTS.map((query) => `cssSupports[${query}]`),
  "mediaDevices.total", "mediaDevices.audioinput", "mediaDevices.audiooutput",
  "mediaDevices.videoinput", "mediaDevices.groups", "mediaDevices.supportedConstraints",
  "keyboard.size", "keyboard.hash", "storage.localStorage", "storage.sessionStorage",
  "storage.indexedDB", "storage.caches", "storage.opfs", "storage.storageBuckets",
  "storage.quotaRoundedGB", "storage.hasQuota", "storage.usageDetails", "storage.persisted",
  ...ENV_PATHS, ...CLIENT_RECTS_PATHS, ...WASM_PATHS,
  'mediaCaps.dec[video/mp4; codecs="avc1.42E01E"]',
  'mediaCaps.dec[video/webm; codecs="vp9"]',
  'mediaCaps.dec[video/mp4; codecs="av01.0.05M.08"]',
  "mediaCaps.webcodecs[avc1.42E01E]", "mediaCaps.webcodecs[vp09.00.10.08]",
  "mediaCaps.webcodecs[av01.0.05M.08]", "mediaCaps.eme[com.widevine.alpha]",
  "mediaCaps.eme[com.microsoft.playready]", "mediaCaps.eme[org.w3.clearkey]",
  "device.gamepads", "device.hasBluetooth", "device.hasUSB", "device.hasHID", "device.hasSerial",
  "device.batteryCharging", "device.batteryLevel", "device.batteryChargingTimeFinite",
  ...INTLX_PATHS, ...ERROR_PATHS, ...DEEP_CORE_PATHS,
]);

function strictCollectorRows(context) {
  const rows = [];
  const put = (path, value = "x", extra = {}) => rows.push(rec(path, value, { context, ...extra }));
  for (const path of STRICT_STATIC_PATHS) {
    let value = "x";
    if (path.startsWith("css[") || path.startsWith("cssSupports[") || path.startsWith("wasm.")) value = true;
    else if (/\.(?:count|Count|Len|Bytes|width|height|sampleRate|baseLatency|outputLatency|timerRes|pluginsLen|mimeTypesLen|groups|audioinput|audiooutput|videoinput|size|quotaRoundedGB|rangeRectCount|batteryLevel|tzCount|currencyCount|stackTraceLimit)$/.test(path)) value = 1;
    else if (/\.(?:stable|compile|link|hasQuota|persisted|gamepads|hasBluetooth|hasUSB|hasHID|hasSerial|batteryCharging|batteryChargingTimeFinite|webdriver)$/.test(path)) value = true;
    put(path, value);
  }
  const replace = (path, value) => replaceEncodedTestValue(rows.find((row) => row.path === path), value);
  replace("canvas.width", 280); replace("canvas.height", 60); replace("canvas.pixelBytes", 67200);
  replace("canvas.pixelFnv", "12345678"); replace("canvas.pixelSha256", "a".repeat(64));
  replace("canvas.repeats", Array(3).fill("a".repeat(64))); replace("canvas.stable", true);
  for (const api of ["webgl", "webgl2"]) {
    const sha = api === "webgl" ? "a".repeat(64) : "b".repeat(64);
    replace(`webgl.${api}.status`, "ok"); replace(`webgl.${api}.render.status`, "ok");
    replace(`webgl.${api}.render.fnv`, "12345678"); replace(`webgl.${api}.render.sha256`, sha);
    replace(`webgl.${api}.render.compile`, true); replace(`webgl.${api}.render.link`, true);
    replace(`webgl.${api}.render.glError`, 0); replace(`webgl.${api}.render.width`, 64);
    replace(`webgl.${api}.render.height`, 64); replace(`webgl.${api}.render.pixelBytes`, 16384);
    replace(`webgl.${api}.render.stable`, true); replace(`webgl.${api}.render.repeats`, Array(3).fill(sha));
    replace(`webgl.${api}.render.sha256Repeats`, Array(3).fill(sha));
    replace(`webgl.${api}.render.fnvRepeats`, Array(3).fill("12345678"));
  }
  replace("audio.status", "ok"); replace("audio.offline.sum", 1.2);
  replace("audio.offline.sha256", "e".repeat(64)); replace("audio.offline.fnv", "12345678");
  replace("audio.offline.sampleCount", 5000); replace("audio.offline.byteLength", 20000);
  replace("audio.offline.sampleRate", 44100); replace("audio.offline.stable", true);
  replace("audio.offline.sha256Repeats", Array(3).fill("e".repeat(64)));
  replace("audio.realtime.status", "ok"); replace("audio.realtime.sampleRate", 44100);
  replace("audio.realtime.state", "suspended");
  replace("fonts.count", 1); replace("fonts.list", "Arial"); replace("fonts.hash", "12345678");
  replace("speech.voices", "Voice|en-US|L|D"); replace("speech.count", 1);
  replace("keyboard.size", 1); replace("keyboard.hash", "12345678");
  replace("mediaDevices.total", 2); replace("mediaDevices.audioinput", 1);
  replace("mediaDevices.audiooutput", 0); replace("mediaDevices.videoinput", 1);
  replace("mediaDevices.groups", 2); replace("mediaDevices.supportedConstraints", "width,height");
  replace("storage.localStorage", "object"); replace("storage.sessionStorage", "object");
  replace("storage.indexedDB", "object"); replace("storage.caches", "object");
  replace("storage.quotaRoundedGB", 10); replace("storage.hasQuota", true);
  replace("storage.usageDetails", "indexedDB"); replace("storage.persisted", false);
  replace("device.gamepads", 0); replace("device.batteryCharging", true);
  replace("device.batteryLevel", 0.8); replace("device.batteryChargingTimeFinite", false);
  replace("errors.syncFrames", ["Error: x", "at fn (origin/a.js:1:2)"]);
  replace("errors.typeErrorFrames", ["TypeError: x"]); replace("errors.nestedFrames", ["Error: n"]);
  replace("errors.evalFrames", ["Error: ev"]); replace("errors.asyncFrames", ["Error: async"]);
  replace("errors.domException", { name: "NotAllowedError", frames: ["NotAllowedError: d"] });
  replace("navigator.languages", ["en-US", "en"]); replace("navigator.hardwareConcurrency", 8);
  if (DOCUMENT_CONTEXTS.has(context)) {
    for (const path of DOCUMENT_DEEP_PATHS) put(path, path.includes("Depth") || /\.(?:width|height|availWidth|availHeight)$/.test(path) ? 24 : "x");
  }
  return rows;
}

function browser(context, measurements = []) {
  return { context, measurements: { _context: context, _schema: "typed-v4", _measurements: measurements } };
}
function collectorBrowser(context, extra = []) {
  const rows = strictCollectorRows(context);
  const jobHasRows = (job) => rows.some((row) => row.path.startsWith(`${job}.`)
    || row.path.startsWith(`${job}[`));
  for (const [job, [path, value, rowExtra]] of Object.entries(REQUIRED_JOB_ROWS)) {
    if (!jobHasRows(job)) rows.push(rec(path, value, { context, ...rowExtra }));
  }
  rows.push(...extra);
  rows.push(rec("collector.__manifest", {
    collectorVersion: "4.4.0", context, expectedJobs: COLLECTOR_JOBS,
    completedJobs: COLLECTOR_JOBS, failedJobs: [], measurementCount: rows.length + 1,
  }, { context }));
  return browser(context, rows);
}
function syncCollectorManifest(record) {
  const rows = record.measurements._measurements;
  const manifestRow = rows.find((row) => row.path === "collector.__manifest");
  const manifest = decodedTestValue(manifestRow);
  manifest.measurementCount = rows.length;
  replaceEncodedTestValue(manifestRow, manifest);
}
function worklet() {
  const context = "audio-worklet";
  const rows = [
    rec("navigator.userAgent", null, { context, status: "unavailable-in-context" }),
    rec("navigator.platform", null, { context, status: "unavailable-in-context" }),
    rec("navigator.hardwareConcurrency", null, { context, status: "unavailable-in-context" }),
    rec("navigator.deviceMemory", null, { context, status: "unavailable-in-context" }),
    rec("locale.tz", "UTC", { context }),
    rec("locale.locale", "en-US", { context }),
    rec("math.tanPI", 0, { context }),
    rec("math.sinh1", 1.175, { context }),
    rec("worklet.sampleRate", 44100, { context }),
    rec("worklet.currentTime", 0, { context }),
    rec("worklet.currentFrame", 0, { context }),
    rec("worklet.hasNavigator", null, { context, status: "unavailable-in-context" }),
    rec("worklet.dsp.sum", 1.2, { context }),
    rec("worklet.dsp.hash", "a".repeat(64), { context }),
    rec("worklet.dsp.len", 256, { context }),
    rec("worklet.globals", "AudioWorkletProcessor", { context }),
    rec("worklet.__manifest", { version: "4.4.0", status: "ok", probeCount: 16 }, { context }),
  ];
  return browser(context, rows);
}
function network() {
  return { context: "network", measurements: {
    netSchemaVersion: "net-v6", ja4: "t13d0207h2_62ed6f6ca7ad_032b58638d3d",
    ja3: "af851f784aed02a8b1e0b6ac13251239", ja3String: "771,4865-4866,0-10-11-13-16-43-51,29,0",
    sni: "capture.example", round: 2, tlsVersion: "13", httpVersion: "2.0", alpnNegotiated: "h2",
    observedIp: "203.0.113.10", observedIpFamily: "ipv4", tlsTerminatedBy: "capture-endpoint",
    captureRuntime: { node: "v22.14.0", v8: "12.4", openssl: "3.0.0", nghttp2: "1.64.0" },
    headerOrder: ":method,:authority,:scheme,:path,user-agent,sec-ch-ua,sec-ch-ua-mobile,sec-ch-ua-platform,sec-ch-ua-platform-version,sec-ch-ua-arch,sec-ch-ua-bitness,sec-ch-ua-model,sec-ch-ua-full-version-list,sec-ch-ua-wow64,sec-ch-ua-form-factors",
    parserVersion: "net-v6", captureBuild: "a".repeat(64),
    acceptChAdvertised: "platform-version,arch,bitness,model,full-version-list,wow64,form-factors", userAgent: "Chrome",
    secChUa: '\"Chromium\";v="140"', secChUaMobile: "?0", secChUaPlatform: '\"macOS\"',
    secChUaPlatformVersion: '\"15.6.0\"', secChUaArch: '\"arm\"', secChUaBitness: '\"64\"',
    secChUaModel: '\"\"', secChUaFullVersionList: '\"Chromium\";v="140.0.0.0"', secChUaWow64: "?0",
    secChUaFormFactors: '\"Desktop\"',
    tlsTyped: {
      tlsRecordVersion: 0x0301, handshakeVersion: 771, supportedVersionMax: 0x0304,
      ciphers: [4865, 4866], extensions: [0, 10, 11, 13, 16, 43, 51], sigAlgs: [1027],
      curves: [29], pointFormats: [0], alpnOffered: ["h2"], alpnRaw: [[104, 50]],
    },
    httpHeadersTyped: [
      { name: ":method", value: "GET", wireIndex: 0 },
      { name: ":authority", value: "capture.example", wireIndex: 1 },
      { name: ":scheme", value: "https", wireIndex: 2 },
      { name: ":path", value: "/?round=2", wireIndex: 3 },
      { name: "user-agent", value: "Chrome", wireIndex: 4 },
      { name: "sec-ch-ua", value: '\"Chromium\";v="140"', wireIndex: 5 },
      { name: "sec-ch-ua-mobile", value: "?0", wireIndex: 6 },
      { name: "sec-ch-ua-platform", value: '\"macOS\"', wireIndex: 7 },
      { name: "sec-ch-ua-platform-version", value: '\"15.6.0\"', wireIndex: 8 },
      { name: "sec-ch-ua-arch", value: '\"arm\"', wireIndex: 9 },
      { name: "sec-ch-ua-bitness", value: '\"64\"', wireIndex: 10 },
      { name: "sec-ch-ua-model", value: '\"\"', wireIndex: 11 },
      { name: "sec-ch-ua-full-version-list", value: '\"Chromium\";v="140.0.0.0"', wireIndex: 12 },
      { name: "sec-ch-ua-wow64", value: "?0", wireIndex: 13 },
      { name: "sec-ch-ua-form-factors", value: '\"Desktop\"', wireIndex: 14 },
    ],
    http2: {
      status: "captured",
      settings: [
        { id: 1, name: "headerTableSize", value: 65536, wireIndex: 0 },
        { id: 4, name: "initialWindowSize", value: 6291456, wireIndex: 1 },
      ],
      settingsOrder: [1, 4], settingsEffective: { headerTableSize: 65536, initialWindowSize: 6291456 },
      settingsPayloadSha256: "9847b1340ba7da770ff193b4f6424c65bde53fbdaa1bb7b36cd7dfe6fb3e772d",
      settingsPayloadHex: "000100010000000400600000",
      pseudoHeaderOrder: [":method", ":authority", ":scheme", ":path"],
      headersStatus: "valid", errors: [],
    },
  } };
}
function manifest(status = "finished", expected = EXPECTED) {
  return { context: "run-manifest", measurements: {
    expected: [...expected],
    realms: Object.fromEntries(expected.map((c) => [c, { status }])),
  } };
}
function gumAttempt(attempt, constraints, outcome, name = null, message = null, lifecycle = "live") {
  return { attempt, constraints: { audio: !!constraints.audio, video: !!constraints.video }, outcome, name, message,
    durationMs: 120, visibilityState: "visible", lifecycle };
}
function gumSingle(outcome, name = null, message = null, trackKinds = []) {
  return { outcome, name, message, durationMs: 90, trackKinds };
}
const PCTX = "permissioned";
const prec = (path, value, extra = {}) => rec(path, value, { context: PCTX, phase: PCTX, ...extra });
/** Rewrite the permissioned side of a complete READY input into a typed gUM outcome. */
function withGumOutcome(input, { result, attempts, audioOnly = null, videoOnly = null, lifecycle = "none",
  mainStatus, mainError, tracks, devicesBefore, devicesAfter }) {
  const permissioned = input.records.find((row) => row.context === PCTX);
  const isGumRow = (row) => row.path === "permissioned.getUserMedia"
    || row.path.startsWith("permissioned.getUserMedia.") || row.path.startsWith("permissioned.track[")
    || (devicesBefore && row.path.startsWith("permissioned.devices."));
  const rows = permissioned.measurements._measurements.filter((row) => !isGumRow(row));
  const deviceRows = (phase, list) => [
    prec(`permissioned.devices.${phase}.count`, list.length),
    prec(`permissioned.devices.${phase}.withLabels`, list.filter((device) => device.label).length),
    ...list.flatMap((device, index) => [
      prec(`permissioned.devices.${phase}[${index}].kind`, device.kind),
      prec(`permissioned.devices.${phase}[${index}].label`, device.label),
      prec(`permissioned.devices.${phase}[${index}].deviceId`, device.deviceId),
      prec(`permissioned.devices.${phase}[${index}].groupId`, device.groupId),
    ]),
  ];
  if (devicesBefore) {
    rows.push(...deviceRows("before", devicesBefore), ...deviceRows("after", devicesAfter));
    rows.push(prec("permissioned.devices.labelsRevealed",
      devicesAfter.filter((device) => device.label).length > devicesBefore.filter((device) => device.label).length));
  }
  if (mainStatus) rows.push(prec("permissioned.getUserMedia", null, { status: mainStatus, error: mainError || null }));
  rows.push(
    prec("permissioned.getUserMedia.result", result),
    prec("permissioned.getUserMedia.failure", result === "granted" ? "none" : result),
    prec("permissioned.getUserMedia.attempts", attempts),
    prec("permissioned.getUserMedia.audioOnly", audioOnly),
    prec("permissioned.getUserMedia.videoOnly", videoOnly),
    prec("permissioned.getUserMedia.lifecycle", lifecycle),
    prec("permissioned.getUserMedia.secureContext", true),
  );
  (tracks || []).forEach((track, index) => rows.push(
    prec(`permissioned.track[${index}].kind`, track.kind),
    prec(`permissioned.track[${index}].label`, track.label),
    prec(`permissioned.track[${index}].settings`, track.settings),
    prec(`permissioned.track[${index}].capabilities`, track.capabilities),
    prec(`permissioned.track[${index}].constraints`, track.constraints),
  ));
  permissioned.measurements._measurements = rows;
  const manifest = permissioned.measurements._phaseManifest;
  manifest.granted = manifest.granted.filter((step) => step !== "getUserMedia");
  if (result === "granted") manifest.granted.unshift("getUserMedia");
  if (result === "denied") manifest.denied.push("getUserMedia");
  if (result === "timeout") manifest.timeout.push("getUserMedia");
  if (result === "no-device" || result === "unsupported") manifest.unsupported.push("getUserMedia");
  manifest.steps.getUserMedia = result;
  return input;
}
const AUDIO_TRACK = { kind: "audio", label: "Built-in Microphone", settings: { deviceId: "audio-device", sampleRate: 48000 },
  capabilities: { sampleRate: { min: 8000, max: 48000 } }, constraints: { echoCancellation: true } };
const AUDIO_DEVICES = (labelled) => [
  { kind: "audioinput", label: labelled ? "Built-in Microphone" : "", deviceId: "audio-device", groupId: "audio-group" },
  { kind: "audiooutput", label: labelled ? "Built-in Speaker" : "", deviceId: "speaker-device", groupId: "audio-group" },
];
function fullInput(overrides = {}) {
  const environment = overrides.environment || "plain";
  const pairKey = overrides.pairKey || "pair-1";
  const captureKey = overrides.captureKey || `${pairKey}:${environment}`;
  const collectorBuild = overrides.collectorBuild || "c".repeat(64);
  const collectorArtifactSha256 = overrides.collectorArtifactSha256 || "d".repeat(64);
  const processEvidence = overrides.oopif?.processEvidence || {
    collectorBuild, configurationId: OOPIF.configurationId,
    parentOrigin: OOPIF.parentOrigin, childOrigin: OOPIF.childOrigin,
    registrableParentSite: OOPIF.registrableParentSite,
    registrableChildSite: OOPIF.registrableChildSite,
    parentProcessId: "browser-process-1", childProcessId: "renderer-process-2",
  };
  const oopif = overrides.oopif || {
    ...OOPIF, processEvidence, processEvidenceSha256: canonicalSha256(processEvidence),
    processEvidenceBuild: collectorBuild,
  };
  const serviceWorkerChallenge = overrides.serviceWorkerChallenge || "S".repeat(22);
  const serviceWorkerRequestId = "R".repeat(22);
  const controls = [
    ...CONTROLS.flatMap(([id, v]) => controlRows(id, v)),
    ...CONTROL_SANITY_PATHS.map((path) => rec(path, true)),
  ];
  const main = collectorBrowser("main-frame", controls);
  const standard = EXPECTED.filter((c) => !["main-frame", "audio-worklet", "network", "permissioned"].includes(c))
    .map((c) => collectorBrowser(c));
  const pctx = "permissioned";
  const permRows = [
    ...["geolocation", "camera", "microphone", "notifications"].flatMap((p) => [
      rec(`permissioned.perm.${p}.before`, "prompt", { context: pctx, phase: pctx }),
      rec(`permissioned.perm.${p}.after`, p === "notifications" ? "prompt" : "granted", { context: pctx, phase: pctx }),
    ]),
    rec("permissioned.devices.before.count", 2, { context: pctx, phase: pctx }),
    rec("permissioned.devices.before.withLabels", 0, { context: pctx, phase: pctx }),
    rec("permissioned.devices.before[0].kind", "audioinput", { context: pctx, phase: pctx }),
    rec("permissioned.devices.before[0].label", "", { context: pctx, phase: pctx }),
    rec("permissioned.devices.before[0].deviceId", "audio-device", { context: pctx, phase: pctx }),
    rec("permissioned.devices.before[0].groupId", "audio-group", { context: pctx, phase: pctx }),
    rec("permissioned.devices.before[1].kind", "videoinput", { context: pctx, phase: pctx }),
    rec("permissioned.devices.before[1].label", "", { context: pctx, phase: pctx }),
    rec("permissioned.devices.before[1].deviceId", "video-device", { context: pctx, phase: pctx }),
    rec("permissioned.devices.before[1].groupId", "video-group", { context: pctx, phase: pctx }),
    rec("permissioned.devices.after.count", 2, { context: pctx, phase: pctx }),
    rec("permissioned.devices.after.withLabels", 2, { context: pctx, phase: pctx }),
    rec("permissioned.devices.after[0].kind", "audioinput", { context: pctx, phase: pctx }),
    rec("permissioned.devices.after[0].label", "Built-in Microphone", { context: pctx, phase: pctx }),
    rec("permissioned.devices.after[0].deviceId", "audio-device", { context: pctx, phase: pctx }),
    rec("permissioned.devices.after[0].groupId", "audio-group", { context: pctx, phase: pctx }),
    rec("permissioned.devices.after[1].kind", "videoinput", { context: pctx, phase: pctx }),
    rec("permissioned.devices.after[1].label", "FaceTime Camera", { context: pctx, phase: pctx }),
    rec("permissioned.devices.after[1].deviceId", "video-device", { context: pctx, phase: pctx }),
    rec("permissioned.devices.after[1].groupId", "video-group", { context: pctx, phase: pctx }),
    rec("permissioned.devices.labelsRevealed", true, { context: pctx, phase: pctx }),
    rec("permissioned.getUserMedia.result", "granted", { context: pctx, phase: pctx }),
    rec("permissioned.getUserMedia.failure", "none", { context: pctx, phase: pctx }),
    rec("permissioned.getUserMedia.attempts", [gumAttempt(1, { audio: true, video: true }, "granted")], { context: pctx, phase: pctx }),
    rec("permissioned.getUserMedia.audioOnly", null, { context: pctx, phase: pctx }),
    rec("permissioned.getUserMedia.videoOnly", null, { context: pctx, phase: pctx }),
    rec("permissioned.getUserMedia.lifecycle", "none", { context: pctx, phase: pctx }),
    rec("permissioned.getUserMedia.secureContext", true, { context: pctx, phase: pctx }),
    rec("permissioned.track[0].kind", "audio", { context: pctx, phase: pctx }),
    rec("permissioned.track[0].label", "Built-in Microphone", { context: pctx, phase: pctx }),
    rec("permissioned.track[0].settings", { deviceId: "audio-device", sampleRate: 48000 }, { context: pctx, phase: pctx }),
    rec("permissioned.track[0].capabilities", { sampleRate: { min: 8000, max: 48000 } }, { context: pctx, phase: pctx }),
    rec("permissioned.track[0].constraints", { echoCancellation: true }, { context: pctx, phase: pctx }),
    rec("permissioned.track[1].kind", "video", { context: pctx, phase: pctx }),
    rec("permissioned.track[1].label", "FaceTime Camera", { context: pctx, phase: pctx }),
    rec("permissioned.track[1].settings", { deviceId: "video-device", width: 1280 }, { context: pctx, phase: pctx }),
    rec("permissioned.track[1].capabilities", { width: { min: 320, max: 1920 } }, { context: pctx, phase: pctx }),
    rec("permissioned.track[1].constraints", { width: 1280 }, { context: pctx, phase: pctx }),
    rec("permissioned.geo.latitude", 50.4, { context: pctx, phase: pctx }),
    rec("permissioned.geo.longitude", 30.5, { context: pctx, phase: pctx }),
    rec("permissioned.geo.accuracy", 10, { context: pctx, phase: pctx }),
    rec("permissioned.geo.altitude", null, { context: pctx, phase: pctx, status: "unavailable-in-context" }),
    rec("permissioned.geo.altitudeAccuracy", null, { context: pctx, phase: pctx, status: "unavailable-in-context" }),
    rec("permissioned.geo.heading", null, { context: pctx, phase: pctx, status: "unavailable-in-context" }),
    rec("permissioned.geo.speed", null, { context: pctx, phase: pctx, status: "unavailable-in-context" }),
    rec("permissioned.geo.timestamp", 1, { context: pctx, phase: pctx }),
    rec("permissioned.geo.coarseBucket", "6c55ec50", { context: pctx, phase: pctx }),
    rec("permissioned.phase.complete", true, { context: pctx, phase: pctx }),
  ];
  const perm = browser(pctx, permRows);
  perm.measurements._phaseManifest = {
    phase: "permissioned", complete: true,
    requested: ["perm.geolocation", "perm.camera", "perm.microphone", "perm.notifications",
      "enumerateDevices", "getUserMedia", "geolocation"],
    granted: ["getUserMedia", "geolocation", "perm.geolocation", "perm.camera", "perm.microphone"],
    denied: [], prompt: ["perm.notifications"], timeout: [], unsupported: [],
    steps: { enumerateBefore: true, enumerateAfter: true, getUserMedia: "granted", geolocation: "granted" },
  };
  const records = [main, ...standard, worklet(), perm, network(), manifest()];
  const sw = records.find((row) => row.context === "service-worker");
  const swScript = new URL("/fingerprint/sw", oopif.parentOrigin);
  swScript.searchParams.set("build", collectorBuild);
  swScript.searchParams.set("artifact", collectorArtifactSha256);
  swScript.searchParams.set("capture", captureKey);
  swScript.searchParams.set("challenge", serviceWorkerChallenge);
  sw.measurements._serviceWorker = {
    context: "service-worker", collectorBuild, collectorArtifactSha256, captureKey,
    challenge: serviceWorkerChallenge,
    handshakeVersion: 1,
    requestId: serviceWorkerRequestId,
    scriptURL: swScript.href,
    scope: new URL(`/fingerprint/sw-scope/${serviceWorkerChallenge}/`, oopif.parentOrigin).href,
    acknowledgementSha256: canonicalSha256({
      context: "service-worker", collectorBuild, collectorArtifactSha256,
      captureKey, challenge: serviceWorkerChallenge,
    }),
  };
  const boundChild = (context) => {
    const core = {
      protocol: "fingerprint-bound-child", handshakeVersion: 1, context,
      collectorBuild, collectorArtifactSha256, captureKey,
      requestId: context === "iframe-url" ? "I".repeat(22) : "X".repeat(22),
      parentOrigin: oopif.parentOrigin,
    };
    return { ...core, acknowledgementSha256: canonicalSha256(core) };
  };
  records.find((row) => row.context === "iframe-url").measurements._boundChild = boundChild("iframe-url");
  const cross = records.find((row) => row.context === "cross-origin-iframe");
  cross.measurements._boundChild = boundChild("cross-origin-iframe");
  cross.measurements._crossOrigin = {
    parentOrigin: oopif.parentOrigin, childOrigin: oopif.childOrigin,
    collectorBuild, collectorArtifactSha256, captureKey,
    requestId: cross.measurements._boundChild.requestId,
    acknowledgementSha256: cross.measurements._boundChild.acknowledgementSha256,
    registrableParentSite: oopif.registrableParentSite,
    registrableChildSite: oopif.registrableChildSite,
    eventOriginVerified: true, crossSiteConfigured: true,
    configurationId: oopif.configurationId,
    processEvidenceSha256: oopif.processEvidenceSha256,
    processEvidenceBuild: oopif.processEvidenceBuild,
  };
  // Browser records carry only the accepted deployment-evidence binding. The
  // raw CDP process IDs stay server-side and are not redundantly trusted from
  // every manual capture row.
  const oopifBinding = {
    parentOrigin: oopif.parentOrigin, childOrigin: oopif.childOrigin,
    registrableParentSite: oopif.registrableParentSite,
    registrableChildSite: oopif.registrableChildSite,
    configurationId: oopif.configurationId,
    processEvidenceSha256: oopif.processEvidenceSha256,
    processEvidenceBuild: oopif.processEvidenceBuild,
  };
  const identity = { environment, pairKey, captureKey, collectorBuild,
    collectorArtifactSha256, oopif: oopifBinding, serviceWorkerChallenge };
  for (const row of records) row.identity = { ...identity };
  records.find((row) => row.context === "run-manifest").measurements.identity = { ...identity };
  return {
    serverExpectedContexts: EXPECTED,
    records,
    unreadableLines: 0,
    environment,
    pairKey,
    captureKey,
    collectorBuild,
    collectorArtifactSha256,
    expectedNetworkBuild: overrides.expectedNetworkBuild || "a".repeat(64),
    oopif,
    serviceWorkerChallenge,
    ...overrides,
  };
}
const has = (result, code) => result.issues.some((x) => x.code === code);

{
  const v = validateSideCapture(fullInput());
  if (process.env.DEBUG_READINESS && !v.ready) console.log(JSON.stringify(v.issues, null, 2));
  ok("complete canonical side is READY", v.ready === true && v.overall === "READY" && v.issues.length === 0);
}
{
  const jobs = Object.keys(DEFAULT_REQUIRED_JOB_EVIDENCE);
  ok("server-owned job evidence covers every non-control collector job exactly", jobs.length === 25
    && COLLECTOR_JOBS.filter((job) => job !== "control").every((job) => jobs.includes(job))
    && !jobs.includes("control"));
}
{
  const missed = [];
  for (const path of WORKLET_PATHS) {
    const input = fullInput();
    const record = input.records.find((row) => row.context === "audio-worklet");
    record.measurements._measurements = record.measurements._measurements.filter((row) => row.path !== path);
    const verdict = validateSideCapture(input);
    if (!verdict.issues.some((entry) => entry.code === "worklet-contract-invalid")) missed.push(path);
  }
  const extra = fullInput();
  extra.records.find((row) => row.context === "audio-worklet")
    .measurements._measurements.push(rec("worklet.forged", true, { context: "audio-worklet" }));
  if (!has(validateSideCapture(extra), "worklet-contract-invalid")) missed.push("unexpected-extra");
  ok("AudioWorklet requires the exact 16-probe build-owned path set", missed.length === 0);
}
{
  const mutations = [
    ["worklet.__manifest", { version: "4.4.0", status: "ok", probeCount: 15 }],
    ["worklet.dsp.len", 255], ["worklet.dsp.hash", "short"], ["worklet.sampleRate", 0],
    ["worklet.hasNavigator", "present"],
  ];
  const missed = [];
  for (const [path, value] of mutations) {
    const input = fullInput();
    const row = input.records.find((entry) => entry.context === "audio-worklet")
      .measurements._measurements.find((entry) => entry.path === path);
    if (path === "worklet.hasNavigator") {
      row.status = "ok"; row.error = null;
    }
    replaceEncodedTestValue(row, value);
    const verdict = validateSideCapture(input);
    if (!has(verdict, "worklet-contract-invalid")) missed.push(path);
  }
  ok("AudioWorklet manifest, DSP and realm invariants cannot be self-certified", missed.length === 0);
}
{
  const input = fullInput();
  const worker = input.records.find((row) => row.context === "dedicated-worker");
  const realtimePaths = ["audio.realtime.status", "audio.realtime.baseLatency", "audio.realtime.outputLatency",
    "audio.realtime.sampleRate", "audio.realtime.state"];
  worker.measurements._measurements = worker.measurements._measurements
    .filter((row) => !realtimePaths.includes(row.path));
  worker.measurements._measurements.push(rec("audio.realtime.available", null, {
    context: worker.context, status: "unavailable-in-context",
  }));
  syncCollectorManifest(worker);
  const terminalReady = validateSideCapture(input).ready;
  worker.measurements._measurements.push(rec("audio.realtime.status", "ok", { context: worker.context }));
  syncCollectorManifest(worker);
  ok("offline audio can succeed with an exact unavailable realtime subbranch, but not a mixed branch",
    terminalReady && has(validateSideCapture(input), "collector-capability-branch-invalid"));
}
{
  const missed = [];
  for (const path of STRICT_STATIC_PATHS) {
    const input = fullInput();
    const worker = input.records.find((row) => row.context === "dedicated-worker");
    worker.measurements._measurements = worker.measurements._measurements.filter((row) => row.path !== path);
    syncCollectorManifest(worker);
    const verdict = validateSideCapture(input);
    if (!verdict.issues.some((entry) => entry.code === "collector-contract-missing"
      && entry.context === "dedicated-worker" && entry.path === path)) missed.push(path);
  }
  ok("each build-owned static collector leaf independently blocks READY when deleted", missed.length === 0);
}
{
  const missed = [];
  for (const path of DOCUMENT_DEEP_PATHS) {
    const input = fullInput();
    const main = input.records.find((row) => row.context === "main-frame");
    main.measurements._measurements = main.measurements._measurements.filter((row) => row.path !== path);
    syncCollectorManifest(main);
    const verdict = validateSideCapture(input);
    if (!verdict.issues.some((entry) => entry.code === "collector-contract-missing"
      && entry.context === "main-frame" && entry.path === path)) missed.push(path);
  }
  ok("document collectors require their screen and document deep-walk leaves", missed.length === 0);
}
{
  const base = fullInput();
  const worker = base.records.find((row) => row.context === "dedicated-worker");
  worker.measurements._measurements = worker.measurements._measurements
    .filter((row) => !row.path.startsWith("uach."));
  for (const path of UACH_SUCCESS_PATHS) {
    const value = path === "uach.mobile" || path === "uach.wow64" ? false
      : path === "uach.formFactors" ? ["Desktop"]
        : path === "uach.brands" || path === "uach.fullVersionList" ? [{ brand: "Chromium", version: "140" }]
        : "x";
    worker.measurements._measurements.push(rec(path, value, { context: worker.context }));
  }
  syncCollectorManifest(worker);
  const missed = [];
  if (!validateSideCapture(base).ready) missed.push("complete");
  for (const path of UACH_SUCCESS_PATHS) {
    const input = structuredClone(base);
    const changed = input.records.find((row) => row.context === "dedicated-worker");
    changed.measurements._measurements = changed.measurements._measurements.filter((row) => row.path !== path);
    syncCollectorManifest(changed);
    if (!has(validateSideCapture(input), "collector-contract-missing")) missed.push(path);
  }
  ok("UA-CH success branch requires every stable requested high-entropy leaf", missed.length === 0);
}
{
  const i = fullInput();
  const worker = i.records.find((r) => r.context === "dedicated-worker");
  const manifestRow = worker.measurements._measurements.find((r) => r.path === "collector.__manifest");
  worker.measurements._measurements = [
    rec("navigator.userAgent", "Chrome", { context: "dedicated-worker" }),
    rec("locale.resolvedTZ", "UTC", { context: "dedicated-worker" }),
    rec("math.powPI", 1.2, { context: "dedicated-worker" }),
    manifestRow,
  ];
  manifestRow.value = encodeValue({
    collectorVersion: "4.4.0", context: "dedicated-worker",
    expectedJobs: COLLECTOR_JOBS, completedJobs: COLLECTOR_JOBS,
    failedJobs: [], measurementCount: 4,
  }).value;
  const v = validateSideCapture(i);
  ok("three paths plus a self-reported full manifest cannot become READY",
    !v.ready && has(v, "required-job-evidence-missing"));
}
{
  const mutations = [
    ["canvas.pixelSha256", "short"],
    ["canvas.pixelFnv", "short"],
    ["canvas.pixelBytes", 4],
    ["canvas.repeats", ["a".repeat(64), "b".repeat(64), "a".repeat(64)]],
    ["canvas.stable", false],
  ];
  const missed = [];
  for (const [path, value] of mutations) {
    const input = fullInput();
    const worker = input.records.find((row) => row.context === "dedicated-worker");
    replaceEncodedTestValue(worker.measurements._measurements.find((row) => row.path === path), value);
    const verdict = validateSideCapture(input);
    if (!verdict.issues.some((x) => x.code === "canvas-evidence-invalid")) missed.push(path);
  }
  ok("canvas READY requires three stable full-RGBA SHA-256 readbacks", missed.length === 0);
}
{
  const mutations = [
    ["webgl.webgl.render.compile", false],
    ["webgl.webgl.render.link", false],
    ["webgl.webgl.render.glError", 1282],
    ["webgl.webgl.render.stable", false],
    ["webgl.webgl.render.sha256", "short"],
    ["webgl.webgl.render.pixelBytes", 4],
  ];
  const missed = [];
  for (const [path, value] of mutations) {
    const input = fullInput();
    const worker = input.records.find((row) => row.context === "dedicated-worker");
    replaceEncodedTestValue(worker.measurements._measurements.find((row) => row.path === path), value);
    const verdict = validateSideCapture(input);
    if (!verdict.issues.some((x) => x.code === "webgl-evidence-invalid")) missed.push(path);
  }
  ok("WebGL READY requires compiled, linked, error-free, stable full readback evidence", missed.length === 0);
}
{
  const mutations = [
    ["audio.offline.sha256", "bad"],
    ["audio.offline.sampleCount", 0],
    ["audio.offline.byteLength", 4],
    ["audio.offline.stable", false],
    ["audio.offline.sha256Repeats", ["e".repeat(64), "f".repeat(64), "e".repeat(64)]],
  ];
  const missed = [];
  for (const [path, value] of mutations) {
    const input = fullInput();
    const worker = input.records.find((row) => row.context === "dedicated-worker");
    replaceEncodedTestValue(worker.measurements._measurements.find((row) => row.path === path), value);
    const verdict = validateSideCapture(input);
    if (!verdict.issues.some((x) => x.code === "audio-evidence-invalid")) missed.push(path);
  }
  ok("audio READY requires stable full-byte SHA-256 evidence", missed.length === 0);
}
{
  const input = fullInput();
  const worker = input.records.find((row) => row.context === "dedicated-worker");
  const rows = worker.measurements._measurements;
  const unavailable = rows.findIndex((row) => row.path === "webgpu.available");
  rows.splice(unavailable, 1,
    rec("webgpu.available", true, { context: worker.context }),
    rec("webgpu.status", "ok", { context: worker.context }),
    rec("webgpu.features", "shader-f16", { context: worker.context }),
    rec("webgpu.limits.maxTextureDimension2D", 8192, { context: worker.context }),
    rec("webgpu.isFallback", false, { context: worker.context }),
    rec("webgpu.vendor", "vendor", { context: worker.context }),
    rec("webgpu.architecture", "architecture", { context: worker.context }),
    rec("webgpu.device", "device", { context: worker.context }),
    rec("webgpu.description", "description", { context: worker.context }),
    rec("webgpu.wgslFeatures", "readonly_and_readwrite_storage_textures", { context: worker.context }),
    rec("webgpu.preferredFormat", "bgra8unorm", { context: worker.context }),
    rec("webgpu.compute.status", "ok", { context: worker.context }),
    rec("webgpu.compute.hash", "c".repeat(64), { context: worker.context }),
    rec("webgpu.compute.sha256", "c".repeat(64), { context: worker.context }),
    rec("webgpu.compute.hashAlgorithm", "sha256", { context: worker.context }),
    rec("webgpu.compute.byteLength", 256, { context: worker.context }),
    rec("webgpu.compute.valueCount", 64, { context: worker.context }),
    rec("webgpu.compute.compilationMessages", 0, { context: worker.context }),
    rec("webgpu.compute.compilationErrors", 0, { context: worker.context }),
    rec("webgpu.compute.deviceLost", false, { context: worker.context }),
    rec("webgpu.render.status", "ok", { context: worker.context }),
    rec("webgpu.render.hash", "d".repeat(64), { context: worker.context }),
    rec("webgpu.render.sha256", "d".repeat(64), { context: worker.context }),
    rec("webgpu.render.hashAlgorithm", "sha256", { context: worker.context }),
    rec("webgpu.render.byteLength", 16384, { context: worker.context }),
    rec("webgpu.render.width", 64, { context: worker.context }),
    rec("webgpu.render.height", 64, { context: worker.context }),
    rec("webgpu.render.bytesPerRow", 256, { context: worker.context }),
    rec("webgpu.render.pixelBytes", 16384, { context: worker.context }),
    rec("webgpu.render.compilationMessages", 0, { context: worker.context }),
    rec("webgpu.render.compilationErrors", 0, { context: worker.context }),
    rec("webgpu.render.deviceLost", false, { context: worker.context }),
  );
  const manifestRow = rows.find((row) => row.path === "collector.__manifest");
  const manifestValue = decodedTestValue(manifestRow);
  manifestValue.measurementCount = rows.length;
  replaceEncodedTestValue(manifestRow, manifestValue);
  ok("complete WebGPU compute and render evidence is READY", validateSideCapture(input).ready);

  const deleted = [];
  for (const path of WEBGPU_SUCCESS_PATHS) {
    const changed = structuredClone(input);
    const changedWorker = changed.records.find((row) => row.context === "dedicated-worker");
    changedWorker.measurements._measurements = changedWorker.measurements._measurements
      .filter((row) => row.path !== path);
    syncCollectorManifest(changedWorker);
    if (!has(validateSideCapture(changed), "webgpu-evidence-invalid")) deleted.push(path);
  }
  ok("WebGPU success requires every fixed output plus at least one adapter limit", deleted.length === 0);

  const mutations = [
    ["webgpu.compute.hash", "e".repeat(64)],
    ["webgpu.compute.sha256", "bad"],
    ["webgpu.compute.byteLength", 255],
    ["webgpu.compute.compilationErrors", 1],
    ["webgpu.render.hash", "e".repeat(64)],
    ["webgpu.render.sha256", "bad"],
    ["webgpu.render.pixelBytes", 1],
    ["webgpu.render.compilationErrors", 1],
  ];
  const missed = [];
  for (const [path, value] of mutations) {
    const changed = structuredClone(input);
    const changedWorker = changed.records.find((row) => row.context === "dedicated-worker");
    replaceEncodedTestValue(changedWorker.measurements._measurements.find((row) => row.path === path), value);
    const verdict = validateSideCapture(changed);
    if (!verdict.issues.some((x) => x.code === "webgpu-evidence-invalid")) missed.push(path);
  }
  ok("malformed WebGPU hashes, lengths or compilation results block READY", missed.length === 0);
}
{
  const input = fullInput();
  const worker = input.records.find((row) => row.context === "dedicated-worker");
  const available = worker.measurements._measurements.find((row) => row.path === "webgpu.available");
  available.status = "ok";
  replaceEncodedTestValue(available, true);
  worker.measurements._measurements.push(rec("webgpu.status", null, {
    context: worker.context, status: "unavailable-in-context",
  }));
  syncCollectorManifest(worker);
  const terminalReady = validateSideCapture(input).ready;
  worker.measurements._measurements.push(rec("webgpu.compute.status", "ok", { context: worker.context }));
  syncCollectorManifest(worker);
  const mixed = validateSideCapture(input);
  ok("WebGPU adapter-null is an exact two-row terminal branch and cannot carry stage evidence",
    terminalReady && has(mixed, "collector-capability-branch-invalid") && has(mixed, "webgpu-evidence-invalid"));
}
{
  const missed = [];
  const gpu = fullInput(), gpuWorker = gpu.records.find((row) => row.context === "dedicated-worker");
  gpuWorker.measurements._measurements.push(rec("webgpu.status", "ok", { context: gpuWorker.context }));
  if (!has(validateSideCapture(gpu), "webgpu-evidence-invalid")) missed.push("webgpu");

  const audio = fullInput(), audioWorker = audio.records.find((row) => row.context === "dedicated-worker");
  audioWorker.measurements._measurements.push({
    path: "audio.available", context: audioWorker.context, phase: "passive",
    status: "unavailable-in-context", valueType: "null", value: null, error: null, meta: {},
  });
  if (!has(validateSideCapture(audio), "audio-evidence-invalid")) missed.push("audio");

  const gl = fullInput(), glWorker = gl.records.find((row) => row.context === "dedicated-worker");
  Object.assign(glWorker.measurements._measurements.find((row) => row.path === "webgl.webgl.status"), {
    status: "unsupported", valueType: "null", value: null, error: null, meta: {},
  });
  if (!has(validateSideCapture(gl), "webgl-evidence-invalid")) missed.push("webgl");
  ok("unavailable WebGL/WebGPU/audio branches reject contradictory same-family rows", missed.length === 0);
}
{
  const cases = [
    { name: "canvas", match: (path) => path.startsWith("canvas."), marker: ["canvas.status", "unavailable-in-context"], contradiction: ["canvas.width", 280] },
    { name: "webgl", match: (path) => path.startsWith("webgl.webgl."), marker: ["webgl.webgl.status", "unsupported"], contradiction: ["webgl.webgl.extensions", "EXT"] },
    { name: "audio", match: (path) => path.startsWith("audio."), marker: ["audio.available", "unavailable-in-context"], contradiction: ["audio.status", "ok"] },
    { name: "fonts", match: (path) => path.startsWith("fonts."), marker: ["fonts.available", "unavailable-in-context"], contradiction: ["fonts.count", 1] },
    { name: "css", match: (path) => path.startsWith("css[") || path.startsWith("css."), marker: ["css.available", "unavailable-in-context"], contradiction: ["css.deviceAspect", true] },
    { name: "speech", match: (path) => path.startsWith("speech."), marker: ["speech.available", "unavailable-in-context"], contradiction: ["speech.count", 1] },
    { name: "uach", match: (path) => path.startsWith("uach."), marker: ["uach.available", "unsupported"], contradiction: ["uach.mobile", false] },
    { name: "cssSupports", match: (path) => path.startsWith("cssSupports"), marker: ["cssSupports.available", "unsupported"], contradiction: ["cssSupports[display:grid]", true] },
    { name: "mediaDevices", match: (path) => path.startsWith("mediaDevices."), marker: ["mediaDevices.available", "unavailable-in-context"], contradiction: ["mediaDevices.total", 2] },
    { name: "keyboard", match: (path) => path.startsWith("keyboard."), marker: ["keyboard.available", "unavailable-in-context"], contradiction: ["keyboard.size", 1] },
    { name: "clientRects", match: (path) => path.startsWith("clientRects."), marker: ["clientRects.status", "unavailable-in-context"], contradiction: ["clientRects.bcr", "1,1"] },
    { name: "wasm", match: (path) => path.startsWith("wasm."), marker: ["wasm.status", "unsupported"], contradiction: ["wasm.core", true] },
    { name: "intlx", match: (path) => path.startsWith("intlx."), marker: ["intlx.status", "unavailable-in-context"], contradiction: ["intlx.tzCount", 400] },
  ];
  const failures = [];
  for (const item of cases) {
    const input = fullInput();
    const worker = input.records.find((row) => row.context === "dedicated-worker");
    worker.measurements._measurements = worker.measurements._measurements.filter((row) => !item.match(row.path));
    worker.measurements._measurements.push(rec(item.marker[0], null, {
      context: worker.context, status: item.marker[1],
    }));
    syncCollectorManifest(worker);
    if (!validateSideCapture(input).ready) failures.push(`${item.name}:terminal`);
    worker.measurements._measurements.push(rec(item.contradiction[0], item.contradiction[1], { context: worker.context }));
    syncCollectorManifest(worker);
    if (!has(validateSideCapture(input), "collector-capability-branch-invalid")) failures.push(`${item.name}:contradiction`);
  }
  ok("reviewed capability terminal branches are exact and reject contradictory success rows", failures.length === 0);
}
{
  const cases = [
    { name: "storage", remove: ["storage.quotaRoundedGB", "storage.hasQuota", "storage.usageDetails", "storage.persisted"], marker: ["storage.estimate", "unavailable-in-context"], contradiction: ["storage.quotaRoundedGB", 10] },
    { name: "battery", remove: ["device.batteryCharging", "device.batteryLevel", "device.batteryChargingTimeFinite"], marker: ["device.battery", "unavailable-in-context"], contradiction: ["device.batteryCharging", true] },
    { name: "mediaCapabilities", remove: STRICT_STATIC_PATHS.filter((path) => path.startsWith("mediaCaps.dec[")), marker: ["mediaCaps.mediaCapabilities", "unavailable-in-context"], contradiction: ['mediaCaps.dec[video/mp4; codecs="avc1.42E01E"]', "true,true,true"] },
    { name: "webcodecs", remove: STRICT_STATIC_PATHS.filter((path) => path.startsWith("mediaCaps.webcodecs[")), marker: ["mediaCaps.webcodecs", "unavailable-in-context"], contradiction: ["mediaCaps.webcodecs[avc1.42E01E]", true] },
    { name: "eme", remove: STRICT_STATIC_PATHS.filter((path) => path.startsWith("mediaCaps.eme[")), marker: ["mediaCaps.eme", "unavailable-in-context"], contradiction: ["mediaCaps.eme[com.widevine.alpha]", false] },
  ];
  const failures = [];
  for (const item of cases) {
    const input = fullInput();
    const worker = input.records.find((row) => row.context === "dedicated-worker");
    worker.measurements._measurements = worker.measurements._measurements
      .filter((row) => !item.remove.includes(row.path));
    worker.measurements._measurements.push(rec(item.marker[0], null, {
      context: worker.context, status: item.marker[1],
    }));
    syncCollectorManifest(worker);
    if (!validateSideCapture(input).ready) failures.push(`${item.name}:terminal`);
    worker.measurements._measurements.push(rec(item.contradiction[0], item.contradiction[1], { context: worker.context }));
    syncCollectorManifest(worker);
    if (!has(validateSideCapture(input), "collector-capability-branch-invalid")) failures.push(`${item.name}:contradiction`);
  }
  ok("independent storage, battery and media capability branches cannot mix terminal and success evidence", failures.length === 0);
}
{
  const input = fullInput();
  const worker = input.records.find((row) => row.context === "dedicated-worker");
  const rows = worker.measurements._measurements;
  const unsupported = rows.findIndex((row) => row.path === "webrtc.status");
  rows.splice(unsupported, 1,
    rec("webrtc.status", "ok", { context: worker.context }),
    rec("webrtc.audio.codecs", "opus/48000/2", { context: worker.context }),
    rec("webrtc.audio.exts", "urn:ietf:params:rtp-hdrext:sdes:mid", { context: worker.context }),
    rec("webrtc.video.codecs", "VP8/90000", { context: worker.context }),
    rec("webrtc.video.exts", "urn:ietf:params:rtp-hdrext:sdes:mid", { context: worker.context }),
    rec("webrtc.iceGatheringComplete", true, { context: worker.context }),
    rec("webrtc.iceCandidateCount", 1, { context: worker.context }),
    rec("webrtc.iceCandidates", [{
      candidate: "candidate:1 1 udp 1 host.local 9 typ host", foundation: "1", component: "rtp",
      protocol: "udp", priority: 1, address: "host.local", port: 9, type: "host",
      tcpType: null, relatedAddress: null, relatedPort: null, usernameFragment: null, family: "mdns",
    }], { context: worker.context }),
    rec("webrtc.iceCandidateTypes", "host:1", { context: worker.context }),
    rec("webrtc.iceCandidateProtocols", "udp:1", { context: worker.context }),
    rec("webrtc.iceCandidateComponents", "rtp:1", { context: worker.context }),
    rec("webrtc.iceCandidateFamilies", "mdns:1", { context: worker.context }),
    rec("webrtc.offerStable", true, { context: worker.context }),
    rec("webrtc.codecs", "audio/opus/48000", { context: worker.context }),
    rec("webrtc.codecsHash", "12345678", { context: worker.context }),
    rec("webrtc.fmtpHash", "12345678", { context: worker.context }),
    rec("webrtc.extmap", "urn:ietf:params:rtp-hdrext:sdes:mid", { context: worker.context }),
    rec("webrtc.fingerprintAlgo", "sha-256", { context: worker.context }),
  );
  const manifestRow = rows.find((row) => row.path === "collector.__manifest");
  const manifestValue = decodedTestValue(manifestRow);
  manifestValue.measurementCount = rows.length;
  replaceEncodedTestValue(manifestRow, manifestValue);
  ok("complete WebRTC ICE and repeated-offer evidence is READY", validateSideCapture(input).ready);

  const noCandidates = structuredClone(input);
  const noCandidateWorker = noCandidates.records.find((row) => row.context === "dedicated-worker");
  for (const [path, value] of [
    ["webrtc.iceCandidateCount", 0], ["webrtc.iceCandidates", []],
    ["webrtc.iceCandidateTypes", ""], ["webrtc.iceCandidateProtocols", ""],
    ["webrtc.iceCandidateComponents", ""], ["webrtc.iceCandidateFamilies", ""],
  ]) replaceEncodedTestValue(noCandidateWorker.measurements._measurements.find((row) => row.path === path), value);
  ok("a completed host-only WebRTC gather may legitimately produce zero candidates",
    validateSideCapture(noCandidates).ready);

  const deleted = [];
  for (const path of WEBRTC_SUCCESS_PATHS) {
    const changed = structuredClone(input);
    const changedWorker = changed.records.find((row) => row.context === "dedicated-worker");
    changedWorker.measurements._measurements = changedWorker.measurements._measurements
      .filter((row) => row.path !== path);
    syncCollectorManifest(changedWorker);
    if (!has(validateSideCapture(changed), "webrtc-evidence-invalid")) deleted.push(path);
  }
  ok("WebRTC success requires the complete emitted SDP and ICE evidence set", deleted.length === 0);

  const mutations = [
    ["webrtc.iceGatheringComplete", false],
    ["webrtc.offerStable", false],
    ["webrtc.iceCandidateCount", 2],
    ["webrtc.iceCandidates", [{ protocol: "udp", address: "host.local", type: "host", family: "mdns" }]],
  ];
  const missed = [];
  for (const [path, value] of mutations) {
    const changed = structuredClone(input);
    const changedWorker = changed.records.find((row) => row.context === "dedicated-worker");
    replaceEncodedTestValue(changedWorker.measurements._measurements.find((row) => row.path === path), value);
    const verdict = validateSideCapture(changed);
    if (!verdict.issues.some((x) => x.code === "webrtc-evidence-invalid")) missed.push(path);
  }
  ok("WebRTC timeout/unstable offer/malformed candidates cannot pass READY", missed.length === 0);
}
{
  const i = fullInput();
  const worker = i.records.find((r) => r.context === "dedicated-worker");
  worker.measurements._measurements = worker.measurements._measurements
    .filter((r) => r.path !== "canvas.pixelSha256");
  worker.measurements._measurements.push(rec("canvas.status", "forged-ok", { context: "dedicated-worker" }));
  const v = validateSideCapture(i);
  ok("capability fallback path only counts with its reviewed non-ok status",
    !v.ready && v.issues.some((x) => x.code === "required-job-evidence-missing" && x.job === "canvas"));
}
{
  const i = fullInput();
  const worker = i.records.find((r) => r.context === "dedicated-worker");
  const codec = worker.measurements._measurements.find((r) => r.path.startsWith("codecs.canPlay["));
  Object.assign(codec, { status: "unavailable-in-context", valueType: "null", value: null, error: null, meta: {} });
  const v = validateSideCapture(i);
  ok("reviewed unavailable codec output is terminal evidence in workers", v.ready);
}
{
  const i = fullInput();
  const sandboxed = i.records.find((r) => r.context === "sandboxed-iframe");
  const storage = sandboxed.measurements._measurements.find((r) => r.path === "storage.localStorage");
  Object.assign(storage, { status: "blocked", valueType: "null", value: null,
    error: { name: "SecurityError", message: "opaque origin" }, meta: {} });
  const v = validateSideCapture(i);
  ok("reviewed opaque-origin storage denial is terminal evidence", v.ready);
}
{
  const v = validateSideCapture(fullInput({ serverExpectedContexts: [] }));
  ok("empty server expected matrix always fails", !v.ready && has(v, "expected-matrix-empty"));
}
{
  const v = validateSideCapture(fullInput({ serverExpectedContexts: ["main-frame", "permissioned", "network"] }));
  ok("caller cannot shrink the build-owned context matrix", !v.ready && has(v, "expected-matrix-contract-mismatch"));
}
{
  const v = validateSideCapture(fullInput({ serverExpectedContexts: [...EXPECTED, "run-manifest"] }));
  ok("terminal run-manifest is outside the canonical context matrix", !v.ready && has(v, "expected-matrix-terminal-context"));
}
{
  const i = fullInput(); i.records = i.records.map((r) => r.context === "run-manifest" ? manifest("finished", []) : r);
  const v = validateSideCapture(i);
  ok("empty browser manifest expected list cannot bypass server matrix", !v.ready && has(v, "manifest-expected-empty"));
}
{
  const i = fullInput();
  i.records = i.records.map((r) => r.context === "run-manifest" ? manifest("finished", [...EXPECTED, "ghost-context"]) : r);
  i.records.find((r) => r.context === "run-manifest").identity = { ...i.records[0].identity };
  i.records.find((r) => r.context === "run-manifest").measurements.identity = { ...i.records[0].identity };
  const v = validateSideCapture(i);
  ok("browser terminal manifest cannot add ghost contexts", !v.ready && has(v, "manifest-expected-mismatch"));
}
{
  const i = fullInput();
  const m = i.records.find((r) => r.context === "run-manifest").measurements;
  m.expected.push(EXPECTED[0]);
  const v = validateSideCapture(i);
  ok("browser terminal manifest rejects duplicate expected contexts", !v.ready && has(v, "manifest-expected-mismatch"));
}
{
  const i = fullInput();
  const m = i.records.find((r) => r.context === "run-manifest").measurements;
  m.realms["ghost-context"] = { status: "finished" };
  const v = validateSideCapture(i);
  ok("browser terminal manifest rejects extra realm keys", !v.ready && has(v, "manifest-realms-mismatch"));
}
{
  const i = fullInput(); i.records = i.records.filter((r) => r.context !== "network");
  const v = validateSideCapture(i);
  ok("missing network blocks readiness", !v.ready && has(v, "missing-context"));
}
{
  const input = fullInput({ expectedNetworkBuild: "d".repeat(64) });
  const v = validateSideCapture(input);
  ok("a structurally current network record from another build is rejected",
    !v.ready && has(v, "network-build-mismatch"));
}
{
  const v = validateSideCapture(fullInput({ expectedNetworkBuild: "human-label" }));
  ok("server expected network build must itself be a full SHA-256 identity",
    !v.ready && has(v, "expected-network-build-invalid"));
}
{
  const v = validateSideCapture(fullInput({ unreadableLines: 1 }));
  ok("one unreadable JSONL line blocks readiness", !v.ready && has(v, "unreadable-jsonl"));
}
{
  const i = fullInput(); i.records.splice(1, 0, i.records[0]);
  const v = validateSideCapture(i);
  ok("duplicate outer context blocks readiness", !v.ready && has(v, "duplicate-context"));
}
{
  const i = fullInput();
  const main = i.records.find((r) => r.context === "main-frame");
  main.measurements._measurements.push(rec("locale.resolvedTZ", "second"));
  const v = validateSideCapture(i);
  ok("duplicate measurement key blocks readiness", !v.ready && has(v, "duplicate-measurement"));
}
{
  const i = fullInput();
  const p = i.records.find((r) => r.context === "permissioned");
  p.measurements._measurements = [rec("totally.fake", true, { context: "permissioned", phase: "permissioned" })];
  p.measurements._phaseManifest = { complete: true };
  const v = validateSideCapture(i);
  ok("permissioned complete:true cannot hide a missing probe matrix", !v.ready && has(v, "required-path-missing"));
}
{
  const requiredTrackPaths = ["kind", "label", "settings", "capabilities", "constraints"];
  const failures = [];
  for (const kind of ["audio", "video"]) {
    for (const leaf of requiredTrackPaths) {
      const i = fullInput();
      const p = i.records.find((r) => r.context === "permissioned");
      const index = kind === "audio" ? 0 : 1;
      p.measurements._measurements = p.measurements._measurements
        .filter((r) => r.path !== `permissioned.track[${index}].${leaf}`);
      const v = validateSideCapture(i);
      if (!has(v, "permissioned-track-evidence-invalid")) failures.push(`${kind}.${leaf}`);
    }
  }
  ok("granted permissioned capture requires kind/settings/capabilities/constraints for audio and video tracks",
    failures.length === 0);
}
{
  const failures = [];
  for (const phase of ["before", "after"]) {
    for (const index of [0, 1]) {
      for (const leaf of ["kind", "label", "deviceId", "groupId"]) {
        const input = fullInput();
        const permissioned = input.records.find((row) => row.context === "permissioned");
        const path = `permissioned.devices.${phase}[${index}].${leaf}`;
        permissioned.measurements._measurements = permissioned.measurements._measurements
          .filter((row) => row.path !== path);
        const verdict = validateSideCapture(input);
        if (!has(verdict, "permissioned-device-evidence-invalid")) failures.push(path);
      }
    }
  }
  ok("permissioned device counts require contiguous exact kind/label/deviceId/groupId rows", failures.length === 0);
}
{
  const geoPaths = ["latitude", "longitude", "accuracy", "altitude", "altitudeAccuracy", "heading",
    "speed", "timestamp", "coarseBucket"].map((leaf) => `permissioned.geo.${leaf}`);
  const failures = [];
  for (const path of geoPaths) {
    const input = fullInput();
    const permissioned = input.records.find((row) => row.context === "permissioned");
    permissioned.measurements._measurements = permissioned.measurements._measurements
      .filter((row) => row.path !== path);
    const verdict = validateSideCapture(input);
    if (!has(verdict, "permissioned-geo-evidence-invalid")) failures.push(path);
  }
  ok("granted geolocation requires every emitted coordinate metadata leaf", failures.length === 0);
}
{
  const mutations = [
    ["permissioned.devices.before.count", 3, "permissioned-device-evidence-invalid"],
    ["permissioned.devices.before.withLabels", 1, "permissioned-device-evidence-invalid"],
    ["permissioned.devices.after.withLabels", 1, "permissioned-device-evidence-invalid"],
    ["permissioned.devices.labelsRevealed", false, "permissioned-device-evidence-invalid"],
    ["permissioned.geo.latitude", 91, "permissioned-geo-evidence-invalid"],
    ["permissioned.geo.longitude", -181, "permissioned-geo-evidence-invalid"],
    ["permissioned.geo.accuracy", -1, "permissioned-geo-evidence-invalid"],
    ["permissioned.geo.timestamp", -1, "permissioned-geo-evidence-invalid"],
    ["permissioned.geo.coarseBucket", "00000000", "permissioned-geo-evidence-invalid"],
    ["permissioned.getUserMedia.result", "denied", "permissioned-manifest-invalid"],
    ["permissioned.perm.camera.after", "maybe", "permissioned-manifest-invalid"],
  ];
  const failures = [];
  for (const [path, value, code] of mutations) {
    const input = fullInput();
    const row = input.records.find((entry) => entry.context === "permissioned")
      .measurements._measurements.find((entry) => entry.path === path);
    replaceEncodedTestValue(row, value);
    const verdict = validateSideCapture(input);
    if (!has(verdict, code)) failures.push(path);
  }
  ok("permissioned counts, states, coordinate ranges and coarse hash are recomputed", failures.length === 0);
}
{
  const failures = [];
  const manifestMutations = [
    (manifest) => { manifest.requested.pop(); },
    (manifest) => { manifest.granted = []; },
    (manifest) => { manifest.denied.push("getUserMedia"); },
    (manifest) => { manifest.steps.getUserMedia = "denied"; },
  ];
  for (let index = 0; index < manifestMutations.length; index++) {
    const input = fullInput();
    const manifest = input.records.find((row) => row.context === "permissioned").measurements._phaseManifest;
    manifestMutations[index](manifest);
    const verdict = validateSideCapture(input);
    if (!has(verdict, "permissioned-manifest-invalid")) failures.push(index);
  }
  ok("permissioned phase manifest must reconcile exact requested and terminal outcomes", failures.length === 0);
}
{
  const i = fullInput();
  const p = i.records.find((r) => r.context === "permissioned");
  p.measurements._measurements.push({
    path: "permissioned.geo", context: "permissioned", phase: "permissioned",
    status: "permission-denied", valueType: "null", value: null, error: null, meta: {},
  });
  const v = validateSideCapture(i);
  ok("permission denial is valid raw but NOT a complete employee snapshot", !v.ready && has(v, "unexpected-non-ok"));
}
{
  const i = fullInput();
  const main = i.records.find((r) => r.context === "main-frame");
  main.measurements._measurements = main.measurements._measurements.filter((r) => r.path !== "control.clientjs.__manifest");
  const v = validateSideCapture(i);
  ok("missing mandatory control engine blocks readiness", !v.ready && has(v, "control-incomplete"));
}
{
  const variants = [
    [{ id: "thumbmark", version: /^1\.11\./ }],
    [
      { id: "unknown", version: /^1\.11\./ },
      { id: "fingerprintjs", version: /^5\./ },
      { id: "fpscanner", version: /^0\.1\.5(?:\b|$)/ },
      { id: "clientjs", version: /^0\.2\./ },
    ],
    [
      { id: "fingerprintjs", version: /^5\./ },
      { id: "thumbmark", version: /^1\.11\./ },
      { id: "fpscanner", version: /^0\.1\.5(?:\b|$)/ },
      { id: "clientjs", version: /^0\.2\./ },
    ],
    [
      { id: "thumbmark", version: /.*/ },
      { id: "fingerprintjs", version: /^5\./ },
      { id: "fpscanner", version: /^0\.1\.5(?:\b|$)/ },
      { id: "clientjs", version: /^0\.2\./ },
    ],
  ];
  const missed = [];
  variants.forEach((requiredControls, index) => {
    const input = fullInput({ requiredControls });
    const main = input.records.find((row) => row.context === "main-frame");
    main.measurements._measurements = main.measurements._measurements
      .filter((row) => !/^control\.(?:fingerprintjs|fpscanner|clientjs)\./.test(row.path));
    const verdict = validateSideCapture(input);
    if (verdict.ready || !has(verdict, "control-matrix-contract-mismatch") || !has(verdict, "control-incomplete")) missed.push(index);
  });
  ok("control subset/unknown/reordered/broad-regex overrides cannot weaken the four-engine contract", missed.length === 0);
}
{
  const i = fullInput();
  const main = i.records.find((r) => r.context === "main-frame");
  const manifestRow = main.measurements._measurements.find((r) => r.path === "control.thumbmark.__manifest");
  const m = decodedTestValue(manifestRow); delete m.componentKeys;
  replaceEncodedTestValue(manifestRow, m);
  const v = validateSideCapture(i);
  ok("control manifest must declare raw component keys", !v.ready && has(v, "control-incomplete"));
}
{
  const i = fullInput();
  const main = i.records.find((r) => r.context === "main-frame");
  main.measurements._measurements.push(rec("control.thumbmark.undeclaredRaw", 9));
  const v = validateSideCapture(i);
  ok("control manifest component key set must exactly match emitted raw rows",
    !v.ready && has(v, "control-incomplete"));
}
{
  const i = fullInput();
  const main = i.records.find((r) => r.context === "main-frame");
  main.measurements._measurements.find((r) => r.path === "control.thumbmark.component0").value = 99;
  const v = validateSideCapture(i);
  ok("server recomputes canonical control SHA-256 from raw component rows",
    !v.ready && has(v, "control-incomplete"));
}
{
  const i = fullInput();
  const main = i.records.find((r) => r.context === "main-frame");
  const manifestRow = main.measurements._measurements.find((r) => r.path === "control.thumbmark.__manifest");
  const m = decodedTestValue(manifestRow);
  m.componentKeys.push("hash");
  m.componentCount++;
  m.hash = "f".repeat(64);
  replaceEncodedTestValue(manifestRow, m);
  main.measurements._measurements.push(rec("control.thumbmark.hash", "f".repeat(64)));
  const v = validateSideCapture(i);
  ok("derived control rows cannot be declared as raw components", !v.ready && has(v, "control-incomplete"));
}
{
  const failures = [];
  for (const key of FPSCANNER_TEST_KEYS) {
    const path = `control.fpscanner.test.${key}`;
    const input = fullInput();
    const main = input.records.find((row) => row.context === "main-frame");
    main.measurements._measurements = main.measurements._measurements.filter((row) => row.path !== path);
    syncCollectorManifest(main);
    const verdict = validateSideCapture(input);
    if (!has(verdict, "control-incomplete")) failures.push(path);
  }
  ok("FPScanner cannot report ok after analyser tests disappear", failures.length === 0);
}
{
  const mutations = [
    ["manifest.testCount", (main) => {
      const row = main.measurements._measurements.find((entry) => entry.path === "control.fpscanner.__manifest");
      const value = decodedTestValue(row); value.testCount = 0; replaceEncodedTestValue(row, value);
    }],
    ["manifest.inconsistentCount", (main) => {
      const row = main.measurements._measurements.find((entry) => entry.path === "control.fpscanner.__manifest");
      const value = decodedTestValue(row); value.inconsistentCount = 2; replaceEncodedTestValue(row, value);
    }],
    ["manifest.invalidTestCount", (main) => {
      const row = main.measurements._measurements.find((entry) => entry.path === "control.fpscanner.__manifest");
      const value = decodedTestValue(row); value.invalidTestCount = 1; replaceEncodedTestValue(row, value);
    }],
    ["manifest.testKeys", (main) => {
      const row = main.measurements._measurements.find((entry) => entry.path === "control.fpscanner.__manifest");
      const value = decodedTestValue(row); value.testKeys.pop(); replaceEncodedTestValue(row, value);
    }],
    ["manifest.expectedTestKeys", (main) => {
      const row = main.measurements._measurements.find((entry) => entry.path === "control.fpscanner.__manifest");
      const value = decodedTestValue(row); value.expectedTestKeys = ["FORGED"]; replaceEncodedTestValue(row, value);
    }],
    ["manifest.testKeySetHash", (main) => {
      const row = main.measurements._measurements.find((entry) => entry.path === "control.fpscanner.__manifest");
      const value = decodedTestValue(row); value.testKeySetHash = "0".repeat(64); replaceEncodedTestValue(row, value);
    }],
    ["manifest.testSetHash", (main) => {
      const row = main.measurements._measurements.find((entry) => entry.path === "control.fpscanner.__manifest");
      const value = decodedTestValue(row); value.testSetHash = "0".repeat(64); replaceEncodedTestValue(row, value);
    }],
    ["manifest.testHashAlgorithm", (main) => {
      const row = main.measurements._measurements.find((entry) => entry.path === "control.fpscanner.__manifest");
      const value = decodedTestValue(row); value.testHashAlgorithm = "fnv"; replaceEncodedTestValue(row, value);
    }],
    ["manifest.expectedTestKeySetHash", (main) => {
      const row = main.measurements._measurements.find((entry) => entry.path === "control.fpscanner.__manifest");
      const value = decodedTestValue(row); value.expectedTestKeySetHash = "0".repeat(64); replaceEncodedTestValue(row, value);
    }],
    ["test.consistent", (main) => {
      const row = main.measurements._measurements.find((entry) => entry.path === "control.fpscanner.test.CHR_BATTERY");
      replaceEncodedTestValue(row, { consistent: 9, verdict: "CONSISTENT", data: {} });
    }],
    ["test.verdict", (main) => {
      const row = main.measurements._measurements.find((entry) => entry.path === "control.fpscanner.test.CHR_BATTERY");
      replaceEncodedTestValue(row, { consistent: 3, verdict: "INCONSISTENT", data: {} });
    }],
    ["manifest.engine", (main) => {
      const row = main.measurements._measurements.find((entry) => entry.path === "control.fpscanner.__manifest");
      const value = decodedTestValue(row); value.engine = "not-fpscanner"; replaceEncodedTestValue(row, value);
    }],
    ["manifest.duration", (main) => {
      const row = main.measurements._measurements.find((entry) => entry.path === "control.fpscanner.__manifest");
      const value = decodedTestValue(row); value.durationMs = -1; replaceEncodedTestValue(row, value);
    }],
  ];
  const failures = [];
  for (const [name, mutate] of mutations) {
    const input = fullInput();
    mutate(input.records.find((row) => row.context === "main-frame"));
    if (!has(validateSideCapture(input), "control-incomplete")) failures.push(name);
  }
  ok("FPScanner manifests and per-test consistency enum are independently validated", failures.length === 0);
}
{
  const v = validateSideCapture({ ...fullInput(), records: [browser("main-frame", [rec("navigator.userAgent")])] });
  ok("a first landed browser line is never completion", !v.ready && has(v, "missing-context") && has(v, "manifest-missing"));
}
{
  const i = fullInput(); i.records = i.records.map((r) => r.context === "run-manifest" ? manifest("fired") : r);
  const v = validateSideCapture(i);
  ok("manifest fired is not server-acknowledged finished", !v.ready && has(v, "manifest-realm-incomplete"));
}
{
  const i = fullInput();
  const p = i.records.find((r) => r.context === "permissioned");
  p.measurements._measurements[0].context = "main-frame";
  const v = validateSideCapture(i);
  ok("embedded measurement context mismatch blocks readiness", !v.ready && has(v, "unexpected-non-ok"));
}
{
  const plain = fullInput();
  const anti = fullInput({ environment: "anti", captureKey: "pair-1:anti" });
  const v = validatePairedCapture({ plain, anti });
  ok("one build-level OOPIF process proof is reusable across distinct manual captures",
    v.ready && v.plain.ready && v.anti.ready
      && !("processEvidence" in plain.records[0].identity.oopif)
      && !("captureKey" in plain.oopif.processEvidence));
  const bad = fullInput({ unreadableLines: 1 });
  const b = validatePairedCapture({ plain, anti: { ...bad, environment: "anti", captureKey: "pair-1:anti" } });
  ok("one bad side blocks the pair", !b.ready && b.plain.ready && !b.anti.ready);
}
{
  const same = fullInput();
  const v = validatePairedCapture({ plain: same, anti: same });
  ok("the same capture cannot be accepted as both sides", !v.ready && v.issues.some((x) => x.code === "pair-capture-not-distinct"));
}
{
  const plain = fullInput();
  const anti = fullInput({ environment: "anti", captureKey: "pair-1:anti" });
  anti.oopif.processEvidence.childProcessId = "renderer-process-3";
  anti.oopif.processEvidenceSha256 = canonicalSha256(anti.oopif.processEvidence);
  for (const row of anti.records) row.identity.oopif.processEvidenceSha256 = anti.oopif.processEvidenceSha256;
  anti.records.find((row) => row.context === "cross-origin-iframe")
    .measurements._crossOrigin.processEvidenceSha256 = anti.oopif.processEvidenceSha256;
  const v = validatePairedCapture({ plain, anti });
  ok("both sides of a pair must use the same accepted OOPIF deployment proof",
    v.plain.ready && v.anti.ready && !v.ready && v.issues.some((x) => x.code === "pair-oopif-mismatch"));
}
{
  const plain = fullInput();
  const anti = fullInput({ environment: "anti", captureKey: "pair-2:anti", pairKey: "pair-2", collectorBuild: "d".repeat(64) });
  const v = validatePairedCapture({ plain, anti });
  ok("pair identity and collector build must match", !v.ready
    && v.issues.some((x) => x.code === "pair-key-mismatch")
    && v.issues.filter((x) => x.code === "pair-build-mismatch").length === 1);
}
{
  const input = fullInput(); delete input.captureKey;
  const v = validateSideCapture(input);
  ok("missing server-side capture identity blocks readiness", !v.ready && has(v, "capture-metadata-invalid"));
}
{
  const input = fullInput();
  input.records[0].identity.environment = "anti";
  const v = validateSideCapture(input);
  ok("outer persisted records are bound to the side identity", !v.ready && has(v, "record-identity-mismatch"));
}
{
  const input = fullInput();
  input.records[0].identity.serviceWorkerChallenge = "B".repeat(22);
  const v = validateSideCapture(input);
  ok("every persisted record is bound to the server SW challenge",
    !v.ready && has(v, "record-identity-mismatch"));
}
{
  const short = validateSideCapture(fullInput({ serviceWorkerChallenge: "short" }));
  const unsafe = validateSideCapture(fullInput({ serviceWorkerChallenge: "A".repeat(22) + "/" }));
  ok("SW challenges are 128-bit-class URL-safe tokens",
    !short.ready && !unsafe.ready
      && has(short, "service-worker-challenge-invalid")
      && has(unsafe, "service-worker-challenge-invalid"));
}
{
  const input = fullInput({ captureKey: "unbound-capture-key" });
  const v = validateSideCapture(input);
  ok("capture key is deterministically bound to pair and environment",
    !v.ready && has(v, "capture-metadata-invalid"));
}
{
  const input = fullInput();
  input.records.find((r) => r.context === "cross-origin-iframe").measurements._crossOrigin.eventOriginVerified = false;
  const v = validateSideCapture(input);
  ok("cross-origin realm requires exact event-origin/configuration evidence", !v.ready && has(v, "cross-origin-evidence-invalid"));
}
{
  const input = fullInput({ oopif: { ...OOPIF, processEvidenceSha256: "not-a-hash" } });
  const v = validateSideCapture(input);
  ok("missing build-level CDP process evidence blocks OOPIF readiness", !v.ready && has(v, "capture-metadata-invalid"));
}
{
  const input = fullInput();
  input.oopif.registrableChildSite = input.oopif.registrableParentSite;
  const v = validateSideCapture(input);
  ok("server-owned registrable sites must be exact and distinct", !v.ready && has(v, "capture-metadata-invalid"));
}
{
  const input = fullInput();
  input.oopif.processEvidence.childProcessId = input.oopif.processEvidence.parentProcessId;
  const v = validateSideCapture(input);
  ok("OOPIF process artifact must prove distinct processes", !v.ready && has(v, "capture-metadata-invalid"));
}
{
  const input = fullInput();
  input.oopif.processEvidence.childProcessId = "renderer-process-tampered";
  const v = validateSideCapture(input);
  ok("OOPIF process artifact SHA-256 is recomputed canonically", !v.ready && has(v, "capture-metadata-invalid"));
}
{
  const input = fullInput();
  input.oopif.processEvidence.captureKey = "other-capture";
  input.oopif.processEvidenceSha256 = canonicalSha256(input.oopif.processEvidence);
  const v = validateSideCapture(input);
  ok("build-level OOPIF proof cannot smuggle a per-capture binding",
    !v.ready && has(v, "capture-metadata-invalid"));
}
{
  const input = fullInput();
  input.records[0].identity.oopif.processEvidence = { parentProcessId: "browser-claimed" };
  const v = validateSideCapture(input);
  ok("browser record identity cannot smuggle server-only OOPIF process evidence",
    !v.ready && has(v, "record-identity-mismatch"));
}
{
  const input = fullInput();
  input.oopif.parentSite = "https://browser-claimed.invalid";
  input.oopif.childSite = "https://browser-claimed.invalid";
  const cross = input.records.find((r) => r.context === "cross-origin-iframe").measurements._crossOrigin;
  cross.parentSite = input.oopif.parentSite;
  cross.childSite = input.oopif.childSite;
  const v = validateSideCapture(input);
  ok("legacy browser site claims never drive registrable-site validation", v.ready);
}
{
  const input = fullInput();
  delete input.records.find((r) => r.context === "service-worker").measurements._serviceWorker;
  const v = validateSideCapture(input);
  ok("service-worker payload requires build/capture handshake", !v.ready && has(v, "service-worker-evidence-invalid"));
}
{
  const input = fullInput();
  const main = input.records.find((r) => r.context === "main-frame");
  const raw = rec("control.thumbmark.__proto__", "preserved");
  main.measurements._measurements.push(raw);
  const manifestRow = main.measurements._measurements.find((r) => r.path === "control.thumbmark.__manifest");
  const manifestValue = decodedTestValue(manifestRow);
  manifestValue.componentKeys.push("__proto__");
  manifestValue.componentKeys.sort();
  manifestValue.componentCount++;
  const rawRows = main.measurements._measurements.filter((row) => row.path.startsWith("control.thumbmark.")
    && row.path !== "control.thumbmark.__manifest" && row.path !== "control.thumbmark.hash");
  const componentMap = Object.fromEntries(rawRows.map((row) => [row.path.slice("control.thumbmark.".length), encodedIdentity(row)]));
  manifestValue.hash = canonicalSha256(componentMap);
  replaceEncodedTestValue(manifestRow, manifestValue);
  const collectorManifest = main.measurements._measurements.find((r) => r.path === "collector.__manifest");
  const collectorValue = decodedTestValue(collectorManifest);
  collectorValue.measurementCount = main.measurements._measurements.length;
  replaceEncodedTestValue(collectorManifest, collectorValue);
  const v = validateSideCapture(input);
  ok("control canonicalization preserves a literal __proto__ component key", v.ready);
}
{
  const input = fullInput();
  input.records.find((r) => r.context === "service-worker")
    .measurements._serviceWorker.captureKey = "another-capture";
  const v = validateSideCapture(input);
  ok("service-worker handshake is bound to this capture", !v.ready && has(v, "service-worker-evidence-invalid"));
}
{
  const fields = ["handshakeVersion", "requestId", "scriptURL", "scope"];
  const missed = [];
  for (const field of fields) {
    const input = fullInput();
    const sw = input.records.find((r) => r.context === "service-worker").measurements._serviceWorker;
    sw[field] = field === "handshakeVersion" ? 2 : "tampered";
    const v = validateSideCapture(input);
    if (!has(v, "service-worker-evidence-invalid")) missed.push(field);
  }
  ok("service-worker evidence binds protocol, request, exact script URL and unique scope", missed.length === 0);
}
{
  const input = fullInput();
  input.records.find((r) => r.context === "run-manifest").measurements.identity.captureKey = "other";
  const v = validateSideCapture(input);
  ok("terminal manifest is bound to the same capture identity", !v.ready && has(v, "manifest-identity-mismatch"));
}
{
  const plain = fullInput();
  const antiTopOnly = { ...plain, environment: "anti", captureKey: "pair-1:anti" };
  const v = validatePairedCapture({ plain, anti: antiTopOnly });
  ok("top-level relabelling cannot reuse plain records as anti", !v.ready && !v.anti.ready
    && v.anti.issues.some((x) => x.code === "record-identity-mismatch"));
}
{
  const plain = fullInput();
  const anti = fullInput({ environment: "anti", captureKey: "pair-1:anti" });
  anti.records.find((r) => r.context === "network").measurements.captureBuild = "f".repeat(64);
  const v = validatePairedCapture({ plain, anti });
  ok("paired network captures must come from the same capture build", !v.ready
    && v.issues.some((x) => x.code === "pair-network-build-mismatch"));
}
{
  const missing = fullInput(); delete missing.collectorArtifactSha256;
  const malformed = fullInput({ collectorArtifactSha256: "not-a-sha256" });
  ok("server-owned collector artifact SHA-256 is mandatory metadata",
    has(validateSideCapture(missing), "collector-artifact-invalid")
      && has(validateSideCapture(malformed), "collector-artifact-invalid"));
}
{
  const input = fullInput();
  input.records.find((row) => row.context === "dedicated-worker")
    .identity.collectorArtifactSha256 = "e".repeat(64);
  const v = validateSideCapture(input);
  ok("every persisted record is bound to the exact collector artifact",
    !v.ready && has(v, "record-identity-mismatch"));
}
{
  const input = fullInput();
  input.records.find((row) => row.context === "run-manifest")
    .measurements.identity.collectorArtifactSha256 = "e".repeat(64);
  const v = validateSideCapture(input);
  ok("terminal manifest is bound to the exact collector artifact",
    !v.ready && has(v, "manifest-identity-mismatch"));
}
{
  const plain = fullInput();
  const anti = fullInput({ environment: "anti", captureKey: "pair-1:anti",
    collectorArtifactSha256: "e".repeat(64) });
  const v = validatePairedCapture({ plain, anti });
  ok("both pair sides must execute the same collector artifact",
    v.plain.ready && v.anti.ready && !v.ready && has(v, "pair-collector-artifact-mismatch"));
}
{
  const missed = [];
  for (const context of ["iframe-url", "cross-origin-iframe"]) {
    const deleted = fullInput();
    delete deleted.records.find((row) => row.context === context).measurements._boundChild;
    if (!has(validateSideCapture(deleted), "bound-child-evidence-invalid")) missed.push(`${context}:missing`);
    for (const field of ["protocol", "handshakeVersion", "context", "collectorBuild",
      "collectorArtifactSha256", "captureKey", "requestId", "parentOrigin",
      "acknowledgementSha256"]) {
      const input = fullInput();
      const binding = input.records.find((row) => row.context === context).measurements._boundChild;
      binding[field] = field === "handshakeVersion" ? 2 : "tampered";
      if (!has(validateSideCapture(input), "bound-child-evidence-invalid")) {
        missed.push(`${context}:${field}`);
      }
    }
  }
  ok("real-URL child realms require exact recomputed artifact/capture bindings", missed.length === 0);
}
{
  const input = fullInput();
  input.records.find((row) => row.context === "service-worker")
    .measurements._serviceWorker.collectorArtifactSha256 = "e".repeat(64);
  const v = validateSideCapture(input);
  ok("service-worker handshake is bound to exact collector bytes",
    !v.ready && has(v, "service-worker-evidence-invalid"));
}
{
  const missed = [];
  for (const path of ["control.thumbmark.hash", "control.fingerprintjs.visitorId",
    ...CLIENTJS_COMPONENT_KEYS.map((key) => `control.clientjs.${key}`),
    ...CONTROL_SANITY_PATHS]) {
    const input = fullInput();
    const main = input.records.find((row) => row.context === "main-frame");
    main.measurements._measurements = main.measurements._measurements.filter((row) => row.path !== path);
    syncCollectorManifest(main);
    if (!has(validateSideCapture(input), path.startsWith("control.sanity.")
      ? "control-sanity-incomplete" : "control-incomplete")) missed.push(path);
  }
  ok("fixed control outputs and every sanity probe are build-owned contracts", missed.length === 0);
}
{
  const input = fullInput();
  const main = input.records.find((row) => row.context === "main-frame");
  main.measurements._measurements.push(rec("control.clientjs.unreviewedGetter", "forged"));
  syncCollectorManifest(main);
  const manifestRow = main.measurements._measurements.find((row) => row.path === "control.clientjs.__manifest");
  const manifestValue = decodedTestValue(manifestRow);
  manifestValue.componentKeys = [...manifestValue.componentKeys, "unreviewedGetter"].sort();
  manifestValue.componentCount++;
  const componentRows = main.measurements._measurements.filter((row) => row.path.startsWith("control.clientjs.")
    && row.path !== "control.clientjs.__manifest");
  manifestValue.hash = canonicalSha256(Object.fromEntries(componentRows.map((row) => [
    row.path.slice("control.clientjs.".length), encodedIdentity(row),
  ])));
  replaceEncodedTestValue(manifestRow, manifestValue);
  const v = validateSideCapture(input);
  ok("ClientJS cannot self-authorize a changed getter surface",
    !v.ready && has(v, "control-incomplete"));
}

// ---- Typed getUserMedia failure model (Codex v4.5) ----
{
  const v = validateSideCapture(fullInput());
  ok("untouched READY fixture stays READY and is a complete capture", v.ready && v.captureComplete === true);
  const paired = validatePairedCapture({ plain: fullInput(), anti: fullInput({ environment: "anti" }) });
  ok("paired verdict exposes captureComplete for both sides",
    paired.ready && paired.captureComplete === true && paired.plain.captureComplete === true && paired.anti.captureComplete === true);
}
{
  const input = withGumOutcome(fullInput(), {
    result: "device-start-failure",
    attempts: [
      gumAttempt(1, { audio: true, video: true }, "rejected", "NotReadableError", "Could not start video source"),
      gumAttempt(2, { audio: true, video: true }, "rejected", "NotReadableError", "Could not start video source"),
      gumAttempt(3, { audio: true }, "rejected", "NotReadableError", "Could not start audio source"),
      gumAttempt(4, { video: true }, "rejected", "NotReadableError", "Could not start video source"),
    ],
    audioOnly: gumSingle("rejected", "NotReadableError", "Could not start audio source"),
    videoOnly: gumSingle("rejected", "NotReadableError", "Could not start video source"),
    mainStatus: "error", mainError: { name: "NotReadableError", message: "Could not start video source" },
    tracks: [],
  });
  const v = validateSideCapture(input);
  ok("FULL validator: complete side with device-start-failure and no tracks is NOT_READY",
    v.ready === false && v.overall === "NOT_READY" && has(v, "permissioned-getusermedia-device-start-failure")
      && has(v, "unexpected-non-ok") && !has(v, "permissioned-getusermedia-evidence-invalid"));
  ok("device-start-failure is still a COMPLETE capture (persisted diagnostics, strict verdict NOT_READY)",
    v.captureComplete === true);
  const paired = validatePairedCapture({ plain: input, anti: fullInput({ environment: "anti" }) });
  ok("device-start-failure on one side blocks the pair but keeps captureComplete", !paired.ready && paired.captureComplete === true);
}
{
  const input = withGumOutcome(fullInput(), {
    result: "no-device",
    attempts: [
      gumAttempt(1, { audio: true, video: true }, "rejected", "NotFoundError", "Requested device not found"),
      gumAttempt(2, { audio: true }, "granted"),
      gumAttempt(3, { video: true }, "rejected", "NotFoundError", "Requested device not found"),
    ],
    audioOnly: gumSingle("granted", null, null, ["audio"]),
    videoOnly: gumSingle("rejected", "NotFoundError", "Requested device not found"),
    mainStatus: "unavailable-in-context", mainError: { name: "NotFoundError", message: "Requested device not found" },
    tracks: [AUDIO_TRACK],
    devicesBefore: AUDIO_DEVICES(false), devicesAfter: AUDIO_DEVICES(true),
  });
  const v = validateSideCapture(input);
  ok("confirmed no-device (no videoinput enumerated, audio-only granted with an audio track) raises no gUM issue",
    !v.issues.some((entry) => entry.code.startsWith("permissioned-")) && v.ready && v.captureComplete === true);
}
{
  const input = withGumOutcome(fullInput(), {
    result: "no-device",
    attempts: [
      gumAttempt(1, { audio: true, video: true }, "rejected", "NotFoundError", "Requested device not found"),
      gumAttempt(2, { audio: true }, "granted"),
      gumAttempt(3, { video: true }, "rejected", "NotFoundError", "Requested device not found"),
    ],
    audioOnly: gumSingle("granted", null, null, ["audio"]),
    videoOnly: gumSingle("rejected", "NotFoundError", "Requested device not found"),
    mainStatus: "unavailable-in-context", mainError: { name: "NotFoundError", message: "Requested device not found" },
    tracks: [AUDIO_TRACK],
  });
  const v = validateSideCapture(input);
  ok("unconfirmed no-device (both kinds enumerated) is blocking",
    !v.ready && has(v, "permissioned-no-device-unconfirmed") && has(v, "permissioned-track-evidence-invalid"));
}
{
  const input = withGumOutcome(fullInput(), {
    result: "no-device",
    attempts: [
      gumAttempt(1, { audio: true, video: true }, "rejected", "NotFoundError", "Requested device not found"),
      gumAttempt(2, { audio: true }, "rejected", "NotFoundError", "Requested device not found"),
      gumAttempt(3, { video: true }, "rejected", "NotFoundError", "Requested device not found"),
    ],
    audioOnly: gumSingle("rejected", "NotFoundError", "Requested device not found"),
    videoOnly: gumSingle("rejected", "NotFoundError", "Requested device not found"),
    mainStatus: "unavailable-in-context", mainError: { name: "NotFoundError", message: "Requested device not found" },
    tracks: [],
    devicesBefore: AUDIO_DEVICES(false), devicesAfter: AUDIO_DEVICES(true),
  });
  const v = validateSideCapture(input);
  ok("no-device is unconfirmed when a PRESENT kind was not granted with a recorded track",
    !v.ready && has(v, "permissioned-no-device-unconfirmed"));
}
{
  const aborted = (lifecycle, attemptLifecycle) => withGumOutcome(fullInput(), {
    result: "aborted",
    attempts: [gumAttempt(1, { audio: true, video: true }, "rejected", "AbortError", "aborted", attemptLifecycle)],
    lifecycle,
    mainStatus: "error", mainError: { name: "AbortError", message: "aborted" },
    tracks: [],
  });
  const native = validateSideCapture(aborted("native", "live"));
  const synthetic = validateSideCapture(aborted("synthetic-pagehide", "pagehide"));
  ok("native AbortError is a blocking lifecycle failure carrying its lifecycle",
    !native.ready && native.issues.some((entry) => entry.code === "permissioned-getusermedia-aborted" && entry.lifecycle === "native"));
  ok("synthetic pagehide abort is a blocking lifecycle failure carrying its lifecycle",
    !synthetic.ready && synthetic.issues.some((entry) => entry.code === "permissioned-getusermedia-aborted" && entry.lifecycle === "synthetic-pagehide"));
  const mislabelled = validateSideCapture(withGumOutcome(fullInput(), {
    result: "aborted",
    attempts: [gumAttempt(1, { audio: true, video: true }, "rejected", "AbortError", "aborted")],
    lifecycle: "none",
    mainStatus: "error", mainError: { name: "AbortError", message: "aborted" }, tracks: [],
  }));
  ok("aborted without a lifecycle is malformed evidence", has(mislabelled, "permissioned-getusermedia-evidence-invalid"));
}
{
  const notSupported = validateSideCapture(withGumOutcome(fullInput(), {
    result: "not-supported",
    attempts: [gumAttempt(1, { audio: true, video: true }, "rejected", "NotSupportedError", "not supported")],
    mainStatus: "error", mainError: { name: "NotSupportedError", message: "not supported" }, tracks: [],
  }));
  ok("NotSupportedError is blocking", !notSupported.ready && has(notSupported, "permissioned-getusermedia-not-supported"));
  const failures = [];
  const generic = [
    ["denied", "permission-denied", "NotAllowedError"],
    ["timeout", "timeout", "TimeoutError"],
    ["error", "error", "TypeError"],
  ];
  for (const [result, mainStatus, name] of generic) {
    const v = validateSideCapture(withGumOutcome(fullInput(), {
      result,
      attempts: [gumAttempt(1, { audio: true, video: true }, result === "timeout" ? "timeout" : "rejected", name, "x")],
      mainStatus, mainError: { name, message: "x" }, tracks: [],
    }));
    if (v.ready || !v.issues.some((entry) => entry.code === "permissioned-getusermedia-failed" && entry.result === result)) failures.push(result);
  }
  ok("denied / timeout / error results raise permissioned-getusermedia-failed", failures.length === 0);
}
{
  const failures = [];
  const detailPaths = ["permissioned.getUserMedia.failure", "permissioned.getUserMedia.attempts",
    "permissioned.getUserMedia.audioOnly", "permissioned.getUserMedia.videoOnly",
    "permissioned.getUserMedia.lifecycle", "permissioned.getUserMedia.secureContext"];
  for (const path of detailPaths) {
    const input = fullInput();
    const permissioned = input.records.find((row) => row.context === PCTX);
    permissioned.measurements._measurements = permissioned.measurements._measurements.filter((row) => row.path !== path);
    const v = validateSideCapture(input);
    if (v.ready || !has(v, "permissioned-getusermedia-evidence-invalid")) failures.push(path);
  }
  const mutations = [
    ["permissioned.getUserMedia.failure", "denied"],
    ["permissioned.getUserMedia.attempts", []],
    ["permissioned.getUserMedia.attempts", [{ attempt: 1, constraints: { audio: true, video: true }, outcome: "granted" }]],
    ["permissioned.getUserMedia.lifecycle", "native"],
    ["permissioned.getUserMedia.secureContext", "true"],
    ["permissioned.getUserMedia.audioOnly", gumSingle("granted", null, null, ["audio"])],
  ];
  for (const [path, value] of mutations) {
    const input = fullInput();
    const row = input.records.find((entry) => entry.context === PCTX)
      .measurements._measurements.find((entry) => entry.path === path);
    replaceEncodedTestValue(row, value);
    const v = validateSideCapture(input);
    if (v.ready || !has(v, "permissioned-getusermedia-evidence-invalid")) failures.push(`${path}=${JSON.stringify(value)}`);
  }
  ok("typed getUserMedia detail rows are required and shape-checked", failures.length === 0);
}
{
  const input = fullInput();
  input.records = input.records.filter((row) => row.context !== "credentialless-iframe");
  const missing = validateSideCapture(input);
  ok("a missing context is neither READY nor a complete capture", !missing.ready && missing.captureComplete === false);
  const unreadable = validateSideCapture({ ...fullInput(), unreadableLines: 1 });
  ok("unreadable lines keep captureComplete false", !unreadable.ready && unreadable.captureComplete === false);
  const stale = fullInput();
  stale.records.find((row) => row.context === "run-manifest").measurements.realms.network = { status: "pending" };
  const staleVerdict = validateSideCapture(stale);
  ok("a non-terminal run-manifest realm keeps captureComplete false", !staleVerdict.ready && staleVerdict.captureComplete === false);
}

// A persisted but malformed context is not a complete raw capture merely
// because its outer row and terminal manifest exist.
{
  const malformed = fullInput();
  const target = malformed.records.find((row) => row.context === "dedicated-worker");
  target.measurements = { _context: "dedicated-worker", _measurementsError: "ERR:TypeError" };
  const verdict = validateSideCapture(malformed);
  ok("ADVERSARIAL: malformed persisted realm is not captureComplete", verdict.captureComplete === false);
}
{
  const incompletePermissioned = fullInput();
  const target = incompletePermissioned.records.find((row) => row.context === "permissioned");
  target.measurements._phaseManifest.complete = false;
  const verdict = validateSideCapture(incompletePermissioned);
  ok("ADVERSARIAL: incomplete permissioned phase is not captureComplete", verdict.captureComplete === false);
}

console.log(`\nfp-readiness: ${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
