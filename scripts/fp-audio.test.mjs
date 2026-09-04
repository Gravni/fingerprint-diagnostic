import { readFileSync } from "node:fs";
import vm from "node:vm";
import { bytesHash, sha256hex } from "../lib/fp-encode.mjs";

let pass = 0, fail = 0;
function ok(label, condition) {
  if (condition) pass++;
  else { fail++; console.log("  ✗ " + label); }
}

const html = readFileSync(new URL("../assets/fingerprint-probe.html", import.meta.url), "utf8");
const start = html.indexOf("function renderAudioOnce(");
const end = html.indexOf("\n  function realtimeAudioSnapshot()", start);
if (start < 0 || end < 0) throw new Error("audio render helper boundary not found");
const source = html.slice(start, end) + "\nthis.renderAudioOnce=renderAudioOnce;";

function audioNodes() {
  return {
    createOscillator() { return { type: "", frequency: { value: 0 }, connect() {}, start() {} }; },
    createDynamicsCompressor() {
      return {
        threshold: { value: 0 }, knee: { value: 0 }, ratio: { value: 0 },
        attack: { value: 0 }, release: { value: 0 }, connect() {},
      };
    },
    destination: {}, sampleRate: 44100,
  };
}

function makeContext(OfflineAudioContext, timerSink = []) {
  const context = {
    Promise, Float32Array, Uint8Array, DataView, ArrayBuffer,
    root: { OfflineAudioContext }, sha256hex, bytesHash, hash: () => "legacy-fnv",
    setTimeout(fn) { timerSink.push(fn); return timerSink.length; },
    clearTimeout() {},
  };
  vm.runInNewContext(source, context);
  return context;
}

{
  const samples = new Float32Array([0, 0.5, -0.25, 1]);
  class OfflineAudioContext {
    constructor() { Object.assign(this, audioNodes()); }
    startRendering() {
      const renderedBuffer = { getChannelData: () => samples };
      queueMicrotask(() => this.oncomplete?.({ renderedBuffer }));
      return Promise.resolve(renderedBuffer);
    }
  }
  const context = makeContext(OfflineAudioContext);
  const result = await context.renderAudioOnce();
  const expectedBytes = new Uint8Array(samples.length * 4);
  const view = new DataView(expectedBytes.buffer);
  samples.forEach((value, index) => view.setFloat32(index * 4, value, true));
  ok("offline audio hashes every Float32 sample in canonical little-endian bytes",
    result.sha256 === sha256hex(expectedBytes) && result.fnv === bytesHash(expectedBytes));
  ok("offline audio reports the exact readback size", result.sampleCount === 4 && result.byteLength === 16);
  ok("offline audio digest is a full lowercase SHA-256", /^[0-9a-f]{64}$/.test(result.sha256));
}

{
  const timers = [];
  class OfflineAudioContext {
    constructor() { Object.assign(this, audioNodes()); }
    startRendering() { return new Promise(() => {}); }
  }
  const context = makeContext(OfflineAudioContext, timers);
  const pending = context.renderAudioOnce();
  timers[0]();
  const result = await pending;
  ok("offline audio timeout is an explicit acquisition result", result.timeout === true);
}

{
  class OfflineAudioContext {
    constructor() { Object.assign(this, audioNodes()); }
    startRendering() { throw new DOMException("blocked", "NotAllowedError"); }
  }
  const context = makeContext(OfflineAudioContext);
  const result = await context.renderAudioOnce();
  ok("offline audio start failure remains typed for the caller", result.error?.name === "NotAllowedError");
}

console.log(`\nfp-audio: ${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
