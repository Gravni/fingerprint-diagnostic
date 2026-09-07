import { readFileSync } from "node:fs";
import vm from "node:vm";
import { bytesHash, sha256hex } from "../lib/fp-encode.mjs";

let pass = 0, fail = 0;
function ok(label, cond) { if (cond) pass++; else { fail++; console.log("  ✗ " + label); } }

const html = readFileSync(new URL("../assets/fingerprint-probe.html", import.meta.url), "utf8");
ok("UA-CH requests the standardized plural formFactors key",
  html.includes("'wow64','formFactors'") && !html.includes("'wow64','formFactor'"));
ok("visualViewport leaves emit typed terminal evidence instead of disappearing",
  html.includes("M('env.vvScale'") && html.includes("M('env.vvWidth'")
    && html.includes("vv?vv.scale:MSTATUS.unavailable"));

{
  const resolverStart = html.indexOf("function resolveCollectUrl(");
  const resolverEnd = html.indexOf("\n}\n", resolverStart);
  if (resolverStart < 0 || resolverEnd < 0) {
    ok("collect URL resolver is executable", false);
  } else {
    const context = { URL, URLSearchParams };
    vm.runInNewContext(html.slice(resolverStart, resolverEnd + 2) + "\nthis.resolveCollectUrl=resolveCollectUrl;", context);
    const resolve = context.resolveCollectUrl;
    ok("collect URL defaults to the local /collect route", resolve("", "https://panel.test/probe") === "/collect");
    ok("collect URL accepts same-origin paths and absolute URLs",
      resolve("?collect=%2Fapi%2Fcollect%3Fx%3D1", "https://panel.test/probe") === "/api/collect?x=1"
      && resolve("?collect=https%3A%2F%2Fpanel.test%2Fother", "https://panel.test/probe") === "/other");
    for (const candidate of ["https://evil.test/collect", "//evil.test/collect", "https://u:p@panel.test/collect"]) {
      let rejected = false;
      try { resolve("?collect=" + encodeURIComponent(candidate), "https://panel.test/probe"); } catch { rejected = true; }
      ok("collect URL rejects unsafe override " + candidate, rejected);
    }
  }
}

const start = html.indexOf("async function netLayer(){");
const end = html.indexOf("\n}\n\n// Permissioned phase", start);
if (start < 0 || end < 0) throw new Error("netLayer source boundary not found");
const netLayerSource = html.slice(start, end + 2) + "\nthis.netLayer = netLayer;";

async function executeNetwork({ captureStatus = 200, rejectRound = 0 } = {}) {
  const statuses = [], requests = [];
  let captureRound = 0;
  const context = {
    URL, URLSearchParams,
    location: { search: "?env=plain&sid=session-1" },
    rstat: (...args) => statuses.push(args),
    log: () => {},
    setTimeout: (fn) => { queueMicrotask(fn); return 1; },
    clearTimeout: () => {},
    AbortController,
    fetch: async (url, options = {}) => {
      requests.push({ url: String(url), options });
      if (String(url).startsWith("/api/fingerprint/net-token")) {
        const round = new URL("http://panel.local" + url).searchParams.get("round");
        return { ok: true, status: 200, json: async () => ({ url: `https://capture.test/?round=${round}` }) };
      }
      captureRound++;
      if (rejectRound === captureRound) throw new TypeError("network failed");
      return { ok: captureStatus >= 200 && captureStatus < 300, status: captureStatus };
    },
  };
  context.boundedFetch = (url, options) => context.fetch(url, options);
  context.boundedJson = async (url, options) => {
    const response = await context.fetch(url, options);
    return { response, data: await response.json() };
  };
  vm.runInNewContext(netLayerSource, context);
  await context.netLayer();
  return { statuses, requests };
}

{
  const r = await executeNetwork();
  ok("one token is reused for prime and final round", r.requests.filter((x) => x.url.startsWith("/api/fingerprint/net-token")).length === 1);
  ok("network uses exactly two capture requests", r.requests.filter((x) => x.url.startsWith("https://capture.test/")).length === 2);
  ok("capture requests use readable CORS responses", r.requests.filter((x) => x.url.startsWith("https://capture.test/")).every((x) => x.options.mode === "cors"));
  ok("network is finished only after both acknowledged responses", r.statuses.some((x) => x[0] === "network" && x[1] === "finished"));
  ok("obsolete fired state is never emitted", !r.statuses.some((x) => x[1] === "fired"));
}
{
  const r = await executeNetwork({ rejectRound: 2 });
  ok("round-2 fetch rejection never marks network finished", !r.statuses.some((x) => x[0] === "network" && x[1] === "finished"));
  ok("round-2 fetch rejection is an explicit error", r.statuses.some((x) => x[0] === "network" && x[1] === "error"));
}
{
  const r = await executeNetwork({ captureStatus: 502 });
  ok("capture non-2xx never marks network finished", !r.statuses.some((x) => x[0] === "network" && x[1] === "finished"));
}

ok("final UI consumes strict readiness, not legacy complete boolean",
  html.includes("st.ready===true") && html.includes("st.overall==='READY'") && !html.includes("if(st&&st.complete)"));
ok("browser payloads never advertise an explicitly partial schema as current",
  !html.includes("typed-v4-partial") && html.includes("_schema='typed-v4'"));
ok("the top-level harness invokes the two-round network flow exactly once",
  (html.match(/await netLayer\(\);/g) || []).length === 1);
ok("FingerprintJS manifest uses a real SHA-256 rather than its 32-hex visitor id",
  html.includes("manifest.hash=ctrlHash(state.map)") && html.includes("manifest.hashAlgorithm='sha256'")
    && html.includes("manifest.componentKeys=state.keys")
    && !html.includes("hash:String(r.visitorId)"));
ok("every full collector realm emits a build-owned terminal block manifest",
  html.includes("path:'collector.__manifest'") && html.includes("expectedJobs")
    && html.includes("measurementCount"));
ok("a deep-walk leaf cap becomes an explicit blocking record",
  html.includes(".__walkLimit") && html.includes("status:STATUS.invalidResult"));
ok("every persisted browser POST carries the initialized capture identity",
  html.includes("async function initRunIdentity()") && html.includes("identity:RUN_IDENTITY")
    && html.includes("collectorBuild:build"));
ok("cached HTML cannot relabel collector A as the newer endpoint build B",
  html.includes("EMBEDDED_COLLECTOR_BUILD")
    && html.includes("build!==EMBEDDED_COLLECTOR_BUILD"));
ok("worker and frame source is a mandatory renderer injection, never runtime toString output",
  html.includes("const COLLECTOR_SRC=/*__FP_COLLECTOR_SOURCE_INJECT__*/")
    && html.includes("const EMBEDDED_COLLECTOR_ARTIFACT_SHA256='__FP_COLLECTOR_ARTIFACT_SHA256__'")
    && !html.includes("COLLECTOR.toString()"));
ok("identity binds the exact collector artifact and verifies its local bytes",
  html.includes("browserCollectorArtifactSha256")
    && html.includes("LinkageProbe.sha256hex(COLLECTOR_SRC)!==EMBEDDED_COLLECTOR_ARTIFACT_SHA256")
    && html.includes("collectorArtifactSha256:artifact"));
ok("cross-site evidence uses server-owned exact origins, not a last-two-label guess",
  html.includes("crossOriginProbe") && html.includes("configurationId")
    && html.includes("processEvidenceSha256") && html.includes("registrableParentSite")
    && html.includes("registrableChildSite") && html.includes("processEvidenceBuild")
    && !html.includes("hostname.split('.').slice(-2)"));
ok("cross-site collector URL is restricted to the reviewed /xprobe endpoint",
  html.includes("childUrl.pathname!=='/xprobe'") && html.includes("childUrl.username")
    && html.includes("childUrl.password") && html.includes("childUrl.hash"));
ok("real-URL child realms require a build/artifact/capture/request handshake",
  html.includes("function expectedBoundChild(") && html.includes("function validateBoundChildMessage(")
    && html.includes("__fpBoundChild") && html.includes("fpArtifact")
    && html.includes("fpCapture") && html.includes("fpRequest")
    && html.includes("payload._boundChild"));
ok("all iframe variants explicitly delegate the keyboard-map policy",
  (html.match(/keyboard-map \*/g) || []).length >= 3);

{
  const bindingStart = html.indexOf("function canonicalIdentityJson(");
  const bindingEnd = html.indexOf("// These are server/session facts", bindingStart);
  if (bindingStart < 0 || bindingEnd < 0) {
    ok("bound child validation is executable", false);
  } else {
    const sourceWindow = {};
    const frame = { contentWindow: sourceWindow };
    const context = {
      URL, URLSearchParams,
      location: { href: "https://panel.example.test/fingerprint", origin: "https://panel.example.test" },
      crypto: { getRandomValues(array) { array.fill(7); } },
      LinkageProbe: { sha256hex },
      RUN_IDENTITY: {
        collectorBuild: "a".repeat(64), collectorArtifactSha256: "b".repeat(64),
        captureKey: "pair-1:plain",
      },
    };
    vm.runInNewContext(html.slice(bindingStart, bindingEnd)
      + "\nthis.expectedBoundChild=expectedBoundChild;this.bindChildUrl=bindChildUrl;this.validateBoundChildMessage=validateBoundChildMessage;", context);
    const expected = context.expectedBoundChild("iframe-url", "ChildRequest_1234567890ab", context.location.origin);
    const payload = { _context: "iframe-url", _boundChild: { ...expected } };
    const event = { source: sourceWindow, origin: context.location.origin,
      data: { __fpBoundChild: 1, binding: { ...expected }, payload } };
    ok("parent accepts only an exact bound child envelope",
      context.validateBoundChildMessage(event, frame, expected, context.location.origin) === payload);
    let rejected = false;
    try {
      context.validateBoundChildMessage({ ...event, data: { ...event.data,
        binding: { ...expected, captureKey: "pair-1:anti" } } }, frame, expected, context.location.origin);
    } catch { rejected = true; }
    ok("parent rejects a child rebound to another capture", rejected);
    const boundURL = context.bindChildUrl("https://panel.example.test/fingerprint/frame", expected);
    ok("bound child URL contains exactly the eight route-contract fields",
      [...boundURL.searchParams.keys()].sort().join(",")
        === ["fpAck", "fpArtifact", "fpBuild", "fpCapture", "fpContext", "fpParent", "fpRequest", "fpVersion"].sort().join(","));
  }
}

ok("the terminal manifest repeats the same capture identity",
  html.includes("identity:RUN_IDENTITY"));
ok("AudioWorklet reuses the injected SHA implementation and emits its own manifest",
  html.includes("WORKLET_SRC=COLLECTOR_SRC+") && html.includes("self.LinkageProbe.sha256hex")
    && html.includes("'worklet.__manifest'"));

{
  const walkStart = html.indexOf("function walkTyped(");
  const walkEnd = html.indexOf("// Current collect() context/phase", walkStart);
  if (walkStart < 0 || walkEnd < 0) {
    ok("sandbox serviceWorker denial is typed", false);
  } else {
    const context = {
      Object, Array, WeakSet,
      MAX_DEPTH: 4, MAX_LEAVES: 6000,
      NOISE: {},
      STATUS: { ok: "ok", blocked: "blocked", error: "error", invalidResult: "invalid-result" },
      encodeValue: (value) => ({ valueType: typeof value, value }),
    };
    vm.runInNewContext(html.slice(walkStart, walkEnd) + "\nthis.walkTyped=walkTyped;", context);
    const navigatorLike = {};
    Object.defineProperty(navigatorLike, "serviceWorker", {
      enumerable: true,
      get() { const error = new Error("opaque sandbox"); error.name = "SecurityError"; throw error; },
    });
    const records = [];
    context.walkTyped(navigatorLike, "navigator", "sandboxed-iframe", "passive", records);
    ok("sandbox serviceWorker denial is typed as blocked at its exact path",
      records.some((row) => row.path === "navigator.serviceWorker" && row.status === "blocked"));
  }
}

{
  const keyboardStart = html.indexOf("function keyboardBlock(");
  const storageEnd = html.indexOf("/* ---- WebAssembly", keyboardStart);
  if (keyboardStart < 0 || storageEnd < 0) {
    ok("opaque sandbox capability normalization is executable", false);
  } else {
    const records = [];
    const blocked = { __mstatus: "blocked" };
    const root = { navigator: {
      keyboard: { getLayoutMap: () => Promise.reject(Object.assign(new Error("policy"), { name: "SecurityError" })) },
      storage: { estimate: () => Promise.reject(Object.assign(new Error("opaque"), { name: "TypeError" })) },
    } };
    for (const name of ["localStorage", "sessionStorage", "caches"]) {
      Object.defineProperty(root, name, { get() { throw Object.assign(new Error("opaque"), { name: "SecurityError" }); } });
    }
    root.indexedDB = {}; root.navigator.storageBuckets = undefined;
    const context = {
      Promise,
      root,
      CUR: { context: "sandboxed-iframe" },
      MSTATUS: { unavailable: { __mstatus: "unavailable-in-context" }, blocked },
      A: (fn) => Promise.resolve().then(fn),
      M(path, getter) {
        try {
          const value = getter();
          const status = value?.__mstatus || "ok";
          records.push({ path, status });
          return status === "ok" ? value : status;
        } catch (error) {
          const status = error?.name === "SecurityError" ? "blocked" : "error";
          records.push({ path, status });
          return "ERR:" + error?.name;
        }
      },
      hash: () => "hash",
    };
    vm.runInNewContext(html.slice(keyboardStart, storageEnd)
      + "\nthis.keyboardBlock=keyboardBlock;this.storageBlock=storageBlock;", context);
    await context.keyboardBlock();
    await context.storageBlock();
    ok("opaque sandbox emits exact blocked capability paths instead of synthetic errors",
      records.some((row) => row.path === "keyboard.available" && row.status === "blocked")
        && records.some((row) => row.path === "storage.estimate" && row.status === "blocked")
        && records.filter((row) => ["storage.localStorage", "storage.sessionStorage", "storage.caches"].includes(row.path))
          .every((row) => row.status === "blocked")
        && !records.some((row) => row.path === "keyboard.error" || row.path === "storage.error"));
  }
}

{
  const canvasStart = html.indexOf("function makeCanvas(");
  const canvasEnd = html.indexOf("\n  /* ---- WebGL", canvasStart);
  if (canvasStart < 0 || canvasEnd < 0) {
    ok("canvas full-readback implementation is executable", false);
  } else {
    const values = {};
    function make2d(canvas) {
      return {
        fillRect() {}, fillText() {}, beginPath() {}, arc() {}, fill() {},
        isPointInPath: () => false,
        getImageData: () => {
          const pixels = new Uint8ClampedArray(canvas.width * canvas.height * 4);
          for (let i = 0; i < pixels.length; i++) pixels[i] = i % 251;
          return { data: pixels };
        },
      };
    }
    const document = {
      createElement: () => {
        const canvas = { width: 0, height: 0, toDataURL: () => "data:image/png;base64,AA==" };
        canvas.getContext = () => make2d(canvas);
        return canvas;
      },
    };
    const context = {
      Promise, Math, Uint8Array, Uint8ClampedArray,
      document, OffscreenCanvas: undefined,
      bytesHash, sha256hex,
      A: (fn) => Promise.resolve().then(fn),
      S: (fn) => { try { return fn(); } catch (error) { return "ERR:" + error.name; } },
      MSTATUS: { unavailable: "unavailable", unsupported: "unsupported", invalid: "invalid" },
      M: (path, getter) => (values[path] = getter()),
    };
    vm.runInNewContext(html.slice(canvasStart, canvasEnd)
      + "\nthis.canvasBlock=canvasBlock;this.pixFnv=pixFnv;", context);
    const result = await context.canvasBlock();
    ok("canvas emits three exact SHA-256 repeats over the full RGBA buffer",
      /^[0-9a-f]{64}$/.test(values["canvas.pixelSha256"] || "")
        && values["canvas.repeats"].length === 3
        && values["canvas.repeats"].every((digest) => digest === values["canvas.pixelSha256"])
        && values["canvas.stable"] === true
        && values["canvas.pixelBytes"] === values["canvas.width"] * values["canvas.height"] * 4
        && result.pixelSha256 === values["canvas.pixelSha256"]);
    const left = new Uint8Array(194), right = new Uint8Array(194);
    right[1] = 1; // deliberately not one of the old 97-byte sample positions
    ok("canvas FNV covers every pixel byte rather than a 1/97 sample",
      context.pixFnv(left) !== context.pixFnv(right));
  }
}

{
  const rtcStart = html.indexOf("function waitForIceGatheringComplete(");
  const rtcEnd = html.indexOf("\n  /* ---- разное", rtcStart);
  if (rtcStart < 0 || rtcEnd < 0) {
    ok("WebRTC lifecycle implementation is executable", false);
  } else {
    const values = {}, errors = {};
    let currentPc = null;
    class FakePeerConnection {
      constructor() {
        this.iceGatheringState = "new";
        this.listeners = new Map();
        this.offerCalls = 0;
        this.closeCalls = 0;
        this.failRepeatedOffer = FakePeerConnection.failNextRepeatedOffer === true;
        FakePeerConnection.failNextRepeatedOffer = false;
        currentPc = this;
      }
      createDataChannel() {}
      createOffer() {
        this.offerCalls++;
        if (this.failRepeatedOffer && this.offerCalls === 2) return Promise.reject(new Error("repeat failed"));
        return Promise.resolve({ sdp: "a=rtpmap:111 opus/48000/2\na=fingerprint:sha-256 00\n" });
      }
      setLocalDescription() {
        if (this.onicecandidate) this.onicecandidate({ candidate: {
          candidate: "candidate:1 1 udp 10 host.local 9 typ host",
          foundation: "1", component: "rtp", protocol: "udp", priority: 10,
          address: "host.local", port: 9, type: "host",
        } });
        this.iceGatheringState = "complete";
        this.listeners.get("icegatheringstatechange")?.();
        return Promise.resolve();
      }
      addEventListener(name, fn) { this.listeners.set(name, fn); }
      removeEventListener(name, fn) { if (this.listeners.get(name) === fn) this.listeners.delete(name); }
      close() { this.closeCalls++; }
    }
    const timers = [];
    const context = {
      Promise, Error, Number, Object,
      root: {
        RTCPeerConnection: FakePeerConnection,
        RTCRtpSender: { getCapabilities: () => ({ codecs: [], headerExtensions: [] }) },
      },
      A: (fn) => Promise.resolve().then(fn).then((value) => value, (error) => "ERR:" + error.name),
      MSTATUS: { unsupported: "unsupported", timeout: "timeout" },
      M: (path, getter) => {
        try { return (values[path] = getter()); }
        catch (error) { errors[path] = error; return "ERR:" + error.name; }
      },
      hash: (value) => bytesHash(new TextEncoder().encode(value)),
      setTimeout: (fn) => { timers.push(fn); return timers.length; },
      clearTimeout: () => {},
    };
    vm.runInNewContext(html.slice(rtcStart, rtcEnd)
      + "\nthis.rtcBlock=rtcBlock;this.waitForIceGatheringComplete=waitForIceGatheringComplete;", context);
    const successful = await context.rtcBlock();
    ok("WebRTC success requires complete ICE, stable repeated offer and structured candidates",
      successful.status === "ok" && values["webrtc.status"] === "ok"
        && values["webrtc.iceGatheringComplete"] === true
        && values["webrtc.offerStable"] === true
        && values["webrtc.iceCandidates"].length === 1
        && values["webrtc.iceCandidates"][0].family === "mdns"
        && currentPc.closeCalls === 1);

    FakePeerConnection.failNextRepeatedOffer = true;
    const failing = context.rtcBlock();
    const failedResult = await failing;
    ok("failed repeated WebRTC offer is typed as an error and always closes the peer",
      failedResult.status === "offer-error" && errors["webrtc.status"]?.message === "repeat failed"
        && currentPc.closeCalls === 1);

    const gathering = {
      iceGatheringState: "gathering", listeners: new Map(),
      addEventListener(name, fn) { this.listeners.set(name, fn); },
      removeEventListener(name, fn) { if (this.listeners.get(name) === fn) this.listeners.delete(name); },
    };
    const waiting = context.waitForIceGatheringComplete(gathering, 3000);
    const timeout = timers.pop(); timeout();
    let timeoutName = null;
    try { await waiting; } catch (error) { timeoutName = error.name; }
    ok("ICE timeout rejects explicitly and removes its state listener",
      timeoutName === "TimeoutError" && gathering.listeners.size === 0);
  }
}

{
  const requestStart = html.indexOf("function boundedRequest(");
  const requestEnd = html.indexOf("async function initRunIdentity()", requestStart);
  const source = html.slice(requestStart, requestEnd) + "\nthis.boundedJson=boundedJson;";
  const context = { AbortController, TextDecoder, setTimeout, clearTimeout, DOMException };
  context.fetch = async () => ({
    ok: true, status: 200,
    body: { getReader: () => ({ read: () => new Promise(() => {}), cancel: () => Promise.resolve() }) },
  });
  vm.runInNewContext(source, context);
  let timedOut = false;
  try { await context.boundedJson("/stalled", {}, 20, 100); }
  catch (e) { timedOut = e && e.name === "TimeoutError"; }
  ok("JSON route timeout covers a body that stalls after response headers", timedOut);
}
{
  const guardStart = html.indexOf("function jobGuard(");
  const guardEnd = html.indexOf("return Promise.all(jobs.map", guardStart);
  const guard = html.slice(guardStart, guardEnd);
  ok("outer job rejection leaves a typed blocking record",
    guard.includes("path:name+'.__job'") && guard.includes("status:STATUS.error") && guard.includes("JobRejected"));
}

{
  const machineStart = html.indexOf("function createCompletionStateMachine(");
  const machineEnd = html.indexOf("\n}\n", machineStart);
  if (machineStart < 0 || machineEnd < 0) {
    ok("completion retry state machine is executable", false);
  } else {
    const context = { Promise };
    vm.runInNewContext(html.slice(machineStart, machineEnd + 2) + "\nthis.createCompletionStateMachine=createCompletionStateMachine;", context);
    let collects = 0, manifestBuilds = 0, statusChecks = 0;
    const sends = [];
    const statusResults = [
      { ready: false, overall: "NOT_READY" },
      new Error("side-status 500"),
      Object.assign(new Error("timeout"), { name: "TimeoutError" }),
      { ready: true, overall: "READY" },
    ];
    const machine = context.createCompletionStateMachine({
      collectPermissioned: async () => { collects++; return { sample: 1 }; },
      send: async (name) => { sends.push(name); },
      buildManifest: () => { manifestBuilds++; return { terminal: true }; },
      queryStatus: async () => {
        const result = statusResults[statusChecks++];
        if (result instanceof Error) throw result;
        return result;
      },
      permissionedAcknowledged: () => {},
    });
    const first = await machine.run();
    for (let i = 0; i < 2; i++) {
      try { await machine.run(); } catch {}
    }
    const fourth = await machine.run();
    ok("NOT_READY/500/timeout retries query status without recollecting", first.overall === "NOT_READY" && fourth.overall === "READY" && collects === 1 && statusChecks === 4);
    ok("acknowledged permissioned and run-manifest payloads are posted once", sends.join(",") === "permissioned,run-manifest" && manifestBuilds === 1);
  }
}

{
  const machineStart = html.indexOf("function createCompletionStateMachine(");
  const machineEnd = html.indexOf("\n}\n", machineStart);
  if (machineStart >= 0 && machineEnd >= 0) {
    const context = { Promise };
    vm.runInNewContext(html.slice(machineStart, machineEnd + 2) + "\nthis.createCompletionStateMachine=createCompletionStateMachine;", context);
    let collects = 0, manifestAttempts = 0;
    const sends = [];
    const machine = context.createCompletionStateMachine({
      collectPermissioned: async () => { collects++; return {}; },
      send: async (name) => {
        sends.push(name);
        if (name === "run-manifest" && ++manifestAttempts === 1) throw new Error("http-500");
      },
      buildManifest: () => ({}),
      queryStatus: async () => ({ ready: true, overall: "READY" }),
      permissionedAcknowledged: () => {},
    });
    try { await machine.run(); } catch {}
    await machine.run();
    ok("manifest retry after its failed ACK does not recollect or resend permissioned", collects === 1 && sends.join(",") === "permissioned,run-manifest,run-manifest");
  }
}

{
  const workerStart = html.indexOf("function viaWorker(");
  const workerEnd = html.indexOf("\nfunction viaWorklet()", workerStart);
  if (workerStart < 0 || workerEnd < 0) {
    ok("worker lifecycle implementation is executable", false);
  } else {
    const timers = [];
    const revoked = [];
    const statuses = [];
    const sends = [];
    let instance = null;
    class FakeWorker {
      constructor(url, opts) {
        this.url = url; this.opts = opts; this.terminateCalls = 0; this.posted = [];
        instance = this;
      }
      postMessage(value) { this.posted.push(value); }
      terminate() { this.terminateCalls++; }
    }
    const context = {
      Promise,
      COLLECTOR_SRC: "collector",
      WORKER_SRC: "worker __KIND__",
      blobURL: () => "blob:worker-1",
      Worker: FakeWorker,
      SharedWorker: FakeWorker,
      URL: { revokeObjectURL: (url) => revoked.push(url) },
      setTimeout: (fn) => { timers.push(fn); return timers.length; },
      clearTimeout: () => {},
      rstat: (...args) => statuses.push(args),
      log: () => {},
      send: async (...args) => { sends.push(args); },
    };
    vm.runInNewContext(html.slice(workerStart, workerEnd) + "\nthis.viaWorker=viaWorker;", context);
    const timed = context.viaWorker("dedicated-worker");
    const timedWorker = instance;
    const lateHandler = timedWorker.onmessage;
    timers.shift()();
    await timed;
    const beforeLate = { statuses: statuses.length, sends: sends.length };
    if (lateHandler) lateHandler({ data: { late: true } });
    await Promise.resolve(); await Promise.resolve();
    ok("worker timeout terminates the worker and revokes its Blob URL",
      timedWorker.terminateCalls === 1 && revoked.join(",") === "blob:worker-1");
    ok("late worker result after timeout cannot send or rewrite terminal status",
      statuses.length === beforeLate.statuses && sends.length === beforeLate.sends
        && statuses[0]?.[0] === "dedicated-worker" && statuses[0]?.[1] === "timeout");

    const successful = context.viaWorker("dedicated-worker-module");
    const successWorker = instance;
    successWorker.onmessage({ data: { _context: "dedicated-worker-module" } });
    await successful;
    ok("successful worker sends once, then terminates and revokes its URL",
      sends.length === 1 && sends[0][0] === "dedicated-worker-module"
        && successWorker.terminateCalls === 1 && revoked.length === 2
        && statuses.some((entry) => entry[0] === "dedicated-worker-module" && entry[1] === "finished"));
  }
}

{
  const workletStart = html.indexOf("function viaWorklet(");
  const workletEnd = html.indexOf("// iframe —", workletStart);
  if (workletStart < 0 || workletEnd < 0) {
    ok("AudioWorklet lifecycle implementation is executable", false);
  } else {
    async function executeWorklet({ rejectRendering = false } = {}) {
      const revoked = [], statuses = [], sends = [], timers = new Map();
      let nextTimer = 1, node = null;
      class FakeOfflineAudioContext {
        constructor() {
          this.destination = {};
          this.audioWorklet = { addModule: async (url) => { this.moduleURL = url; } };
        }
        startRendering() {
          return rejectRendering ? Promise.reject(new Error("render failed")) : Promise.resolve({});
        }
      }
      class FakeAudioWorkletNode {
        constructor() {
          this.disconnectCalls = 0;
          this.port = {
            closeCalls: 0,
            postMessage: () => {
              if (!rejectRendering) queueMicrotask(() => this.port.onmessage?.({ data: { _context: "audio-worklet", sample: 1 } }));
            },
            close() { this.closeCalls++; },
          };
          node = this;
        }
        connect() {}
        disconnect() { this.disconnectCalls++; }
      }
      const context = {
        Promise, Error,
        window: { OfflineAudioContext: FakeOfflineAudioContext },
        AudioWorkletNode: FakeAudioWorkletNode,
        WORKLET_SRC: "worklet-source",
        blobURL: () => "blob:worklet-1",
        URL: { revokeObjectURL: (url) => revoked.push(url) },
        setTimeout: (fn) => { const id = nextTimer++; timers.set(id, fn); return id; },
        clearTimeout: (id) => timers.delete(id),
        typifyWorklet: () => [],
        send: async (...args) => { sends.push(args); },
        rstat: (...args) => statuses.push(args),
        log: () => {},
      };
      vm.runInNewContext(html.slice(workletStart, workletEnd) + "\nthis.viaWorklet=viaWorklet;", context);
      await context.viaWorklet();
      return { revoked, statuses, sends, timers, node };
    }

    const success = await executeWorklet();
    ok("successful AudioWorklet clears timeout, closes its port, disconnects and revokes module URL",
      success.sends.length === 1 && success.statuses.some((entry) => entry[1] === "finished")
        && success.timers.size === 0 && success.node?.port.closeCalls === 1
        && success.node?.disconnectCalls === 1 && success.revoked.join(",") === "blob:worklet-1");

    const failure = await executeWorklet({ rejectRendering: true });
    ok("startRendering rejection is observed and still cleans every AudioWorklet resource",
      failure.sends.length === 0 && failure.statuses.some((entry) => entry[1] === "error" && entry[2] === "render failed")
        && failure.timers.size === 0 && failure.node?.port.closeCalls === 1
        && failure.node?.disconnectCalls === 1 && failure.revoked.join(",") === "blob:worklet-1");
  }
}

{
  const mediaStart = html.indexOf("var ACTIVE_MEDIA_STREAMS=");
  const mediaEnd = html.indexOf("\nfunction permissionedCollect()", mediaStart);
  if (mediaStart < 0 || mediaEnd < 0) {
    ok("late getUserMedia resolution is executable", false);
    ok("pagehide releases accepted media streams", false);
  } else {
    const timers = [], listeners = {};
    let resolveGum;
    const lateTrack = { stops: 0, stop() { this.stops++; } };
    const context = {
      Promise,
      navigator: { mediaDevices: { getUserMedia: () => new Promise((resolve) => { resolveGum = resolve; }) } },
      window: { addEventListener: (name, fn) => { listeners[name] = fn; } },
      setTimeout: (fn) => { timers.push(fn); return timers.length; },
      clearTimeout: () => {},
    };
    vm.runInNewContext(html.slice(mediaStart, mediaEnd), context);
    const request = context.requestUserMediaWithTimeout({ audio: true, video: true }, 20);
    timers[0]();
    try { await request; } catch {}
    resolveGum({ getTracks: () => [lateTrack] });
    await Promise.resolve(); await Promise.resolve();
    ok("late getUserMedia resolution stops every track immediately", lateTrack.stops === 1 && context.ACTIVE_MEDIA_STREAMS.length === 0);

    const hiddenLateTrack = { stops: 0, stop() { this.stops++; } };
    const pendingOnHide = context.requestUserMediaWithTimeout({ audio: true }, 20);
    listeners.pagehide();
    let hiddenError = null;
    try { await pendingOnHide; } catch (error) { hiddenError = error; }
    resolveGum({ getTracks: () => [hiddenLateTrack] });
    await Promise.resolve(); await Promise.resolve();
    ok("pagehide settles a pending getUserMedia request and stops its eventual late stream",
      hiddenError?.name === "AbortError" && hiddenLateTrack.stops === 1
        && context.PENDING_MEDIA_REQUESTS.length === 0 && context.ACTIVE_MEDIA_STREAMS.length === 0);

    listeners.pageshow();
    const activeTrack = { stops: 0, stop() { this.stops++; } };
    context.navigator.mediaDevices.getUserMedia = async () => ({ getTracks: () => [activeTrack] });
    await context.requestUserMediaWithTimeout({ audio: true }, 20);
    listeners.pagehide();
    ok("pagehide releases accepted media streams", activeTrack.stops === 1 && context.ACTIVE_MEDIA_STREAMS.length === 0);
  }
}

{
  const realtimeStart = html.indexOf("function realtimeAudioSnapshot(");
  const realtimeEnd = html.indexOf("\n  function audioBlock()", realtimeStart);
  const audioStart = realtimeEnd >= 0 ? realtimeEnd + 1 : -1;
  const audioEnd = html.indexOf("\n  /* ---- шрифты", audioStart);
  if (realtimeStart < 0 || realtimeEnd < 0 || audioEnd < 0) {
    ok("realtime audio lifecycle is executable", false);
  } else {
    let insideGetter = false, constructed = 0, closed = 0;
    const records = {};
    class FakeAudioContext {
      constructor() {
        if (insideGetter) throw new Error("AudioContext constructed inside measurement getter");
        constructed++;
        this.baseLatency = 0.01;
        this.outputLatency = 0.02;
        this.sampleRate = 48000;
        this.state = "running";
      }
      close() { closed++; return Promise.resolve(); }
    }
    const rendered = { sum: 3, hash: "same", sampleRate: 44100, bufLen: 5000 };
    const context = {
      Promise,
      root: { OfflineAudioContext: function () {}, AudioContext: FakeAudioContext },
      MSTATUS: { unavailable: "unavailable-in-context", timeout: "timeout" },
      renderAudioOnce: async () => rendered,
      A: (fn) => Promise.resolve().then(fn),
      M: (path, getter) => {
        insideGetter = true;
        try { return (records[path] = getter()); }
        finally { insideGetter = false; }
      },
    };
    const source = html.slice(realtimeStart, realtimeEnd) + html.slice(audioStart, audioEnd)
      + "\nthis.audioBlock=audioBlock;this.realtimeAudioSnapshot=realtimeAudioSnapshot;";
    vm.runInNewContext(source, context);
    await context.audioBlock();
    ok("realtime AudioContext is constructed outside M getters and closed", constructed === 1 && closed === 1);
    ok("realtime audio records typed latency/rate/state fields", records["audio.realtime.baseLatency"] === 0.01
      && records["audio.realtime.outputLatency"] === 0.02 && records["audio.realtime.sampleRate"] === 48000
      && records["audio.realtime.state"] === "running");
    context.root.AudioContext = class {
      constructor() {
        Object.defineProperty(this, "baseLatency", { get() { throw new Error("getter failed"); } });
      }
      close() { closed++; return Promise.resolve(); }
    };
    try { await context.realtimeAudioSnapshot(); } catch {}
    ok("realtime AudioContext closes when a property getter throws", closed === 2);

    context.root.AudioContext = FakeAudioContext;
    const delayed = [];
    context.renderAudioOnce = () => new Promise((resolve) => delayed.push(resolve));
    const lateAudio = context.audioBlock();
    await Promise.resolve();
    const outerResult = await Promise.race([lateAudio, Promise.resolve("outer-timeout")]);
    delayed[0](rendered);
    await Promise.resolve(); await Promise.resolve();
    delayed[1](rendered); delayed[2](rendered);
    await lateAudio;
    ok("late audioBlock completion does not leave a realtime context open", outerResult === "outer-timeout" && constructed === 2 && closed === 3);
  }
}

{
  const markerStart = html.indexOf("var MSTATUS={");
  const markerEnd = html.indexOf("\n  };", markerStart);
  if (markerStart < 0 || markerEnd < 0) {
    ok("typed timeout marker is executable", false);
  } else {
    const context = { STATUS: { timeout: "timeout" } };
    vm.runInNewContext(html.slice(markerStart, markerEnd + 5) + "\nthis.MSTATUS=MSTATUS;", context);
    ok("audio/WebGPU timeout has an explicit typed marker",
      context.MSTATUS.timeout && context.MSTATUS.timeout.__mstatus === "timeout");
  }
}

{
  const glStart = html.indexOf("function glRender(");
  const glEnd = html.indexOf("\n  function glContext", glStart);
  if (glStart < 0 || glEnd < 0) {
    ok("WebGL renderer is executable", false);
  } else {
    const context = { Uint8Array, Float32Array, Number, sha256hex };
    vm.runInNewContext(html.slice(glStart, glEnd)
      + "\nthis.glRender=glRender;", context);

    function fakeGl({ compile = true, link = true, finalError = 0 } = {}) {
      const deleted = { shader: 0, program: 0, buffer: 0 };
      const detached = { buffer: 0, program: 0 };
      const sources = [];
      const errorQueue = [0, finalError];
      const gl = {
        VERTEX_SHADER: 1, FRAGMENT_SHADER: 2, COMPILE_STATUS: 3, LINK_STATUS: 4,
        ARRAY_BUFFER: 5, STATIC_DRAW: 6, FLOAT: 7, TRIANGLE_STRIP: 8,
        RGBA: 9, UNSIGNED_BYTE: 10, NO_ERROR: 0,
        drawingBufferWidth: 2, drawingBufferHeight: 2,
        createShader: (kind) => ({ kind }), shaderSource: (_s, source) => sources.push(source),
        compileShader() {}, getShaderParameter: () => compile,
        getShaderInfoLog: () => compile ? "" : "compile failed",
        createProgram: () => ({}), attachShader() {}, linkProgram() {},
        getProgramParameter: () => link, getProgramInfoLog: () => link ? "" : "link failed",
        useProgram: (value) => { if (value === null) detached.program++; }, createBuffer: () => ({}),
        bindBuffer: (_target, value) => { if (value === null) detached.buffer++; }, bufferData() {},
        getAttribLocation: () => 0, enableVertexAttribArray() {}, vertexAttribPointer() {},
        drawArrays() {}, readPixels: (_x, _y, _w, _h, _fmt, _type, px) => px.fill(7),
        getError: () => errorQueue.length ? errorQueue.shift() : 0,
        disableVertexAttribArray() {}, deleteBuffer: () => { deleted.buffer++; },
        deleteProgram: () => { deleted.program++; }, deleteShader: () => { deleted.shader++; },
      };
      return { gl, deleted, detached, sources };
    }

    const badCompile = fakeGl({ compile: false });
    const badCompileResult = context.glRender(badCompile.gl, false);
    ok("WebGL shader compilation failure is an invalid result",
      !badCompileResult.ok && badCompileResult.status === "invalid-result" && badCompileResult.stage === "vertex-compile");
    ok("WebGL compilation failure still deletes the allocated shader",
      badCompile.deleted.shader === 1);

    const badError = fakeGl({ finalError: 1282 });
    const badErrorResult = context.glRender(badError.gl, false);
    ok("WebGL non-NO_ERROR cannot be reported as a successful render",
      !badErrorResult.ok && badErrorResult.status === "invalid-result" && badErrorResult.glError === 1282);
    ok("WebGL render resources are released after semantic failure",
      badError.deleted.shader === 2 && badError.deleted.program === 1 && badError.deleted.buffer === 1);

    const gl2 = fakeGl();
    const gl2Result = context.glRender(gl2.gl, true);
    ok("WebGL2 uses GLSL 300 ES shaders and succeeds with clean GL state",
      gl2Result.ok && gl2.sources.length === 2 && gl2.sources.every((source) => source.startsWith("#version 300 es")));
    ok("successful WebGL render also releases all resources",
      gl2.deleted.shader === 2 && gl2.deleted.program === 1 && gl2.deleted.buffer === 1
        && gl2.detached.buffer === 1 && gl2.detached.program === 1);
  }
}

{
  const gpuStart = html.indexOf("function gpuResourceScope(");
  const gpuEnd = html.indexOf("\n  function gpuBlock()", gpuStart);
  if (gpuStart < 0 || gpuEnd < 0) {
    ok("WebGPU lifecycle helpers are executable", false);
  } else {
    const timers = [];
    const records = [];
    const context = {
      Promise, Uint8Array, Float32Array, Number,
      sha256hex,
      setTimeout: (fn) => { timers.push(fn); return timers.length; },
      clearTimeout: () => {},
      STATUS: { ok: "ok", timeout: "timeout", error: "error", invalidResult: "invalid-result",
        unsupported: "unsupported", unavailableInContext: "unavailable-in-context", blocked: "blocked" },
      encodeValue: (value) => ({ valueType: typeof value, value }),
      pushRec: (...args) => records.push(args),
      M: () => { throw new Error("non-ok GPU result must not use M()"); },
      GPUBufferUsage: { STORAGE: 1, COPY_SRC: 2, COPY_DST: 4, MAP_READ: 8 },
      GPUTextureUsage: { RENDER_ATTACHMENT: 1, COPY_SRC: 2 },
      GPUMapMode: { READ: 1 },
    };
    vm.runInNewContext(html.slice(gpuStart, gpuEnd)
      + "\nthis.gpuResourceScope=gpuResourceScope;this.raceGpuTask=raceGpuTask;"
      + "this.emitGpuStatus=emitGpuStatus;this.gpuBytesResult=gpuBytesResult;"
      + "this.gpuResultFromRace=gpuResultFromRace;this.createGpuComputeOperation=createGpuComputeOperation;"
      + "this.createGpuRenderOperation=createGpuRenderOperation;", context);

    const scope = context.gpuResourceScope();
    let firstClosed = 0, lateClosed = 0;
    scope.own({}, () => { firstClosed++; });
    scope.close(); scope.close();
    scope.own({}, () => { lateClosed++; });
    ok("WebGPU cleanup is idempotent and cleans late-owned resources immediately",
      firstClosed === 1 && lateClosed === 1);

    let resolveLate, cancels = 0;
    const raced = context.raceGpuTask({
      promise: new Promise((resolve) => { resolveLate = resolve; }),
      cancel: () => { cancels++; },
    }, 10);
    timers.shift()();
    const timeoutResult = await raced;
    const timeoutTyped = context.gpuResultFromRace(timeoutResult, "test GPU");
    context.emitGpuStatus("webgpu.compute.status", timeoutTyped);
    const recordsAtTimeout = records.length;
    resolveLate({ status: "ok", hash: "late" });
    await Promise.resolve(); await Promise.resolve();
    ok("timed-out WebGPU work resolves once as timeout and cancellation runs once",
      timeoutResult.kind === "timeout" && cancels === 1 && records.length === recordsAtTimeout);

    context.emitGpuStatus("webgpu.render.status", { status: "invalid-result", error: { name: "GpuInvalidResult" } });
    ok("WebGPU timeout/invalid outcomes are typed non-ok records, never ok undefined",
      records.length === 2 && records[0][1] === "timeout" && records[1][1] === "invalid-result"
        && records.every((record) => record[2] === null));

    const bytesA = new Uint8Array(256); const bytesB = new Uint8Array(256);
    bytesB[17] = 1;
    const byteResultA = context.gpuBytesResult(bytesA, {});
    const byteResultB = context.gpuBytesResult(bytesB, {});
    ok("WebGPU hashes every output byte with SHA-256",
      byteResultA.hash === sha256hex(bytesA) && byteResultB.hash === sha256hex(bytesB)
        && byteResultA.hash !== byteResultB.hash && byteResultA.hashAlgorithm === "sha256");

    let resolveDevice;
    const lateDevice = { destroyCalls: 0, destroy() { this.destroyCalls++; } };
    const compute = context.createGpuComputeOperation({
      requestDevice: () => new Promise((resolve) => { resolveDevice = resolve; }),
    });
    await Promise.resolve();
    compute.cancel(); compute.cancel();
    resolveDevice(lateDevice);
    const cancelledCompute = await compute.promise;
    ok("a device acquired after WebGPU cancellation is destroyed and cannot produce data",
      cancelledCompute.status === "timeout" && lateDevice.destroyCalls === 1);

    const mappedFloats = new Float32Array(64);
    for (let i = 0; i < mappedFloats.length; i++) mappedFloats[i] = i / 10;
    const storage = { destroyCalls: 0, destroy() { this.destroyCalls++; } };
    const readback = {
      destroyCalls: 0, unmapCalls: 0,
      mapAsync: async () => {}, getMappedRange: () => mappedFloats.buffer,
      unmap() { this.unmapCalls++; }, destroy() { this.destroyCalls++; },
    };
    let bufferIndex = 0;
    const successDevice = {
      destroyCalls: 0, lost: new Promise(() => {}),
      createShaderModule: () => ({ getCompilationInfo: async () => ({ messages: [] }) }),
      createComputePipeline: () => ({ getBindGroupLayout: () => ({}) }),
      createBuffer: () => bufferIndex++ === 0 ? storage : readback,
      createBindGroup: () => ({}),
      createCommandEncoder: () => ({
        beginComputePass: () => ({ setPipeline() {}, setBindGroup() {}, dispatchWorkgroups() {}, end() {} }),
        copyBufferToBuffer() {}, finish: () => ({}),
      }),
      queue: { submit() {} }, destroy() { this.destroyCalls++; },
    };
    const successCompute = await context.createGpuComputeOperation({ requestDevice: async () => successDevice }).promise;
    ok("successful WebGPU compute hashes the exact 256-byte readback and exposes readiness fields",
      successCompute.status === "ok" && successCompute.byteLength === 256
        && successCompute.sha256 === sha256hex(new Uint8Array(mappedFloats.buffer))
        && successCompute.compilationErrors === 0);
    ok("successful WebGPU compute unmaps and destroys buffers/device exactly once",
      readback.unmapCalls === 1 && readback.destroyCalls === 1
        && storage.destroyCalls === 1 && successDevice.destroyCalls === 1);
  }
}

{
  // permissioned getUserMedia: every DOMException the browser can raise must land
  // on an ENUMERATED status. A device that enumerates but cannot be started
  // (NotReadableError "Could not start audio source" — OS/driver refusal, or an
  // anti-detect profile with fake mediaDevices) is an environment outcome →
  // `unavailable-in-context` (allowlisted for READY), never a raw `error`
  // (collector bug, blocks readiness). Unknown names stay strict.
  const permStart = html.indexOf("\nfunction permissionedCollect()");
  const permEnd = html.indexOf("\n(async function(){", permStart);
  if (permStart < 0 || permEnd < 0) {
    ok("permissioned collector is executable", false);
  } else {
    const { validateMeasurement, nonOkAllowed } = await import("../lib/fp-schema.mjs");
    async function runPermissioned(gumError) {
      const err = new Error(gumError.message); err.name = gumError.name;
      const context = {
        Promise,
        self: { LinkageProbe: { encodeValue: (v) => ({ valueType: typeof v, value: v }), hash: (s) => "h:" + s } },
        navigator: {
          mediaDevices: {
            enumerateDevices: async () => [{ kind: "audioinput", label: "", deviceId: "a", groupId: "g" }],
            getUserMedia: () => Promise.reject(err),
          },
        },
        requestUserMediaWithTimeout: (constraints) => context.navigator.mediaDevices.getUserMedia(constraints),
        releaseMediaStream: () => { throw new Error("no stream to release on rejection"); },
        setTimeout, clearTimeout,
      };
      vm.runInNewContext(html.slice(permStart, permEnd) + "\nthis.permissionedCollect=permissionedCollect;", context);
      const out = await context.permissionedCollect();
      const byPath = Object.fromEntries(out._measurements.map((r) => [r.path, r]));
      return { out, byPath, gum: byPath["permissioned.getUserMedia"], result: byPath["permissioned.getUserMedia.result"] };
    }

    const unreadable = await runPermissioned({ name: "NotReadableError", message: "Could not start audio source" });
    ok("NotReadableError → permissioned.getUserMedia is unavailable-in-context with the DOMException kept",
      unreadable.gum?.status === "unavailable-in-context" && unreadable.gum.value === null
        && unreadable.gum.error?.name === "NotReadableError" && unreadable.gum.error?.message === "Could not start audio source");
    ok("NotReadableError → result/manifest report device-unreadable and the phase still completes",
      unreadable.result?.value === "device-unreadable" && unreadable.out._phaseManifest.steps.getUserMedia === "device-unreadable"
        && unreadable.out._phaseManifest.unsupported.includes("getUserMedia") && unreadable.out._phaseManifest.complete === true);
    ok("NotReadableError record is schema-valid and READY-allowlisted",
      validateMeasurement(unreadable.gum).length === 0 && nonOkAllowed(unreadable.gum.path, "permissioned", unreadable.gum.status));
    ok("every permissioned record of the unreadable run is schema-valid",
      unreadable.out._measurements.every((r) => validateMeasurement(r).length === 0));

    const noDevice = await runPermissioned({ name: "NotFoundError", message: "Requested device not found" });
    ok("NotFoundError still maps to no-device / unavailable-in-context",
      noDevice.gum?.status === "unavailable-in-context" && noDevice.result?.value === "no-device");

    const denied = await runPermissioned({ name: "NotAllowedError", message: "Permission denied" });
    ok("NotAllowedError still maps to permission-denied (not READY-allowlisted)",
      denied.gum?.status === "permission-denied" && denied.result?.value === "denied"
        && !nonOkAllowed(denied.gum.path, "permissioned", denied.gum.status));

    const unknown = await runPermissioned({ name: "TypeError", message: "Failed to execute 'getUserMedia'" });
    ok("an unmapped exception stays a strict raw error that blocks readiness",
      unknown.gum?.status === "error" && unknown.gum.error?.name === "TypeError" && unknown.result?.value === "error"
        && validateMeasurement(unknown.gum).length === 0 && !nonOkAllowed(unknown.gum.path, "permissioned", unknown.gum.status));
  }
}

console.log(`\nfp-probe: ${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
