import vm from "node:vm";
import { readFileSync } from "node:fs";
import * as probeArtifact from "../lib/fp-probe-artifact.mjs";
import { sha256hex } from "../lib/fp-encode.mjs";

let pass = 0, fail = 0;
function ok(label, condition) { if (condition) pass++; else { fail++; console.log("  ✗ " + label); } }

const build = "b".repeat(64);
const captureKey = "pair-7:plain";
const challenge = "AbCdEfGhIjKlMnOpQrStUv";
const collectorSource = `(function COLLECTOR(root){
  root.LinkageProbe={
    sha256hex:function(input){return root.__sha256hex(input);},
    collect:function(context){return root.__collect(context);}
  };
})(self);`;
const collectorArtifactSha256 = sha256hex(collectorSource);
const scriptURL = `https://panel.example.test/fingerprint/sw?build=${build}&artifact=${collectorArtifactSha256}&capture=${encodeURIComponent(captureKey)}&challenge=${challenge}`;
const scope = `https://panel.example.test/fingerprint/sw-scope/${challenge}/`;
const pageSource = readFileSync(new URL("../assets/fingerprint-probe.html", import.meta.url), "utf8");
const swDeadline = Number(/serviceWorkerRoundTrip\(target,request,(\d+)\)/.exec(pageSource)?.[1]);
const gpuJobCap = Number(/j\[0\]==='webgpu'\?(\d+):/.exec(pageSource)?.[1]);
ok("Service Worker transport deadline exceeds the longest collector job cap",
  Number.isFinite(swDeadline) && Number.isFinite(gpuJobCap) && swDeadline >= gpuJobCap + 5_000);

function canonical(value) {
  if (Array.isArray(value)) return value.map(canonical);
  if (value && typeof value === "object") {
    return Object.fromEntries(Object.keys(value).sort().map((key) => [key, canonical(value[key])]));
  }
  return value;
}

function makeRequest(requestId, overrides = {}) {
  return {
    type: "fingerprint-service-worker-collect",
    handshakeVersion: 1,
    requestId,
    context: "service-worker",
    collectorBuild: build,
    collectorArtifactSha256,
    captureKey,
    challenge,
    ...overrides,
  };
}

function makePort() {
  return {
    messages: [],
    closed: false,
    postMessage(message) { this.messages.push(message); },
    close() { this.closed = true; },
  };
}

function createWorker(collect) {
  const handlers = new Map();
  const self = {
    location: { href: scriptURL },
    registration: { scope },
    skipWaitingCalls: 0,
    skipWaiting() { this.skipWaitingCalls++; return Promise.resolve(); },
    addEventListener(type, handler) { handlers.set(type, handler); },
    __sha256hex: sha256hex,
    __collect: collect,
  };
  const context = vm.createContext({ self, Promise, Object, Array, String, Error, TypeError, JSON });
  const rendered = probeArtifact.renderServiceWorkerProbe({
    collectorSource, browserCollectorBuild: build,
    collectorArtifactSha256, captureKey, challenge,
  });
  new vm.Script(rendered.source).runInContext(context);
  return { self, handlers, rendered };
}

async function dispatch(worker, request, port = makePort()) {
  let lifetime;
  const event = {
    data: request,
    ports: [port],
    waitUntil(promise) { lifetime = Promise.resolve(promise); },
  };
  worker.handlers.get("message")(event);
  await lifetime;
  return port;
}

if (typeof probeArtifact.renderServiceWorkerProbe !== "function") {
  ok("Service Worker renderer exists", false);
} else {
  {
    let calls = 0;
    const worker = createWorker(async () => { calls++; return { _context: "service-worker" }; });
    let installLifetime;
    worker.handlers.get("install")({ waitUntil(promise) { installLifetime = Promise.resolve(promise); } });
    await installLifetime;
    ok("install waits for skipWaiting without claiming clients",
      worker.self.skipWaitingCalls === 1 && !worker.handlers.has("fetch") && !worker.handlers.has("activate"));

    const requestId = "RequestToken_1234567890ab";
    const port = await dispatch(worker, makeRequest(requestId, { challenge: "X".repeat(22) }));
    ok("an identity mismatch never invokes the collector", calls === 0);
    ok("a rejected request returns a structured correlated error and closes its port",
      port.closed && port.messages.length === 1
        && port.messages[0].type === "fingerprint-service-worker-result"
        && port.messages[0].handshakeVersion === 1
        && port.messages[0].requestId === requestId
        && port.messages[0].ok === false
        && port.messages[0].error?.name === "InvalidServiceWorkerRequest");
  }

  {
    const pending = [];
    let active = 0, maxActive = 0, calls = 0;
    const worker = createWorker((context) => new Promise((resolve) => {
      calls++; active++; maxActive = Math.max(maxActive, active);
      pending.push(() => { active--; resolve({ _context: context, sequence: calls }); });
    }));
    const port1 = makePort(), port2 = makePort();
    let lifetime1, lifetime2;
    worker.handlers.get("message")({
      data: makeRequest("RequestToken_1234567890aa"), ports: [port1],
      waitUntil(promise) { lifetime1 = Promise.resolve(promise); },
    });
    worker.handlers.get("message")({
      data: makeRequest("RequestToken_1234567890bb"), ports: [port2],
      waitUntil(promise) { lifetime2 = Promise.resolve(promise); },
    });
    await Promise.resolve(); await Promise.resolve();
    ok("only one collector run starts while a prior request owns global collector state",
      calls === 1 && active === 1);
    pending.shift()();
    await lifetime1;
    await Promise.resolve(); await Promise.resolve();
    ok("the second simultaneous request starts only after the first completes",
      calls === 2 && active === 1 && maxActive === 1);
    pending.shift()();
    await lifetime2;
    const evidence = port1.messages[0]?.payload?._serviceWorker;
    const expectedAck = sha256hex(JSON.stringify({
      captureKey, challenge, collectorArtifactSha256, collectorBuild: build,
      context: "service-worker",
    }));
    ok("successful replies echo the handshake and close both ports",
      port1.closed && port2.closed && port1.messages[0]?.ok === true && port2.messages[0]?.ok === true
        && port1.messages[0]?.requestId === "RequestToken_1234567890aa"
        && port2.messages[0]?.requestId === "RequestToken_1234567890bb");
    ok("successful collection emits exact readiness and script isolation evidence",
      evidence?.context === "service-worker" && evidence.collectorBuild === build
        && evidence.collectorArtifactSha256 === collectorArtifactSha256
        && evidence.captureKey === captureKey && evidence.challenge === challenge
        && evidence.acknowledgementSha256 === expectedAck
        && evidence.handshakeVersion === 1
        && evidence.requestId === "RequestToken_1234567890aa"
        && evidence.scriptURL === scriptURL && evidence.scope === scope);
  }

  {
    const worker = createWorker(async () => { throw new TypeError("collector exploded"); });
    const port = await dispatch(worker, makeRequest("RequestToken_1234567890cc"));
    ok("collector errors produce a correlated structured error and close the port",
      port.closed && port.messages.length === 1 && port.messages[0].ok === false
        && port.messages[0].requestId === "RequestToken_1234567890cc"
        && port.messages[0].error?.name === "TypeError"
        && port.messages[0].error?.message === "collector exploded");
  }

  {
    const worker = createWorker(async () => Object.freeze({ _context: "service-worker" }));
    const port = makePort(); let escaped = false;
    try { await dispatch(worker, makeRequest("RequestToken_1234567890dd"), port); } catch { escaped = true; }
    ok("post-collection evidence errors still return an error and close the port",
      !escaped && port.closed && port.messages.length === 1 && port.messages[0].ok === false
        && port.messages[0].requestId === "RequestToken_1234567890dd"
        && port.messages[0].error?.name === "TypeError");
  }

  {
    const identityStart = pageSource.indexOf("function canonicalIdentityJson(");
    const identityEnd = pageSource.indexOf("// Terminal-manifest bookkeeping", identityStart);
    ok("page contains executable canonical capture-identity validation",
      identityStart >= 0 && identityEnd > identityStart);
    if (identityStart >= 0 && identityEnd > identityStart) {
      const processEvidence = {
        parentProcessId: "browser-process-1",
        nested: { z: 1, a: [3, { y: 2, b: 1 }] },
        childOrigin: "https://probe.other.test",
        collectorBuild: build,
        registrableChildSite: "other.test",
        configurationId: "oopif-config-7",
        parentOrigin: "https://panel.example.test",
        childProcessId: "renderer-process-2",
        registrableParentSite: "example.test",
      };
      const processEvidenceSha256 = sha256hex(JSON.stringify(canonical(processEvidence)));
      const embeddedCollectorSource = "exact-rendered-collector-source";
      const embeddedCollectorArtifactSha256 = sha256hex(embeddedCollectorSource);
      const payload = {
        browserCollectorBuild: build,
        browserCollectorArtifactSha256: embeddedCollectorArtifactSha256,
        serviceWorkerChallenge: challenge,
        crossOriginProbe: {
          parentOrigin: "https://panel.example.test",
          childOrigin: "https://probe.other.test",
          registrableParentSite: "example.test",
          registrableChildSite: "other.test",
          configurationId: "oopif-config-7",
          processEvidence,
          processEvidenceSha256,
          processEvidenceBuild: build,
        },
      };
      let requestedURL = null;
      const context = vm.createContext({
        URL, URLSearchParams,
        location: { origin: "https://panel.example.test", href: "https://panel.example.test/fingerprint?env=plain&sid=pair-7", search: "?env=plain&sid=pair-7" },
        LinkageProbe: { sha256hex },
        EMBEDDED_COLLECTOR_BUILD: build,
        EMBEDDED_COLLECTOR_ARTIFACT_SHA256: embeddedCollectorArtifactSha256,
        COLLECTOR_SRC: embeddedCollectorSource,
        RUN_IDENTITY: null,
        OOPIF_EXPECTATION: null,
        boundedJson: async (url) => {
          requestedURL = url;
          return { response: { ok: true }, data: payload };
        },
      });
      new vm.Script(`${pageSource.slice(identityStart, identityEnd)}\nthis.__initRunIdentity=initRunIdentity;`).runInContext(context);
      const identity = await context.__initRunIdentity();
      ok("identity endpoint is explicitly bound to env and sid",
        requestedURL === "/api/fingerprint/build?env=plain&sid=pair-7");
      ok("RUN_IDENTITY carries the challenge and complete server OOPIF evidence",
        identity.serviceWorkerChallenge === challenge
          && identity.collectorArtifactSha256 === embeddedCollectorArtifactSha256
          && identity.oopif.processEvidence === undefined
          && identity.oopif.processEvidenceSha256 === processEvidenceSha256
          && identity.oopif.registrableParentSite === "example.test"
          && identity.oopif.registrableChildSite === "other.test");

      payload.crossOriginProbe.processEvidence = { ...processEvidence, childProcessId: "tampered-process" };
      let rejected = false;
      try { await context.__initRunIdentity(); } catch { rejected = true; }
      ok("identity initialization rejects re-bound process evidence even when the outer digest is unchanged", rejected);

      payload.crossOriginProbe.processEvidence = { ...processEvidence, captureKey };
      payload.crossOriginProbe.processEvidenceSha256 = sha256hex(JSON.stringify(canonical(payload.crossOriginProbe.processEvidence)));
      rejected = false;
      try { await context.__initRunIdentity(); } catch { rejected = true; }
      ok("browser rejects per-capture fields smuggled into build-level process evidence", rejected);
    }
  }

  {
    const swStart = pageSource.indexOf("function serviceWorkerRequestId(");
    const swEnd = pageSource.indexOf("function viaCrossOrigin()", swStart);
    ok("page contains an isolated Service Worker handshake implementation",
      swStart >= 0 && swEnd > swStart);
    if (swStart >= 0 && swEnd > swStart) {
      const expectedScriptURL = `https://panel.example.test/fingerprint/sw?build=${build}&artifact=${collectorArtifactSha256}&capture=${encodeURIComponent(captureKey)}&challenge=${challenge}`;
      const expectedScope = `https://panel.example.test/fingerprint/sw-scope/${challenge}/`;
      let registerURL, registerOptions, unregistered = 0, controllerReads = 0;
      let sendPayload = null, finalStatus = null;
      const closedPorts = [];
      class FakePort {
        constructor() { this.listeners = new Map(); this.closed = false; }
        addEventListener(type, fn) { this.listeners.set(type, fn); }
        removeEventListener(type, fn) { if (this.listeners.get(type) === fn) this.listeners.delete(type); }
        start() {}
        close() { this.closed = true; closedPorts.push(this); }
        emit(type, value) { this.listeners.get(type)?.(value); }
      }
      class FakeMessageChannel {
        constructor() {
          this.port1 = new FakePort(); this.port2 = new FakePort();
          this.port2.emit = (type, value) => this.port1.emit(type, value);
        }
      }
      const active = {
        state: "activated",
        scriptURL: expectedScriptURL,
        postMessage(request, ports) {
          const evidence = {
            context: "service-worker", collectorBuild: build, collectorArtifactSha256,
            captureKey, challenge,
            acknowledgementSha256: sha256hex(JSON.stringify(canonical({
              context: "service-worker", collectorBuild: build, collectorArtifactSha256,
              captureKey, challenge,
            }))),
            handshakeVersion: 1, requestId: request.requestId,
            scriptURL: expectedScriptURL, scope: expectedScope,
          };
          queueMicrotask(() => ports[0].emit("message", { data: {
            type: "fingerprint-service-worker-result", handshakeVersion: 1,
            requestId: request.requestId, ok: true,
            payload: { _context: "service-worker", _serviceWorker: evidence },
          } }));
        },
      };
      const registration = {
        active, installing: null, waiting: null,
        scope: expectedScope, updateViaCache: "none",
        addEventListener() {}, removeEventListener() {},
        async unregister() { unregistered++; return true; },
      };
      const serviceWorker = {
        async register(url, options) { registerURL = url; registerOptions = options; return registration; },
      };
      Object.defineProperty(serviceWorker, "controller", { get() { controllerReads++; throw new Error("global controller is forbidden"); } });
      const context = vm.createContext({
        URL, URLSearchParams, Uint8Array, Promise, Object, Array, String, Error, TypeError, JSON,
        location: { origin: "https://panel.example.test" },
        navigator: { serviceWorker },
        MessageChannel: FakeMessageChannel,
        crypto: { getRandomValues(bytes) { bytes.fill(1); return bytes; } },
        LinkageProbe: { sha256hex },
        RUN_IDENTITY: { collectorBuild: build, collectorArtifactSha256,
          captureKey, serviceWorkerChallenge: challenge },
        validServiceWorkerToken(value) { return typeof value === "string" && /^[A-Za-z0-9_-]{22,240}$/.test(value); },
        canonicalIdentityJson(value) { return JSON.stringify(canonical(value)); },
        setTimeout, clearTimeout, queueMicrotask,
        rstat(_name, status) { finalStatus = status; },
        log() {},
        async send(_context, payload) { sendPayload = payload; },
      });
      new vm.Script(`${pageSource.slice(swStart, swEnd)}\nthis.__viaServiceWorker=viaServiceWorker;`).runInContext(context);
      await context.__viaServiceWorker();
      ok("page registers a capture-bound script and challenge-unique scope with cache bypass",
        registerURL === `/fingerprint/sw?build=${build}&artifact=${collectorArtifactSha256}&capture=${encodeURIComponent(captureKey)}&challenge=${challenge}`
          && registerOptions?.scope === `/fingerprint/sw-scope/${challenge}/`
          && registerOptions?.updateViaCache === "none");
      ok("page talks only to the exact activated registration worker",
        controllerReads === 0 && registration.active === active && active.state === "activated");
      ok("page validates and forwards the bound readiness payload",
        finalStatus === "finished" && sendPayload?._serviceWorker?.scriptURL === expectedScriptURL
          && sendPayload._serviceWorker.scope === expectedScope
          && /^[A-Za-z0-9_-]{22,240}$/.test(sendPayload._serviceWorker.requestId));
      ok("page closes both MessageChannel ports and unregisters its unique registration",
        closedPorts.length === 2 && closedPorts.every((port) => port.closed) && unregistered === 1);
    }
  }
}

console.log(`\nfp-sw: ${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
