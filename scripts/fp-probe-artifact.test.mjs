import { readFileSync } from "node:fs";
import vm from "node:vm";
import * as probeArtifact from "../lib/fp-probe-artifact.mjs";
import { sha256hex } from "../lib/fp-encode.mjs";

const { renderFingerprintProbe, renderBoundChildProbe, renderServiceWorkerProbe } = probeArtifact;

let pass = 0, fail = 0;
function ok(label, condition) { if (condition) pass++; else { fail++; console.log("  ✗ " + label); } }

const template = readFileSync(new URL("../assets/fingerprint-probe.html", import.meta.url), "utf8");
const encoderSource = readFileSync(new URL("../lib/fp-encode.mjs", import.meta.url), "utf8");
const build = "a".repeat(64);
const rendered = renderFingerprintProbe({ template, encoderSource, browserCollectorBuild: build });

ok("both mandatory template markers are resolved",
  !rendered.html.includes("__FP_ENCODE_INJECT__") && !rendered.html.includes("__FP_BROWSER_COLLECTOR_BUILD__")
    && !rendered.html.includes("__FP_COLLECTOR_SOURCE_INJECT__")
    && !rendered.html.includes("__FP_COLLECTOR_ARTIFACT_SHA256__"));
ok("the exact build is embedded into cached executable HTML",
  rendered.html.includes(`var EMBEDDED_COLLECTOR_BUILD='${build}'`));
ok("module exports become in-scope collector declarations",
  rendered.html.includes("function encodeValue(") && !/^\s*export\s/m.test(rendered.html));
ok("the final artifact digest covers the served HTML bytes",
  rendered.artifactSha256 === sha256hex(rendered.html) && /^[0-9a-f]{64}$/.test(rendered.artifactSha256));
ok("the cross-site collector is derived from the same injected function",
  rendered.collectorSource.startsWith("(function COLLECTOR(root){")
    && rendered.collectorSource.endsWith("})(self);")
    && rendered.collectorSource.includes("function encodeValue(")
    && !rendered.collectorSource.includes("__FP_ENCODE_INJECT__"));
ok("the collector endpoint receives its own exact-byte artifact digest",
  rendered.collectorArtifactSha256 === sha256hex(rendered.collectorSource)
    && /^[0-9a-f]{64}$/.test(rendered.collectorArtifactSha256));
ok("the main page embeds the exact server-derived collector bytes and digest",
  rendered.html.includes(`const EMBEDDED_COLLECTOR_ARTIFACT_SHA256='${rendered.collectorArtifactSha256}'`)
    && !rendered.html.includes("COLLECTOR.toString()"));

{
  const start = rendered.html.indexOf("const COLLECTOR_SRC=");
  const end = rendered.html.indexOf("var WORKER_SRC=", start);
  const context = vm.createContext({});
  new vm.Script("Function.prototype.toString=function(){throw new Error('poisoned');};\n"
    + rendered.html.slice(start, end)
    + "\nthis.source=COLLECTOR_SRC;this.digest=EMBEDDED_COLLECTOR_ARTIFACT_SHA256;").runInContext(context);
  ok("patched Function.prototype.toString cannot influence child collector bytes",
    context.source === rendered.collectorSource && context.digest === rendered.collectorArtifactSha256);
}

const scriptStart = rendered.html.indexOf("<script>") + "<script>".length;
const scriptEnd = rendered.html.lastIndexOf("</script>");
let parses = true;
try { new vm.Script(rendered.html.slice(scriptStart, scriptEnd)); } catch { parses = false; }
ok("rendered browser script parses as JavaScript", parses);
let collectorParses = true;
try { new vm.Script(rendered.collectorSource); } catch { collectorParses = false; }
ok("derived /fingerprint/collector source parses as JavaScript", collectorParses);

ok("the artifact API exposes a Service Worker renderer",
  typeof renderServiceWorkerProbe === "function");

ok("the artifact API exposes a bound real-URL child renderer",
  typeof renderBoundChildProbe === "function");
if (typeof renderBoundChildProbe === "function") {
  const source = "self.LinkageProbe={collect:async function(context){return {_context:context,value:7};}};";
  const collectorArtifactSha256 = sha256hex(source);
  const input = {
    collectorSource: source,
    browserCollectorBuild: build,
    collectorArtifactSha256,
    captureKey: "pair-1:plain",
    requestId: "ChildRequest_1234567890ab",
    context: "iframe-url",
    parentOrigin: "https://panel.example.test",
  };
  const first = renderBoundChildProbe(input);
  const second = renderBoundChildProbe(input);
  const changedCapture = renderBoundChildProbe({ ...input, captureKey: "pair-1:anti" });
  const changedRequest = renderBoundChildProbe({ ...input, requestId: "ChildRequest_1234567890ac" });
  ok("bound child rendering is deterministic and all capture bindings affect its bytes",
    first.html === second.html && first.artifactSha256 === second.artifactSha256
      && first.artifactSha256 !== changedCapture.artifactSha256
      && first.artifactSha256 !== changedRequest.artifactSha256);
  ok("bound child acknowledgement covers build/artifact/capture/context/request/parent",
    first.binding.collectorBuild === build
      && first.binding.collectorArtifactSha256 === collectorArtifactSha256
      && first.binding.captureKey === input.captureKey
      && first.binding.context === input.context
      && first.binding.requestId === input.requestId
      && first.binding.parentOrigin === input.parentOrigin
      && first.acknowledgementSha256 === sha256hex(JSON.stringify(Object.fromEntries(
        Object.entries(first.binding).filter(([key]) => key !== "acknowledgementSha256").sort(([a], [b]) => a.localeCompare(b)),
      ))));
  let childParses = true;
  const scripts = [...first.html.matchAll(/<script>([\s\S]*?)<\/script>/g)].map((match) => match[1]);
  try { for (const sourceText of scripts) new vm.Script(sourceText); } catch { childParses = false; }
  ok("generated bound child scripts parse", childParses && scripts.length === 2);

  const messages = [];
  const childContext = vm.createContext({
    self: {}, Promise, Object, Array, TypeError, String, JSON,
    parent: { postMessage(message, targetOrigin) { messages.push({ message, targetOrigin }); } },
  });
  for (const sourceText of scripts) new vm.Script(sourceText).runInContext(childContext);
  await new Promise((resolve) => setImmediate(resolve));
  ok("bound child posts one exact correlated envelope to the exact parent origin",
    messages.length === 1 && messages[0].targetOrigin === input.parentOrigin
      && messages[0].message.__fpBoundChild === 1
      && messages[0].message.payload?._context === input.context
      && messages[0].message.payload?._boundChild?.acknowledgementSha256 === first.acknowledgementSha256);

  const frozenSource = "self.LinkageProbe={collect:async function(context){return Object.freeze({_context:context});}};";
  const frozenRendered = renderBoundChildProbe({
    ...input,
    collectorSource: frozenSource,
    collectorArtifactSha256: sha256hex(frozenSource),
  });
  const frozenScripts = [...frozenRendered.html.matchAll(/<script>([\s\S]*?)<\/script>/g)].map((match) => match[1]);
  const frozenMessages = [];
  const frozenContext = vm.createContext({
    self: {}, Promise, Object, Array, TypeError, String, JSON,
    parent: { postMessage(message, targetOrigin) { frozenMessages.push({ message, targetOrigin }); } },
  });
  for (const sourceText of frozenScripts) new vm.Script(sourceText).runInContext(frozenContext);
  await new Promise((resolve) => setImmediate(resolve));
  ok("a post-collection binding failure returns a correlated error instead of hanging",
    frozenMessages.length === 1 && frozenMessages[0].message.payload?._context === input.context
      && /read only|extensible|Cannot add/i.test(frozenMessages[0].message.payload?.error || "")
      && frozenMessages[0].message.payload?._boundChild?.acknowledgementSha256 === frozenRendered.acknowledgementSha256);

  for (const [label, overrides] of [
    ["mismatched collector digest", { collectorArtifactSha256: "f".repeat(64) }],
    ["unsupported child context", { context: "iframe" }],
    ["non-canonical parent origin", { parentOrigin: "https://panel.example.test/path" }],
    ["short request id", { requestId: "short" }],
  ]) {
    let rejected = false;
    try { renderBoundChildProbe({ ...input, ...overrides }); } catch { rejected = true; }
    ok(label + " is rejected by the bound child renderer", rejected);
  }
}

if (typeof renderServiceWorkerProbe === "function") {
  const captureKey = "pair-1:plain";
  const challenge = "AbCdEfGhIjKlMnOpQrStUv";
  const input = {
    collectorSource: rendered.collectorSource,
    browserCollectorBuild: build,
    collectorArtifactSha256: rendered.collectorArtifactSha256,
    captureKey,
    challenge,
  };
  const first = renderServiceWorkerProbe(input);
  const second = renderServiceWorkerProbe(input);
  const changedCapture = renderServiceWorkerProbe({ ...input, captureKey: "pair-1:anti" });
  const changedChallenge = renderServiceWorkerProbe({ ...input, challenge: "ZbCdEfGhIjKlMnOpQrStUv" });
  const changedSource = rendered.collectorSource + "\n/* reviewed variant */";
  const changedArtifact = renderServiceWorkerProbe({
    ...input,
    collectorSource: changedSource,
    collectorArtifactSha256: sha256hex(changedSource),
  });

  ok("Service Worker rendering is byte-deterministic",
    first.source === second.source && first.artifactSha256 === second.artifactSha256);
  ok("Service Worker source contains the exact rendered collector source once",
    first.source.indexOf(rendered.collectorSource) >= 0
      && first.source.indexOf(rendered.collectorSource) === first.source.lastIndexOf(rendered.collectorSource)
      && first.collectorArtifactSha256 === rendered.collectorArtifactSha256);
  ok("Service Worker artifact identity covers the exact generated bytes",
    first.artifactSha256 === sha256hex(first.source)
      && /^[0-9a-f]{64}$/.test(first.artifactSha256));
  ok("capture and challenge bindings change the generated artifact",
    first.artifactSha256 !== changedCapture.artifactSha256
      && first.artifactSha256 !== changedChallenge.artifactSha256
      && first.artifactSha256 !== changedArtifact.artifactSha256);
  ok("Service Worker renderer returns the exact immutable bindings",
    first.browserCollectorBuild === build && first.captureKey === captureKey
      && first.challenge === challenge && Object.isFrozen(first));
  let swParses = true;
  try { new vm.Script(first.source); } catch { swParses = false; }
  ok("generated Service Worker source parses as JavaScript", swParses);
  ok("generated worker installs without request interception or client takeover",
    first.source.includes("skipWaiting")
      && !first.source.includes("addEventListener('fetch'")
      && !first.source.includes('addEventListener("fetch"')
      && !first.source.includes("clients.claim"));

  for (const [label, overrides] of [
    ["empty collector source", { collectorSource: "" }],
    ["human collector build", { browserCollectorBuild: "v4.4" }],
    ["mismatched collector artifact", { collectorArtifactSha256: "f".repeat(64) }],
    ["empty capture key", { captureKey: "" }],
    ["short challenge", { challenge: "too-short" }],
    ["non URL-safe challenge", { challenge: "A".repeat(22) + "/" }],
    ["oversized challenge", { challenge: "A".repeat(241) }],
  ]) {
    let rejected = false;
    try { renderServiceWorkerProbe({ ...input, ...overrides }); } catch { rejected = true; }
    ok(label + " is rejected by the Service Worker renderer", rejected);
  }
}

for (const [label, input] of [
  ["missing encoder marker", { template: template.replace("/*__FP_ENCODE_INJECT__*/", ""), encoderSource, browserCollectorBuild: build }],
  ["duplicate build marker", { template: template.replace("__FP_BROWSER_COLLECTOR_BUILD__", "__FP_BROWSER_COLLECTOR_BUILD____FP_BROWSER_COLLECTOR_BUILD__"), encoderSource, browserCollectorBuild: build }],
  ["missing collector-source marker", { template: template.replace("/*__FP_COLLECTOR_SOURCE_INJECT__*/", "null"), encoderSource, browserCollectorBuild: build }],
  ["missing collector-artifact marker", { template: template.replace("__FP_COLLECTOR_ARTIFACT_SHA256__", "a".repeat(64)), encoderSource, browserCollectorBuild: build }],
  ["human build label", { template, encoderSource, browserCollectorBuild: "v4.4" }],
]) {
  let rejected = false;
  try { renderFingerprintProbe(input); } catch { rejected = true; }
  ok(label + " is rejected", rejected);
}

console.log(`\nfp-probe-artifact: ${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
