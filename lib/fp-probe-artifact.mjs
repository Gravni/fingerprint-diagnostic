// Deterministic renderer for the checked-in browser probe template. The private
// panel must use this function (or byte-equivalent logic) instead of serving the
// raw template: both the encoder and the build identity are mandatory runtime
// substitutions.

import { sha256hex } from "./fp-encode.mjs";

const ENCODER_MARKER = "/*__FP_ENCODE_INJECT__*/";
const BUILD_MARKER = "__FP_BROWSER_COLLECTOR_BUILD__";
const COLLECTOR_SOURCE_MARKER = "/*__FP_COLLECTOR_SOURCE_INJECT__*/";
const COLLECTOR_ARTIFACT_MARKER = "__FP_COLLECTOR_ARTIFACT_SHA256__";
const COLLECTOR_START = "function COLLECTOR(root){";
const COLLECTOR_END = "\nCOLLECTOR(typeof self!=='undefined'?self:this);";
const SHA256_RE = /^[0-9a-f]{64}$/;
const URL_SAFE_TOKEN_RE = /^[A-Za-z0-9_-]{22,240}$/;
const CHILD_CONTEXTS = new Set(["iframe-url", "cross-origin-iframe"]);

function occurrences(source, marker) {
  return source.split(marker).length - 1;
}

function canonical(value) {
  if (Array.isArray(value)) return value.map(canonical);
  if (value && typeof value === "object") {
    const out = {};
    for (const key of Object.keys(value).sort()) out[key] = canonical(value[key]);
    return out;
  }
  return value;
}

function scriptString(value) {
  // JSON is a valid JavaScript string literal. Escaping '<' prevents an exact
  // collector source containing "</script" from terminating the surrounding
  // HTML script element while preserving the runtime string byte-for-byte.
  return JSON.stringify(value)
    .replace(/</g, "\\u003c")
    .replace(/\u2028/g, "\\u2028")
    .replace(/\u2029/g, "\\u2029");
}

function canonicalOrigin(value, name) {
  let parsed;
  try { parsed = new URL(value); } catch { throw new Error(`${name} must be an absolute HTTP(S) origin`); }
  if (!/^https?:$/.test(parsed.protocol) || parsed.username || parsed.password
      || parsed.pathname !== "/" || parsed.search || parsed.hash || parsed.origin !== value) {
    throw new Error(`${name} must be a canonical HTTP(S) origin`);
  }
  return parsed.origin;
}

export function renderFingerprintProbe({ template, encoderSource, browserCollectorBuild } = {}) {
  if (typeof template !== "string" || occurrences(template, ENCODER_MARKER) !== 1) {
    throw new Error("probe template must contain exactly one encoder injection marker");
  }
  if (occurrences(template, BUILD_MARKER) !== 1) {
    throw new Error("probe template must contain exactly one collector-build marker");
  }
  if (occurrences(template, COLLECTOR_SOURCE_MARKER) !== 1) {
    throw new Error("probe template must contain exactly one collector-source marker");
  }
  if (occurrences(template, COLLECTOR_ARTIFACT_MARKER) !== 1) {
    throw new Error("probe template must contain exactly one collector-artifact marker");
  }
  if (typeof encoderSource !== "string" || encoderSource.length === 0) {
    throw new Error("encoderSource is required");
  }
  if (!SHA256_RE.test(browserCollectorBuild || "")) {
    throw new Error("browserCollectorBuild must be a lowercase SHA-256");
  }

  const injected = encoderSource.replace(/^export\s+/gm, "");
  if (/^\s*(?:import|export)\s/m.test(injected)) {
    throw new Error("encoderSource contains unsupported module syntax");
  }
  const intermediate = template
    .replace(ENCODER_MARKER, injected)
    .replace(BUILD_MARKER, browserCollectorBuild);
  // `/fingerprint/collector` must execute the exact same injected COLLECTOR as
  // the main HTML. Derive it from the rendered artifact; never maintain a
  // second hand-copied source string that can drift across realms.
  if (occurrences(intermediate, COLLECTOR_START) !== 1 || occurrences(intermediate, COLLECTOR_END) !== 1) {
    throw new Error("rendered probe must contain exactly one collector boundary");
  }
  const collectorStart = intermediate.indexOf(COLLECTOR_START);
  const collectorEnd = intermediate.indexOf(COLLECTOR_END, collectorStart);
  const collectorFunction = intermediate.slice(collectorStart, collectorEnd).trim();
  const collectorSource = `(${collectorFunction})(self);`;
  if (collectorSource.includes(ENCODER_MARKER) || collectorSource.includes(BUILD_MARKER)
      || collectorSource.includes(COLLECTOR_SOURCE_MARKER)
      || collectorSource.includes(COLLECTOR_ARTIFACT_MARKER)) {
    throw new Error("collector rendering left an unresolved marker");
  }
  const collectorArtifactSha256 = sha256hex(collectorSource);
  // The page harness receives immutable server-derived bytes. It never asks the
  // runtime (and therefore never a patched Function.prototype.toString) to
  // reconstruct the worker/iframe collector.
  const html = intermediate
    .replace(COLLECTOR_SOURCE_MARKER, scriptString(collectorSource))
    .replace(COLLECTOR_ARTIFACT_MARKER, collectorArtifactSha256);
  if (html.includes(ENCODER_MARKER) || html.includes(BUILD_MARKER)
      || html.includes(COLLECTOR_SOURCE_MARKER) || html.includes(COLLECTOR_ARTIFACT_MARKER)) {
    throw new Error("probe rendering left an unresolved marker");
  }
  return Object.freeze({
    html,
    artifactSha256: sha256hex(html),
    collectorSource,
    collectorArtifactSha256,
    browserCollectorBuild,
  });
}

/**
 * Render a real-URL child realm around the exact reviewed collector bytes.
 * Both `/fingerprint/frame` and the capture-origin `/xprobe` route use this
 * handshake. The parent accepts a result only when build, collector artifact,
 * capture, context and per-frame request id all match.
 */
export function renderBoundChildProbe({
  collectorSource,
  browserCollectorBuild,
  collectorArtifactSha256,
  captureKey,
  requestId,
  context,
  parentOrigin,
} = {}) {
  if (typeof collectorSource !== "string" || collectorSource.length === 0) {
    throw new Error("collectorSource is required");
  }
  if (collectorSource.includes(ENCODER_MARKER) || collectorSource.includes(BUILD_MARKER)
      || collectorSource.includes(COLLECTOR_SOURCE_MARKER)
      || collectorSource.includes(COLLECTOR_ARTIFACT_MARKER)) {
    throw new Error("collectorSource contains an unresolved marker");
  }
  if (/<\/script/i.test(collectorSource)) {
    throw new Error("collectorSource cannot be embedded safely in a child script element");
  }
  if (!SHA256_RE.test(browserCollectorBuild || "")) {
    throw new Error("browserCollectorBuild must be a lowercase SHA-256");
  }
  if (!SHA256_RE.test(collectorArtifactSha256 || "")
      || sha256hex(collectorSource) !== collectorArtifactSha256) {
    throw new Error("collectorArtifactSha256 must match collectorSource");
  }
  if (typeof captureKey !== "string" || captureKey.length === 0 || captureKey.length > 240) {
    throw new Error("captureKey must contain 1-240 characters");
  }
  if (!URL_SAFE_TOKEN_RE.test(requestId || "")) {
    throw new Error("requestId must be a 22-240 character URL-safe token");
  }
  if (!CHILD_CONTEXTS.has(context)) throw new Error("unsupported child context");
  const exactParentOrigin = canonicalOrigin(parentOrigin, "parentOrigin");
  const bindingCore = {
    protocol: "fingerprint-bound-child",
    handshakeVersion: 1,
    context,
    collectorBuild: browserCollectorBuild,
    collectorArtifactSha256,
    captureKey,
    requestId,
    parentOrigin: exactParentOrigin,
  };
  const acknowledgementSha256 = sha256hex(JSON.stringify(canonical(bindingCore)));
  const binding = Object.freeze({ ...bindingCore, acknowledgementSha256 });
  const bindingLiteral = scriptString(binding);
  const wrapper = String.raw`
(function boundChildHandshake(){
  'use strict';
  var BINDING=Object.freeze(${bindingLiteral});
  function post(payload){
    var envelope={__fpBoundChild:1,binding:BINDING,payload:payload};
    try{parent.postMessage(envelope,BINDING.parentOrigin);}
    catch(first){
      try{envelope.payload=JSON.parse(JSON.stringify(payload));parent.postMessage(envelope,BINDING.parentOrigin);}
      catch(second){parent.postMessage({__fpBoundChild:1,binding:BINDING,payload:{_context:BINDING.context,error:'post-failed:'+String(first&&first.name)}},BINDING.parentOrigin);}
    }
  }
  Promise.resolve().then(function(){return self.LinkageProbe.collect(BINDING.context);}).then(function(payload){
    if(!payload||typeof payload!=='object'||Array.isArray(payload))throw new TypeError('collector returned a non-object payload');
    payload._boundChild=BINDING;
    post(payload);
  }).then(undefined,function(error){
    post({_context:BINDING.context,error:String(error&&error.message||error),_boundChild:BINDING});
  });
})();
`;
  // `<body>` MUST precede the scripts: the handshake collects in a microtask
  // right after the second script, before the parser would create an implicit
  // body, so document.body was null and every DOM-measuring job (fonts,
  // clientRects) failed in iframe-url / cross-origin-iframe (C1 smoke 2026-09-07).
  const html = `<!doctype html><meta charset="utf-8"><body><script>${collectorSource}</script><script>${wrapper}</script>`;
  return Object.freeze({
    html,
    artifactSha256: sha256hex(html),
    collectorArtifactSha256,
    browserCollectorBuild,
    captureKey,
    requestId,
    context,
    parentOrigin: exactParentOrigin,
    acknowledgementSha256,
    binding,
  });
}

/**
 * Render one capture-bound Service Worker around the collector bytes extracted
 * from renderFingerprintProbe(). The collector uses process-global CUR state,
 * so message jobs are deliberately serialized inside the generated worker.
 */
export function renderServiceWorkerProbe({
  collectorSource,
  browserCollectorBuild,
  collectorArtifactSha256,
  captureKey,
  challenge,
} = {}) {
  if (typeof collectorSource !== "string" || collectorSource.length === 0) {
    throw new Error("collectorSource is required");
  }
  if (collectorSource.includes(ENCODER_MARKER) || collectorSource.includes(BUILD_MARKER)
      || collectorSource.includes(COLLECTOR_SOURCE_MARKER)
      || collectorSource.includes(COLLECTOR_ARTIFACT_MARKER)) {
    throw new Error("collectorSource contains an unresolved marker");
  }
  if (!SHA256_RE.test(browserCollectorBuild || "")) {
    throw new Error("browserCollectorBuild must be a lowercase SHA-256");
  }
  if (!SHA256_RE.test(collectorArtifactSha256 || "")
      || sha256hex(collectorSource) !== collectorArtifactSha256) {
    throw new Error("collectorArtifactSha256 must match collectorSource");
  }
  if (typeof captureKey !== "string" || captureKey.length === 0 || captureKey.length > 240) {
    throw new Error("captureKey must contain 1-240 characters");
  }
  if (!URL_SAFE_TOKEN_RE.test(challenge || "")) {
    throw new Error("challenge must be a 22-240 character URL-safe token");
  }

  const acknowledgementSha256 = sha256hex(JSON.stringify(canonical({
    context: "service-worker",
    collectorBuild: browserCollectorBuild,
    collectorArtifactSha256,
    captureKey,
    challenge,
  })));
  const binding = JSON.stringify({
    collectorBuild: browserCollectorBuild,
    collectorArtifactSha256,
    captureKey,
    challenge,
    acknowledgementSha256,
  });

  const wrapper = String.raw`
(function serviceWorkerHandshake(){
  'use strict';
  var BINDING=Object.freeze(${binding});
  var REQUEST_TYPE='fingerprint-service-worker-collect';
  var RESULT_TYPE='fingerprint-service-worker-result';
  var TOKEN_RE=/^[A-Za-z0-9_-]{22,240}$/;
  var queue=Promise.resolve();

  function validRequest(data){
    if(!data||typeof data!=='object'||Array.isArray(data))return false;
    var keys=Object.keys(data).sort().join(',');
    if(keys!=='captureKey,challenge,collectorArtifactSha256,collectorBuild,context,handshakeVersion,requestId,type')return false;
    return data.type===REQUEST_TYPE&&data.handshakeVersion===1
      &&typeof data.requestId==='string'&&TOKEN_RE.test(data.requestId)
      &&data.context==='service-worker'
      &&data.collectorBuild===BINDING.collectorBuild
      &&data.collectorArtifactSha256===BINDING.collectorArtifactSha256
      &&data.captureKey===BINDING.captureKey
      &&data.challenge===BINDING.challenge;
  }
  function errorValue(error,fallbackName){
    return {name:String(error&&error.name||fallbackName||'Error'),message:String(error&&error.message||'')};
  }
  function replyAndClose(port,message){
    try{port.postMessage(message);}finally{try{port.close();}catch(_){}}
  }
  function failure(port,requestId,error,fallbackName){
    replyAndClose(port,{type:RESULT_TYPE,handshakeVersion:1,requestId:requestId,ok:false,
      error:errorValue(error,fallbackName)});
  }
  function collect(port,data){
    return Promise.resolve().then(function(){
      return self.LinkageProbe.collect('service-worker');
    }).then(function(payload){
      if(!payload||typeof payload!=='object'||Array.isArray(payload))
        throw new TypeError('collector returned a non-object payload');
      payload._serviceWorker={
        context:'service-worker',collectorBuild:BINDING.collectorBuild,
        collectorArtifactSha256:BINDING.collectorArtifactSha256,
        captureKey:BINDING.captureKey,challenge:BINDING.challenge,
        acknowledgementSha256:BINDING.acknowledgementSha256,
        handshakeVersion:1,requestId:data.requestId,
        scriptURL:self.location.href,scope:self.registration.scope
      };
      replyAndClose(port,{type:RESULT_TYPE,handshakeVersion:1,requestId:data.requestId,ok:true,payload:payload});
    }).then(undefined,function(error){
      failure(port,data.requestId,error,'ServiceWorkerCollectionError');
    });
  }

  self.addEventListener('install',function(event){
    event.waitUntil(Promise.resolve(self.skipWaiting()));
  });
  self.addEventListener('message',function(event){
    var ports=event.ports||[],port=ports[0],data=event.data;
    if(!port)return;
    for(var i=1;i<ports.length;i++){try{ports[i].close();}catch(_){}}
    var task;
    if(ports.length!==1||!validRequest(data)){
      task=Promise.resolve().then(function(){
        var requestId=(data&&typeof data.requestId==='string')?data.requestId:null;
        failure(port,requestId,{name:'InvalidServiceWorkerRequest',message:'request identity mismatch'});
      });
    }else{
      task=queue.then(function(){return collect(port,data);});
      queue=task.then(function(){},function(){});
    }
    event.waitUntil(task);
  });
})();
`;
  const source = `${collectorSource}${wrapper}`;
  return Object.freeze({
    source,
    artifactSha256: sha256hex(source),
    collectorArtifactSha256,
    browserCollectorBuild,
    captureKey,
    challenge,
    acknowledgementSha256,
  });
}
