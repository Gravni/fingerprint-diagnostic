// Passive HTTP/2 fingerprint helpers.
//
// Node's HTTP/2 implementation already decodes HPACK and exposes rawHeaders in
// receive order. The only bytes it abstracts away are the client's initial
// connection preface and SETTINGS frame, so we parse exactly that small,
// uncompressed prefix and leave all HTTP/2 protocol handling to Node/nghttp2.

import { createHash } from "node:crypto";

export const H2_CLIENT_PREFACE = Buffer.from("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", "ascii");
export const H2_DEFAULT_MAX_FRAME_SIZE = 16_384;

const SETTINGS_NAMES = Object.freeze({
  1: "headerTableSize",
  2: "enablePush",
  3: "maxConcurrentStreams",
  4: "initialWindowSize",
  5: "maxFrameSize",
  6: "maxHeaderListSize",
  8: "enableConnectProtocol",
});

const incomplete = (needed = null) => ({ status: "incomplete", needed });
const invalid = (error) => ({ status: "invalid", error });

/** Parse only the client preface + first SETTINGS frame (RFC 9113 section 3.4). */
export function parseInitialH2Settings(input) {
  const buf = Buffer.isBuffer(input) ? input : Buffer.from(input || []);
  const prefixBytes = Math.min(buf.length, H2_CLIENT_PREFACE.length);
  if (!buf.subarray(0, prefixBytes).equals(H2_CLIENT_PREFACE.subarray(0, prefixBytes))) {
    return invalid("bad-client-preface");
  }
  if (buf.length < H2_CLIENT_PREFACE.length) return incomplete(H2_CLIENT_PREFACE.length - buf.length);

  const frameAt = H2_CLIENT_PREFACE.length;
  if (buf.length < frameAt + 9) return incomplete(frameAt + 9 - buf.length);
  const length = buf.readUIntBE(frameAt, 3);
  const type = buf[frameAt + 3];
  const flags = buf[frameAt + 4];
  const streamId = buf.readUInt32BE(frameAt + 5) & 0x7fffffff;
  if (type !== 0x4) return invalid("initial-frame-not-settings");
  if (streamId !== 0) return invalid("settings-stream-not-zero");
  if ((flags & 0x1) !== 0) return invalid("initial-settings-cannot-ack");
  if (length > H2_DEFAULT_MAX_FRAME_SIZE) return invalid("initial-settings-too-large");
  if (length % 6 !== 0) return invalid("settings-length-not-multiple-of-six");
  const end = frameAt + 9 + length;
  if (buf.length < end) return incomplete(end - buf.length);

  const payload = buf.subarray(frameAt + 9, end);
  const settings = [];
  const effective = {};
  for (let p = 0, wireIndex = 0; p < payload.length; p += 6, wireIndex++) {
    const id = payload.readUInt16BE(p), value = payload.readUInt32BE(p + 2);
    const name = SETTINGS_NAMES[id] || null;
    settings.push({ id, name, value, wireIndex });
    effective[name || `unknown_${id}`] = value; // RFC: last duplicate wins
  }
  return {
    status: "complete",
    consumed: end,
    settings,
    settingsOrder: settings.map((x) => x.id),
    effective,
    payloadHex: payload.toString("hex"),
    payloadSha256: createHash("sha256").update(payload).digest("hex"),
  };
}

/** Incremental bounded observer suitable for a passive TLSSocket `data` tee. */
export class H2PrefaceObserver {
  constructor(maxBytes = H2_CLIENT_PREFACE.length + 9 + H2_DEFAULT_MAX_FRAME_SIZE) {
    this.maxBytes = maxBytes;
    this.chunks = [];
    this.length = 0;
    this.result = incomplete();
  }

  push(chunk) {
    if (this.result.status !== "incomplete") return this.result;
    const b = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk || []);
    this.chunks.push(b); this.length += b.length;
    this.result = parseInitialH2Settings(Buffer.concat(this.chunks, this.length));
    // A normal first application-data chunk can contain SETTINGS plus HEADERS
    // and legitimately exceed the SETTINGS-only cap. Accept it once parsing is
    // complete; enforce the cap only while the required prefix is still absent.
    if (this.result.status === "incomplete" && this.length > this.maxBytes)
      this.result = invalid("observer-byte-cap-exceeded");
    return this.result;
  }
}

/** Validate and preserve Node's ordered HTTP/2 rawHeaders list. */
export function analyzeH2RawHeaders(rawHeaders) {
  if (!Array.isArray(rawHeaders) || rawHeaders.length % 2 !== 0) return invalid("raw-headers-shape");
  const headersTyped = [], pseudoHeaderOrder = [], seenPseudo = new Set(), errors = [];
  let regularSeen = false;
  const allowedPseudo = new Set([":method", ":scheme", ":authority", ":path", ":protocol"]);

  for (let i = 0; i < rawHeaders.length; i += 2) {
    const name = rawHeaders[i], value = rawHeaders[i + 1];
    if (typeof name !== "string" || !name || typeof value !== "string") {
      errors.push("header-not-string");
      continue;
    }
    const pseudo = name.startsWith(":");
    if (pseudo) {
      if (regularSeen) errors.push("pseudo-after-regular:" + name);
      if (!allowedPseudo.has(name)) errors.push("unknown-pseudo:" + name);
      if (seenPseudo.has(name)) errors.push("duplicate-pseudo:" + name);
      seenPseudo.add(name); pseudoHeaderOrder.push(name);
    } else {
      regularSeen = true;
    }
    headersTyped.push({ name, value, wireIndex: i / 2, pseudo });
  }

  const get = (name) => headersTyped.find((h) => h.name === name)?.value;
  const method = get(":method");
  if (!method) errors.push("missing-pseudo::method");
  if (method === "CONNECT") {
    if (!get(":authority")) errors.push("missing-pseudo::authority");
    if (!get(":protocol") && (get(":scheme") || get(":path"))) errors.push("connect-has-scheme-or-path");
  } else {
    for (const name of [":scheme", ":path", ":authority"]) if (!get(name)) errors.push("missing-pseudo:" + name);
  }
  return {
    status: errors.length ? "invalid" : "valid",
    errors,
    pseudoHeaderOrder,
    headersTyped,
  };
}
