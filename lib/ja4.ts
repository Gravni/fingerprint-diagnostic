// TLS ClientHello parser + JA4/JA3 fingerprint.
//
// The network layer of the fingerprint: what the browser reveals in the raw
// TLS handshake, before any HTTP or JavaScript. A JS probe cannot see this —
// only a server that terminates TLS and reads the ClientHello can, which is
// why the capture server (scripts/capture-server.js) exists separately from
// the panel and must be hit directly, not through a proxy.
//
// JA4 spec: https://github.com/FoxIO-LLC/ja4 — implemented here from the spec,
// to be validated against real browser handshakes once it's deployed behind a
// cert (a synthetic ClientHello in the test only checks the assembly logic).

import { createHash } from "node:crypto";
import { md5hex } from "./md5.mjs";

/** GREASE values (RFC 8701) are random padding a client sends to keep the
 *  ecosystem flexible; they must be stripped everywhere or the fingerprint is
 *  unstable run to run. They follow the pattern 0x?a?a. */
function isGrease(v: number): boolean {
  return (v & 0x0f0f) === 0x0a0a && (v >> 8) === (v & 0xff);
}

export interface ClientHello {
  tlsRecordVersion: number;
  handshakeVersion: number;
  /** From supported_versions ext if present — the real negotiated max. */
  supportedVersionMax: number | null;
  ciphers: number[];        // GREASE included; callers strip as needed
  extensions: number[];     // in wire order, GREASE included
  sni: string | null;
  alpn: string[];
  /** Exact ALPN protocol bytes. JA4 must not round-trip these through Unicode. */
  alpnRaw: number[][];
  sigAlgs: number[];        // signature_algorithms, in wire order
  curves: number[];         // supported_groups (ext 0x000a), wire order, GREASE incl.
  pointFormats: number[];   // ec_point_formats (ext 0x000b), wire order
}

// Concatenate the handshake fragments from consecutive TLS handshake records
// (type 0x16). A ClientHello can span MULTIPLE TLS records — a single-record
// parse silently truncates exactly the large post-quantum hellos we care about
// (Codex v4.3 #8). Returns the reassembled handshake bytes (type+len+body), or
// null if the first record isn't a handshake.
function reassembleHandshake(buf: Buffer): Buffer | null {
  if (buf.length < 5 || buf[0] !== 0x16) return null;
  const frags: Buffer[] = [];
  let p = 0, total = 0, wanted: number | null = null;
  while (p < buf.length) {
    if (p + 5 > buf.length || buf[p] !== 0x16) return null;
    const recLen = buf.readUInt16BE(p + 3);
    const recEnd = p + 5 + recLen;
    // Never accept a partial TLS record. The previous implementation used
    // Math.min(), which could turn a truncated packet into a plausible hello.
    if (recEnd > buf.length) return null;
    const frag = buf.subarray(p + 5, recEnd);
    frags.push(frag); total += frag.length;
    if (wanted === null && total >= 4) {
      const prefix = Buffer.concat(frags, total);
      if (prefix[0] !== 0x01) return null;
      wanted = 4 + prefix.readUIntBE(1, 3);
    }
    if (wanted !== null && total >= wanted) return Buffer.concat(frags, total).subarray(0, wanted);
    p += 5 + recLen;
  }
  return null;
}

/** True once the full ClientHello handshake message has arrived across however
 *  many TLS records — the capture server accumulates until this is true. */
export function clientHelloComplete(buf: Buffer): boolean {
  const hs = reassembleHandshake(buf);
  if (!hs || hs.length < 4 || hs[0] !== 0x01) return false;
  const hsLen = hs.readUIntBE(1, 3);
  return hs.length >= 4 + hsLen;
}

/** Parse a TLS ClientHello — reassembling it from one OR MANY TLS records first,
 *  then parsing the handshake. Returns null if the bytes are not a handshake
 *  ClientHello (e.g. a plain HTTP request hit the port). */
export function parseClientHello(buf: Buffer): ClientHello | null {
  try {
    if (buf.length < 5 || buf[0] !== 0x16) return null;
    const tlsRecordVersion = buf.readUInt16BE(1);
    const hs = reassembleHandshake(buf);
    if (!hs) return null;
    if (hs.length < 4 || hs[0] !== 0x01 || hs.readUIntBE(1, 3) !== hs.length - 4) return null;
    let p = 4;
    const end = hs.length;
    const need = (n: number) => p + n <= end;

    if (!need(2 + 32 + 1)) return null;
    const handshakeVersion = hs.readUInt16BE(p); p += 2;
    p += 32; // random

    const sidLen = hs[p++];
    if (!need(sidLen + 2)) return null;
    p += sidLen;

    const cipherLen = hs.readUInt16BE(p); p += 2;
    if ((cipherLen & 1) !== 0 || !need(cipherLen + 1)) return null;
    const ciphers: number[] = [];
    for (let i = 0; i < cipherLen; i += 2) ciphers.push(hs.readUInt16BE(p + i));
    p += cipherLen;

    const compLen = hs[p++];
    if (!need(compLen)) return null;
    p += compLen;

    const out: ClientHello = {
      tlsRecordVersion, handshakeVersion,
      supportedVersionMax: null,
      ciphers, extensions: [], sni: null, alpn: [], alpnRaw: [], sigAlgs: [], curves: [], pointFormats: [],
    };

    if (p === end) return out; // old TLS ClientHello with no extensions block
    if (!need(2)) return null;
    const extTotal = hs.readUInt16BE(p); p += 2;
    if (p + extTotal !== end) return null;
    const extEnd = p + extTotal;

    while (p < extEnd) {
      if (p + 4 > extEnd) return null;
      const type = hs.readUInt16BE(p);
      const len = hs.readUInt16BE(p + 2);
      const body = p + 4;
      const bodyEnd = body + len;
      if (bodyEnd > extEnd) return null;
      out.extensions.push(type);

      if (type === 0x0000) {
        if (len < 2) return null;
        const listLen = hs.readUInt16BE(body);
        if (listLen !== len - 2) return null;
        let q = body + 2;
        while (q < bodyEnd) {
          if (q + 3 > bodyEnd) return null;
          const nameType = hs[q++], nameLen = hs.readUInt16BE(q); q += 2;
          if (q + nameLen > bodyEnd) return null;
          if (nameType === 0 && out.sni === null) out.sni = hs.toString("ascii", q, q + nameLen);
          q += nameLen;
        }
      } else if (type === 0x0010) {
        // ALPN: list_len(2) then [len(1) proto]...
        if (len < 2) return null;
        const listLen = hs.readUInt16BE(body);
        if (listLen !== len - 2) return null;
        let q = body + 2;
        while (q < bodyEnd) {
          const l = hs[q++];
          if (l === 0 || q + l > bodyEnd) return null;
          const raw = [...hs.subarray(q, q + l)];
          out.alpnRaw.push(raw);
          out.alpn.push(Buffer.from(raw).toString("latin1"));
          q += l;
        }
      } else if (type === 0x002b) {
        // supported_versions: list_len(1) then versions(2 each)
        if (len < 1) return null;
        const n = hs[body];
        if (n !== len - 1 || (n & 1) !== 0) return null;
        let best = 0;
        for (let i = 0; i < n; i += 2) {
          const v = hs.readUInt16BE(body + 1 + i);
          if (!isGrease(v) && v > best) best = v;
        }
        if (best) out.supportedVersionMax = best;
      } else if (type === 0x000d) {
        // signature_algorithms: list_len(2) then algs(2 each)
        if (len < 2) return null;
        const n = hs.readUInt16BE(body);
        if (n !== len - 2 || (n & 1) !== 0) return null;
        for (let i = 0; i < n; i += 2) out.sigAlgs.push(hs.readUInt16BE(body + 2 + i));
      } else if (type === 0x000a) {
        // supported_groups / elliptic_curves: list_len(2) then curves(2 each).
        // Omitting this made JA3 field 4 always empty → never matched real JA3.
        if (len < 2) return null;
        const n = hs.readUInt16BE(body);
        if (n !== len - 2 || (n & 1) !== 0) return null;
        for (let i = 0; i < n; i += 2) out.curves.push(hs.readUInt16BE(body + 2 + i));
      } else if (type === 0x000b) {
        // ec_point_formats: list_len(1) then formats(1 each). JA3 field 5.
        if (len < 1) return null;
        const n = hs[body];
        if (n !== len - 1) return null;
        for (let i = 0; i < n; i += 1) out.pointFormats.push(hs[body + 1 + i]);
      }
      p = bodyEnd;
    }
    return out;
  } catch {
    return null;
  }
}

const VER: Record<number, string> = {
  0x0304: "13", 0x0303: "12", 0x0302: "11", 0x0301: "10", 0x0300: "s3",
  0x0002: "s2", 0xfeff: "d1", 0xfefd: "d2", 0xfefc: "d3",
};
function verStr(ch: ClientHello): string {
  const v = ch.supportedVersionMax ?? ch.tlsRecordVersion;
  return VER[v] ?? "00";
}

const hex2 = (n: number) => n.toString(16).padStart(2, "0");
const hex4 = (n: number) => n.toString(16).padStart(4, "0");
const sha12 = (s: string) => createHash("sha256").update(s).digest("hex").slice(0, 12);
const cap99 = (n: number) => (n > 99 ? 99 : n).toString().padStart(2, "0");

/**
 * JA4 fingerprint of a TLS ClientHello.
 *
 *   ja4_a: t + tlsver + (d|i for SNI) + ciphercount + extcount + alpn[0][first+last]
 *   ja4_b: sha256(ciphers sorted asc, GREASE stripped)[:12]
 *   ja4_c: sha256(extensions sorted asc minus GREASE/SNI/ALPN, "_", sigalgs in order)[:12]
 */
export function ja4(ch: ClientHello, transport: "t" | "q" = "t"): string {
  const ciphers = ch.ciphers.filter((c) => !isGrease(c));
  const exts = ch.extensions.filter((e) => !isGrease(e));

  const sni = ch.sni ? "d" : "i";
  const alpnBytes = ch.alpnRaw?.[0]?.length
    ? ch.alpnRaw[0]
    : ch.alpn[0] ? [...Buffer.from(ch.alpn[0], "utf8")] : [];
  const isAlnum = (b: number) => (b >= 0x30 && b <= 0x39) || (b >= 0x41 && b <= 0x5a) || (b >= 0x61 && b <= 0x7a);
  let alpnCode = "00";
  if (alpnBytes.length) {
    const first = alpnBytes[0], last = alpnBytes[alpnBytes.length - 1];
    if (isAlnum(first) && isAlnum(last)) alpnCode = String.fromCharCode(first) + String.fromCharCode(last);
    else {
      const hex = alpnBytes.map(hex2).join("");
      alpnCode = hex[0] + hex[hex.length - 1];
    }
  }
  const a = `${transport}${verStr(ch)}${sni}${cap99(ciphers.length)}${cap99(exts.length)}${alpnCode}`;

  const cipherText = ciphers.map(hex4).sort().join(",");
  const b = cipherText ? sha12(cipherText) : "000000000000";

  // ja4_c: extensions sorted, but SNI (0000) and ALPN (0010) removed from the
  // sorted list; signature algorithms appended in their original order.
  const extForC = exts.filter((e) => e !== 0x0000 && e !== 0x0010).map(hex4).sort();
  const sig = ch.sigAlgs.filter((s) => !isGrease(s)).map(hex4).join(",");
  const extText = extForC.join(",");
  const c = extText ? sha12(sig ? `${extText}_${sig}` : extText) : "000000000000";

  return `${a}_${b}_${c}`;
}

/** The canonical (salesforce) JA3 string:
 *  `SSLVersion,Ciphers,Extensions,EllipticCurves,ECPointFormats` — decimal,
 *  `-`-joined within a field, GREASE stripped (matching python/ja3.py). Field 1
 *  is the LEGACY ClientHello version (not supported_versions). Point formats are
 *  not GREASE. All five fields are now populated (curves/point-formats parsed). */
export function ja3String(ch: ClientHello): string {
  const strip = (arr: number[]) => arr.filter((v) => !isGrease(v));
  return [
    ch.handshakeVersion,
    strip(ch.ciphers).join("-"),
    strip(ch.extensions).join("-"),
    strip(ch.curves).join("-"),
    ch.pointFormats.join("-"),
  ].join(",");
}
/** JA3 MD5 of the canonical string above. */
export function ja3(ch: ClientHello): string {
  return md5hex(ja3String(ch));
}

export function fingerprintFromClientHello(buf: Buffer):
  | { ja4: string; ja3: string; ja3String: string; sni: string | null; alpn: string[]; tlsVersion: string; raw: ClientHello }
  | null {
  const ch = parseClientHello(buf);
  if (!ch) return null;
  return {
    ja4: ja4(ch),
    ja3: ja3(ch),
    ja3String: ja3String(ch),
    sni: ch.sni,
    alpn: ch.alpn,
    tlsVersion: verStr(ch),
    raw: ch,
  };
}
