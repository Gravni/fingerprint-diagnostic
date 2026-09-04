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
  let p = 0;
  while (p + 5 <= buf.length && buf[p] === 0x16) {
    const recLen = buf.readUInt16BE(p + 3);
    frags.push(buf.subarray(p + 5, Math.min(p + 5 + recLen, buf.length)));
    p += 5 + recLen;
  }
  return frags.length ? Buffer.concat(frags) : null;
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
    // Re-wrap the reassembled handshake as a single synthetic record so the parse
    // offsets below (record header at 0, handshake at 5) stay unchanged.
    buf = Buffer.concat([Buffer.from([0x16, buf[1], buf[2], (hs.length >> 8) & 0xff, hs.length & 0xff]), hs]);
    let p = 5;

    // Handshake header: type(1)=0x01 ClientHello, length(3)
    if (buf[p] !== 0x01) return null;
    p += 4;

    const handshakeVersion = buf.readUInt16BE(p); p += 2;
    p += 32; // random

    const sidLen = buf[p]; p += 1 + sidLen;

    const cipherLen = buf.readUInt16BE(p); p += 2;
    const ciphers: number[] = [];
    for (let i = 0; i < cipherLen; i += 2) ciphers.push(buf.readUInt16BE(p + i));
    p += cipherLen;

    const compLen = buf[p]; p += 1 + compLen;

    const out: ClientHello = {
      tlsRecordVersion, handshakeVersion,
      supportedVersionMax: null,
      ciphers, extensions: [], sni: null, alpn: [], sigAlgs: [], curves: [], pointFormats: [],
    };

    if (p + 2 > buf.length) return out; // no extensions block
    const extTotal = buf.readUInt16BE(p); p += 2;
    const extEnd = Math.min(p + extTotal, buf.length);

    while (p + 4 <= extEnd) {
      const type = buf.readUInt16BE(p);
      const len = buf.readUInt16BE(p + 2);
      const body = p + 4;
      out.extensions.push(type);

      if (type === 0x0000 && len >= 5) {
        // server_name: list(2) + type(1) + name_len(2) + name
        const nameLen = buf.readUInt16BE(body + 3);
        out.sni = buf.toString("ascii", body + 5, body + 5 + nameLen);
      } else if (type === 0x0010 && len >= 2) {
        // ALPN: list_len(2) then [len(1) proto]...
        let q = body + 2;
        const listEnd = body + len;
        while (q < listEnd) {
          const l = buf[q]; q += 1;
          out.alpn.push(buf.toString("ascii", q, q + l)); q += l;
        }
      } else if (type === 0x002b && len >= 1) {
        // supported_versions: list_len(1) then versions(2 each)
        const n = buf[body];
        let best = 0;
        for (let i = 0; i < n; i += 2) {
          const v = buf.readUInt16BE(body + 1 + i);
          if (!isGrease(v) && v > best) best = v;
        }
        if (best) out.supportedVersionMax = best;
      } else if (type === 0x000d && len >= 2) {
        // signature_algorithms: list_len(2) then algs(2 each)
        const n = buf.readUInt16BE(body);
        for (let i = 0; i < n && body + 2 + i + 1 < extEnd; i += 2) out.sigAlgs.push(buf.readUInt16BE(body + 2 + i));
      } else if (type === 0x000a && len >= 2) {
        // supported_groups / elliptic_curves: list_len(2) then curves(2 each).
        // Omitting this made JA3 field 4 always empty → never matched real JA3.
        const n = buf.readUInt16BE(body);
        for (let i = 0; i < n && body + 2 + i + 1 < extEnd; i += 2) out.curves.push(buf.readUInt16BE(body + 2 + i));
      } else if (type === 0x000b && len >= 1) {
        // ec_point_formats: list_len(1) then formats(1 each). JA3 field 5.
        const n = buf[body];
        for (let i = 0; i < n && body + 1 + i < extEnd; i += 1) out.pointFormats.push(buf[body + 1 + i]);
      }
      p = body + len;
    }
    return out;
  } catch {
    return null;
  }
}

const VER: Record<number, string> = {
  0x0304: "13", 0x0303: "12", 0x0302: "11", 0x0301: "10", 0x0300: "s3",
};
function verStr(ch: ClientHello): string {
  const v = ch.supportedVersionMax ?? ch.handshakeVersion;
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
  const alpn0 = ch.alpn[0] ?? "";
  const alpnCode = alpn0 ? alpn0[0] + alpn0[alpn0.length - 1] : "00";
  const a = `${transport}${verStr(ch)}${sni}${cap99(ciphers.length)}${cap99(exts.length)}${alpnCode}`;

  const b = sha12(ciphers.map(hex4).sort().join(","));

  // ja4_c: extensions sorted, but SNI (0000) and ALPN (0010) removed from the
  // sorted list; signature algorithms appended in their original order.
  const extForC = exts.filter((e) => e !== 0x0000 && e !== 0x0010).map(hex4).sort();
  const sig = ch.sigAlgs.map(hex4).join(",");
  const c = sha12(`${extForC.join(",")}_${sig}`);

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
  return createHash("md5").update(ja3String(ch)).digest("hex");
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
