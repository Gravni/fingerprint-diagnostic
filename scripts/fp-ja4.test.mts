// JA4 / JA3 tests against OFFICIAL vectors + ClientHello parser fuzz/bounds
// (Codex v4.3 #8). Run with: node --experimental-strip-types (imports ja4.ts).
import { ja3, ja3String, ja4, parseClientHello, clientHelloComplete, fingerprintFromClientHello, type ClientHello } from "../lib/ja4.ts";
import { createHash } from "node:crypto";

let pass = 0, fail = 0;
const ok = (label: string, cond: boolean) => { if (cond) pass++; else { fail++; console.log("  ✗ " + label); } };

const CH = (o: Partial<ClientHello>): ClientHello => Object.assign({
  tlsRecordVersion: 0x0301, handshakeVersion: 0x0301, supportedVersionMax: null,
  ciphers: [], extensions: [], sni: null, alpn: [], alpnRaw: [], sigAlgs: [], curves: [], pointFormats: [],
}, o);

// ---- JA3: canonical salesforce vector -------------------------------------
{
  const ch = CH({
    handshakeVersion: 769, // 0x0301
    ciphers: [47, 53, 5, 10, 49161, 49162, 49171, 49172, 50, 56, 19, 4],
    extensions: [0, 10, 11],
    curves: [23, 24, 25],
    pointFormats: [0],
  });
  const want = "769,47-53-5-10-49161-49162-49171-49172-50-56-19-4,0-10-11,23-24-25,0";
  ok("JA3 string = salesforce vector (5 fields populated)", ja3String(ch) === want);
  ok("JA3 md5 = ada70206e40642a3e4461f35503241d5", ja3(ch) === "ada70206e40642a3e4461f35503241d5");
}
// curves/point-formats field must NOT be empty when present (the old bug)
ok("JA3 no longer emits empty curve/pf fields", !/,,$/.test(ja3String(CH({ handshakeVersion: 769, ciphers: [1], extensions: [0], curves: [23], pointFormats: [0] }))));

// ---- JA4: official FoxIO vector t13d1516h2_8daaf6152771_e5627efa2ab1 -------
{
  const ciphers = [0x002f,0x0035,0x009c,0x009d,0x1301,0x1302,0x1303,0xc013,0xc014,0xc02b,0xc02c,0xc02f,0xc030,0xcca8,0xcca9];
  const extC = [0x0005,0x000a,0x000b,0x000d,0x0012,0x0015,0x0017,0x001b,0x0023,0x002b,0x002d,0x0033,0x4469,0xff01];
  const extensions = [0x0000, 0x0010, ...extC];          // + SNI + ALPN → 16 total
  const sigAlgs = [0x0403,0x0804,0x0401,0x0503,0x0805,0x0501,0x0806,0x0601];
  const ch = CH({ handshakeVersion: 0x0303, supportedVersionMax: 0x0304, ciphers, extensions, sni: "example.com", alpn: ["h2"], sigAlgs });
  ok("JA4 = official vector", ja4(ch) === "t13d1516h2_8daaf6152771_e5627efa2ab1");
  // GREASE must not change the JA4 (stripped from counts + hashes)
  const chG = CH({ handshakeVersion: 0x0303, supportedVersionMax: 0x0304, ciphers: [0x0a0a, ...ciphers], extensions: [0x1a1a, ...extensions], sni: "example.com", alpn: ["h2"], sigAlgs });
  ok("JA4 GREASE-invariant", ja4(chG) === "t13d1516h2_8daaf6152771_e5627efa2ab1");
}
ok("JA4 SNI absent → 'i'", ja4(CH({ handshakeVersion: 0x0303, supportedVersionMax: 0x0304, ciphers: [0x1301], extensions: [0x002b], alpn: ["h2"] })).indexOf("t13i") === 0);
ok("JA4 no ALPN → '00'", /h2_|00_/.test(ja4(CH({ handshakeVersion: 0x0303, supportedVersionMax: 0x0304, ciphers: [0x1301], extensions: [0x002b] }))) && ja4(CH({ handshakeVersion: 0x0303, supportedVersionMax: 0x0304, ciphers: [0x1301], extensions: [0x002b] })).slice(8, 10) === "00");

// ---- JA4 edge cases from the official FoxIO technical details ------------
{
  const empty = ja4(CH({ tlsRecordVersion: 0x0303, handshakeVersion: 0x0303, supportedVersionMax: 0x0304 }));
  ok("JA4 empty cipher/extension lists use twelve zeroes", empty === "t13i000000_000000000000_000000000000");
}
{
  const ch = CH({ tlsRecordVersion: 0x0303, handshakeVersion: 0x0303, supportedVersionMax: 0x0304,
    ciphers: [0x1301], extensions: [0x002b], sigAlgs: [] });
  const extOnly = createHash("sha256").update("002b").digest("hex").slice(0, 12);
  ok("JA4 extension hash has no trailing underscore without sig-algs", ja4(ch).split("_")[2] === extOnly);
}
{
  const base = CH({ tlsRecordVersion: 0x0303, handshakeVersion: 0x0303, supportedVersionMax: 0x0304,
    ciphers: [0x1301], extensions: [0x002b, 0x000d], sigAlgs: [0x0403, 0x0804] });
  const greased = CH({ ...base, sigAlgs: [0x0a0a, 0x0403, 0x1a1a, 0x0804] });
  ok("JA4 ignores GREASE inside signature algorithms", ja4(base) === ja4(greased));
}
{
  const code = (bytes: number[]) => ja4(CH({ tlsRecordVersion: 0x0303, handshakeVersion: 0x0303,
    supportedVersionMax: 0x0304, alpnRaw: [bytes], alpn: [Buffer.from(bytes).toString("latin1")] })).split("_")[0].slice(-2);
  const vectors: Array<[number[], string]> = [
    [[0xab], "ab"], [[0x20], "20"], [[0xab, 0xcd], "ad"], [[0x20, 0x61], "21"],
    [[0x30, 0xab], "3b"], [[0x61, 0x20], "60"], [[0x30, 0x31, 0xab, 0xcd], "3d"],
    [[0x30, 0xab, 0xcd, 0x31], "01"], [[0x78], "xx"],
  ];
  ok("JA4 ALPN hex fallback matches every official example", vectors.every(([bytes, want]) => code(bytes) === want));
}
ok("JA4 version fallback uses TLS record protocol version, not ClientHello legacy version",
  ja4(CH({ tlsRecordVersion: 0x0303, handshakeVersion: 0x0301, ciphers: [0x1301] })).startsWith("t12"));

// ---- parser round-trip (build a real ClientHello, parse it) ---------------
function u16(n: number) { return [(n >> 8) & 0xff, n & 0xff]; }
function ext(type: number, body: number[]) { return [...u16(type), ...u16(body.length), ...body]; }
function buildHello(): Buffer {
  const ciphers = [0x1301, 0x1302, 0xc02b];
  const cipherBytes = ciphers.flatMap(u16);
  const sni = "abc.example";
  const sniBody = [...u16(sni.length + 3), 0x00, ...u16(sni.length), ...[...sni].map((c) => c.charCodeAt(0))];
  const alpnBody = [...u16(3), 2, "h".charCodeAt(0), "2".charCodeAt(0)];
  const svBody = [4, ...u16(0x0304), ...u16(0x0303)];
  const saBody = [...u16(4), ...u16(0x0403), ...u16(0x0804)];
  const grpBody = [...u16(4), ...u16(0x001d), ...u16(0x0017)];
  const pfBody = [1, 0x00];
  const exts = [
    ...ext(0x0000, sniBody), ...ext(0x0010, alpnBody), ...ext(0x002b, svBody),
    ...ext(0x000d, saBody), ...ext(0x000a, grpBody), ...ext(0x000b, pfBody),
  ];
  const body = [
    ...u16(0x0303), ...new Array(32).fill(0), 0,                 // version, random, sid=0
    ...u16(cipherBytes.length), ...cipherBytes, 1, 0,            // ciphers, comp
    ...u16(exts.length), ...exts,
  ];
  const hs = [0x01, (body.length >> 16) & 0xff, (body.length >> 8) & 0xff, body.length & 0xff, ...body];
  const rec = [0x16, ...u16(0x0301), ...u16(hs.length), ...hs];
  return Buffer.from(rec);
}
{
  const buf = buildHello();
  const ch = parseClientHello(buf);
  ok("parser: not null", !!ch);
  ok("parser: ciphers", !!ch && ch.ciphers.join(",") === "4865,4866,49195");
  ok("parser: sni", !!ch && ch.sni === "abc.example");
  ok("parser: alpn", !!ch && ch.alpn.join(",") === "h2");
  ok("parser: supportedVersionMax = 0x0304", !!ch && ch.supportedVersionMax === 0x0304);
  ok("parser: sigAlgs", !!ch && ch.sigAlgs.join(",") === "1027,2052");
  ok("parser: curves (ext 0x000a)", !!ch && ch.curves.join(",") === "29,23");
  ok("parser: pointFormats (ext 0x000b)", !!ch && ch.pointFormats.join(",") === "0");
  ok("fingerprintFromClientHello returns ja4+ja3+ja3String", !!fingerprintFromClientHello(buf)?.ja4 && !!fingerprintFromClientHello(buf)?.ja3String);
}

// ---- fuzz / bounds: never throw on hostile input --------------------------
ok("non-TLS bytes → null", parseClientHello(Buffer.from("GET / HTTP/1.1\r\n\r\n")) === null);
ok("empty buffer → null", parseClientHello(Buffer.from([])) === null);
ok("record-type wrong → null", parseClientHello(Buffer.from([0x17, 3, 3, 0, 5, 1, 2, 3, 4, 5])) === null);
{
  const full = buildHello();
  let threw = false;
  for (let n = 0; n <= full.length; n++) { try { parseClientHello(full.subarray(0, n)); } catch { threw = true; break; } }
  ok("truncation at EVERY length never throws", !threw);
  ok("every proper ClientHello prefix is rejected as incomplete",
    Array.from({ length: full.length }, (_, n) => n).every((n) => parseClientHello(full.subarray(0, n)) === null));
  const badRecordLength = Buffer.from(full);
  badRecordLength.writeUInt16BE(full.readUInt16BE(3) + 1, 3);
  ok("declared TLS record length larger than bytes is incomplete", !clientHelloComplete(badRecordLength));
  ok("declared TLS record length larger than bytes is not parsed", parseClientHello(badRecordLength) === null);
}
{
  // overrun: claim a huge cipher length
  const b = Buffer.from(buildHello());
  b.writeUInt16BE(0xffff, 5 + 4 + 2 + 32 + 1); // cipherLen field → absurd
  let threw = false; try { parseClientHello(b); } catch { threw = true; }
  ok("cipher-length overrun never throws", !threw);
}

// ---- multi-record ClientHello reassembly (Codex v4.3 #8) ------------------
function refragment(single: Buffer, chunk: number): Buffer {
  const ver = [single[1], single[2]]; const hs = single.subarray(5); const out: number[] = [];
  for (let i = 0; i < hs.length; i += chunk) { const f = hs.subarray(i, i + chunk); out.push(0x16, ver[0], ver[1], (f.length >> 8) & 0xff, f.length & 0xff, ...f); }
  return Buffer.from(out);
}
{
  const single = buildHello();
  const multi = refragment(single, 40);   // handshake split across many TLS records
  const a = parseClientHello(single), b = parseClientHello(multi);
  ok("multi-record: parses (not null)", !!a && !!b);
  ok("multi-record: same ciphers as single", !!a && !!b && JSON.stringify(a.ciphers) === JSON.stringify(b.ciphers));
  ok("multi-record: same sni", !!a && !!b && a.sni === b.sni);
  ok("multi-record: same curves/sigAlgs", !!a && !!b && JSON.stringify(a.curves) === JSON.stringify(b.curves) && JSON.stringify(a.sigAlgs) === JSON.stringify(b.sigAlgs));
  ok("multi-record: identical JA4", !!a && !!b && ja4(a) === ja4(b));
  ok("clientHelloComplete: true for full multi-record", clientHelloComplete(multi));
  ok("clientHelloComplete: false for truncated multi-record", !clientHelloComplete(multi.subarray(0, multi.length - 25)));
  ok("clientHelloComplete: false for non-TLS", !clientHelloComplete(Buffer.from("GET / HTTP/1.1")));
}

console.log(`\nfp-ja4: ${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
