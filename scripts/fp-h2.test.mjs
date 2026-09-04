import { createHash } from "node:crypto";
import http2 from "node:http2";
import net from "node:net";
import { parseInitialH2Settings, H2PrefaceObserver, analyzeH2RawHeaders } from "../lib/h2-observe.mjs";

let pass = 0, fail = 0;
function ok(label, cond) { if (cond) pass++; else { fail++; console.log("  ✗ " + label); } }

const PREFACE = Buffer.from("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", "ascii");
function frame(type, flags, streamId, payload = Buffer.alloc(0)) {
  const out = Buffer.alloc(9 + payload.length);
  out.writeUIntBE(payload.length, 0, 3); out[3] = type; out[4] = flags;
  out.writeUInt32BE(streamId & 0x7fffffff, 5); payload.copy(out, 9);
  return out;
}
function settings(items, flags = 0, streamId = 0) {
  const payload = Buffer.alloc(items.length * 6);
  items.forEach(([id, value], i) => { payload.writeUInt16BE(id, i * 6); payload.writeUInt32BE(value, i * 6 + 2); });
  return Buffer.concat([PREFACE, frame(0x4, flags, streamId, payload)]);
}

{
  const wire = settings([[1, 65536], [2, 0], [4, 6291456], [0xf0f0, 7], [1, 32768]]);
  const r = parseInitialH2Settings(wire);
  ok("valid preface + SETTINGS parses", r.status === "complete");
  ok("SETTINGS wire order, unknown IDs and duplicates are preserved",
    r.settings.map((x) => x.id).join(",") === "1,2,4,61680,1" && r.settings[3].name === null);
  ok("effective SETTINGS uses the final duplicate value", r.effective.headerTableSize === 32768);
  ok("SETTINGS payload SHA-256 is exact", r.payloadSha256 === createHash("sha256").update(wire.subarray(PREFACE.length + 9)).digest("hex"));
  ok("SETTINGS payload bytes are retained for independent hash verification",
    r.payloadHex === wire.subarray(PREFACE.length + 9).toString("hex"));
}
{
  const wire = settings([[1, 4096], [3, 100], [4, 65535], [6, 262144]]);
  let every = true;
  for (let split = 1; split < wire.length; split++) {
    const o = new H2PrefaceObserver();
    const a = o.push(wire.subarray(0, split));
    const b = o.push(wire.subarray(split));
    if (a.status !== "incomplete" || b.status !== "complete") { every = false; break; }
  }
  ok("observer handles every two-chunk boundary", every);
}
ok("partial preface is incomplete", parseInitialH2Settings(PREFACE.subarray(0, 10)).status === "incomplete");
ok("wrong preface is invalid", parseInitialH2Settings(Buffer.from("GET / HTTP/1.1\r\n\r\n")).status === "invalid");
ok("first frame must be SETTINGS", parseInitialH2Settings(Buffer.concat([PREFACE, frame(0x8, 0, 0, Buffer.alloc(4))])).status === "invalid");
ok("initial SETTINGS must be stream zero", parseInitialH2Settings(settings([[1, 1]], 0, 1)).status === "invalid");
ok("initial SETTINGS ACK is invalid", parseInitialH2Settings(settings([], 0x1, 0)).status === "invalid");
{
  const bad = Buffer.concat([PREFACE, frame(0x4, 0, 0, Buffer.from([0, 1, 0, 0, 0]))]);
  ok("SETTINGS payload length must be divisible by six", parseInitialH2Settings(bad).status === "invalid");
}
{
  const header = Buffer.alloc(9); header.writeUIntBE(16385, 0, 3); header[3] = 4;
  ok("oversized initial SETTINGS frame is invalid before allocation", parseInitialH2Settings(Buffer.concat([PREFACE, header])).status === "invalid");
}
{
  const wire = settings([[1, 4096]]);
  const plus = Buffer.concat([wire, frame(0x8, 0, 0, Buffer.from([0, 1, 0, 0]))]);
  const r = parseInitialH2Settings(plus);
  ok("extra frames in same chunk do not alter initial SETTINGS", r.status === "complete" && r.consumed === wire.length);
}
{
  const raw = [":method", "GET", ":authority", "capture.example", ":scheme", "https", ":path", "/?token=x", "user-agent", "Chrome", "accept", "*/*"];
  const r = analyzeH2RawHeaders(raw);
  ok("native rawHeaders preserve pseudo-header order", r.status === "valid" && r.pseudoHeaderOrder.join(",") === ":method,:authority,:scheme,:path");
  ok("all regular and pseudo header values are retained", r.headersTyped.length === raw.length / 2 && r.headersTyped[4].value === "Chrome");
}
ok("pseudo-header after a regular header is malformed",
  analyzeH2RawHeaders([":method", "GET", "x", "1", ":path", "/", ":scheme", "https", ":authority", "x"]).status === "invalid");
ok("duplicate pseudo-header is malformed",
  analyzeH2RawHeaders([":method", "GET", ":method", "POST", ":scheme", "https", ":path", "/", ":authority", "x"]).status === "invalid");
ok("unknown pseudo-header is malformed",
  analyzeH2RawHeaders([":method", "GET", ":wat", "x", ":scheme", "https", ":path", "/", ":authority", "x"]).status === "invalid");
ok("normal request requires method/scheme/path/authority",
  analyzeH2RawHeaders([":method", "GET", ":path", "/"]).status === "invalid");
ok("odd rawHeaders list is malformed", analyzeH2RawHeaders([":method"]).status === "invalid");

// Real Node h2c integration: peek the preface before handing the socket to
// Node/nghttp2, restore every byte with unshift(), then use rawHeaders for the
// decoded order. This is the same boundary used after TLS in capture-server.
{
  const server = net.createServer();
  let observed = null, analyzed = null;
  server.on("connection", (socket) => {
    const observer = new H2PrefaceObserver();
    const chunks = []; let total = 0;
    const onData = (chunk) => {
      chunks.push(chunk); total += chunk.length;
      const result = observer.push(chunk);
      if (result.status === "incomplete") return;
      observed = result;
      socket.removeListener("data", onData);
      if (result.status !== "complete") { socket.destroy(); return; }
      socket.pause(); socket.unshift(Buffer.concat(chunks, total));
      const session = http2.performServerHandshake(socket);
      session.on("error", () => {});
      session.on("stream", (stream, _headers, _flags, rawHeaders) => {
        analyzed = analyzeH2RawHeaders(rawHeaders);
        stream.respond({ ":status": 204 }); stream.end();
      });
      process.nextTick(() => socket.resume());
    };
    socket.on("data", onData);
  });
  await new Promise((resolve, reject) => server.listen(0, "127.0.0.1", (e) => e ? reject(e) : resolve()));
  const address = server.address();
  const client = http2.connect(`http://127.0.0.1:${address.port}`, { settings: { headerTableSize: 8192, initialWindowSize: 1_000_000 } });
  await new Promise((resolve, reject) => {
    client.on("error", reject);
    const req = client.request({ ":method": "GET", ":authority": `127.0.0.1:${address.port}`, ":scheme": "http", ":path": "/", "x-probe": "one" });
    req.on("response", () => {}); req.on("end", resolve); req.on("error", reject); req.end(); req.resume();
  });
  client.close();
  await new Promise((resolve) => server.close(resolve));
  ok("pre-handshake peek observes real Node client SETTINGS", observed?.status === "complete" && observed.settings.length > 0);
  ok("real Node stream rawHeaders yields a valid ordered pseudo-header list", analyzed?.status === "valid" && analyzed.pseudoHeaderOrder.join(",") === ":method,:authority,:scheme,:path");
}

console.log(`\nfp-h2: ${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
