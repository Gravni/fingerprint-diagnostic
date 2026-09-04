// Small dependency-free MD5 implementation for protocol fingerprints.
// JA3 specifies MD5, but OpenSSL-backed `crypto.createHash("md5")` can be
// unavailable when Node runs under a FIPS provider. This implementation keeps
// that wire-format requirement independent of the host crypto policy.

const ROTATIONS = [
  7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
  5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
  4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
  6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
];
const CONSTANTS = Array.from({ length: 64 }, (_, i) =>
  Math.floor(Math.abs(Math.sin(i + 1)) * 0x100000000) >>> 0);

const rotateLeft = (value, amount) => (value << amount) | (value >>> (32 - amount));
const byteHex = (value) => value.toString(16).padStart(2, "0");

/** Return the lowercase MD5 digest of a UTF-8 string or exact byte sequence. */
export function md5hex(input) {
  const bytes = typeof input === "string"
    ? new TextEncoder().encode(input)
    : input instanceof Uint8Array ? input : null;
  if (!bytes) throw new TypeError("md5hex input must be a string or Uint8Array");

  const paddedLength = Math.ceil((bytes.length + 9) / 64) * 64;
  const padded = new Uint8Array(paddedLength);
  padded.set(bytes);
  padded[bytes.length] = 0x80;
  const bitLength = bytes.length * 8;
  const low = bitLength >>> 0;
  const high = Math.floor(bitLength / 0x100000000) >>> 0;
  const lengthOffset = paddedLength - 8;
  for (let i = 0; i < 4; i++) {
    padded[lengthOffset + i] = (low >>> (i * 8)) & 0xff;
    padded[lengthOffset + 4 + i] = (high >>> (i * 8)) & 0xff;
  }

  let a0 = 0x67452301;
  let b0 = 0xefcdab89;
  let c0 = 0x98badcfe;
  let d0 = 0x10325476;
  const words = new Uint32Array(16);

  for (let offset = 0; offset < padded.length; offset += 64) {
    for (let i = 0; i < 16; i++) {
      const p = offset + i * 4;
      words[i] = (padded[p] | (padded[p + 1] << 8) | (padded[p + 2] << 16) | (padded[p + 3] << 24)) >>> 0;
    }
    let a = a0, b = b0, c = c0, d = d0;
    for (let i = 0; i < 64; i++) {
      let f, g;
      if (i < 16) { f = (b & c) | (~b & d); g = i; }
      else if (i < 32) { f = (d & b) | (~d & c); g = (5 * i + 1) % 16; }
      else if (i < 48) { f = b ^ c ^ d; g = (3 * i + 5) % 16; }
      else { f = c ^ (b | ~d); g = (7 * i) % 16; }
      const sum = (a + f + CONSTANTS[i] + words[g]) | 0;
      a = d;
      d = c;
      c = b;
      b = (b + rotateLeft(sum, ROTATIONS[i])) | 0;
    }
    a0 = (a0 + a) | 0;
    b0 = (b0 + b) | 0;
    c0 = (c0 + c) | 0;
    d0 = (d0 + d) | 0;
  }

  let out = "";
  for (const word of [a0, b0, c0, d0]) {
    out += byteHex(word & 0xff) + byteHex((word >>> 8) & 0xff)
      + byteHex((word >>> 16) & 0xff) + byteHex((word >>> 24) & 0xff);
  }
  return out;
}
