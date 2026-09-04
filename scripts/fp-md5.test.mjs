// Dependency-free MD5 regression vectors. This test must run in environments
// where OpenSSL/Node may disable MD5 through FIPS policy.
import { md5hex } from "../lib/md5.mjs";

let pass = 0, fail = 0;
function ok(label, cond) { if (cond) pass++; else { fail++; console.log("  ✗ " + label); } }

const vectors = [
  ["", "d41d8cd98f00b204e9800998ecf8427e"],
  ["a", "0cc175b9c0f1b6a831c399e269772661"],
  ["abc", "900150983cd24fb0d6963f7d28e17f72"],
  ["message digest", "f96b697d7cb7938d525a2f31aaf161d0"],
  ["abcdefghijklmnopqrstuvwxyz", "c3fcd3d76192e4007dfb496cca67e13b"],
  ["ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", "d174ab98d277d9f5a5611c2c9f419d9f"],
  ["12345678901234567890123456789012345678901234567890123456789012345678901234567890", "57edf4a22be3c955ac49da2e2107b67a"],
];
ok("MD5 matches all RFC 1321 test-suite vectors", vectors.every(([input, want]) => md5hex(input) === want));
ok("MD5 encodes strings as UTF-8", md5hex("héllo 😀") === "207dd4f0cd7a4f13b4932646cd1f8f2b");

console.log(`\nfp-md5: ${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
