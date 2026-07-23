// tests/extension/rsabssa_vectors.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import {
  os2ip, i2osp, modinv, bitLength, emsaPssEncode, blindWith, finalize,
} from "../../extension/core/rsabssa.js";
import { bytesToB64u } from "../../extension/core/bytes.js";

const subtle = globalThis.crypto.subtle;
const V = JSON.parse(
  readFileSync(new URL("../vectors/rfc9474_deterministic.json", import.meta.url))
);
const hex = (name) => Uint8Array.from(V[name].match(/../g).map((h) => parseInt(h, 16)));
const bigHex = (name) => BigInt("0x" + V[name]);

async function pubFromVector() {
  const n = bigHex("n");
  const e = bigHex("e");
  const jwk = { kty: "RSA", n: bytesToB64u(hex("n")), e: bytesToB64u(hex("e")), ext: true };
  const verifyKey = await subtle.importKey(
    "jwk", jwk, { name: "RSA-PSS", hash: "SHA-384" }, true, ["verify"]
  );
  return { n, e, modulusLen: Math.ceil(bitLength(n) / 8), verifyKey };
}

test("EMSA-PSS encode matches the RFC vector", async () => {
  const pub = await pubFromVector();
  const encoded = await emsaPssEncode(hex("msg"), bitLength(pub.n) - 1, hex("salt"));
  assert.deepEqual([...encoded], [...hex("encoded_msg")]);
});

test("blindWith reproduces the RFC blinded_msg and inv", async () => {
  const pub = await pubFromVector();
  const inv = bigHex("inv");
  const r = modinv(inv, pub.n);
  const { blinded, inv: gotInv } = await blindWith(pub, hex("msg"), hex("salt"), r);
  assert.deepEqual([...blinded], [...hex("blinded_msg")]);
  assert.equal(gotInv, inv);
});

test("finalize reproduces the RFC signature and verifies", async () => {
  const pub = await pubFromVector();
  const sig = await finalize(pub, hex("msg"), hex("blind_sig"), bigHex("inv"));
  assert.deepEqual([...sig], [...hex("sig")]);
});
