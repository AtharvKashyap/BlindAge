import { test } from "node:test";
import assert from "node:assert/strict";
import {
  RSABSSA_ALGORITHM, BlindError, os2ip, i2osp, modpow, modinv, bitLength,
  importRsaPublicKey, blind, blindWith, finalize, SALT_LEN,
} from "../../extension/core/rsabssa.js";
import { b64uToBytes, bytesToB64u, utf8 } from "../../extension/core/bytes.js";

const subtle = globalThis.crypto.subtle;

async function makeKeypair() {
  const kp = await subtle.generateKey(
    { name: "RSA-PSS", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-384" },
    true, ["sign", "verify"]
  );
  const spki = new Uint8Array(await subtle.exportKey("spki", kp.publicKey));
  const jwk = await subtle.exportKey("jwk", kp.privateKey);
  return { spkiB64u: bytesToB64u(spki), jwk };
}

// TEST-ONLY: raw RSA blind-sign (m^d mod n) standing in for the issuer.
function testBlindSign(jwk, blinded) {
  const n = os2ip(b64uToBytes(jwk.n));
  const d = os2ip(b64uToBytes(jwk.d));
  const m = os2ip(blinded);
  const s = modpow(m, d, n);
  const modLen = Math.ceil(bitLength(n) / 8);
  return i2osp(s, modLen);
}

test("os2ip/i2osp round trip", () => {
  const b = new Uint8Array([1, 2, 3, 0, 255]);
  assert.deepEqual([...i2osp(os2ip(b), b.length)], [...b]);
});

test("modpow and modinv", () => {
  assert.equal(modpow(4n, 13n, 497n), 445n);
  assert.equal((7n * modinv(7n, 26n)) % 26n, 1n);
});

test("full JS blind protocol round trip verifies", async () => {
  const { spkiB64u, jwk } = await makeKeypair();
  const pub = await importRsaPublicKey(spkiB64u);
  const message = utf8("token-nonce-abc");
  const { blinded, inv } = await blind(pub, message);
  assert.equal(blinded.length, pub.modulusLen);
  const blindSig = testBlindSign(jwk, blinded);
  const sig = await finalize(pub, message, blindSig, inv);
  assert.equal(sig.length, pub.modulusLen);
  // Independently confirm with Web Crypto verify.
  const ok = await subtle.verify(
    { name: "RSA-PSS", saltLength: SALT_LEN }, pub.verifyKey, sig, message
  );
  assert.ok(ok);
});

test("blind produces fresh blinding each call", async () => {
  const { spkiB64u } = await makeKeypair();
  const pub = await importRsaPublicKey(spkiB64u);
  const a = await blind(pub, utf8("m"));
  const b = await blind(pub, utf8("m"));
  assert.notDeepEqual([...a.blinded], [...b.blinded]);
});

test("finalize throws BlindError on a wrong-key signature", async () => {
  const { spkiB64u } = await makeKeypair();
  const { jwk: otherJwk } = await makeKeypair();
  const pub = await importRsaPublicKey(spkiB64u);
  const message = utf8("m");
  const { blinded, inv } = await blind(pub, message);
  const wrongSig = testBlindSign(otherJwk, blinded);
  await assert.rejects(() => finalize(pub, message, wrongSig, inv), BlindError);
});

test("importRsaPublicKey rejects garbage", async () => {
  await assert.rejects(() => importRsaPublicKey("!!!not-spki"), BlindError);
});
