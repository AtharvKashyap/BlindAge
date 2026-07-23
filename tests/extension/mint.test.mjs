// tests/extension/mint.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  tokenMessage, findTokenKey, randomNonce, prepareBlindBatch, assembleTokens, MintError,
} from "../../extension/core/mint.js";
import { importRsaPublicKey, os2ip, i2osp, modpow, bitLength } from "../../extension/core/rsabssa.js";
import { b64uToBytes, bytesToB64u } from "../../extension/core/bytes.js";

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
function rawBlindSign(jwk, blindedB64u) {
  const n = os2ip(b64uToBytes(jwk.n)), d = os2ip(b64uToBytes(jwk.d));
  const s = modpow(os2ip(b64uToBytes(blindedB64u)), d, n);
  return bytesToB64u(i2osp(s, Math.ceil(bitLength(n) / 8)));
}

test("tokenMessage is the utf-8 of the nonce", () => {
  assert.deepEqual([...tokenMessage("abc")], [...new TextEncoder().encode("abc")]);
});

test("findTokenKey matches the tuple", () => {
  const wk = { keys: [
    { key_id: "k1", purpose: "token_signing", algorithm: "rsabssa-sha384-pss-deterministic",
      public_key: "pk", claim: "AGE_OVER_18", assurance_level: "AAL2", epoch: "2026-Q3" },
  ] };
  assert.equal(findTokenKey(wk, "AGE_OVER_18", "AAL2", "2026-Q3").key_id, "k1");
  assert.equal(findTokenKey(wk, "AGE_OVER_21", "AAL2", "2026-Q3"), null);
});

test("randomNonce is fresh 32-byte base64url", () => {
  const a = randomNonce(), b = randomNonce();
  assert.notEqual(a, b);
  assert.equal(b64uToBytes(a).length, 32);
});

test("prepare + assemble yields verifiable tokens (full round trip)", async () => {
  const { spkiB64u, jwk } = await makeKeypair();
  const pub = await importRsaPublicKey(spkiB64u);
  const { nonces, invs, blindedB64u } = await prepareBlindBatch(pub, 3);
  assert.equal(nonces.length, 3);
  const signaturesB64u = blindedB64u.map((b) => rawBlindSign(jwk, b));
  const tokens = await assembleTokens({
    pub, nonces, invs, signaturesB64u, claim: "AGE_OVER_18",
    assuranceLevel: "AAL2", epoch: "2026-Q3", issuerId: "did:web:issuer.test", keyId: "k1",
  });
  assert.equal(tokens.length, 3);
  for (const t of tokens) {
    assert.equal(t.claim, "AGE_OVER_18");
    assert.ok(nonces.includes(t.nonce));
    assert.equal(b64uToBytes(t.signature).length, pub.modulusLen);
  }
});

test("assembleTokens throws on count mismatch", async () => {
  const { spkiB64u } = await makeKeypair();
  const pub = await importRsaPublicKey(spkiB64u);
  const { nonces, invs } = await prepareBlindBatch(pub, 2);
  await assert.rejects(() => assembleTokens({
    pub, nonces, invs, signaturesB64u: ["only-one"], claim: "AGE_OVER_18",
    assuranceLevel: "AAL2", epoch: "2026-Q3", issuerId: "i", keyId: "k",
  }), MintError);
});
