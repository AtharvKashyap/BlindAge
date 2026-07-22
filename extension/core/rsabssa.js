// Pure-JS RSABSSA-SHA384-PSS-Deterministic (RFC 9474), ported from
// blindage/crypto/rsabssa.py. SHA-384 + final RSA-PSS verify use Web Crypto;
// blinding arithmetic uses BigInt. Gated by RFC 9474 Appendix A vectors.
// The extension only blinds/unblinds/verifies — never generates keys or signs.
import { b64uToBytes } from "./bytes.js";

export const RSABSSA_ALGORITHM = "rsabssa-sha384-pss-deterministic";
export const SALT_LEN = 48;
const HASH = "SHA-384";
const HASH_LEN = 48;
const subtle = globalThis.crypto.subtle;

export class BlindError extends Error {}

export function os2ip(bytes) {
  let v = 0n;
  for (const b of bytes) v = (v << 8n) | BigInt(b);
  return v;
}
export function i2osp(value, len) {
  const out = new Uint8Array(len);
  let v = value;
  for (let i = len - 1; i >= 0; i--) { out[i] = Number(v & 255n); v >>= 8n; }
  if (v !== 0n) throw new BlindError("integer too large for length");
  return out;
}
export function bitLength(n) {
  return n <= 0n ? 0 : n.toString(2).length;
}
export function modpow(base, exp, mod) {
  let result = 1n;
  let b = base % mod;
  let e = exp;
  while (e > 0n) {
    if (e & 1n) result = (result * b) % mod;
    e >>= 1n;
    b = (b * b) % mod;
  }
  return result;
}
export function modinv(a, m) {
  let [old_r, r] = [((a % m) + m) % m, m];
  let [old_s, s] = [1n, 0n];
  while (r !== 0n) {
    const q = old_r / r;
    [old_r, r] = [r, old_r - q * r];
    [old_s, s] = [s, old_s - q * s];
  }
  if (old_r !== 1n) throw new BlindError("value not invertible");
  return ((old_s % m) + m) % m;
}
function gcd(a, b) { while (b) { [a, b] = [b, a % b]; } return a; }

async function sha384(bytes) {
  return new Uint8Array(await subtle.digest(HASH, bytes));
}

export async function mgf1(seed, maskLen) {
  const out = new Uint8Array(maskLen);
  let counter = 0;
  let pos = 0;
  while (pos < maskLen) {
    const c = new Uint8Array(4);
    new DataView(c.buffer).setUint32(0, counter, false);
    const block = await sha384(concat(seed, c));
    const take = Math.min(HASH_LEN, maskLen - pos);
    out.set(block.subarray(0, take), pos);
    pos += take;
    counter += 1;
  }
  return out;
}
function concat(...arrs) {
  const len = arrs.reduce((n, a) => n + a.length, 0);
  const out = new Uint8Array(len);
  let o = 0;
  for (const a of arrs) { out.set(a, o); o += a.length; }
  return out;
}

export async function emsaPssEncode(message, emBits, salt) {
  const mHash = await sha384(message);
  const emLen = Math.ceil(emBits / 8);
  const sLen = salt.length;
  if (emLen < HASH_LEN + sLen + 2) throw new BlindError("encoding error");
  const mPrime = concat(new Uint8Array(8), mHash, salt);
  const h = await sha384(mPrime);
  const ps = new Uint8Array(emLen - sLen - HASH_LEN - 2);
  const db = concat(ps, new Uint8Array([0x01]), salt);
  const dbMask = await mgf1(h, emLen - HASH_LEN - 1);
  const maskedDb = new Uint8Array(db.length);
  for (let i = 0; i < db.length; i++) maskedDb[i] = db[i] ^ dbMask[i];
  const topBits = 8 * emLen - emBits;
  maskedDb[0] &= 0xff >> topBits;
  return concat(maskedDb, h, new Uint8Array([0xbc]));
}

export async function importRsaPublicKey(spkiB64u) {
  let verifyKey, jwk;
  try {
    const spki = b64uToBytes(spkiB64u);
    verifyKey = await subtle.importKey(
      "spki", spki, { name: "RSA-PSS", hash: HASH }, true, ["verify"]
    );
    jwk = await subtle.exportKey("jwk", verifyKey);
  } catch (e) {
    throw new BlindError("invalid RSA public key: " + e.message);
  }
  const n = os2ip(b64uToBytes(jwk.n));
  const e = os2ip(b64uToBytes(jwk.e));
  return { n, e, modulusLen: Math.ceil(bitLength(n) / 8), verifyKey };
}

export async function blindWith(pub, message, salt, r) {
  const encoded = await emsaPssEncode(message, bitLength(pub.n) - 1, salt);
  const m = os2ip(encoded);
  if (gcd(m, pub.n) !== 1n) throw new BlindError("message not coprime with modulus");
  if (gcd(r, pub.n) !== 1n) throw new BlindError("blinding factor not coprime");
  const inv = modinv(r, pub.n);
  const z = (m * modpow(r, pub.e, pub.n)) % pub.n;
  return { blinded: i2osp(z, pub.modulusLen), inv };
}

function randomBigIntBelow(n) {
  const bytes = new Uint8Array(Math.ceil(bitLength(n) / 8) + 8);
  globalThis.crypto.getRandomValues(bytes);
  return os2ip(bytes) % n;
}

export async function blind(pub, message) {
  const salt = new Uint8Array(SALT_LEN);
  globalThis.crypto.getRandomValues(salt);
  let r;
  do { r = (randomBigIntBelow(pub.n - 1n)) + 1n; } while (gcd(r, pub.n) !== 1n);
  return blindWith(pub, message, salt, r);
}

export async function finalize(pub, message, blindSig, inv) {
  if (blindSig.length !== pub.modulusLen) throw new BlindError("bad blind signature length");
  const z = os2ip(blindSig);
  const s = (z * inv) % pub.n;
  const sig = i2osp(s, pub.modulusLen);
  const ok = await subtle.verify(
    { name: "RSA-PSS", saltLength: SALT_LEN }, pub.verifyKey, sig, message
  );
  if (!ok) throw new BlindError("signature invalid after unblinding");
  return sig;
}
