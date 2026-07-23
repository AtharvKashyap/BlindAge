// extension/core/mint.js
import { importRsaPublicKey, blind, finalize } from "./rsabssa.js";
import { b64uToBytes, bytesToB64u, utf8 } from "./bytes.js";

export class MintError extends Error {}

export function tokenMessage(nonce) {
  return utf8(nonce);
}

export function findTokenKey(wellKnown, claim, assuranceLevel, epoch) {
  for (const key of (wellKnown && wellKnown.keys) || []) {
    if (
      key.purpose === "token_signing" &&
      key.claim === claim &&
      key.assurance_level === assuranceLevel &&
      key.epoch === epoch
    ) return key;
  }
  return null;
}

export function randomNonce() {
  const b = new Uint8Array(32);
  globalThis.crypto.getRandomValues(b);
  return bytesToB64u(b);
}

export async function prepareBlindBatch(pub, count) {
  const nonces = [];
  const invs = [];
  const blindedB64u = [];
  for (let i = 0; i < count; i++) {
    const nonce = randomNonce();
    const { blinded, inv } = await blind(pub, tokenMessage(nonce));
    nonces.push(nonce);
    invs.push(inv);
    blindedB64u.push(bytesToB64u(blinded));
  }
  return { nonces, invs, blindedB64u };
}

export async function assembleTokens({
  pub, nonces, invs, signaturesB64u, claim, assuranceLevel, epoch, issuerId, keyId,
}) {
  if (signaturesB64u.length !== nonces.length || invs.length !== nonces.length) {
    throw new MintError("signature/nonce count mismatch");
  }
  const tokens = [];
  for (let i = 0; i < nonces.length; i++) {
    let sig;
    try {
      sig = await finalize(pub, tokenMessage(nonces[i]), b64uToBytes(signaturesB64u[i]), invs[i]);
    } catch (e) {
      throw new MintError("finalize failed: " + e.message);
    }
    tokens.push({
      version: "1.0", claim, assurance_level: assuranceLevel, epoch,
      issuer_id: issuerId, issuer_key_id: keyId,
      nonce: nonces[i], signature: bytesToB64u(sig),
    });
  }
  return tokens;
}
