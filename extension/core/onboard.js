// extension/core/onboard.js
// Pure onboarding logic for self-service enrollment (Phase 6). No chrome.* here —
// this module is tested under Node; background.js is the only glue.
import { RSABSSA_ALGORITHM } from "./rsabssa.js";

export const DEFAULT_CLAIM = "AGE_OVER_18";
export const DEFAULT_ASSURANCE = "AAL2";
export const DEFAULT_COUNT = 5;
export const ENROLL_TTL_MS = 10 * 60 * 1000;

export function issuerOrigin(baseUrl) {
  let u;
  try { u = new URL(baseUrl); } catch { throw new Error("invalid issuer URL"); }
  if (u.protocol !== "http:" && u.protocol !== "https:") throw new Error("issuer URL must be http(s)");
  return u.origin;
}

export function validIssuerRecord(rec) {
  if (!rec || typeof rec !== "object") return false;
  for (const f of ["baseUrl", "issuerId", "enrollmentId", "enrolledAt"]) {
    if (typeof rec[f] !== "string" || rec[f].length === 0) return false;
  }
  try { issuerOrigin(rec.baseUrl); } catch { return false; }
  return true;
}

// Fail-closed gate for the enrollment handoff: only a pending, unexpired enroll
// whose issuer origin matches the sending page may deliver an enrollment_id.
export function matchPendingEnroll(pending, senderOrigin, msg, nowMs) {
  if (!pending) return { ok: false, reason: "no enrollment in progress" };
  if (typeof pending.createdAt !== "number" || nowMs - pending.createdAt > ENROLL_TTL_MS) {
    return { ok: false, reason: "enrollment expired — start again from the popup" };
  }
  let expected;
  try { expected = issuerOrigin(pending.issuer); } catch {
    return { ok: false, reason: "invalid pending issuer" };
  }
  if (senderOrigin !== expected) return { ok: false, reason: "message origin does not match issuer" };
  if (typeof msg.enrollment_id !== "string" || msg.enrollment_id.length === 0) {
    return { ok: false, reason: "missing enrollment id" };
  }
  if (typeof msg.issuer_id !== "string" || msg.issuer_id.length === 0) {
    return { ok: false, reason: "missing issuer id" };
  }
  return { ok: true };
}

// Among token_signing rsabssa keys matching claim+assurance, pick the highest
// epoch string (epochs are YYYY-Qn, so lexicographic order is chronological).
export function pickLatestKey(wellKnown, claim, assuranceLevel) {
  let best = null;
  for (const key of (wellKnown && wellKnown.keys) || []) {
    if (key.purpose !== "token_signing") continue;
    if (key.claim !== claim || key.assurance_level !== assuranceLevel) continue;
    if (key.algorithm !== RSABSSA_ALGORITHM) continue;
    if (typeof key.epoch !== "string") continue;
    if (!best || key.epoch > best.epoch) best = key;
  }
  return best;
}
