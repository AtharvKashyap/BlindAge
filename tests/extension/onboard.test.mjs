// tests/extension/onboard.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  DEFAULT_CLAIM, DEFAULT_ASSURANCE, DEFAULT_COUNT, ENROLL_TTL_MS,
  issuerOrigin, validIssuerRecord, matchPendingEnroll, pickLatestKey,
} from "../../extension/core/onboard.js";

const RSABSSA = "rsabssa-sha384-pss-deterministic";
const REC = {
  baseUrl: "http://localhost:8400", issuerId: "did:web:issuer.test",
  enrollmentId: "e-1", enrolledAt: "2026-07-23T00:00:00Z",
};
const PENDING = { issuer: "http://localhost:8400", issuerId: "did:web:issuer.test", createdAt: 1000 };
const MSG = { issuer_id: "did:web:issuer.test", enrollment_id: "e-1" };

test("issuerOrigin normalizes and rejects garbage", () => {
  assert.equal(issuerOrigin("http://localhost:8400/x"), "http://localhost:8400");
  assert.throws(() => issuerOrigin("not a url"), Error);
  assert.throws(() => issuerOrigin("ftp://x"), Error);
});

test("validIssuerRecord accepts a full record and rejects broken ones", () => {
  assert.equal(validIssuerRecord(REC), true);
  assert.equal(validIssuerRecord(null), false);
  assert.equal(validIssuerRecord({ ...REC, enrollmentId: "" }), false);
  assert.equal(validIssuerRecord({ ...REC, issuerId: 7 }), false);
  assert.equal(validIssuerRecord({ ...REC, baseUrl: "nope" }), false);
});

test("matchPendingEnroll accepts the matching origin within TTL", () => {
  assert.deepEqual(matchPendingEnroll(PENDING, "http://localhost:8400", MSG, 2000), { ok: true });
});

test("matchPendingEnroll fails closed", () => {
  assert.equal(matchPendingEnroll(null, "http://localhost:8400", MSG, 2000).ok, false);
  assert.equal( // expired
    matchPendingEnroll(PENDING, "http://localhost:8400", MSG, 1000 + ENROLL_TTL_MS + 1).ok, false);
  assert.equal( // wrong origin
    matchPendingEnroll(PENDING, "http://evil.localhost:8400", MSG, 2000).ok, false);
  assert.equal( // missing enrollment id
    matchPendingEnroll(PENDING, "http://localhost:8400", { ...MSG, enrollment_id: "" }, 2000).ok, false);
  assert.equal( // missing issuer id
    matchPendingEnroll(PENDING, "http://localhost:8400", { ...MSG, issuer_id: undefined }, 2000).ok, false);
});

test("pickLatestKey picks the highest epoch among matching rsabssa keys", () => {
  const k = (epoch, over = { claim: DEFAULT_CLAIM, assurance_level: DEFAULT_ASSURANCE, algorithm: RSABSSA, purpose: "token_signing" }) =>
    ({ key_id: "k-" + epoch, epoch, ...over });
  const wk = { keys: [
    k("2026-Q2"),
    k("2026-Q3"),
    k("2026-Q4", { claim: "AGE_OVER_21", assurance_level: DEFAULT_ASSURANCE, algorithm: RSABSSA, purpose: "token_signing" }),
    k("2026-Q4", { claim: DEFAULT_CLAIM, assurance_level: DEFAULT_ASSURANCE, algorithm: "ed25519", purpose: "token_signing" }),
    k("2026-Q4", { claim: DEFAULT_CLAIM, assurance_level: DEFAULT_ASSURANCE, algorithm: RSABSSA, purpose: "registry" }),
  ] };
  assert.equal(pickLatestKey(wk, DEFAULT_CLAIM, DEFAULT_ASSURANCE).key_id, "k-2026-Q3");
  assert.equal(pickLatestKey({ keys: [] }, DEFAULT_CLAIM, DEFAULT_ASSURANCE), null);
  assert.equal(pickLatestKey(undefined, DEFAULT_CLAIM, DEFAULT_ASSURANCE), null);
});

test("defaults are the spec values", () => {
  assert.equal(DEFAULT_CLAIM, "AGE_OVER_18");
  assert.equal(DEFAULT_ASSURANCE, "AAL2");
  assert.equal(DEFAULT_COUNT, 5);
  assert.equal(ENROLL_TTL_MS, 10 * 60 * 1000);
});
