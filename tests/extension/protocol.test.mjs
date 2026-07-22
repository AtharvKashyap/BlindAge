import { test } from "node:test";
import assert from "node:assert/strict";
import {
  AGE_CLAIMS,
  assuranceAtLeast,
  normalizeOrigin,
  validateChallenge,
  selectToken,
  buildPresentation,
  consentSummary,
} from "../../extension/core/protocol.js";

const NOW = Date.parse("2026-07-22T20:00:00Z");

function challenge(overrides = {}) {
  return {
    version: "1.0",
    challenge_id: "11111111-1111-1111-1111-111111111111",
    required_claim: "AGE_OVER_18",
    minimum_assurance_level: "AAL2",
    audience: "example.com",
    challenge: "Y2hhbGxlbmdl",
    issued_at: "2026-07-22T19:59:00Z",
    expires_at: "2026-07-22T20:05:00Z",
    ...overrides,
  };
}

function token(overrides = {}) {
  return {
    version: "1.0",
    claim: "AGE_OVER_18",
    assurance_level: "AAL2",
    epoch: "2026-Q3",
    issuer_id: "did:web:issuer.test",
    issuer_key_id: "dev-AGE_OVER_18-AAL2-2026-Q3",
    nonce: "bm9uY2U",
    signature: "c2ln",
    spent: false,
    ...overrides,
  };
}

test("normalizeOrigin strips scheme/port/path and lowercases", () => {
  assert.equal(normalizeOrigin("https://Example.com:8500/protected"), "example.com");
  assert.equal(normalizeOrigin("localhost"), "localhost");
});

test("assurance ordering", () => {
  assert.ok(assuranceAtLeast("AAL2", "AAL2"));
  assert.ok(assuranceAtLeast("AAL3", "AAL1"));
  assert.ok(!assuranceAtLeast("AAL1", "AAL2"));
});

test("validateChallenge accepts a matching, unexpired challenge", () => {
  assert.deepEqual(validateChallenge(challenge(), "example.com", NOW), { ok: true });
});

test("validateChallenge rejects audience mismatch", () => {
  const r = validateChallenge(challenge({ audience: "evil.com" }), "example.com", NOW);
  assert.equal(r.ok, false);
  assert.match(r.reason, /audience/i);
});

test("validateChallenge rejects expired", () => {
  const late = Date.parse("2026-07-22T20:10:00Z");
  const r = validateChallenge(challenge(), "example.com", late);
  assert.equal(r.ok, false);
  assert.match(r.reason, /expired/i);
});

test("validateChallenge rejects unknown claim and missing fields", () => {
  assert.equal(validateChallenge(challenge({ required_claim: "AGE_OVER_99" }), "example.com", NOW).ok, false);
  assert.equal(validateChallenge({ audience: "example.com" }, "example.com", NOW).ok, false);
});

test("selectToken picks first eligible unspent token", () => {
  const tokens = [
    token({ spent: true, nonce: "spent" }),
    token({ claim: "AGE_OVER_13", nonce: "wrongclaim" }),
    token({ nonce: "good" }),
    token({ nonce: "second" }),
  ];
  assert.equal(selectToken(tokens, challenge()).nonce, "good");
});

test("selectToken returns null when none eligible", () => {
  assert.equal(selectToken([token({ spent: true })], challenge()), null);
  assert.equal(selectToken([token({ assurance_level: "AAL1" })], challenge()), null);
});

test("buildPresentation matches the Python schema shape", () => {
  const p = buildPresentation(token(), challenge(), "2026-07-22T20:01:00Z");
  assert.equal(p.presentation_type, "blindage.age_token");
  assert.equal(p.required_claim, "AGE_OVER_18");
  assert.equal(p.token.nonce, "bm9uY2U");
  assert.ok(!("spent" in p.token), "internal 'spent' flag must not leak into the presentation");
  assert.deepEqual(p.domain_binding, {
    audience: "example.com",
    challenge: "Y2hhbGxlbmdl",
    challenge_id: "11111111-1111-1111-1111-111111111111",
    timestamp: "2026-07-22T20:01:00Z",
  });
});

test("consentSummary lists what the site will and will not receive", () => {
  const s = consentSummary(challenge(), "example.com");
  assert.equal(s.site, "example.com");
  assert.equal(s.claim, "AGE_OVER_18");
  assert.ok(s.willReceive.some((x) => /age/i.test(x)));
  assert.ok(s.willNotReceive.some((x) => /name|birth|identity/i.test(x)));
});
