import { test } from "node:test";
import assert from "node:assert/strict";
import { mergeTokens, approveRequest } from "../../extension/core/store.js";

function token(nonce, overrides = {}) {
  return {
    version: "1.0", claim: "AGE_OVER_18", assurance_level: "AAL2", epoch: "2026-Q3",
    issuer_id: "did:web:issuer.test", issuer_key_id: "dev-AGE_OVER_18-AAL2-2026-Q3",
    nonce, signature: "sig-" + nonce, spent: false, ...overrides,
  };
}
function challenge() {
  return {
    version: "1.0", challenge_id: "cid", required_claim: "AGE_OVER_18",
    minimum_assurance_level: "AAL2", audience: "example.com", challenge: "chal",
    issued_at: "2026-07-22T19:59:00Z", expires_at: "2026-07-22T20:05:00Z",
  };
}

test("mergeTokens dedupes by nonce", () => {
  const { tokens, added } = mergeTokens([token("a")], [token("a"), token("b")]);
  assert.equal(tokens.length, 2);
  assert.equal(added, 1);
});

test("approveRequest builds a presentation and marks the token spent", () => {
  const tokens = [token("x")];
  const r = approveRequest(tokens, challenge(), "2026-07-22T20:01:00Z");
  assert.equal(r.presentation.token.nonce, "x");
  assert.ok(!("spent" in r.presentation.token));
  const spent = r.tokens.find((t) => t.nonce === "x");
  assert.equal(spent.spent, true);
});

test("approveRequest returns error when no eligible token", () => {
  const r = approveRequest([token("x", { spent: true })], challenge(), "2026-07-22T20:01:00Z");
  assert.ok(r.error);
  assert.ok(!r.presentation);
});

test("approveRequest does not spend a token when it errors", () => {
  const tokens = [token("x", { claim: "AGE_OVER_13" }), token("y", { spent: true })];
  const before = tokens.map((t) => ({ nonce: t.nonce, spent: t.spent }));
  const r = approveRequest(tokens, challenge(), "2026-07-22T20:01:00Z");
  assert.ok(r.error);
  assert.equal(r.presentation, undefined);
  assert.equal(r.tokens, undefined);
  const after = tokens.map((t) => ({ nonce: t.nonce, spent: t.spent }));
  assert.deepEqual(after, before);
});
