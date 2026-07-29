import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import {
  RegistryError, canonicalJsonBytes, verifyRegistry,
  TOPUP_THRESHOLD, approvedIssuers, isRollback, registryKeyFor, topUpPlan,
} from "../../extension/core/registry.js";

const V = JSON.parse(
  readFileSync(new URL("../vectors/registry_signing.json", import.meta.url))
);
const toHex = (bytes) => [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");

test("canonicalJsonBytes matches the Python reference byte-for-byte", () => {
  assert.equal(toHex(canonicalJsonBytes(V.registry)), V.canonical_hex);
});

test("verifyRegistry accepts the vector (any JSON spacing)", async () => {
  const text = JSON.stringify(V.registry, null, 2); // non-canonical spacing on purpose
  const registry = await verifyRegistry(text, V.signature_b64, V.root_public_key_b64);
  assert.equal(registry.issuers[0].issuer_id, "did:web:issuer.test");
});

test("verifyRegistry rejects a tampered registry", async () => {
  const tampered = structuredClone(V.registry);
  tampered.issuers[0].status = "revoked";
  await assert.rejects(
    () => verifyRegistry(JSON.stringify(tampered), V.signature_b64, V.root_public_key_b64),
    RegistryError,
  );
});

test("verifyRegistry rejects a corrupted signature and malformed inputs", async () => {
  const sig = V.signature_b64.replace(/^./, (c) => (c === "A" ? "B" : "A"));
  await assert.rejects(
    () => verifyRegistry(JSON.stringify(V.registry), sig, V.root_public_key_b64),
    RegistryError,
  );
  await assert.rejects(
    () => verifyRegistry("{not json", V.signature_b64, V.root_public_key_b64),
    RegistryError,
  );
  await assert.rejects(
    () => verifyRegistry(JSON.stringify(V.registry), V.signature_b64, "!!bad-key"),
    RegistryError,
  );
});

const NOW = "2026-07-29T12:00:00Z";
const issuer = (over = {}) => ({
  issuer_id: "did:web:issuer.test", status: "active",
  valid_from: "2026-01-01T00:00:00Z", valid_until: "2027-01-01T00:00:00Z",
  keys: [{
    key_id: "k1", purpose: "token_signing", algorithm: "rsabssa-sha384-pss-deterministic",
    public_key: "pub1", claim: "AGE_OVER_18", assurance_level: "AAL2", epoch: "2026-Q3",
  }],
  ...over,
});

test("approvedIssuers filters status and validity window", () => {
  const reg = { issuers: [
    issuer(),
    issuer({ issuer_id: "did:web:revoked.test", status: "revoked" }),
    issuer({ issuer_id: "did:web:expired.test", valid_until: "2026-06-01T00:00:00Z" }),
    issuer({ issuer_id: "did:web:future.test", valid_from: "2026-12-01T00:00:00Z" }),
  ] };
  assert.deepEqual(approvedIssuers(reg, NOW).map((i) => i.issuer_id), ["did:web:issuer.test"]);
  assert.deepEqual(approvedIssuers(undefined, NOW), []);
});

test("isRollback rejects older or unparseable generated_at, allows equal/newer", () => {
  assert.equal(isRollback("2026-07-29T00:00:00Z", { generated_at: "2026-07-28T00:00:00Z" }), true);
  assert.equal(isRollback("2026-07-29T00:00:00Z", {}), true);
  assert.equal(isRollback("2026-07-29T00:00:00Z", { generated_at: "2026-07-29T00:00:00Z" }), false);
  assert.equal(isRollback("2026-07-29T00:00:00Z", { generated_at: "2026-07-30T00:00:00Z" }), false);
});

test("registryKeyFor finds only token_signing keys of the right issuer", () => {
  const reg = { issuers: [issuer()] };
  assert.equal(registryKeyFor(reg, "did:web:issuer.test", "k1").public_key, "pub1");
  assert.equal(registryKeyFor(reg, "did:web:issuer.test", "nope"), null);
  assert.equal(registryKeyFor(reg, "did:web:other.test", "k1"), null);
  const regWrongPurpose = { issuers: [issuer({ keys: [{ key_id: "k1", purpose: "registry" }] })] };
  assert.equal(registryKeyFor(regWrongPurpose, "did:web:issuer.test", "k1"), null);
});

test("topUpPlan tops up only issuers below threshold", () => {
  const rec = (id, base) => ({ baseUrl: base, issuerId: id, enrollmentId: "e", enrolledAt: "t" });
  const tok = (id, spent = false) => ({ issuer_id: id, claim: "AGE_OVER_18", spent });
  const issuers = [rec("did:a", "http://a"), rec("did:b", "http://b"), rec("did:c", "http://c")];
  const tokens = [
    tok("did:a"), tok("did:a"),            // at threshold (2) — no top-up
    tok("did:b"), tok("did:b", true),      // 1 unspent — top up
    // did:c has none — top up
  ];
  const plan = topUpPlan(tokens, issuers, { claim: "AGE_OVER_18", threshold: 2, batch: 5 });
  assert.deepEqual(plan.map((p) => [p.issuer.baseUrl, p.count]), [["http://b", 5], ["http://c", 5]]);
  assert.deepEqual(topUpPlan([], [], { claim: "AGE_OVER_18", threshold: 2, batch: 5 }), []);
  assert.equal(TOPUP_THRESHOLD, 2);
});
