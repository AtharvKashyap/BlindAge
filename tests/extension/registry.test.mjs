import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import {
  RegistryError, canonicalJsonBytes, verifyRegistry,
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
