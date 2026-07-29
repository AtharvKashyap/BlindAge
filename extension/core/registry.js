// Registry trust logic for the extension (Phase 8). Ed25519 verification goes
// through Web Crypto (reviewed primitive); only JSON canonicalization is
// hand-written, gated byte-for-byte by tests/vectors/registry_signing.json.
import { b64uToBytes, utf8 } from "./bytes.js";

const subtle = globalThis.crypto.subtle;

export class RegistryError extends Error {}

// Byte-for-byte port of blindage/canonical.py canonical_json_bytes:
// sort_keys=True, separators=(",",":"), ensure_ascii=False, UTF-8.
// NOTE: Python sorts keys by Unicode code point; JS sort() compares UTF-16
// code units — identical for ASCII keys, which is all the registry uses.
function canonicalString(value) {
  if (value === null || typeof value === "number" || typeof value === "boolean"
      || typeof value === "string") {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return "[" + value.map(canonicalString).join(",") + "]";
  }
  if (typeof value === "object") {
    const keys = Object.keys(value).sort();
    return "{" + keys.map((k) => JSON.stringify(k) + ":" + canonicalString(value[k])).join(",") + "}";
  }
  throw new RegistryError("unsupported value in canonical JSON");
}

export function canonicalJsonBytes(value) {
  return utf8(canonicalString(value));
}

export async function verifyRegistry(registryText, sigB64u, rootKeyB64u) {
  let registry;
  try {
    registry = JSON.parse(registryText);
  } catch {
    throw new RegistryError("malformed registry JSON");
  }
  if (!registry || typeof registry !== "object" || Array.isArray(registry)) {
    throw new RegistryError("registry must be a JSON object");
  }
  let key;
  try {
    key = await subtle.importKey(
      "raw", b64uToBytes(rootKeyB64u), { name: "Ed25519" }, false, ["verify"]
    );
  } catch (e) {
    throw new RegistryError("invalid root public key: " + e.message);
  }
  let ok = false;
  try {
    ok = await subtle.verify(
      "Ed25519", key, b64uToBytes(sigB64u), canonicalJsonBytes(registry)
    );
  } catch {
    ok = false;
  }
  if (!ok) throw new RegistryError("registry signature verification failed");
  return registry;
}
