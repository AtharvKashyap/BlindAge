#!/usr/bin/env python3
"""Fetch the official BBS BLS12-381-SHA-256 fixtures and emit committed JSON.

Downloads the CFRG BBS draft's canonical test fixtures from the
decentralized-identity/bbs-signature repository and normalizes them into
``tests/vectors/bbs_bls12381_sha256.json``. These are the SHA-256 (XMD)
ciphersuite fixtures -- ``BLS12-381-SHA-256`` -- not the SHAKE-256 ones.

The script is committed for reproducibility; the produced JSON is committed
so the conformance tests never need network access. If any download fails or
the upstream layout is unrecognizable, the script exits non-zero WITHOUT
writing anything -- vectors are never fabricated or hand-computed.

Upstream layout (probed 2026-08, default branch ``main``):
    tooling/fixtures/fixture_data/bls12-381-sha-256/
        keypair.json                 -> {"keyPair": {"secretKey", "publicKey"}}
        signature/signature0NN.json  -> {"caseName", "signerKeyPair":
                                          {"secretKey","publicKey"}, "header",
                                          "messages":[...], "signature",
                                          "result": {"valid", "reason"?}}
        proof/proof0NN.json          -> {"caseName", "signerPublicKey",
                                          "signature", "header",
                                          "presentationHeader", "messages":[...],
                                          "disclosedIndexes":[...], "proof",
                                          "result": {"valid", "reason"?}}

Signature/proof files are probed sequentially (signature001, signature002, ...)
until a 404 stops the run. Each case's per-case public key is preserved (some
cases -- e.g. "wrong public key" -- deliberately use a key differing from the
top-level keypair, so dropping it would make the case unreproducible).

All hex strings are kept verbatim from upstream; only field names are remapped.

Usage:
    python scripts/fetch_bbs_vectors.py
"""
from __future__ import annotations

import json
import ssl
import sys
import urllib.error
import urllib.request
from pathlib import Path

RAW_BASE = (
    "https://raw.githubusercontent.com/decentralized-identity/bbs-signature/"
    "main/tooling/fixtures/fixture_data/bls12-381-sha-256"
)


def _ssl_context() -> ssl.SSLContext:
    """Build an SSL context, preferring certifi's CA bundle when available."""
    try:
        import certifi

        return ssl.create_default_context(cafile=certifi.where())
    except Exception:  # noqa: BLE001
        return ssl.create_default_context()


def _fetch_json(path: str, ctx: ssl.SSLContext) -> dict:
    url = f"{RAW_BASE}/{path}"
    with urllib.request.urlopen(url, timeout=60, context=ctx) as resp:  # noqa: S310
        return json.loads(resp.read().decode("utf-8"))


def _fetch_sequence(subdir: str, stem: str, ctx: ssl.SSLContext) -> list[dict]:
    """Fetch subdir/stem001.json, stem002.json, ... until a 404 is hit."""
    out: list[dict] = []
    for i in range(1, 1000):
        path = f"{subdir}/{stem}{i:03d}.json"
        try:
            out.append(_fetch_json(path, ctx))
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                break
            raise
    return out


def build_signatures(raw: list[dict]) -> list[dict]:
    out: list[dict] = []
    for i, r in enumerate(raw, start=1):
        try:
            out.append(
                {
                    "case": r["caseName"],
                    "public_key": r["signerKeyPair"]["publicKey"],
                    "header": r.get("header", ""),
                    "messages": list(r.get("messages", [])),
                    "signature": r["signature"],
                    "valid": bool(r["result"]["valid"]),
                }
            )
        except (KeyError, TypeError) as exc:
            raise SystemExit(
                f"BLOCKED: signature fixture #{i} has unexpected layout: {exc}"
            )
    return out


def build_proofs(raw: list[dict]) -> list[dict]:
    out: list[dict] = []
    for i, r in enumerate(raw, start=1):
        try:
            out.append(
                {
                    "case": r["caseName"],
                    "public_key": r["signerPublicKey"],
                    "header": r.get("header", ""),
                    "presentation_header": r.get("presentationHeader", ""),
                    "messages": list(r.get("messages", [])),
                    "disclosed_indexes": list(r.get("disclosedIndexes", [])),
                    "signature": r["signature"],
                    "proof": r["proof"],
                    "valid": bool(r["result"]["valid"]),
                }
            )
        except (KeyError, TypeError) as exc:
            raise SystemExit(
                f"BLOCKED: proof fixture #{i} has unexpected layout: {exc}"
            )
    return out


def build_vector() -> dict:
    ctx = _ssl_context()

    keypair_raw = _fetch_json("keypair.json", ctx)
    try:
        keypair = {
            "secret_key": keypair_raw["keyPair"]["secretKey"],
            "public_key": keypair_raw["keyPair"]["publicKey"],
        }
    except (KeyError, TypeError) as exc:
        raise SystemExit(f"BLOCKED: keypair.json has unexpected layout: {exc}")

    signatures = build_signatures(_fetch_sequence("signature", "signature", ctx))
    proofs = build_proofs(_fetch_sequence("proof", "proof", ctx))

    return {"keypair": keypair, "signatures": signatures, "proofs": proofs}


def validate(vector: dict) -> None:
    """Sanity-check the normalized shape before writing (no crypto here)."""
    kp = vector["keypair"]
    if len(kp["public_key"]) != 192:  # 96-byte G2 point, hex
        raise SystemExit(
            f"BLOCKED: public key is {len(kp['public_key'])} hex chars, expected 192"
        )
    if len(kp["secret_key"]) != 64:  # 32-byte scalar, hex
        raise SystemExit(
            f"BLOCKED: secret key is {len(kp['secret_key'])} hex chars, expected 64"
        )

    sigs = vector["signatures"]
    if len(sigs) < 5:
        raise SystemExit(f"BLOCKED: only {len(sigs)} signature cases, expected >= 5")
    if not any(c["valid"] for c in sigs):
        raise SystemExit("BLOCKED: no valid signature cases found")
    if not any(not c["valid"] for c in sigs):
        raise SystemExit("BLOCKED: no invalid signature cases found")

    proofs = vector["proofs"]
    if len(proofs) < 5:
        raise SystemExit(f"BLOCKED: only {len(proofs)} proof cases, expected >= 5")
    if not any(c["valid"] for c in proofs):
        raise SystemExit("BLOCKED: no valid proof cases found")

    # Every hex string must be even-length and decode as hex.
    def _check_hex(label: str, val: str) -> None:
        if len(val) % 2 != 0:
            raise SystemExit(f"BLOCKED: field '{label}' has odd-length hex")
        bytes.fromhex(val)

    _check_hex("keypair.secret_key", kp["secret_key"])
    _check_hex("keypair.public_key", kp["public_key"])
    for c in sigs:
        _check_hex(f"signature[{c['case']}].signature", c["signature"])
        _check_hex(f"signature[{c['case']}].public_key", c["public_key"])
        for m in c["messages"]:
            _check_hex(f"signature[{c['case']}].message", m)
    for c in proofs:
        _check_hex(f"proof[{c['case']}].proof", c["proof"])
        _check_hex(f"proof[{c['case']}].signature", c["signature"])
        _check_hex(f"proof[{c['case']}].public_key", c["public_key"])
        for m in c["messages"]:
            _check_hex(f"proof[{c['case']}].message", m)


def main() -> int:
    try:
        vector = build_vector()
    except SystemExit:
        raise
    except Exception as exc:  # noqa: BLE001
        print(f"BLOCKED: could not fetch BBS fixtures: {exc}", file=sys.stderr)
        return 1

    validate(vector)

    out_path = (
        Path(__file__).resolve().parents[1]
        / "tests"
        / "vectors"
        / "bbs_bls12381_sha256.json"
    )
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(vector, indent=2) + "\n")
    print(
        f"Wrote {out_path} "
        f"({len(vector['signatures'])} signature cases, "
        f"{len(vector['proofs'])} proof cases)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
