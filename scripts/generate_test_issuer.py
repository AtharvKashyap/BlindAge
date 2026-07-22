"""Generate dev issuer keys + signed registry under config/dev/. Dev only.

config/dev/ is gitignored; in mock mode the registry 'public_key' IS the HMAC
secret (Phase 1 only, closed by Phase 3 blind signatures).
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))  # robust against editable-install .pth quirks

import argparse
import json
import secrets

from blindage.crypto import b64u_encode, generate_token_keypair
from blindage.registry import generate_root_keypair, sign_registry

CLAIMS = ["AGE_OVER_13", "AGE_OVER_16", "AGE_OVER_18", "AGE_OVER_21"]
ISSUER_ID = "did:web:issuer.test"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--epoch", default="2026-Q3")
    parser.add_argument("--valid-from", default="2026-07-01T00:00:00Z")
    parser.add_argument("--valid-until", default="2026-10-01T00:00:00Z")
    parser.add_argument("--out", default="config/dev")
    parser.add_argument(
        "--algorithm",
        default="ed25519",
        choices=["ed25519", "mock-hmac-sha256"],
    )
    args = parser.parse_args()

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)

    key_entries = []
    registry_keys = []
    for claim in CLAIMS:
        key_id = f"dev-{claim}-AAL2-{args.epoch}"
        if args.algorithm == "ed25519":
            private_b64, public_b64 = generate_token_keypair()
            key_entries.append(
                {
                    "key_id": key_id,
                    "algorithm": "ed25519",
                    "private_key_b64": private_b64,
                    "public_key_b64": public_b64,
                    "claim": claim,
                    "assurance_level": "AAL2",
                    "epoch": args.epoch,
                    "valid_until": args.valid_until,
                }
            )
            registry_public = public_b64
        else:
            secret_b64 = b64u_encode(secrets.token_bytes(32))
            key_entries.append(
                {
                    "key_id": key_id,
                    "algorithm": "mock-hmac-sha256",
                    "secret_b64": secret_b64,
                    "claim": claim,
                    "assurance_level": "AAL2",
                    "epoch": args.epoch,
                    "valid_until": args.valid_until,
                }
            )
            registry_public = secret_b64  # mock mode: secret doubles as public key
        registry_keys.append(
            {
                "key_id": key_id,
                "purpose": "token_signing",
                "algorithm": args.algorithm,
                "public_key": registry_public,
                "claim": claim,
                "assurance_level": "AAL2",
                "epoch": args.epoch,
                "valid_from": args.valid_from,
                "valid_until": args.valid_until,
            }
        )

    registry = {
        "version": "1.0",
        "generated_at": args.valid_from,
        "issuers": [
            {
                "version": "1.0",
                "issuer_id": ISSUER_ID,
                "legal_name": "BlindAge Dev Issuer",
                "jurisdiction": "US",
                "supported_claims": CLAIMS,
                "assurance_levels": ["AAL2"],
                "keys": registry_keys,
                "status": "active",
                "valid_from": "2026-01-01T00:00:00Z",
                "valid_until": "2027-01-01T00:00:00Z",
            }
        ],
    }

    root_priv, root_pub = generate_root_keypair()
    (out / "issuer_keys.json").write_text(json.dumps({"keys": key_entries}, indent=2))
    (out / "registry.json").write_text(json.dumps(registry, indent=2))
    (out / "registry.sig").write_text(sign_registry(registry, root_priv))
    (out / "root_public_key.txt").write_text(root_pub)
    (out / "root_private_key.txt").write_text(root_priv)
    print(f"Dev issuer material written to {out}/")


if __name__ == "__main__":
    main()
