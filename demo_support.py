# demo_support.py  (repo root — dev/demo only)
"""Uvicorn factories for the demo script. Not part of the package."""
import os
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[0]))  # robust against editable-install .pth quirks

from blindage.example_site.app import create_site
from blindage.issuer.app import create_app
from blindage.issuer.keys import IssuerKeyStore
from blindage.issuer.storage import EnrollmentStore
from blindage.registry import TrustRegistry

DEV = Path("config/dev")


def issuer_app():
    key_store = IssuerKeyStore.from_file(DEV / "issuer_keys.json")
    store = EnrollmentStore("config/dev/issuer.sqlite")
    if os.environ.get("BLINDAGE_PROOFING") == "oidc":
        import httpx
        from blindage.issuer.proofing import OidcConfig, OidcProofing
        cfg = OidcConfig(
            idp_base_url="http://localhost:8600",
            client_id="blindage-issuer",
            client_secret="dev-secret",
            redirect_uri="http://localhost:8400/oidc/callback",
        )
        return create_app(key_store, store, proofing=OidcProofing(cfg, httpx.Client()))
    return create_app(key_store, store)


def idp_app():
    from blindage.dev_idp.app import create_idp
    return create_idp()


def site_app():
    registry = TrustRegistry.load(
        DEV / "registry.json", DEV / "registry.sig", (DEV / "root_public_key.txt").read_text().strip()
    )
    return create_site(registry, trusted_issuer="did:web:issuer.test", audience="localhost")
