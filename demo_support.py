# demo_support.py  (repo root — dev/demo only)
"""Uvicorn factories for the demo script. Not part of the package."""
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
    return create_app(IssuerKeyStore.from_file(DEV / "issuer_keys.json"), EnrollmentStore("config/dev/issuer.sqlite"))


def site_app():
    registry = TrustRegistry.load(
        DEV / "registry.json", DEV / "registry.sig", (DEV / "root_public_key.txt").read_text().strip()
    )
    return create_site(registry, trusted_issuer="did:web:issuer.test", audience="localhost")
