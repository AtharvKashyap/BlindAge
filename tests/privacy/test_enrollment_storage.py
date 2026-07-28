"""Constitution rule 1: the issuer stores only what age assurance needs.
After a full OIDC enrollment, the issuer database must contain exactly one
table with exactly (enrollment_id, date_of_birth, expires_at) — no IdP sub,
no names, no emails, nothing else."""
import sqlite3
import uuid
from datetime import datetime, timezone

from fastapi.testclient import TestClient

from blindage.dev_idp.app import create_idp
from blindage.issuer.app import create_app as create_issuer
from blindage.issuer.keys import IssuerKeyStore
from blindage.issuer.proofing import OidcConfig, OidcProofing
from blindage.issuer.storage import EnrollmentStore
from tests.conftest import dev_key_entries
from tests.integration import test_oidc_enrollment as t
from tests.integration.test_oidc_enrollment import _enroll


def _build_pair_with_db(db_path):
    # Same wiring as the integration test but with a file-backed store we can
    # inspect. Mirrors _build_pair: httpx.Client(transport=ASGITransport(...))
    # is incompatible with the installed sync httpx (no handle_request), so the
    # issuer's server-side HTTP client is a fastapi TestClient over the IdP app.
    idp_app = create_idp(
        issuer_url=t.IDP_URL, client_id="blindage-issuer", client_secret="dev-secret",
        redirect_uri=f"{t.ISSUER_URL}/oidc/callback",
    )
    idp = TestClient(idp_app, base_url=t.IDP_URL)
    idp_http = TestClient(idp_app, base_url=t.IDP_URL)
    proofing = OidcProofing(
        OidcConfig(
            idp_base_url=t.IDP_URL, client_id="blindage-issuer",
            client_secret="dev-secret", redirect_uri=f"{t.ISSUER_URL}/oidc/callback",
        ),
        http=idp_http,
    )
    store = EnrollmentStore(db_path)
    issuer = TestClient(
        create_issuer(IssuerKeyStore(dev_key_entries()), store, proofing=proofing),
        base_url=t.ISSUER_URL,
    )
    return idp, issuer, store


def test_issuer_db_holds_only_dob_and_expiry(tmp_path):
    db_path = str(tmp_path / "issuer.sqlite")
    idp, issuer, store = _build_pair_with_db(db_path)
    eid = _enroll(idp, issuer, dob="2000-01-01")

    con = sqlite3.connect(db_path)
    tables = {r[0] for r in con.execute(
        "SELECT name FROM sqlite_master WHERE type='table'")}
    assert tables == {"enrollments"}
    cols = [r[1] for r in con.execute("PRAGMA table_info(enrollments)")]
    assert cols == ["enrollment_id", "date_of_birth", "expires_at"]
    rows = list(con.execute("SELECT * FROM enrollments"))
    assert len(rows) == 1
    row_eid, dob, expires_at = rows[0]
    assert row_eid == eid and uuid.UUID(row_eid)          # opaque random id
    assert dob == "2000-01-01"                             # the verified DOB, nothing more
    assert datetime.fromisoformat(expires_at) > datetime.now(timezone.utc)
