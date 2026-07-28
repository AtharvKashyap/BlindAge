import sqlite3
from datetime import date, datetime, timedelta, timezone

from blindage.issuer.app import create_app
from blindage.issuer.keys import IssuerKeyStore
from blindage.issuer.storage import EnrollmentStore
from fastapi.testclient import TestClient
from tests.conftest import dev_key_entries

DOB = date(2000, 1, 1)
NOW = datetime.now(timezone.utc)


def test_store_roundtrips_dob_and_expiry():
    store = EnrollmentStore(":memory:")
    eid = store.create(DOB, NOW + timedelta(days=365))
    dob, expires_at = store.get(eid)
    assert dob == DOB
    assert expires_at.tzinfo is not None
    assert store.get("missing") is None


def test_store_migrates_pre_phase7_schema(tmp_path):
    db = tmp_path / "old.sqlite"
    con = sqlite3.connect(db)
    con.execute(
        "CREATE TABLE enrollments (enrollment_id TEXT PRIMARY KEY, date_of_birth TEXT NOT NULL)"
    )
    con.execute("INSERT INTO enrollments VALUES ('old-id', '1990-06-15')")
    con.commit()
    con.close()
    store = EnrollmentStore(str(db))
    dob, expires_at = store.get("old-id")
    assert dob == date(1990, 6, 15)
    assert expires_at > NOW  # migrated rows get a default future expiry


def test_store_migration_is_idempotent_and_single_shot(tmp_path):
    # Build an old-schema DB with a row, then open it twice with fresh
    # connections. A half-migrated state ('' expires_at) is now impossible
    # because the migration is a single atomic ALTER, so the second open
    # (which skips the migration branch — column already exists) must still
    # read a valid, timezone-aware expiry.
    db = tmp_path / "old.sqlite"
    con = sqlite3.connect(db)
    con.execute(
        "CREATE TABLE enrollments (enrollment_id TEXT PRIMARY KEY, date_of_birth TEXT NOT NULL)"
    )
    con.execute("INSERT INTO enrollments VALUES ('old-id', '1990-06-15')")
    con.commit()
    con.close()

    EnrollmentStore(str(db))  # first open performs the migration
    store = EnrollmentStore(str(db))  # second, fresh connection: no migration
    dob, expires_at = store.get("old-id")
    assert dob == date(1990, 6, 15)
    assert isinstance(expires_at, datetime)
    assert expires_at.tzinfo is not None
    assert expires_at > NOW


def _issue_body(eid):
    return {
        "version": "1.0", "enrollment_id": eid, "claim": "AGE_OVER_18",
        "assurance_level": "AAL2", "epoch": "2026-Q3",
        "blinded_messages": ["AA=="],
    }


def test_issue_rejects_expired_enrollment():
    store = EnrollmentStore(":memory:")
    eid = store.create(DOB, NOW - timedelta(seconds=1))
    client = TestClient(create_app(IssuerKeyStore(dev_key_entries()), store))
    resp = client.post("/v1/tokens/issue", json=_issue_body(eid))
    assert resp.status_code == 403
    assert resp.json()["detail"] == "enrollment expired"


def test_enroll_endpoint_sets_year_long_expiry():
    store = EnrollmentStore(":memory:")
    client = TestClient(create_app(IssuerKeyStore(dev_key_entries()), store))
    eid = client.post("/v1/enrollment", json={"date_of_birth": "2000-01-01"}).json()["enrollment_id"]
    _, expires_at = store.get(eid)
    days = (expires_at - NOW).days
    assert 360 <= days <= 366
