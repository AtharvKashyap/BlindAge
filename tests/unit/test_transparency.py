from fastapi.testclient import TestClient

from blindage.transparency.app import create_log_server
from blindage.transparency.auditor import check_history


def _e(version, generated_at):
    return {"version": version, "generated_at": generated_at,
            "registry_hash": "ab" * 32, "block_number": version, "tx_hash": "0x1"}


def test_check_history_clean():
    assert check_history([]) == []
    assert check_history([_e(1, "2026-08-01T00:00:00Z")]) == []
    assert check_history([
        _e(1, "2026-08-01T00:00:00Z"), _e(2, "2026-08-02T00:00:00Z"),
    ]) == []


def test_check_history_flags_rollbacks():
    version_rollback = check_history([
        _e(2, "2026-08-01T00:00:00Z"), _e(2, "2026-08-02T00:00:00Z"),
    ])
    assert len(version_rollback) == 1 and "version" in version_rollback[0]
    time_rollback = check_history([
        _e(1, "2026-08-02T00:00:00Z"), _e(2, "2026-08-01T00:00:00Z"),
    ])
    assert len(time_rollback) == 1 and "generated_at" in time_rollback[0]
    both = check_history([
        _e(3, "2026-08-03T00:00:00Z"), _e(2, "2026-08-02T00:00:00Z"),
    ])
    assert len(both) == 2  # one problem per violated dimension


def test_log_server_503_when_rpc_down():
    client = TestClient(
        create_log_server("http://127.0.0.1:1", "0x" + "11" * 20, cache_ttl=0.0),
        raise_server_exceptions=False,
    )
    assert client.get("/log").status_code == 503
    assert client.get("/health").json() == {"status": "ok"}


def test_auditor_fails_closed_when_everything_down():
    from blindage.transparency.auditor import audit

    result = audit("http://127.0.0.1:1", "http://127.0.0.1:1", "0x" + "11" * 20)
    assert result["ok"] is False
    assert result["problems"]
