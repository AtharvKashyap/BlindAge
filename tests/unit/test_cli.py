import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from typer.testing import CliRunner

import blindage.wallet.cli as cli
from blindage.crypto import b64u_encode
from blindage.issuer.app import create_app
from blindage.issuer.keys import IssuerKeyStore
from blindage.issuer.storage import EnrollmentStore
from blindage.wallet.vault import WalletVault

runner = CliRunner()


@pytest.fixture(autouse=True)
def issuer_transport(monkeypatch):
    """Route the CLI's httpx client at an in-process issuer app.

    NOTE: httpx.Client(transport=httpx.ASGITransport(...)) is incompatible with the
    installed httpx/starlette versions in this environment (AttributeError:
    'ASGITransport' object has no attribute '__enter__' — same issue hit in Task 9).
    We substitute fastapi's TestClient, which subclasses httpx.Client and exposes the
    same context-manager / request API, via the same `cli.make_http_client`
    monkeypatch seam. Production `make_http_client` in cli.py is untouched.
    """
    from fastapi.testclient import TestClient

    key_store = IssuerKeyStore(
        [
            {
                "key_id": "dev-AGE_OVER_18-AAL2-2026-Q3",
                "secret_b64": b64u_encode(b"e" * 32),
                "claim": "AGE_OVER_18",
                "assurance_level": "AAL2",
                "epoch": "2026-Q3",
                "valid_until": "2026-10-01T00:00:00Z",
            }
        ]
    )
    app = create_app(key_store, EnrollmentStore(":memory:"))

    def make_client(base_url: str):
        return TestClient(app, base_url=base_url)

    monkeypatch.setattr(cli, "make_http_client", make_client)


def vault_args(tmp_path: Path) -> list[str]:
    return ["--vault", str(tmp_path / "vault.blindage"), "--passphrase", "pw"]


def test_enroll_mint_tokens_prove_flow(tmp_path: Path):
    result = runner.invoke(
        cli.app,
        ["enroll", "--issuer", "http://issuer.test", "--test-dob", "2000-01-01"]
        + vault_args(tmp_path),
    )
    assert result.exit_code == 0, result.output

    result = runner.invoke(
        cli.app,
        [
            "mint", "--issuer", "http://issuer.test", "--claim", "AGE_OVER_18",
            "--assurance", "AAL2", "--epoch", "2026-Q3", "--count", "3",
        ]
        + vault_args(tmp_path),
    )
    assert result.exit_code == 0, result.output

    result = runner.invoke(cli.app, ["tokens"] + vault_args(tmp_path))
    assert result.exit_code == 0
    assert "AGE_OVER_18" in result.output and "3" in result.output

    now = datetime.now(timezone.utc)
    challenge = {
        "version": "1.0",
        "challenge_id": "11111111-1111-1111-1111-111111111111",
        "required_claim": "AGE_OVER_18",
        "minimum_assurance_level": "AAL2",
        "audience": "example.test",
        "challenge": "Y2hhbGxlbmdl",
        "issued_at": now.isoformat(),
        "expires_at": (now + timedelta(minutes=5)).isoformat(),
    }
    challenge_file = tmp_path / "challenge.json"
    challenge_file.write_text(json.dumps(challenge))
    out_file = tmp_path / "presentation.json"
    result = runner.invoke(
        cli.app,
        ["prove", "--challenge-file", str(challenge_file), "--out", str(out_file)]
        + vault_args(tmp_path),
    )
    assert result.exit_code == 0, result.output
    presentation = json.loads(out_file.read_text())
    assert presentation["domain_binding"]["audience"] == "example.test"

    # Token was marked spent inside the vault.
    data = WalletVault(tmp_path / "vault.blindage", "pw").load()
    assert sum(1 for t in data.tokens if t.spent) == 1


def test_mint_without_enrollment_fails(tmp_path: Path):
    result = runner.invoke(
        cli.app,
        [
            "mint", "--issuer", "http://issuer.test", "--claim", "AGE_OVER_18",
            "--assurance", "AAL2", "--epoch", "2026-Q3", "--count", "1",
        ]
        + vault_args(tmp_path),
    )
    assert result.exit_code == 1
    assert "enroll" in result.output.lower()


def test_export_writes_unspent_tokens(tmp_path: Path):
    # Enroll + mint, then export.
    runner.invoke(
        cli.app,
        ["enroll", "--issuer", "http://issuer.test", "--test-dob", "2000-01-01"] + vault_args(tmp_path),
    )
    runner.invoke(
        cli.app,
        ["mint", "--issuer", "http://issuer.test", "--claim", "AGE_OVER_18",
         "--assurance", "AAL2", "--epoch", "2026-Q3", "--count", "3"] + vault_args(tmp_path),
    )
    out_file = tmp_path / "tokens.json"
    result = runner.invoke(cli.app, ["export", "--out", str(out_file)] + vault_args(tmp_path))
    assert result.exit_code == 0, result.output
    data = json.loads(out_file.read_text())
    assert data["version"] == "1.0"
    assert len(data["tokens"]) == 3
    t = data["tokens"][0]
    assert set(t) >= {"claim", "assurance_level", "epoch", "issuer_id", "issuer_key_id", "nonce", "signature"}
    assert "spent" not in t  # exported tokens carry no wallet-internal state
