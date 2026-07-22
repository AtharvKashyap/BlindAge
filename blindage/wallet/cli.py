import json
from collections import Counter
from pathlib import Path

import httpx
import typer

from blindage.schemas import AgeClaim, AssuranceLevel, VerifierChallenge
from blindage.wallet.client import WalletError, build_presentation, enroll, mint
from blindage.wallet.vault import StoredToken, VaultData, WalletVault

app = typer.Typer(help="BlindAge wallet (Phase 1 — mock crypto, local dev only)")

DEFAULT_VAULT = Path.home() / ".blindage" / "vault.blindage"

VaultOpt = typer.Option(DEFAULT_VAULT, "--vault")
PassOpt = typer.Option(..., "--passphrase", envvar="BLINDAGE_WALLET_PASSPHRASE")


def make_http_client(base_url: str) -> httpx.Client:
    # Separated so tests can monkeypatch in an in-process ASGI transport.
    return httpx.Client(base_url=base_url, timeout=10.0)


def _open_vault(vault_path: Path, passphrase: str) -> tuple[WalletVault, VaultData]:
    vault_path.parent.mkdir(parents=True, exist_ok=True)
    vault = WalletVault(vault_path, passphrase)
    return vault, vault.load()


@app.command("enroll")
def enroll_cmd(
    issuer: str = typer.Option(...),
    test_dob: str = typer.Option(..., "--test-dob"),
    vault_path: Path = VaultOpt,
    passphrase: str = PassOpt,
) -> None:
    vault, data = _open_vault(vault_path, passphrase)
    with make_http_client(issuer) as http:
        enrollment_id = enroll(http, test_dob)
    data.enrollments[issuer] = enrollment_id
    vault.save(data)
    typer.echo(f"Enrolled with {issuer} (enrollment stored in vault).")


@app.command("mint")
def mint_cmd(
    issuer: str = typer.Option(...),
    claim: AgeClaim = typer.Option(...),
    assurance: AssuranceLevel = typer.Option(AssuranceLevel.AAL2, "--assurance"),
    epoch: str = typer.Option(...),
    count: int = typer.Option(10),
    vault_path: Path = VaultOpt,
    passphrase: str = PassOpt,
) -> None:
    vault, data = _open_vault(vault_path, passphrase)
    enrollment_id = data.enrollments.get(issuer)
    if enrollment_id is None:
        typer.echo(f"Not enrolled with {issuer} — run `blindage enroll` first.")
        raise typer.Exit(code=1)
    try:
        with make_http_client(issuer) as http:
            tokens = mint(http, enrollment_id, claim, assurance, epoch, count)
    except WalletError as exc:
        typer.echo(str(exc))
        raise typer.Exit(code=1)
    data.tokens.extend(StoredToken(token=t) for t in tokens)
    vault.save(data)
    typer.echo(f"Minted {len(tokens)} {claim.value} tokens for epoch {epoch}.")


@app.command("tokens")
def tokens_cmd(vault_path: Path = VaultOpt, passphrase: str = PassOpt) -> None:
    _, data = _open_vault(vault_path, passphrase)
    counts: Counter[tuple[str, str, bool]] = Counter(
        (t.token.claim.value, t.token.epoch, t.spent) for t in data.tokens
    )
    if not counts:
        typer.echo("Vault is empty.")
        return
    for (claim, epoch, spent), n in sorted(counts.items()):
        state = "spent" if spent else "unspent"
        typer.echo(f"{claim}  {epoch}  {state}: {n}")


@app.command("prove")
def prove_cmd(
    challenge_file: Path = typer.Option(..., "--challenge-file"),
    out: Path = typer.Option(..., "--out"),
    vault_path: Path = VaultOpt,
    passphrase: str = PassOpt,
) -> None:
    vault, data = _open_vault(vault_path, passphrase)
    challenge = VerifierChallenge.model_validate_json(challenge_file.read_text())
    try:
        presentation = build_presentation(data, challenge)
    except WalletError as exc:
        typer.echo(str(exc))
        raise typer.Exit(code=1)
    vault.save(data)  # persists the spent flag BEFORE releasing the presentation
    out.write_text(presentation.model_dump_json(indent=2))
    typer.echo(f"Presentation written to {out} (token marked spent).")


if __name__ == "__main__":
    app()
