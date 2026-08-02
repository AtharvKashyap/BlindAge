"""Dev registry mirror — serves the signed trust registry.

Holds and serves ONLY public issuer trust data (constitution rule 3). Raw
passthrough: the bytes on disk are the bytes served, so clients verify the
exact signed artifact.

When an optional ``anchor`` is supplied, ``GET /registry.json`` fails closed:
it 503s if the served registry's keccak hash disagrees with the on-chain
anchor, or if the anchor lookup itself is unavailable. ``blindage.registry_chain``
is imported lazily inside the route so this module stays importable in minimal
environments without web3 installed.
"""
import json
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import PlainTextResponse, Response


def create_mirror(dev_dir: Path = Path("config/dev"), anchor=None) -> FastAPI:
    app = FastAPI(title="BlindAge Registry Mirror (dev)")

    def _read(name: str) -> str:
        try:
            return (Path(dev_dir) / name).read_text()
        except OSError:
            raise HTTPException(404, detail=f"{name} not available")

    @app.get("/registry.json")
    def registry_json() -> Response:
        text = _read("registry.json")
        if anchor is not None:
            # Fail closed: an operator who opts into anchoring gets anchoring,
            # not silent fallback (spec: error handling).
            from blindage.registry_chain.anchor import AnchorError, registry_keccak

            try:
                onchain = anchor.current()["registry_hash"]
                served = registry_keccak(json.loads(text))
            except (AnchorError, ValueError) as exc:
                raise HTTPException(503, detail=f"anchor check unavailable: {exc}")
            if served != onchain:
                raise HTTPException(
                    503, detail="registry does not match the on-chain anchor"
                )
        return Response(text, media_type="application/json")

    @app.get("/registry.sig", response_class=PlainTextResponse)
    def registry_sig() -> str:
        return _read("registry.sig")

    @app.get("/registry.sig.mldsa", response_class=PlainTextResponse)
    def registry_sig_mldsa() -> str:
        return _read("registry.sig.mldsa")

    @app.get("/health")
    def health() -> dict:
        return {"status": "ok"}

    return app
