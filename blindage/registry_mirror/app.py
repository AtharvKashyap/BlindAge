"""Dev registry mirror — serves the signed trust registry.

Holds and serves ONLY public issuer trust data (constitution rule 3). Raw
passthrough: the bytes on disk are the bytes served, so clients verify the
exact signed artifact.
"""
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import PlainTextResponse, Response


def create_mirror(dev_dir: Path = Path("config/dev")) -> FastAPI:
    app = FastAPI(title="BlindAge Registry Mirror (dev)")

    def _read(name: str) -> str:
        try:
            return (Path(dev_dir) / name).read_text()
        except OSError:
            raise HTTPException(404, detail=f"{name} not available")

    @app.get("/registry.json")
    def registry_json() -> Response:
        return Response(_read("registry.json"), media_type="application/json")

    @app.get("/registry.sig", response_class=PlainTextResponse)
    def registry_sig() -> str:
        return _read("registry.sig")

    @app.get("/health")
    def health() -> dict:
        return {"status": "ok"}

    return app
