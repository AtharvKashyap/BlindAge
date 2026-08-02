"""Transparency log server: a stateless cached view over AnchorUpdated events.

The chain is the log — this serves ordered public trust history (rule 3: no
identity anywhere). Fail closed: RPC trouble → 503, never a stale or partial
answer presented as complete.
"""
import threading
import time

from fastapi import FastAPI, HTTPException

from blindage.transparency.auditor import fetch_history


def create_log_server(
    rpc_url: str, contract_address: str, cache_ttl: float = 30.0
) -> FastAPI:
    app = FastAPI(title="BlindAge Transparency Log (dev)")
    lock = threading.Lock()
    cache: dict = {"entries": None, "at": 0.0}

    def _entries() -> list[dict]:
        with lock:
            now = time.monotonic()
            if cache["entries"] is not None and now - cache["at"] < cache_ttl:
                return cache["entries"]
            entries = fetch_history(rpc_url, contract_address)
            cache["entries"] = entries
            cache["at"] = time.monotonic()
            return entries

    @app.get("/log")
    def log() -> dict:
        try:
            return {"entries": _entries()}
        except Exception as exc:  # fail closed — no partial/stale answers
            raise HTTPException(503, detail=f"chain history unavailable: {exc}")

    @app.get("/health")
    def health() -> dict:
        return {"status": "ok"}

    return app
