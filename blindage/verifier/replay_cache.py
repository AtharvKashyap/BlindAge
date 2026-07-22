import sqlite3


class ReplayCache:
    """Stores SHA-256 hashes of spent token nonces. Nothing else — no identity,
    no fingerprint, no history (spec privacy rule)."""

    def __init__(self, db_path: str) -> None:
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.execute(
            "CREATE TABLE IF NOT EXISTS spent (nonce_hash TEXT PRIMARY KEY)"
        )
        self._conn.commit()

    def check_and_insert(self, nonce_hash: str) -> bool:
        try:
            self._conn.execute("INSERT INTO spent (nonce_hash) VALUES (?)", (nonce_hash,))
            self._conn.commit()
            return True
        except sqlite3.IntegrityError:
            return False
