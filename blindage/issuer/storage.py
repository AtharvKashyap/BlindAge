import sqlite3
import threading
import uuid
from datetime import date, datetime, timedelta, timezone


class EnrollmentStore:
    def __init__(self, db_path: str) -> None:
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        # FastAPI sync endpoints run on a thread pool, so the single shared
        # connection is accessed concurrently. sqlite3 connections are not
        # safe for concurrent use across threads even with
        # check_same_thread=False, so serialize access with this lock.
        self._lock = threading.Lock()
        with self._lock:
            self._conn.execute(
                "CREATE TABLE IF NOT EXISTS enrollments ("
                "  enrollment_id TEXT PRIMARY KEY,"
                "  date_of_birth TEXT NOT NULL,"
                "  expires_at TEXT NOT NULL"
                ")"
            )
            # Migrate pre-Phase-7 dev databases (no expires_at column):
            # existing rows get a fresh year-long expiry.
            cols = [r[1] for r in self._conn.execute("PRAGMA table_info(enrollments)")]
            if "expires_at" not in cols:
                default = (datetime.now(timezone.utc) + timedelta(days=365)).isoformat()
                self._conn.execute(
                    "ALTER TABLE enrollments ADD COLUMN expires_at TEXT NOT NULL DEFAULT ''"
                )
                self._conn.execute(
                    "UPDATE enrollments SET expires_at = ? WHERE expires_at = ''", (default,)
                )
            self._conn.commit()

    def create(self, date_of_birth: date, expires_at: datetime) -> str:
        enrollment_id = str(uuid.uuid4())
        with self._lock:
            self._conn.execute(
                "INSERT INTO enrollments (enrollment_id, date_of_birth, expires_at)"
                " VALUES (?, ?, ?)",
                (enrollment_id, date_of_birth.isoformat(), expires_at.isoformat()),
            )
            self._conn.commit()
        return enrollment_id

    def get(self, enrollment_id: str) -> tuple[date, datetime] | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT date_of_birth, expires_at FROM enrollments WHERE enrollment_id = ?",
                (enrollment_id,),
            ).fetchone()
        if row is None:
            return None
        return date.fromisoformat(row[0]), datetime.fromisoformat(row[1])
