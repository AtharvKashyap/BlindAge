import sqlite3
import threading
import uuid
from datetime import date


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
                "  date_of_birth TEXT NOT NULL"
                ")"
            )
            self._conn.commit()

    def create(self, date_of_birth: date) -> str:
        enrollment_id = str(uuid.uuid4())
        with self._lock:
            self._conn.execute(
                "INSERT INTO enrollments (enrollment_id, date_of_birth) VALUES (?, ?)",
                (enrollment_id, date_of_birth.isoformat()),
            )
            self._conn.commit()
        return enrollment_id

    def get_dob(self, enrollment_id: str) -> date | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT date_of_birth FROM enrollments WHERE enrollment_id = ?",
                (enrollment_id,),
            ).fetchone()
        return date.fromisoformat(row[0]) if row else None
