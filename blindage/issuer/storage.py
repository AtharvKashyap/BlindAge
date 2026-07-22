import sqlite3
import uuid
from datetime import date


class EnrollmentStore:
    def __init__(self, db_path: str) -> None:
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.execute(
            "CREATE TABLE IF NOT EXISTS enrollments ("
            "  enrollment_id TEXT PRIMARY KEY,"
            "  date_of_birth TEXT NOT NULL"
            ")"
        )
        self._conn.commit()

    def create(self, date_of_birth: date) -> str:
        enrollment_id = str(uuid.uuid4())
        self._conn.execute(
            "INSERT INTO enrollments (enrollment_id, date_of_birth) VALUES (?, ?)",
            (enrollment_id, date_of_birth.isoformat()),
        )
        self._conn.commit()
        return enrollment_id

    def get_dob(self, enrollment_id: str) -> date | None:
        row = self._conn.execute(
            "SELECT date_of_birth FROM enrollments WHERE enrollment_id = ?",
            (enrollment_id,),
        ).fetchone()
        return date.fromisoformat(row[0]) if row else None
