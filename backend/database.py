"""
database.py
Scan-history storage (assignment requirement 08).

Two backends, same functions:
  - DATABASE_URL set   -> Postgres (e.g. Neon). Used in production on Vercel,
                          where there is no persistent disk for a SQLite file.
  - DATABASE_URL unset -> local SQLite file (scans.db). Used for local dev.

Each row stores the full scan result as JSON in 'findings_json', plus flat
columns for the summary fields so history views can query/sort without
parsing JSON every time.
"""

import os
import json
import sqlite3
import datetime
from contextlib import contextmanager
from pathlib import Path

try:
    from dotenv import load_dotenv
    load_dotenv()  # so DATABASE_URL in .env is visible when running this file directly
except ImportError:
    pass

DATABASE_URL = os.getenv("DATABASE_URL")
USE_POSTGRES = bool(DATABASE_URL)

DB_PATH = Path(__file__).parent / "scans.db"

# Placeholder style differs between the two drivers.
PH = "%s" if USE_POSTGRES else "?"


def _connect():
    if USE_POSTGRES:
        import psycopg
        from psycopg.rows import dict_row

        # prepare_threshold=None turns off server-side prepared statements, which
        # can misbehave behind a pooled (PgBouncer-style) connection string.
        return psycopg.connect(DATABASE_URL, row_factory=dict_row, prepare_threshold=None)

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row  # lets us access columns by name
    return conn


@contextmanager
def _db():
    """Opens a connection, commits on success, rolls back on error, always closes."""
    conn = _connect()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db():
    """Creates the scans table if it doesn't already exist. Safe to call every startup."""
    id_column = "SERIAL PRIMARY KEY" if USE_POSTGRES else "INTEGER PRIMARY KEY AUTOINCREMENT"
    with _db() as conn:
        conn.execute(f"""
            CREATE TABLE IF NOT EXISTS scans (
                id {id_column},
                submitted_url TEXT NOT NULL,
                final_url TEXT NOT NULL,
                score INTEGER NOT NULL,
                grade TEXT NOT NULL,
                classification TEXT NOT NULL,
                checks_performed INTEGER NOT NULL,
                findings_json TEXT NOT NULL,
                scanned_at TEXT NOT NULL
            )
        """)


def save_scan(report: dict) -> int:
    """Saves a full scan report (from scoring.run_full_scan) and returns the new row's id."""
    sql = f"""
        INSERT INTO scans (submitted_url, final_url, score, grade, classification,
                           checks_performed, findings_json, scanned_at)
        VALUES ({", ".join([PH] * 8)})
    """
    params = (
        report["submitted_url"],
        report["final_url"],
        report["score"],
        report["grade"],
        report["classification"],
        report["checks_performed"],
        json.dumps(report["findings"]),
        datetime.datetime.now(datetime.timezone.utc).isoformat(),
    )
    with _db() as conn:
        if USE_POSTGRES:
            row = conn.execute(sql + " RETURNING id", params).fetchone()
            return row["id"]
        cursor = conn.execute(sql, params)
        return cursor.lastrowid


def get_history(limit: int = 50) -> list:
    """Returns a summary list of past scans, most recent first. No full findings included."""
    with _db() as conn:
        rows = conn.execute(
            f"""
            SELECT id, submitted_url, final_url, score, grade, classification, scanned_at
            FROM scans
            ORDER BY id DESC
            LIMIT {PH}
            """,
            (limit,),
        ).fetchall()
    return [dict(row) for row in rows]


def get_scan_by_id(scan_id: int) -> dict | None:
    """Returns the full report (including findings) for one past scan, or None if not found."""
    with _db() as conn:
        row = conn.execute(f"SELECT * FROM scans WHERE id = {PH}", (scan_id,)).fetchone()

    if row is None:
        return None

    result = dict(row)
    result["findings"] = json.loads(result.pop("findings_json"))
    return result


def delete_scan(scan_id: int) -> bool:
    """Deletes a scan by id. Returns True if a row was actually deleted."""
    with _db() as conn:
        cursor = conn.execute(f"DELETE FROM scans WHERE id = {PH}", (scan_id,))
        return cursor.rowcount > 0


# Quick manual test — run this file directly: python database.py
if __name__ == "__main__":
    init_db()
    print(f"Backend: {'Postgres' if USE_POSTGRES else f'SQLite at {DB_PATH}'}")

    fake_report = {
        "submitted_url": "http://example.com",
        "final_url": "https://example.com/",
        "score": 88,
        "grade": "B",
        "classification": "Safe",
        "checks_performed": 15,
        "findings": [{"check": "Test Check", "passed": True, "impact": 0, "detail": "This is a test."}],
    }
    new_id = save_scan(fake_report)
    print(f"Saved test scan with id: {new_id}")

    print("\nHistory:")
    for scan in get_history():
        print(scan)

    print("\nFull record for that scan:")
    print(get_scan_by_id(new_id))

    print(f"\nDeleted test scan: {delete_scan(new_id)}")
