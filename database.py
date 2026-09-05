"""
database.py
SQLite setup for storing scan history (assignment requirement 08).

Creates a single 'scans' table. Each row stores the full scan result as
JSON in 'findings_json', plus flat columns for the summary fields so
history views can query/sort without parsing JSON every time.
"""

import sqlite3
import json
import datetime
from pathlib import Path

DB_PATH = Path(__file__).parent / "scans.db"


def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row  # lets us access columns by name
    return conn


def init_db():
    """Creates the scans table if it doesn't already exist. Safe to call every startup."""
    conn = get_connection()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
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
    conn.commit()
    conn.close()


def save_scan(report: dict) -> int:
    """Saves a full scan report (from scoring.run_full_scan) and returns the new row's id."""
    conn = get_connection()
    cursor = conn.execute(
        """
        INSERT INTO scans (submitted_url, final_url, score, grade, classification,
                            checks_performed, findings_json, scanned_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            report["submitted_url"],
            report["final_url"],
            report["score"],
            report["grade"],
            report["classification"],
            report["checks_performed"],
            json.dumps(report["findings"]),
            datetime.datetime.now(datetime.timezone.utc).isoformat(),
        ),
    )
    conn.commit()
    new_id = cursor.lastrowid
    conn.close()
    return new_id


def get_history(limit: int = 50) -> list:
    """Returns a summary list of past scans, most recent first. No full findings included."""
    conn = get_connection()
    rows = conn.execute(
        """
        SELECT id, submitted_url, final_url, score, grade, classification, scanned_at
        FROM scans
        ORDER BY id DESC
        LIMIT ?
        """,
        (limit,),
    ).fetchall()
    conn.close()
    return [dict(row) for row in rows]


def get_scan_by_id(scan_id: int) -> dict | None:
    """Returns the full report (including findings) for one past scan, or None if not found."""
    conn = get_connection()
    row = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
    conn.close()

    if row is None:
        return None

    result = dict(row)
    result["findings"] = json.loads(result.pop("findings_json"))
    return result


def delete_scan(scan_id: int) -> bool:
    """Deletes a scan by id. Returns True if a row was actually deleted."""
    conn = get_connection()
    cursor = conn.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
    conn.commit()
    deleted = cursor.rowcount > 0
    conn.close()
    return deleted


# Quick manual test — run this file directly: python database.py
if __name__ == "__main__":
    init_db()
    print(f"Database initialized at: {DB_PATH}")

    # Insert a fake scan to confirm everything works end-to-end
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