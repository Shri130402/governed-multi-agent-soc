
import sqlite3
import json
from datetime import datetime

DB_NAME = "soc_database.db"


def get_connection():
    return sqlite3.connect(DB_NAME)


def initialize_db():
    with get_connection() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS investigations (
                alert_id TEXT PRIMARY KEY,
                alert_data TEXT NOT NULL,
                result_data TEXT NOT NULL,
                decision TEXT DEFAULT 'Awaiting review',
                analyst_note TEXT DEFAULT '',
                reviewed_at TEXT DEFAULT ''
            )
        """)

        conn.execute("""
            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                alert_id TEXT NOT NULL,
                event TEXT NOT NULL,
                details TEXT,
                timestamp TEXT NOT NULL
            )
        """)


def save_investigation(alert, result):
    alert_id = alert["Alert ID"]
    timestamp = datetime.now().isoformat(timespec="seconds")

    with get_connection() as conn:
        # Preserve an existing analyst decision if this alert is updated.
        conn.execute("""
            INSERT INTO investigations
            (alert_id, alert_data, result_data)
            VALUES (?, ?, ?)
            ON CONFLICT(alert_id) DO UPDATE SET
                alert_data = excluded.alert_data,
                result_data = excluded.result_data
        """, (
            alert_id,
            json.dumps(alert),
            json.dumps(result)
        ))

        conn.execute("""
            INSERT INTO audit_logs
            (alert_id, event, details, timestamp)
            VALUES (?, ?, ?, ?)
        """, (
            alert_id,
            "Investigation completed",
            "Multi-agent investigation result saved",
            timestamp
        ))


def save_decision(alert_id, decision, note):
    timestamp = datetime.now().isoformat(timespec="seconds")

    with get_connection() as conn:
        cursor = conn.execute("""
            UPDATE investigations
            SET decision = ?, analyst_note = ?, reviewed_at = ?
            WHERE alert_id = ?
        """, (decision, note, timestamp, alert_id))

        if cursor.rowcount == 0:
            raise ValueError(
                f"Investigation {alert_id} was not found in the database."
            )

        conn.execute("""
            INSERT INTO audit_logs
            (alert_id, event, details, timestamp)
            VALUES (?, ?, ?, ?)
        """, (
            alert_id,
            "Analyst decision",
            f"Decision: {decision}. Comment: {note}",
            timestamp
        ))


def load_investigations():
    with get_connection() as conn:
        rows = conn.execute("""
            SELECT alert_id, alert_data, result_data,
                   decision, analyst_note, reviewed_at
            FROM investigations
            ORDER BY rowid
        """).fetchall()

    records = []
    for row in rows:
        records.append({
            "alert_id": row[0],
            "alert": json.loads(row[1]),
            "result": json.loads(row[2]),
            "decision": row[3],
            "note": row[4],
            "reviewed_at": row[5]
        })

    return records


def load_audit_logs():
    with get_connection() as conn:
        rows = conn.execute("""
            SELECT alert_id, event, details, timestamp
            FROM audit_logs
            ORDER BY id DESC
        """).fetchall()

    return [
        {
            "alert_id": row[0],
            "event": row[1],
            "details": row[2],
            "timestamp": row[3]
        }
        for row in rows
    ]


initialize_db()
