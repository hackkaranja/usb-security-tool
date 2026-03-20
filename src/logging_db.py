# src/logging_db.py
import sqlite3
import threading
from datetime import datetime
from pathlib import Path

from src.webview_bridge import add_new_log

DB_PATH = Path(__file__).parent.parent / "usb_security.db"


def _connect():
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def init_db():
    conn = _connect()
    try:
        cursor = conn.cursor()
        cursor.execute("PRAGMA busy_timeout=10000")
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                type TEXT NOT NULL,
                details TEXT NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                event_type TEXT NOT NULL,
                details TEXT
            )
            """
        )
        cursor.execute("DROP TABLE IF EXISTS app_meta")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_logs_timestamp ON logs(timestamp)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_logs_type ON logs(type)")

        # Migrate historical rows from legacy events table into logs table.
        # Best-effort only: app startup should continue even if legacy schema differs.
        try:
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='events'")
            has_events_table = cursor.fetchone() is not None
            if has_events_table:
                events_count = cursor.execute("SELECT COUNT(*) FROM events").fetchone()[0]
                logs_count = cursor.execute("SELECT COUNT(*) FROM logs").fetchone()[0]
                if events_count > 0 and logs_count < events_count:
                    event_columns = {
                        row[1] for row in cursor.execute("PRAGMA table_info(events)").fetchall()
                    }
                    if "timestamp" in event_columns and "details" in event_columns:
                        if "event_type" in event_columns:
                            type_col = "event_type"
                        elif "type" in event_columns:
                            type_col = "type"
                        else:
                            type_col = None

                        if type_col is not None:
                            cursor.execute(
                                f"""
                                INSERT INTO logs (timestamp, type, details)
                                SELECT e.timestamp, e.{type_col}, COALESCE(e.details, '')
                                FROM events e
                                WHERE NOT EXISTS (
                                    SELECT 1
                                    FROM logs l
                                    WHERE l.timestamp = e.timestamp
                                      AND l.type = e.{type_col}
                                      AND l.details = COALESCE(e.details, '')
                                )
                                """
                            )
                # Backfill logs into legacy events table when events is behind.
                if logs_count > events_count:
                    cursor.execute(
                        """
                        INSERT INTO events (timestamp, event_type, details)
                        SELECT l.timestamp, l.type, COALESCE(l.details, '')
                        FROM logs l
                        WHERE NOT EXISTS (
                            SELECT 1
                            FROM events e
                            WHERE e.timestamp = l.timestamp
                              AND e.event_type = l.type
                              AND COALESCE(e.details, '') = COALESCE(l.details, '')
                        )
                        """
                    )
        except sqlite3.Error:
            pass

        conn.commit()
    finally:
        conn.close()


def _emit_live_log(log_entry: dict):
    """Best-effort live log push to frontend."""
    try:
        add_new_log(log_entry)
    except Exception:
        return


def log_event(event_type: str, details: str = ""):
    conn = None
    try:
        conn = _connect()
        cursor = conn.cursor()
        ts = datetime.now().isoformat()
        cursor.execute(
            "INSERT INTO logs (timestamp, type, details) VALUES (?, ?, ?)",
            (ts, event_type, details or ""),
        )
        # Keep legacy events table in sync for compatibility with older views/tools.
        cursor.execute(
            "INSERT INTO events (timestamp, event_type, details) VALUES (?, ?, ?)",
            (ts, event_type, details or ""),
        )
        conn.commit()
        log_id = cursor.lastrowid
        if log_id:
            threading.Thread(
                target=_emit_live_log,
                args=({"id": log_id, "timestamp": ts, "type": event_type, "details": details or ""},),
                daemon=True,
            ).start()
        return log_id
    except sqlite3.Error:
        return None
    finally:
        if conn:
            conn.close()


def get_recent_logs(limit: int = 100):
    conn = _connect()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT id, timestamp, type, details FROM logs ORDER BY id DESC LIMIT ?",
        (limit,),
    )
    rows = cursor.fetchall()
    conn.close()
    return [{"id": r[0], "timestamp": r[1], "type": r[2], "details": r[3]} for r in rows]


def get_new_logs(last_id: int = 0, limit: int = 100):
    conn = _connect()
    cursor = conn.cursor()
    cursor.execute(
        """
        SELECT id, timestamp, type, details
        FROM logs
        WHERE id > ?
        ORDER BY id ASC
        LIMIT ?
        """,
        (last_id, limit),
    )
    rows = cursor.fetchall()
    conn.close()
    return [{"id": r[0], "timestamp": r[1], "type": r[2], "details": r[3]} for r in rows]


def clear_all_logs() -> int:
    """Delete all log rows and return number of deleted records."""
    conn = _connect()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM logs")
        total = int(cursor.fetchone()[0] or 0)
        cursor.execute("DELETE FROM logs")
        conn.commit()
        return total
    finally:
        conn.close()
