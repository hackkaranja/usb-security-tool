# src/logging_db.py
import sqlite3
from datetime import datetime
from pathlib import Path

DB_PATH = Path(__file__).parent.parent / "events.db"


def _connect():
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.execute("PRAGMA journal_mode=WAL")
    return conn

def init_db():
    conn = _connect()
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            event_type TEXT NOT NULL,
            details TEXT
        )
    """)
    conn.commit()
    conn.close()

def log_event(event_type: str, details: str = ""):
    conn = None
    try:
        conn = _connect()
        cursor = conn.cursor()
        ts = datetime.now().isoformat()
        cursor.execute(
            "INSERT INTO events (timestamp, event_type, details) VALUES (?, ?, ?)",
            (ts, event_type, details)
        )
        conn.commit()
        return cursor.lastrowid
    except sqlite3.Error:
        return None
    finally:
        if conn:
            conn.close()

def get_recent_logs(limit: int = 100):
    conn = _connect()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT id, timestamp, event_type, details FROM events ORDER BY id DESC LIMIT ?",
        (limit,)
    )
    rows = cursor.fetchall()
    conn.close()
    return [{"id": r[0], "timestamp": r[1], "type": r[2], "details": r[3]} for r in rows]


def get_new_logs(last_id: int = 0, limit: int = 100):
    conn = _connect()
    cursor = conn.cursor()
    cursor.execute(
        """
        SELECT id, timestamp, event_type, details
        FROM events
        WHERE id > ?
        ORDER BY id ASC
        LIMIT ?
        """,
        (last_id, limit)
    )
    rows = cursor.fetchall()
    conn.close()
    return [{"id": r[0], "timestamp": r[1], "type": r[2], "details": r[3]} for r in rows]
