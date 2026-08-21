"""Local SQLite cache for message/key metadata — per-user, not shared state."""

import sqlite3
from contextlib import contextmanager

DB_PATH = "qumail.db"


def init_db():
    with _conn() as c:
        c.execute("""
            CREATE TABLE IF NOT EXISTS sent_messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                to_addr TEXT,
                subject TEXT,
                security_level INTEGER,
                key_id TEXT,
                sent_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        """)


@contextmanager
def _conn():
    conn = sqlite3.connect(DB_PATH)
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def log_sent_message(to_addr: str, subject: str, security_level: int, key_id: str | None):
    with _conn() as c:
        c.execute(
            "INSERT INTO sent_messages (to_addr, subject, security_level, key_id) VALUES (?, ?, ?, ?)",
            (to_addr, subject, security_level, key_id),
        )
