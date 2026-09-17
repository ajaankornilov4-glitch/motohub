import sqlite3
from datetime import datetime, timezone
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent
DB_PATH = BASE / "motohub.db"


def now():
    return datetime.now(timezone.utc).replace(tzinfo=None)


def conn():
    c = sqlite3.connect(DB_PATH, check_same_thread=False)
    c.row_factory = sqlite3.Row
    return c


def _add_column(c, table, column, definition):
    columns = {row["name"] for row in c.execute(f"PRAGMA table_info({table})").fetchall()}
    if column not in columns:
        c.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")


def init_db():
    c = conn()
    c.executescript("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT,
        display_name TEXT,
        role TEXT NOT NULL DEFAULT 'USER',
        is_banned INTEGER NOT NULL DEFAULT 0,
        muted_until TEXT,
        avatar_url TEXT,
        bio TEXT,
        motorcycle TEXT,
        city TEXT,
        theme_accent TEXT NOT NULL DEFAULT '#ff2636',
        theme_mode TEXT NOT NULL DEFAULT 'dark',
        created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS otp (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT NOT NULL,
        code_hash TEXT NOT NULL,
        expires_at TEXT NOT NULL,
        attempts INTEGER NOT NULL DEFAULT 0,
        consumed INTEGER NOT NULL DEFAULT 0,
        created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS pending_auth (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT NOT NULL,
        password_hash TEXT,
        purpose TEXT NOT NULL,
        expires_at TEXT NOT NULL,
        created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS trusted_devices (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        token_hash TEXT NOT NULL UNIQUE,
        device_name TEXT,
        created_at TEXT NOT NULL,
        last_used_at TEXT NOT NULL,
        FOREIGN KEY(user_id) REFERENCES users(id)
    );

    CREATE TABLE IF NOT EXISTS punishments (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        admin_id INTEGER,
        kind TEXT NOT NULL DEFAULT 'warning',
        reason TEXT NOT NULL,
        duration_minutes INTEGER,
        created_at TEXT NOT NULL,
        expires_at TEXT,
        FOREIGN KEY(user_id) REFERENCES users(id)
    );

    CREATE TABLE IF NOT EXISTS notifications (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        kind TEXT NOT NULL,
        title TEXT NOT NULL,
        body TEXT NOT NULL,
        created_at TEXT NOT NULL,
        read_at TEXT,
        FOREIGN KEY(user_id) REFERENCES users(id)
    );

    CREATE TABLE IF NOT EXISTS news (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT NOT NULL,
        body TEXT NOT NULL,
        created_at TEXT NOT NULL,
        updated_at TEXT
    );

    CREATE TABLE IF NOT EXISTS events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT NOT NULL,
        description TEXT NOT NULL,
        starts_at TEXT NOT NULL,
        location TEXT,
        created_at TEXT NOT NULL,
        updated_at TEXT
    );

    CREATE TABLE IF NOT EXISTS news_photos (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        news_id INTEGER NOT NULL,
        url TEXT NOT NULL,
        is_cover INTEGER NOT NULL DEFAULT 0,
        created_at TEXT NOT NULL,
        FOREIGN KEY(news_id) REFERENCES news(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS event_photos (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        event_id INTEGER NOT NULL,
        url TEXT NOT NULL,
        is_cover INTEGER NOT NULL DEFAULT 0,
        created_at TEXT NOT NULL,
        FOREIGN KEY(event_id) REFERENCES events(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT NOT NULL,
        display_name TEXT,
        text TEXT,
        created_at TEXT NOT NULL,
        recipient_id INTEGER,
        is_read INTEGER NOT NULL DEFAULT 0,
        attachment_url TEXT,
        attachment_type TEXT,
        attachment_name TEXT
    );

    CREATE TABLE IF NOT EXISTS achievements (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        event_id INTEGER,
        place INTEGER,
        award TEXT,
        note TEXT,
        created_at TEXT NOT NULL,
        FOREIGN KEY(user_id) REFERENCES users(id),
        FOREIGN KEY(event_id) REFERENCES events(id)
    );
    """)

    # Non-destructive migrations for existing installations.
    _add_column(c, "users", "password_hash", "TEXT")
    _add_column(c, "users", "theme_accent", "TEXT NOT NULL DEFAULT '#ff2636'")
    _add_column(c, "users", "theme_mode", "TEXT NOT NULL DEFAULT 'dark'")
    _add_column(c, "punishments", "kind", "TEXT NOT NULL DEFAULT 'warning'")
    _add_column(c, "news", "updated_at", "TEXT")
    _add_column(c, "events", "updated_at", "TEXT")
    _add_column(c, "messages", "attachment_url", "TEXT")
    _add_column(c, "messages", "attachment_type", "TEXT")
    _add_column(c, "messages", "attachment_name", "TEXT")

    c.commit()
    c.close()


def get_user(email):
    if not email:
        return None
    c = conn()
    row = c.execute("SELECT * FROM users WHERE email=? LIMIT 1", (email.strip().lower(),)).fetchone()
    c.close()
    return row


def get_user_by_id(user_id):
    c = conn()
    row = c.execute("SELECT * FROM users WHERE id=? LIMIT 1", (user_id,)).fetchone()
    c.close()
    return row


def create_user(email, password_hash=None):
    email = email.strip().lower()
    existing = get_user(email)
    if existing:
        if password_hash and not existing["password_hash"]:
            c = conn()
            c.execute("UPDATE users SET password_hash=? WHERE id=?", (password_hash, existing["id"]))
            c.commit()
            c.close()
            return get_user(email)
        return existing

    c = conn()
    c.execute(
        """INSERT INTO users(email,password_hash,display_name,role,theme_accent,theme_mode,created_at)
           VALUES(?,?,?,?,?,?,?)""",
        (email, password_hash, email.split("@")[0], "USER", "#ff2636", "dark", now().isoformat()),
    )
    c.commit()
    user_id = c.execute("SELECT last_insert_rowid()").fetchone()[0]
    c.close()
    return get_user_by_id(user_id)
