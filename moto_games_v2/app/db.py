import sqlite3
from pathlib import Path
from datetime import datetime

DB = Path(__file__).resolve().parent.parent / "motohub.db"

def conn():
    c = sqlite3.connect(DB)
    c.row_factory = sqlite3.Row
    return c

def init_db():
    c = conn()
    c.executescript("""
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      email TEXT UNIQUE NOT NULL,
      display_name TEXT,
      role TEXT NOT NULL DEFAULT 'USER',
      is_banned INTEGER NOT NULL DEFAULT 0,
      muted_until TEXT,
      avatar_url TEXT,
      bio TEXT,
      motorcycle TEXT,
      city TEXT,
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
    CREATE TABLE IF NOT EXISTS news (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      title TEXT NOT NULL,
      body TEXT NOT NULL,
      created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS events (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      title TEXT NOT NULL,
      description TEXT NOT NULL,
      starts_at TEXT NOT NULL,
      location TEXT,
      created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS messages (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      email TEXT NOT NULL,
      display_name TEXT,
      text TEXT NOT NULL,
      created_at TEXT NOT NULL,
      recipient_id INTEGER,
      is_read INTEGER NOT NULL DEFAULT 0
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
    # Safe upgrades for older MotoHub databases.
    cols = {r[1] for r in c.execute("PRAGMA table_info(users)").fetchall()}
    for col, ddl in [
        ("avatar_url", "ALTER TABLE users ADD COLUMN avatar_url TEXT"),
        ("bio", "ALTER TABLE users ADD COLUMN bio TEXT"),
        ("motorcycle", "ALTER TABLE users ADD COLUMN motorcycle TEXT"),
        ("city", "ALTER TABLE users ADD COLUMN city TEXT"),
    ]:
        if col not in cols:
            c.execute(ddl)
    cols = {r[1] for r in c.execute("PRAGMA table_info(messages)").fetchall()}
    if "recipient_id" not in cols:
        c.execute("ALTER TABLE messages ADD COLUMN recipient_id INTEGER")
    if "is_read" not in cols:
        c.execute("ALTER TABLE messages ADD COLUMN is_read INTEGER NOT NULL DEFAULT 0")
    c.commit()
    c.close()

def now():
    return datetime.utcnow()

def get_user(email):
    c=conn(); row=c.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone(); c.close()
    return row

def get_user_by_id(user_id):
    c=conn(); row=c.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone(); c.close()
    return row

def create_user(email):
    c=conn()
    c.execute("INSERT OR IGNORE INTO users(email,created_at) VALUES(?,?)",(email,now().isoformat()))
    c.commit()
    row=c.execute("SELECT * FROM users WHERE email=?",(email,)).fetchone()
    c.close()
    return row
