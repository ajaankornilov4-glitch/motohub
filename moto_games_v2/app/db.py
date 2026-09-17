import os
import sqlite3
from datetime import datetime, timezone

from dotenv import load_dotenv

load_dotenv()


BASE_DIR = os.path.dirname(
    os.path.dirname(
        os.path.abspath(__file__)
    )
)


DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "sqlite:///motohub.db"
)


def get_db_path():
    if DATABASE_URL.startswith("sqlite:///"):
        path = DATABASE_URL.replace(
            "sqlite:///",
            "",
            1
        )

        if not os.path.isabs(path):
            path = os.path.join(
                BASE_DIR,
                path
            )

        return path

    return os.path.join(
        BASE_DIR,
        "motohub.db"
    )


DB_PATH = get_db_path()


def conn():
    connection = sqlite3.connect(
        DB_PATH,
        check_same_thread=False
    )

    connection.row_factory = sqlite3.Row

    connection.execute(
        "PRAGMA foreign_keys = ON"
    )

    return connection


def now():
    return datetime.now(
        timezone.utc
    ).replace(
        tzinfo=None
    )


def init_db():

    c = conn()

    # =========================================================
    # USERS
    # =========================================================

    c.execute(
        """
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

            created_at TEXT NOT NULL
        )
        """
    )


    # =========================================================
    # OTP
    # =========================================================

    c.execute(
        """
        CREATE TABLE IF NOT EXISTS otp (
            id INTEGER PRIMARY KEY AUTOINCREMENT,

            email TEXT NOT NULL,

            code_hash TEXT NOT NULL,

            expires_at TEXT NOT NULL,

            attempts INTEGER NOT NULL DEFAULT 0,

            consumed INTEGER NOT NULL DEFAULT 0,

            created_at TEXT NOT NULL
        )
        """
    )


    # =========================================================
    # PENDING AUTH
    #
    # Используется для:
    # registration
    # new_device
    # set_password
    # reset_password
    # =========================================================

    c.execute(
        """
        CREATE TABLE IF NOT EXISTS pending_auth (
            id INTEGER PRIMARY KEY AUTOINCREMENT,

            email TEXT NOT NULL,

            password_hash TEXT,

            purpose TEXT NOT NULL,

            expires_at TEXT NOT NULL,

            created_at TEXT NOT NULL
        )
        """
    )


    # =========================================================
    # TRUSTED DEVICES
    # =========================================================

    c.execute(
        """
        CREATE TABLE IF NOT EXISTS trusted_devices (
            id INTEGER PRIMARY KEY AUTOINCREMENT,

            user_id INTEGER NOT NULL,

            token_hash TEXT NOT NULL UNIQUE,

            device_name TEXT,

            created_at TEXT NOT NULL,

            last_used_at TEXT NOT NULL,

            FOREIGN KEY(user_id)
                REFERENCES users(id)
                ON DELETE CASCADE
        )
        """
    )


    # =========================================================
    # PUNISHMENTS
    # =========================================================

    c.execute(
        """
        CREATE TABLE IF NOT EXISTS punishments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,

            user_id INTEGER NOT NULL,

            admin_id INTEGER,

            reason TEXT NOT NULL,

            duration_minutes INTEGER,

            created_at TEXT NOT NULL,

            expires_at TEXT,

            FOREIGN KEY(user_id)
                REFERENCES users(id)
                ON DELETE CASCADE,

            FOREIGN KEY(admin_id)
                REFERENCES users(id)
                ON DELETE SET NULL
        )
        """
    )


    # =========================================================
    # NEWS
    # =========================================================

    c.execute(
        """
        CREATE TABLE IF NOT EXISTS news (
            id INTEGER PRIMARY KEY AUTOINCREMENT,

            title TEXT NOT NULL,

            body TEXT NOT NULL,

            created_at TEXT NOT NULL
        )
        """
    )


    # =========================================================
    # EVENTS
    # =========================================================

    c.execute(
        """
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,

            title TEXT NOT NULL,

            description TEXT NOT NULL,

            starts_at TEXT NOT NULL,

            location TEXT,

            created_at TEXT NOT NULL
        )
        """
    )


    # =========================================================
    # MESSAGES
    # =========================================================

    c.execute(
        """
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,

            email TEXT NOT NULL,

            display_name TEXT,

            text TEXT NOT NULL,

            created_at TEXT NOT NULL,

            recipient_id INTEGER,

            is_read INTEGER NOT NULL DEFAULT 0
        )
        """
    )


    # =========================================================
    # ACHIEVEMENTS
    # =========================================================

    c.execute(
        """
        CREATE TABLE IF NOT EXISTS achievements (
            id INTEGER PRIMARY KEY AUTOINCREMENT,

            user_id INTEGER NOT NULL,

            event_id INTEGER,

            place INTEGER,

            award TEXT,

            note TEXT,

            created_at TEXT NOT NULL,

            FOREIGN KEY(user_id)
                REFERENCES users(id)
                ON DELETE CASCADE,

            FOREIGN KEY(event_id)
                REFERENCES events(id)
                ON DELETE SET NULL
        )
        """
    )


    # =========================================================
    # ДОПОЛНИТЕЛЬНЫЕ ИНДЕКСЫ
    # =========================================================

    c.execute(
        """
        CREATE INDEX IF NOT EXISTS
        idx_otp_email
        ON otp(email)
        """
    )

    c.execute(
        """
        CREATE INDEX IF NOT EXISTS
        idx_pending_auth_email
        ON pending_auth(email)
        """
    )

    c.execute(
        """
        CREATE INDEX IF NOT EXISTS
        idx_trusted_devices_user
        ON trusted_devices(user_id)
        """
    )

    c.execute(
        """
        CREATE INDEX IF NOT EXISTS
        idx_messages_recipient
        ON messages(recipient_id)
        """
    )

    c.execute(
        """
        CREATE INDEX IF NOT EXISTS
        idx_achievements_user
        ON achievements(user_id)
        """
    )


    # =========================================================
    # МИГРАЦИЯ СТАРОЙ БАЗЫ
    #
    # Если users уже существовала от старой версии MotoHub,
    # добавляем password_hash без удаления пользователей.
    # =========================================================

    columns = c.execute(
        "PRAGMA table_info(users)"
    ).fetchall()

    column_names = {
        row["name"]
        for row in columns
    }

    if "password_hash" not in column_names:

        c.execute(
            """
            ALTER TABLE users
            ADD COLUMN password_hash TEXT
            """
        )


    if "avatar_url" not in column_names:

        c.execute(
            """
            ALTER TABLE users
            ADD COLUMN avatar_url TEXT
            """
        )


    if "bio" not in column_names:

        c.execute(
            """
            ALTER TABLE users
            ADD COLUMN bio TEXT
            """
        )


    if "motorcycle" not in column_names:

        c.execute(
            """
            ALTER TABLE users
            ADD COLUMN motorcycle TEXT
            """
        )


    if "city" not in column_names:

        c.execute(
            """
            ALTER TABLE users
            ADD COLUMN city TEXT
            """
        )


    if "muted_until" not in column_names:

        c.execute(
            """
            ALTER TABLE users
            ADD COLUMN muted_until TEXT
            """
        )


    c.commit()
    c.close()


# =============================================================
# GET USER BY EMAIL
# =============================================================

def get_user(email):

    if not email:
        return None

    email = email.strip().lower()

    c = conn()

    row = c.execute(
        """
        SELECT *
        FROM users
        WHERE email=?
        LIMIT 1
        """,
        (email,)
    ).fetchone()

    c.close()

    return row


# =============================================================
# GET USER BY ID
# =============================================================

def get_user_by_id(user_id):

    c = conn()

    row = c.execute(
        """
        SELECT *
        FROM users
        WHERE id=?
        LIMIT 1
        """,
        (user_id,)
    ).fetchone()

    c.close()

    return row


# =============================================================
# CREATE USER
# =============================================================

def create_user(
    email,
    password_hash=None
):

    email = email.strip().lower()

    existing = get_user(email)

    if existing:

        if password_hash:

            c = conn()

            c.execute(
                """
                UPDATE users
                SET password_hash=?
                WHERE id=?
                """,
                (
                    password_hash,
                    existing["id"]
                )
            )

            c.commit()
            c.close()

            return get_user(email)

        return existing


    created_at = now().isoformat()

    c = conn()

    c.execute(
        """
        INSERT INTO users (
            email,
            password_hash,
            display_name,
            role,
            is_banned,
            muted_until,
            avatar_url,
            bio,
            motorcycle,
            city,
            created_at
        )
        VALUES (
            ?,
            ?,
            ?,
            'USER',
            0,
            NULL,
            NULL,
            '',
            '',
            '',
            ?
        )
        """,
        (
            email,
            password_hash,
            email.split("@")[0],
            created_at
        )
    )

    c.commit()
    c.close()

    return get_user(email)
