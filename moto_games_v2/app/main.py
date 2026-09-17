import hashlib
import os
import secrets
import uuid

from datetime import datetime, timedelta
from pathlib import Path

from dotenv import load_dotenv

from fastapi import (
    FastAPI,
    Request,
    Form,
    WebSocket,
    WebSocketDisconnect,
    UploadFile,
    File,
    HTTPException,
)

from fastapi.responses import (
    HTMLResponse,
    RedirectResponse,
    JSONResponse,
)

from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles

from itsdangerous import (
    URLSafeSerializer,
    BadSignature,
)

from .db import (
    init_db,
    conn,
    get_user,
    get_user_by_id,
    create_user,
    now,
)

from .emailer import send_otp


# =========================================================
# CONFIG
# =========================================================

load_dotenv()

BASE = Path(__file__).resolve().parent.parent

UPLOADS = BASE / "static" / "uploads"
CHAT_UPLOADS = UPLOADS / "chat"

UPLOADS.mkdir(
    parents=True,
    exist_ok=True,
)

CHAT_UPLOADS.mkdir(
    parents=True,
    exist_ok=True,
)


# Максимальные размеры файлов

MAX_AVATAR_SIZE = 4 * 1024 * 1024

MAX_CHAT_IMAGE_SIZE = 300 * 1024 * 1024

MAX_CHAT_VIDEO_SIZE = 500 * 1024 * 1024


ALLOWED_IMAGE_TYPES = {
    "image/jpeg",
    "image/jpg",
    "image/png",
    "image/webp",
    "image/gif",
}


ALLOWED_VIDEO_TYPES = {
    "video/mp4",
    "video/webm",
    "video/quicktime",
}


# =========================================================
# APP
# =========================================================

app = FastAPI(
    title="MotoHub"
)


templates = Jinja2Templates(
    directory=str(
        Path(__file__).parent / "templates"
    )
)


app.mount(
    "/static",
    StaticFiles(
        directory=str(
            BASE / "static"
        )
    ),
    name="static",
)


serializer = URLSafeSerializer(
    os.getenv(
        "SECRET_KEY",
        "dev-secret"
    )
)


# =========================================================
# STARTUP
# =========================================================

@app.on_event("startup")
def startup():
    init_db()


# =========================================================
# PASSWORD HELPERS
# =========================================================

def hash_password(password: str) -> str:
    """
    PBKDF2-SHA256 hash.

    Формат:
    pbkdf2$iterations$salt$hash
    """

    password = str(password)

    iterations = 310000

    salt = secrets.token_bytes(16)

    digest = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        iterations,
    )

    return (
        f"pbkdf2${iterations}$"
        f"{salt.hex()}$"
        f"{digest.hex()}"
    )


def verify_password(
    password: str,
    stored_hash: str | None,
) -> bool:

    if not password:
        return False

    if not stored_hash:
        return False

    try:

        parts = stored_hash.split("$")

        if len(parts) != 4:
            return False

        algorithm = parts[0]
        iterations = int(parts[1])
        salt = bytes.fromhex(parts[2])
        expected = bytes.fromhex(parts[3])

        if algorithm != "pbkdf2":
            return False

        actual = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt,
            iterations,
        )

        return secrets.compare_digest(
            actual,
            expected,
        )

    except Exception:
        return False


# =========================================================
# AUTH HELPERS
# =========================================================

def clean_email(email: str):
    return email.strip().lower()


def valid_email(email: str) -> bool:

    if not email:
        return False

    if "@" not in email:
        return False

    domain = email.split("@")[-1]

    if "." not in domain:
        return False

    if len(email) > 255:
        return False

    return True


def create_session_response(
    email: str,
    redirect_to: str = "/",
):

    response = RedirectResponse(
        redirect_to,
        303,
    )

    response.set_cookie(
        "motohub_session",
        serializer.dumps(
            {
                "email": email,
            }
        ),
        httponly=True,
        samesite="lax",
        max_age=604800,
    )

    return response


def session_email(request: Request):

    token = request.cookies.get(
        "motohub_session"
    )

    if not token:
        return None

    try:

        data = serializer.loads(
            token
        )

        return data.get(
            "email"
        )

    except BadSignature:

        return None


def session_user(request: Request):

    email = session_email(
        request
    )

    if not email:
        return None

    return get_user(
        email
    )


def ws_user(ws: WebSocket):

    token = ws.cookies.get(
        "motohub_session"
    )

    if not token:
        return None

    try:

        data = serializer.loads(
            token
        )

        email = data.get(
            "email"
        )

        if not email:
            return None

        return get_user(
            email
        )

    except BadSignature:

        return None


def public_user(row):

    data = dict(row)

    data.pop(
        "muted_until",
        None,
    )

    data.pop(
        "is_banned",
        None,
    )

    data.pop(
        "password_hash",
        None,
    )

    return data


# =========================================================
# HOME
# =========================================================

@app.get(
    "/",
    response_class=HTMLResponse,
)
def home(
    request: Request,
):

    c = conn()

    news = c.execute(
        """
        SELECT *
        FROM news
        ORDER BY id DESC
        LIMIT 6
        """
    ).fetchall()

    events = c.execute(
        """
        SELECT *
        FROM events
        ORDER BY starts_at ASC
        LIMIT 6
        """
    ).fetchall()

    c.close()

    return templates.TemplateResponse(
        "index.html",
        {
            "request": request,
            "news": news,
            "events": events,
            "user": session_user(
                request
            ),
        },
    )


# =========================================================
# REGISTER PAGE
# =========================================================

@app.get(
    "/register",
    response_class=HTMLResponse,
)
def register_page(
    request: Request,
):

    user = session_user(
        request
    )

    if user:
        return RedirectResponse(
            "/",
            303,
        )

    return templates.TemplateResponse(
        "register.html",
        {
            "request": request,
            "user": None,
        },
    )


# =========================================================
# REGISTER REQUEST OTP
# =========================================================

@app.post(
    "/auth/register/request"
)
def register_request(
    email: str = Form(...),
    password: str = Form(...),
):

    email = clean_email(
        email
    )

    password = str(
        password
    )


    # -----------------------------------------------------
    # EMAIL
    # -----------------------------------------------------

    if not valid_email(email):

        return JSONResponse(
            {
                "detail":
                    "Введите корректный email.",
            },
            status_code=400,
        )


    # -----------------------------------------------------
    # PASSWORD
    # -----------------------------------------------------

    if len(password) < 8:

        return JSONResponse(
            {
                "detail":
                    "Пароль должен содержать минимум 8 символов.",
            },
            status_code=400,
        )


    if not any(
        char.isalpha()
        for char in password
    ):

        return JSONResponse(
            {
                "detail":
                    "Пароль должен содержать хотя бы одну букву.",
            },
            status_code=400,
        )


    if not any(
        char.isdigit()
        for char in password
    ):

        return JSONResponse(
            {
                "detail":
                    "Пароль должен содержать хотя бы одну цифру.",
            },
            status_code=400,
        )


    # -----------------------------------------------------
    # EXISTING USER
    # -----------------------------------------------------

    existing = get_user(
        email
    )

    if existing:

        return JSONResponse(
            {
                "detail":
                    "Аккаунт с таким email уже существует. Войдите в аккаунт.",
            },
            status_code=409,
        )


    # -----------------------------------------------------
    # RATE LIMIT
    # -----------------------------------------------------

    c = conn()

    recent = c.execute(
        """
        SELECT id
        FROM otp
        WHERE email=?
          AND created_at>?
        ORDER BY id DESC
        LIMIT 1
        """,
        (
            email,
            (
                now()
                - timedelta(
                    seconds=60
                )
            ).isoformat(),
        ),
    ).fetchone()

    if recent:

        c.close()

        return JSONResponse(
            {
                "detail":
                    "Подождите 60 секунд перед повторной отправкой кода.",
            },
            status_code=429,
        )


    # -----------------------------------------------------
    # OTP
    # -----------------------------------------------------

    code = (
        f"{secrets.randbelow(1000000):06d}"
    )

    code_hash = hashlib.sha256(
        code.encode()
    ).hexdigest()

    created = now()


    c.execute(
        """
        INSERT INTO otp(
            email,
            code_hash,
            expires_at,
            created_at
        )
        VALUES(?,?,?,?)
        """,
        (
            email,
            code_hash,
            (
                created
                + timedelta(
                    minutes=10
                )
            ).isoformat(),
            created.isoformat(),
        ),
    )


    # -----------------------------------------------------
    # SAVE PENDING REGISTRATION
    # -----------------------------------------------------

    password_hash = hash_password(
        password
    )

    c.execute(
        """
        DELETE FROM pending_auth
        WHERE email=?
          AND purpose='register'
        """,
        (
            email,
        ),
    )

    c.execute(
        """
        INSERT INTO pending_auth(
            email,
            password_hash,
            purpose,
            expires_at,
            created_at
        )
        VALUES(?,?,?,?,?)
        """,
        (
            email,
            password_hash,
            "register",
            (
                created
                + timedelta(
                    minutes=10
                )
            ).isoformat(),
            created.isoformat(),
        ),
    )


    c.commit()
    c.close()


    # -----------------------------------------------------
    # SEND EMAIL
    # -----------------------------------------------------

    try:

        send_otp(
            email,
            code,
        )

    except Exception:

        # Удаляем OTP и pending registration,
        # если письмо не отправилось.

        c = conn()

        c.execute(
            """
            DELETE FROM otp
            WHERE email=?
              AND code_hash=?
            """,
            (
                email,
                code_hash,
            ),
        )

        c.execute(
            """
            DELETE FROM pending_auth
            WHERE email=?
              AND purpose='register'
            """,
            (
                email,
            ),
        )

        c.commit()
        c.close()

        return JSONResponse(
            {
                "detail":
                    "Не удалось отправить код на email. Проверь настройки Gmail.",
            },
            status_code=500,
        )


    return {
        "ok": True,
        "email": email,
    }


# =========================================================
# REGISTER VERIFY OTP
# =========================================================

@app.post(
    "/auth/register/verify"
)
def register_verify(
    email: str = Form(...),
    code: str = Form(...),
):

    email = clean_email(
        email
    )

    code = (
        str(code)
        .strip()
        .replace(" ", "")
    )


    if not valid_email(email):

        return JSONResponse(
            {
                "detail":
                    "Некорректный email.",
            },
            status_code=400,
        )


    if not code.isdigit() or len(code) != 6:

        return JSONResponse(
            {
                "detail":
                    "Введите 6-значный код.",
            },
            status_code=400,
        )


    c = conn()


    # -----------------------------------------------------
    # PENDING REGISTRATION
    # -----------------------------------------------------

    pending = c.execute(
        """
        SELECT *
        FROM pending_auth
        WHERE email=?
          AND purpose='register'
        ORDER BY id DESC
        LIMIT 1
        """,
        (
            email,
        ),
    ).fetchone()


    if not pending:

        c.close()

        return JSONResponse(
            {
                "detail":
                    "Регистрация не найдена. Запросите новый код.",
            },
            status_code=404,
        )


    if (
        datetime.fromisoformat(
            pending["expires_at"]
        )
        < now()
    ):

        c.execute(
            """
            DELETE FROM pending_auth
            WHERE id=?
            """,
            (
                pending["id"],
            ),
        )

        c.commit()
        c.close()

        return JSONResponse(
            {
                "detail":
                    "Срок регистрации истёк. Запросите новый код.",
            },
            status_code=400,
        )


    # -----------------------------------------------------
    # OTP
    # -----------------------------------------------------

    otp = c.execute(
        """
        SELECT *
        FROM otp
        WHERE email=?
          AND consumed=0
        ORDER BY id DESC
        LIMIT 1
        """,
        (
            email,
        ),
    ).fetchone()


    if not otp:

        c.close()

        return JSONResponse(
            {
                "detail":
                    "Код не найден. Запросите новый код.",
            },
            status_code=400,
        )


    if (
        datetime.fromisoformat(
            otp["expires_at"]
        )
        < now()
    ):

        c.close()

        return JSONResponse(
            {
                "detail":
                    "Код истёк. Запросите новый код.",
            },
            status_code=400,
        )


    if otp["attempts"] >= 5:

        c.close()

        return JSONResponse(
            {
                "detail":
                    "Слишком много попыток. Запросите новый код.",
            },
            status_code=429,
        )


    entered_hash = hashlib.sha256(
        code.encode()
    ).hexdigest()


    if not secrets.compare_digest(
        entered_hash,
        otp["code_hash"],
    ):

        c.execute(
            """
            UPDATE otp
            SET attempts=attempts+1
            WHERE id=?
            """,
            (
                otp["id"],
            ),
        )

        c.commit()
        c.close()

        return JSONResponse(
            {
                "detail":
                    "Неверный код.",
            },
            status_code=400,
        )


    # -----------------------------------------------------
    # CHECK AGAIN
    # -----------------------------------------------------

    existing = get_user(
        email
    )

    if existing:

        c.close()

        return JSONResponse(
            {
                "detail":
                    "Аккаунт с таким email уже существует.",
            },
            status_code=409,
        )


    # -----------------------------------------------------
    # CREATE USER
    # -----------------------------------------------------

    c.execute(
        """
        INSERT INTO users(
            email,
            password_hash,
            display_name,
            role,
            created_at
        )
        VALUES(?,?,?,?,?)
        """,
        (
            email,
            pending["password_hash"],
            email.split("@")[0],
            "USER",
            now().isoformat(),
        ),
    )


    # OTP consumed

    c.execute(
        """
        UPDATE otp
        SET consumed=1
        WHERE id=?
        """,
        (
            otp["id"],
        ),
    )


    # Remove pending registration

    c.execute(
        """
        DELETE FROM pending_auth
        WHERE id=?
        """,
        (
            pending["id"],
        ),
    )


    c.commit()

    user_id = c.execute(
        "SELECT last_insert_rowid()"
    ).fetchone()[0]

    c.close()


    # -----------------------------------------------------
    # CREATE SESSION
    # -----------------------------------------------------

    response = JSONResponse(
        {
            "ok": True,
            "redirect": "/",
            "user_id": user_id,
        }
    )


    response.set_cookie(
        "motohub_session",
        serializer.dumps(
            {
                "email": email,
            }
        ),
        httponly=True,
        samesite="lax",
        max_age=604800,
    )


    return response


# =========================================================
# LOGIN
# =========================================================

@app.get(
    "/login",
    response_class=HTMLResponse,
)
def login(
    request: Request,
):

    return templates.TemplateResponse(
        "login.html",
        {
            "request": request,
            "error": None,
            "user": session_user(
                request
            ),
        },
    )


# =========================================================
# OLD LOGIN OTP REQUEST
# =========================================================

@app.post(
    "/auth/request"
)
def request_code(
    email: str = Form(...),
):

    email = clean_email(
        email
    )


    if not valid_email(email):

        return RedirectResponse(
            "/login?error=Неверный email",
            303,
        )


    c = conn()


    recent = c.execute(
        """
        SELECT id
        FROM otp
        WHERE email=?
          AND created_at>?
        """,
        (
            email,
            (
                now()
                - timedelta(
                    seconds=60
                )
            ).isoformat(),
        ),
    ).fetchone()


    if recent:

        c.close()

        return RedirectResponse(
            "/login?error=Подождите 60 секунд",
            303,
        )


    code = (
        f"{secrets.randbelow(1000000):06d}"
    )


    code_hash = hashlib.sha256(
        code.encode()
    ).hexdigest()


    created = now()


    c.execute(
        """
        INSERT INTO otp(
            email,
            code_hash,
            expires_at,
            created_at
        )
        VALUES(?,?,?,?)
        """,
        (
            email,
            code_hash,
            (
                created
                + timedelta(
                    minutes=10
                )
            ).isoformat(),
            created.isoformat(),
        ),
    )


    c.commit()
    c.close()


    try:

        send_otp(
            email,
            code,
        )

    except Exception:

        return RedirectResponse(
            "/login?error=Не удалось отправить код на email",
            303,
        )


    return RedirectResponse(
        f"/verify?email={email}",
        303,
    )


# =========================================================
# VERIFY PAGE
# =========================================================

@app.get(
    "/verify",
    response_class=HTMLResponse,
)
def verify_page(
    request: Request,
    email: str,
):

    return templates.TemplateResponse(
        "verify.html",
        {
            "request": request,
            "email": email,
            "error": None,
            "user": session_user(
                request
            ),
        },
    )


# =========================================================
# OLD LOGIN VERIFY OTP
# =========================================================

@app.post(
    "/auth/verify"
)
def verify(
    email: str = Form(...),
    code: str = Form(...),
):

    email = clean_email(
        email
    )


    c = conn()


    row = c.execute(
        """
        SELECT *
        FROM otp
        WHERE email=?
          AND consumed=0
        ORDER BY id DESC
        LIMIT 1
        """,
        (
            email,
        ),
    ).fetchone()


    if not row:

        c.close()

        return RedirectResponse(
            f"/verify?email={email}&error=Код не найден",
            303,
        )


    if (
        datetime.fromisoformat(
            row["expires_at"]
        )
        < now()
    ):

        c.close()

        return RedirectResponse(
            f"/verify?email={email}&error=Код истёк",
            303,
        )


    if row["attempts"] >= 5:

        c.close()

        return RedirectResponse(
            f"/verify?email={email}&error=Слишком много попыток",
            303,
        )


    entered_hash = hashlib.sha256(
        code.strip().encode()
    ).hexdigest()


    if not secrets.compare_digest(
        entered_hash,
        row["code_hash"],
    ):

        c.execute(
            """
            UPDATE otp
            SET attempts=attempts+1
            WHERE id=?
            """,
            (
                row["id"],
            ),
        )

        c.commit()
        c.close()

        return RedirectResponse(
            f"/verify?email={email}&error=Неверный код",
            303,
        )


    c.execute(
        """
        UPDATE otp
        SET consumed=1
        WHERE id=?
        """,
        (
            row["id"],
        ),
    )


    c.commit()
    c.close()


    create_user(
        email
    )


    return create_session_response(
        email,
        "/",
    )


# =========================================================
# LOGOUT
# =========================================================

@app.post(
    "/logout"
)
def logout():

    response = RedirectResponse(
        "/",
        303,
    )

    response.delete_cookie(
        "motohub_session"
    )

    return response


# =========================================================
# PROFILE REDIRECT
# =========================================================

@app.get(
    "/profile",
    response_class=HTMLResponse,
)
def my_profile(
    request: Request,
):

    user = session_user(
        request
    )


    if not user:

        return RedirectResponse(
            "/login",
            303,
        )


    return RedirectResponse(
        f"/profile/{user['id']}",
        303,
    )


# =========================================================
# PROFILE PAGE
# =========================================================

@app.get(
    "/profile/{user_id}",
    response_class=HTMLResponse,
)
def profile_page(
    request: Request,
    user_id: int,
):

    viewer = session_user(
        request
    )

    profile = get_user_by_id(
        user_id
    )


    if not profile:

        return RedirectResponse(
            "/",
            303,
        )


    c = conn()


    achievements = c.execute(
        """
        SELECT
            a.*,
            e.title AS event_title,
            e.starts_at,
            e.location
        FROM achievements a
        LEFT JOIN events e
            ON e.id = a.event_id
        WHERE a.user_id=?
        ORDER BY
            COALESCE(
                e.starts_at,
                a.created_at
            ) DESC,
            a.id DESC
        """,
        (
            user_id,
        ),
    ).fetchall()


    stats = c.execute(
        """
        SELECT
            COUNT(*) total,

            SUM(
                CASE
                    WHEN place=1
                    THEN 1
                    ELSE 0
                END
            ) firsts,

            SUM(
                CASE
                    WHEN place=2
                    THEN 1
                    ELSE 0
                END
            ) seconds,

            SUM(
                CASE
                    WHEN place=3
                    THEN 1
                    ELSE 0
                END
            ) thirds

        FROM achievements

        WHERE user_id=?
        """,
        (
            user_id,
        ),
    ).fetchone()


    c.close()


    return templates.TemplateResponse(
        "profile.html",
        {
            "request": request,
            "user": viewer,
            "profile": profile,
            "achievements": achievements,
            "stats": stats,
        },
    )


# =========================================================
# PROFILE UPDATE
# =========================================================

@app.post(
    "/profile/update"
)
async def profile_update(
    request: Request,
    display_name: str = Form(""),
    bio: str = Form(""),
    motorcycle: str = Form(""),
    city: str = Form(""),
    avatar: UploadFile | None = File(None),
):

    user = session_user(
        request
    )


    if not user:

        return RedirectResponse(
            "/login",
            303,
        )


    avatar_url = user[
        "avatar_url"
    ]


    if (
        avatar
        and avatar.filename
    ):

        extension = Path(
            avatar.filename
        ).suffix.lower()


        if extension not in {
            ".jpg",
            ".jpeg",
            ".png",
            ".webp",
        }:

            return RedirectResponse(
                "/profile?error=Формат фото не поддерживается",
                303,
            )


        if (
            avatar.content_type
            and not avatar.content_type.startswith(
                "image/"
            )
        ):

            return RedirectResponse(
                "/profile?error=Это не изображение",
                303,
            )


        data = await avatar.read()


        if len(data) > MAX_AVATAR_SIZE:

            return RedirectResponse(
                "/profile?error=Фото больше 4 МБ",
                303,
            )


        filename = (
            f"user_{user['id']}"
            f"{extension}"
        )


        (
            UPLOADS / filename
        ).write_bytes(
            data
        )


        avatar_url = (
            f"/static/uploads/{filename}"
        )


    c = conn()


    c.execute(
        """
        UPDATE users
        SET
            display_name=?,
            bio=?,
            motorcycle=?,
            city=?,
            avatar_url=?
        WHERE id=?
        """,
        (
            display_name.strip()[:80]
            or None,

            bio.strip()[:500],

            motorcycle.strip()[:100],

            city.strip()[:100],

            avatar_url,

            user["id"],
        ),
    )


    c.commit()
    c.close()


    return RedirectResponse(
        f"/profile/{user['id']}",
        303,
    )


# =========================================================
# CHAT PAGE
# =========================================================

@app.get(
    "/chat",
    response_class=HTMLResponse,
)
def chat_page(
    request: Request,
):

    user = session_user(
        request
    )


    if not user:

        return RedirectResponse(
            "/login",
            303,
        )


    return templates.TemplateResponse(
        "chat.html",
        {
            "request": request,
            "user": user,
        },
    )


# =========================================================
# CHAT USERS
# =========================================================

@app.get(
    "/api/chat/users"
)
def chat_users(
    request: Request,
):

    user = session_user(
        request
    )


    if not user:

        return JSONResponse(
            {
                "error": "auth",
            },
            status_code=401,
        )


    c = conn()


    rows = c.execute(
        """
        SELECT
            id,
            email,
            display_name,
            role,
            is_banned,
            avatar_url,
            motorcycle,
            city
        FROM users
        WHERE id != ?
        ORDER BY
            COALESCE(
                display_name,
                email
            )
        """,
        (
            user["id"],
        ),
    ).fetchall()


    c.close()


    return [
        public_user(row)
        for row in rows
        if not row["is_banned"]
    ]


# =========================================================
# CHAT HISTORY
# =========================================================

@app.get(
    "/api/chat/messages/{other_id}"
)
def chat_history(
    request: Request,
    other_id: int,
):

    user = session_user(
        request
    )

    other = get_user_by_id(
        other_id
    )


    if not user:

        return JSONResponse(
            {
                "error": "auth",
            },
            status_code=401,
        )


    if not other:

        return JSONResponse(
            {
                "error": "user_not_found",
            },
            status_code=404,
        )


    c = conn()


    rows = c.execute(
        """
        SELECT
            id,
            email,
            display_name,
            text,
            created_at,
            recipient_id,
            is_read,
            attachment_url,
            attachment_type,
            attachment_name
        FROM messages
        WHERE recipient_id IS NOT NULL
        AND (
            (
                email=?
                AND recipient_id=?
            )
            OR
            (
                email=?
                AND recipient_id=?
            )
        )
        ORDER BY id DESC
        LIMIT 100
        """,
        (
            user["email"],
            other_id,

            other["email"],
            user["id"],
        ),
    ).fetchall()


    c.close()


    return [
        dict(row)
        for row in reversed(rows)
    ]


# =========================================================
# MARK READ
# =========================================================

@app.post(
    "/api/chat/read/{other_id}"
)
def mark_read(
    request: Request,
    other_id: int,
):

    user = session_user(
        request
    )

    other = get_user_by_id(
        other_id
    )


    if not user:

        return JSONResponse(
            {
                "error": "auth",
            },
            status_code=401,
        )


    if not other:

        return JSONResponse(
            {
                "error": "user_not_found",
            },
            status_code=404,
        )


    c = conn()


    c.execute(
        """
        UPDATE messages
        SET is_read=1
        WHERE
            email=?
            AND recipient_id=?
        """,
        (
            other["email"],
            user["id"],
        ),
    )


    c.commit()
    c.close()


    return {
        "ok": True,
    }


# =========================================================
# UNREAD
# =========================================================

@app.get(
    "/api/chat/unread"
)
def unread(
    request: Request,
):

    user = session_user(
        request
    )


    if not user:

        return JSONResponse(
            {
                "error": "auth",
            },
            status_code=401,
        )


    c = conn()


    rows = c.execute(
        """
        SELECT
            email,
            COUNT(*) count
        FROM messages
        WHERE
            recipient_id=?
            AND is_read=0
        GROUP BY email
        """,
        (
            user["id"],
        ),
    ).fetchall()


    c.close()


    return [
        dict(row)
        for row in rows
    ]


# =========================================================
# CHAT FILE UPLOAD
#
# PHOTO = 300 MB
# VIDEO = 500 MB
# =========================================================

@app.post(
    "/api/chat/upload"
)
async def chat_upload(
    request: Request,
    file: UploadFile = File(...),
):

    user = session_user(
        request
    )


    if not user:

        return JSONResponse(
            {
                "error": "auth",
            },
            status_code=401,
        )


    if user["is_banned"]:

        return JSONResponse(
            {
                "error":
                    "Аккаунт заблокирован",
            },
            status_code=403,
        )


    if not file.filename:

        raise HTTPException(
            status_code=400,
            detail="Файл не выбран",
        )


    content_type = (
        file.content_type
        or ""
    ).lower().strip()


    # -----------------------------------------------------
    # DETERMINE TYPE
    # -----------------------------------------------------

    if content_type in ALLOWED_IMAGE_TYPES:

        attachment_type = "image"

        max_size = (
            MAX_CHAT_IMAGE_SIZE
        )

    elif content_type in ALLOWED_VIDEO_TYPES:

        attachment_type = "video"

        max_size = (
            MAX_CHAT_VIDEO_SIZE
        )

    else:

        raise HTTPException(
            status_code=400,
            detail=(
                "Поддерживаются только "
                "JPG, PNG, WEBP, GIF, "
                "MP4, WEBM и MOV"
            ),
        )


    # -----------------------------------------------------
    # EXTENSION
    # -----------------------------------------------------

    extension = Path(
        file.filename
    ).suffix.lower()


    allowed_extensions = {
        ".jpg",
        ".jpeg",
        ".png",
        ".webp",
        ".gif",
        ".mp4",
        ".webm",
        ".mov",
    }


    if extension not in allowed_extensions:

        raise HTTPException(
            status_code=400,
            detail="Расширение файла не поддерживается",
        )


    # -----------------------------------------------------
    # UNIQUE FILE NAME
    # -----------------------------------------------------

    filename = (
        uuid.uuid4().hex
        + extension
    )


    destination = (
        CHAT_UPLOADS
        / filename
    )


    # -----------------------------------------------------
    # STREAM FILE TO DISK
    # -----------------------------------------------------

    total_size = 0

    chunk_size = 1024 * 1024


    try:

        with destination.open(
            "wb"
        ) as output:

            while True:

                chunk = await file.read(
                    chunk_size
                )


                if not chunk:
                    break


                total_size += len(
                    chunk
                )


                # -------------------------------------------------
                # SIZE CHECK
                # -------------------------------------------------

                if total_size > max_size:

                    output.close()


                    try:

                        destination.unlink(
                            missing_ok=True
                        )

                    except Exception:
                        pass


                    if attachment_type == "image":

                        raise HTTPException(
                            status_code=413,
                            detail=(
                                "Фото не должно "
                                "быть больше 300 МБ"
                            ),
                        )

                    else:

                        raise HTTPException(
                            status_code=413,
                            detail=(
                                "Видео не должно "
                                "быть больше 500 МБ"
                            ),
                        )


                output.write(
                    chunk
                )


    except HTTPException:

        raise


    except Exception:

        try:

            destination.unlink(
                missing_ok=True
            )

        except Exception:
            pass


        raise HTTPException(
            status_code=500,
            detail="Ошибка сохранения файла",
        )


    finally:

        try:

            await file.close()

        except Exception:
            pass


    return {
        "ok": True,

        "url":
            f"/static/uploads/chat/{filename}",

        "type":
            attachment_type,

        "name":
            file.filename,

        "size":
            total_size,
    }


# =========================================================
# ADMIN HELPERS
# =========================================================

def is_staff(
    user
):

    return (
        user
        and user["role"]
        in (
            "ADMIN",
            "MODERATOR",
        )
    )


def is_admin(
    user
):

    return (
        user
        and user["role"]
        == "ADMIN"
    )


# =========================================================
# ADMIN PAGE
# =========================================================

@app.get(
    "/admin",
    response_class=HTMLResponse,
)
def admin(
    request: Request,
):

    user = session_user(
        request
    )


    if not is_staff(
        user
    ):

        return RedirectResponse(
            "/",
            303,
        )


    c = conn()


    users = c.execute(
        """
        SELECT *
        FROM users
        ORDER BY id DESC
        """
    ).fetchall()


    news = c.execute(
        """
        SELECT *
        FROM news
        ORDER BY id DESC
        """
    ).fetchall()


    events = c.execute(
        """
        SELECT *
        FROM events
        ORDER BY starts_at ASC
        """
    ).fetchall()


    c.close()


    return templates.TemplateResponse(
        "admin.html",
        {
            "request": request,
            "user": user,
            "users": users,
            "news": news,
            "events": events,
        },
    )


# =========================================================
# ADMIN NEWS
# =========================================================

@app.post(
    "/admin/news"
)
def add_news(
    request: Request,
    title: str = Form(...),
    body: str = Form(...),
):

    user = session_user(
        request
    )


    if not is_staff(
        user
    ):

        return RedirectResponse(
            "/",
            303,
        )


    c = conn()


    c.execute(
        """
        INSERT INTO news(
            title,
            body,
            created_at
        )
        VALUES(?,?,?)
        """,
        (
            title.strip(),
            body.strip(),
            now().isoformat(),
        ),
    )


    c.commit()
    c.close()


    return RedirectResponse(
        "/admin",
        303,
    )


# =========================================================
# ADMIN EVENTS
# =========================================================

@app.post(
    "/admin/events"
)
def add_event(
    request: Request,
    title: str = Form(...),
    description: str = Form(...),
    starts_at: str = Form(...),
    location: str = Form(""),
):

    user = session_user(
        request
    )


    if not is_staff(
        user
    ):

        return RedirectResponse(
            "/",
            303,
        )


    c = conn()


    c.execute(
        """
        INSERT INTO events(
            title,
            description,
            starts_at,
            location,
            created_at
        )
        VALUES(?,?,?,?,?)
        """,
        (
            title.strip(),
            description.strip(),
            starts_at,
            location.strip(),
            now().isoformat(),
        ),
    )


    c.commit()
    c.close()


    return RedirectResponse(
        "/admin",
        303,
    )


# =========================================================
# ADMIN ROLE
# =========================================================

@app.post(
    "/admin/role"
)
def role(
    request: Request,
    user_id: int = Form(...),
    role: str = Form(...),
):

    actor = session_user(
        request
    )


    if (
        not is_admin(actor)
        or role
        not in (
            "USER",
            "MODERATOR",
            "ADMIN",
        )
    ):

        return RedirectResponse(
            "/admin",
            303,
        )


    c = conn()


    c.execute(
        """
        UPDATE users
        SET role=?
        WHERE id=?
        """,
        (
            role,
            user_id,
        ),
    )


    c.commit()
    c.close()


    return RedirectResponse(
        "/admin",
        303,
    )


# =========================================================
# ADMIN BAN
# =========================================================

@app.post(
    "/admin/ban"
)
def ban(
    request: Request,
    user_id: int = Form(...),
    banned: int = Form(...),
):

    actor = session_user(
        request
    )


    if not is_admin(
        actor
    ):

        return RedirectResponse(
            "/admin",
            303,
        )


    c = conn()


    c.execute(
        """
        UPDATE users
        SET is_banned=?
        WHERE id=?
        """,
        (
            1 if banned else 0,
            user_id,
        ),
    )


    c.commit()
    c.close()


    return RedirectResponse(
        "/admin",
        303,
    )


# =========================================================
# ADMIN PROFILE
# =========================================================

@app.post(
    "/admin/profile"
)
def admin_profile(
    request: Request,
    user_id: int = Form(...),
    display_name: str = Form(""),
    bio: str = Form(""),
    motorcycle: str = Form(""),
    city: str = Form(""),
):

    actor = session_user(
        request
    )


    if not is_staff(
        actor
    ):

        return RedirectResponse(
            "/admin",
            303,
        )


    c = conn()


    c.execute(
        """
        UPDATE users
        SET
            display_name=?,
            bio=?,
            motorcycle=?,
            city=?
        WHERE id=?
        """,
        (
            display_name.strip()[:80]
            or None,

            bio.strip()[:500],

            motorcycle.strip()[:100],

            city.strip()[:100],

            user_id,
        ),
    )


    c.commit()
    c.close()


    return RedirectResponse(
        "/admin",
        303,
    )


# =========================================================
# ADMIN ACHIEVEMENT
# =========================================================

@app.post(
    "/admin/achievement"
)
def admin_achievement(
    request: Request,
    user_id: int = Form(...),
    event_id: str = Form(""),
    place: str = Form(""),
    award: str = Form(""),
    note: str = Form(""),
):

    actor = session_user(
        request
    )


    if not is_staff(
        actor
    ):

        return RedirectResponse(
            "/admin",
            303,
        )


    # -----------------------------------------------------
    # EVENT ID
    # -----------------------------------------------------

    event_id_num = None


    if event_id.strip():

        try:

            event_id_num = int(
                event_id.strip()
            )

        except ValueError:

            event_id_num = None


    # -----------------------------------------------------
    # PLACE
    # -----------------------------------------------------

    place_num = None


    if place.strip():

        try:

            place_num = int(
                place.strip()
            )

        except ValueError:

            place_num = None


    c = conn()


    c.execute(
        """
        INSERT INTO achievements(
            user_id,
            event_id,
            place,
            award,
            note,
            created_at
        )
        VALUES(?,?,?,?,?,?)
        """,
        (
            user_id,

            event_id_num,

            place_num,

            award.strip()[:120],

            note.strip()[:500],

            now().isoformat(),
        ),
    )


    c.commit()
    c.close()


    return RedirectResponse(
        "/admin",
        303,
    )


# =========================================================
# DELETE ACHIEVEMENT
# =========================================================

@app.post(
    "/admin/achievement/delete"
)
def admin_achievement_delete(
    request: Request,
    achievement_id: int = Form(...),
):

    actor = session_user(
        request
    )


    if not is_staff(
        actor
    ):

        return RedirectResponse(
            "/admin",
            303,
        )


    c = conn()


    c.execute(
        """
        DELETE FROM achievements
        WHERE id=?
        """,
        (
            achievement_id,
        ),
    )


    c.commit()
    c.close()


    return RedirectResponse(
        "/admin",
        303,
    )


# =========================================================
# CHAT MANAGER
# =========================================================

class ChatManager:

    def __init__(self):

        self.connections = {}


    async def connect(
        self,
        user_id,
        ws,
    ):

        await ws.accept()

        self.connections.setdefault(
            user_id,
            set(),
        ).add(
            ws
        )


    def disconnect(
        self,
        user_id,
        ws,
    ):

        if (
            user_id
            not in self.connections
        ):

            return


        self.connections[
            user_id
        ].discard(
            ws
        )


        if not self.connections[
            user_id
        ]:

            del self.connections[
                user_id
            ]


    async def send_user(
        self,
        user_id,
        payload,
    ):

        dead = []


        for ws in list(
            self.connections.get(
                user_id,
                set(),
            )
        ):

            try:

                await ws.send_json(
                    payload
                )

            except Exception:

                dead.append(
                    ws
                )


        for ws in dead:

            self.disconnect(
                user_id,
                ws,
            )


    async def broadcast_public(
        self,
        payload,
    ):

        for user_id in list(
            self.connections
        ):

            await self.send_user(
                user_id,
                payload,
            )


    def online_ids(self):

        return list(
            self.connections
        )


manager = ChatManager()


# =========================================================
# PUBLIC CHAT HISTORY
# =========================================================

def public_history():

    c = conn()


    rows = c.execute(
        """
        SELECT
            id,
            email,
            display_name,
            text,
            created_at,
            recipient_id,
            is_read,
            attachment_url,
            attachment_type,
            attachment_name
        FROM messages
        WHERE recipient_id IS NULL
        ORDER BY id DESC
        LIMIT 60
        """
    ).fetchall()


    c.close()


    return [
        dict(row)
        for row in reversed(rows)
    ]


# =========================================================
# WEBSOCKET CHAT
# =========================================================

@app.websocket(
    "/ws/chat"
)
async def chat(
    ws: WebSocket,
):

    user = ws_user(
        ws
    )


    if (
        not user
        or user["is_banned"]
    ):

        await ws.close(
            code=1008
        )

        return


    await manager.connect(
        user["id"],
        ws,
    )


    try:

        # -------------------------------------------------
        # PRESENCE
        # -------------------------------------------------

        await ws.send_json(
            {
                "type": "presence",
                "online":
                    manager.online_ids(),
            }
        )


        # -------------------------------------------------
        # PUBLIC HISTORY
        # -------------------------------------------------

        for message in public_history():

            await ws.send_json(
                {
                    "type": "public",
                    "message": message,
                }
            )


        # -------------------------------------------------
        # LOOP
        # -------------------------------------------------

        while True:

            data = await ws.receive_json()


            text = str(
                data.get(
                    "text",
                    "",
                )
            ).strip()


            attachment_url = data.get(
                "attachment_url"
            )

            attachment_type = data.get(
                "attachment_type"
            )

            attachment_name = data.get(
                "attachment_name"
            )


            # -------------------------------------------------
            # MESSAGE VALIDATION
            # -------------------------------------------------

            if len(text) > 2000:

                continue


            if (
                not text
                and not attachment_url
            ):

                continue


            # -------------------------------------------------
            # MUTE
            # -------------------------------------------------

            if (
                user["muted_until"]
                and user["muted_until"]
                > now().isoformat()
            ):

                continue


            # -------------------------------------------------
            # RECIPIENT
            # -------------------------------------------------

            target = data.get(
                "recipient_id"
            )


            recipient = None


            if target not in (
                None,
                "",
                0,
                "0",
            ):

                try:

                    target = int(
                        target
                    )

                except (
                    ValueError,
                    TypeError,
                ):

                    continue


                recipient = get_user_by_id(
                    target
                )


                if (
                    not recipient
                    or recipient["is_banned"]
                    or recipient["id"]
                    == user["id"]
                ):

                    continue


            # -------------------------------------------------
            # ATTACHMENT VALIDATION
            # -------------------------------------------------

            if attachment_url:

                if (
                    not isinstance(
                        attachment_url,
                        str,
                    )
                    or not attachment_url.startswith(
                        "/static/uploads/chat/"
                    )
                ):

                    attachment_url = None
                    attachment_type = None
                    attachment_name = None


                if attachment_type not in (
                    "image",
                    "video",
                    None,
                ):

                    attachment_type = None


            # -------------------------------------------------
            # SAVE
            # -------------------------------------------------

            c = conn()


            created = now().isoformat()


            c.execute(
                """
                INSERT INTO messages(
                    email,
                    display_name,
                    text,
                    created_at,
                    recipient_id,
                    is_read,
                    attachment_url,
                    attachment_type,
                    attachment_name
                )
                VALUES(?,?,?,?,?,?,?,?,?)
                """,
                (
                    user["email"],

                    (
                        user["display_name"]
                        or user["email"]
                        .split("@")[0]
                    ),

                    text,

                    created,

                    (
                        recipient["id"]
                        if recipient
                        else None
                    ),

                    (
                        0
                        if recipient
                        else 1
                    ),

                    attachment_url,

                    attachment_type,

                    (
                        str(
                            attachment_name
                        )[:255]
                        if attachment_name
                        else None
                    ),
                ),
            )


            c.commit()


            row = c.execute(
                """
                SELECT
                    id,
                    email,
                    display_name,
                    text,
                    created_at,
                    recipient_id,
                    is_read,
                    attachment_url,
                    attachment_type,
                    attachment_name
                FROM messages
                WHERE id=last_insert_rowid()
                """
            ).fetchone()


            c.close()


            payload = {
                "type":
                    "dm"
                    if recipient
                    else "public",

                "message":
                    dict(row),
            }


            # -------------------------------------------------
            # PRIVATE MESSAGE
            # -------------------------------------------------

            if recipient:

                await manager.send_user(
                    user["id"],
                    payload,
                )


                await manager.send_user(
                    recipient["id"],
                    payload,
                )


            # -------------------------------------------------
            # PUBLIC MESSAGE
            # -------------------------------------------------

            else:

                await manager.broadcast_public(
                    payload
                )


            # -------------------------------------------------
            # PRESENCE UPDATE
            # -------------------------------------------------

            await manager.broadcast_public(
                {
                    "type": "presence",

                    "online":
                        manager.online_ids(),
                }
            )


    except WebSocketDisconnect:

        manager.disconnect(
            user["id"],
            ws,
        )


    except Exception:

        manager.disconnect(
            user["id"],
            ws,
        )
