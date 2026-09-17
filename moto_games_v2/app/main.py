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
# AUTH HELPERS
# =========================================================

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


def clean_email(
    email: str
):

    return email.strip().lower()


def public_user(row):

    data = dict(row)

    data.pop(
        "muted_until",
        None
    )

    data.pop(
        "is_banned",
        None
    )

    data.pop(
        "password_hash",
        None
    )

    return data


# =========================================================
# HOME
# =========================================================

@app.get(
    "/",
    response_class=HTMLResponse
)
def home(
    request: Request
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
        }
    )


# =========================================================
# AUTH HELPERS / PASSWORDS / DEVICES
# =========================================================

PBKDF2_ITERATIONS = 310_000
DEVICE_COOKIE = "motohub_device"
SESSION_MAX_AGE = 60 * 60 * 24 * 7
DEVICE_MAX_AGE = 60 * 60 * 24 * 365
OTP_TTL_MINUTES = 10
OTP_RESEND_SECONDS = 60


def hash_password(password: str) -> str:
    password = password or ""
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        PBKDF2_ITERATIONS,
    )
    return "pbkdf2_sha256$%d$%s$%s" % (
        PBKDF2_ITERATIONS,
        salt.hex(),
        digest.hex(),
    )


def verify_password(password: str, encoded: str | None) -> bool:
    if not password or not encoded:
        return False
    try:
        scheme, iterations, salt_hex, digest_hex = encoded.split("$", 3)
        if scheme != "pbkdf2_sha256":
            return False
        iterations = int(iterations)
        salt = bytes.fromhex(salt_hex)
        expected = bytes.fromhex(digest_hex)
        actual = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt,
            iterations,
        )
        return secrets.compare_digest(actual, expected)
    except Exception:
        return False


def valid_email(email: str) -> bool:
    email = clean_email(email)
    if len(email) > 254 or "@" not in email:
        return False
    local, domain = email.rsplit("@", 1)
    return bool(local and domain and "." in domain and " " not in email)


def valid_password(password: str) -> bool:
    if len(password) < 8 or len(password) > 128:
        return False
    return bool(
        any(ch.isalpha() for ch in password)
        and any(ch.isdigit() for ch in password)
    )


def make_session_response(email: str, redirect: str = "/", device_token: str | None = None):
    response = RedirectResponse(redirect, 303)
    response.set_cookie(
        "motohub_session",
        serializer.dumps({"email": email}),
        httponly=True,
        samesite="lax",
        secure=False,
        max_age=SESSION_MAX_AGE,
    )
    if device_token:
        response.set_cookie(
            DEVICE_COOKIE,
            device_token,
            httponly=True,
            samesite="lax",
            secure=False,
            max_age=DEVICE_MAX_AGE,
        )
    return response


def device_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def trusted_device_user(email: str, token: str | None):
    if not token:
        return None
    user = get_user(email)
    if not user:
        return None
    c = conn()
    row = c.execute(
        """
        SELECT * FROM trusted_devices
        WHERE user_id=? AND token_hash=?
        LIMIT 1
        """,
        (user["id"], device_hash(token)),
    ).fetchone()
    if row:
        c.execute(
            "UPDATE trusted_devices SET last_used_at=? WHERE id=?",
            (now().isoformat(), row["id"]),
        )
        c.commit()
    c.close()
    return user if row else None


def create_trusted_device(user_id: int, request: Request):
    token = secrets.token_urlsafe(48)
    user_agent = (request.headers.get("user-agent") or "")[:200]
    c = conn()
    c.execute(
        """
        INSERT INTO trusted_devices(
            user_id, token_hash, device_name, created_at, last_used_at
        ) VALUES(?,?,?,?,?)
        """,
        (
            user_id,
            device_hash(token),
            user_agent or "Устройство",
            now().isoformat(),
            now().isoformat(),
        ),
    )
    c.commit()
    c.close()
    return token


def create_otp(email: str, purpose: str, password_hash: str | None = None):
    email = clean_email(email)
    c = conn()
    recent = c.execute(
        """
        SELECT id FROM otp
        WHERE email=? AND created_at>?
        ORDER BY id DESC LIMIT 1
        """,
        (
            email,
            (now() - timedelta(seconds=OTP_RESEND_SECONDS)).isoformat(),
        ),
    ).fetchone()
    if recent:
        c.close()
        raise ValueError("Подождите 60 секунд")

    code = f"{secrets.randbelow(1000000):06d}"
    created = now()
    c.execute(
        """
        INSERT INTO otp(email, code_hash, expires_at, attempts, consumed, created_at)
        VALUES(?,?,?,0,0,?)
        """,
        (
            email,
            hashlib.sha256(code.encode()).hexdigest(),
            (created + timedelta(minutes=OTP_TTL_MINUTES)).isoformat(),
            created.isoformat(),
        ),
    )
    c.execute("DELETE FROM pending_auth WHERE email=?", (email,))
    c.execute(
        """
        INSERT INTO pending_auth(email,password_hash,purpose,expires_at,created_at)
        VALUES(?,?,?,?,?)
        """,
        (
            email,
            password_hash,
            purpose,
            (created + timedelta(minutes=OTP_TTL_MINUTES)).isoformat(),
            created.isoformat(),
        ),
    )
    c.commit()
    c.close()

    try:
        send_otp(email, code)
    except Exception:
        c = conn()
        c.execute("DELETE FROM pending_auth WHERE email=? AND purpose=?", (email, purpose))
        c.commit()
        c.close()
        raise


def verify_otp(email: str, code: str):
    email = clean_email(email)
    c = conn()
    row = c.execute(
        """
        SELECT * FROM otp
        WHERE email=? AND consumed=0
        ORDER BY id DESC LIMIT 1
        """,
        (email,),
    ).fetchone()
    pending = c.execute(
        """
        SELECT * FROM pending_auth
        WHERE email=?
        ORDER BY id DESC LIMIT 1
        """,
        (email,),
    ).fetchone()

    if not row:
        c.close()
        raise ValueError("Код не найден")
    if datetime.fromisoformat(row["expires_at"]) < now():
        c.close()
        raise ValueError("Код истёк")
    if row["attempts"] >= 5:
        c.close()
        raise ValueError("Слишком много попыток")

    entered = hashlib.sha256(code.strip().encode()).hexdigest()
    if not secrets.compare_digest(entered, row["code_hash"]):
        c.execute("UPDATE otp SET attempts=attempts+1 WHERE id=?", (row["id"],))
        c.commit()
        c.close()
        raise ValueError("Неверный код")

    c.execute("UPDATE otp SET consumed=1 WHERE id=?", (row["id"],))
    if pending:
        c.execute("DELETE FROM pending_auth WHERE id=?", (pending["id"],))
    c.commit()
    c.close()
    return pending


# =========================================================
# LOGIN PAGE
# =========================================================

@app.get("/login", response_class=HTMLResponse)
def login(request: Request):
    if session_user(request):
        return RedirectResponse("/", 303)
    return templates.TemplateResponse(
        "login.html",
        {
            "request": request,
            "error": request.query_params.get("error"),
        },
    )


# =========================================================
# REGISTER PAGE
# =========================================================

@app.get("/register", response_class=HTMLResponse)
def register_page(request: Request):
    if session_user(request):
        return RedirectResponse("/", 303)
    return templates.TemplateResponse(
        "register.html",
        {"request": request, "user": None},
    )


# =========================================================
# REGISTER REQUEST
# =========================================================

@app.post("/auth/register/request")
def register_request(email: str = Form(...), password: str = Form(...)):
    email = clean_email(email)
    password = password or ""

    if not valid_email(email):
        return JSONResponse({"detail": "Введите корректный email."}, status_code=400)
    if not valid_password(password):
        return JSONResponse(
            {"detail": "Пароль должен содержать минимум 8 символов, буквы и цифры."},
            status_code=400,
        )

    existing = get_user(email)
    if existing and existing["password_hash"]:
        return JSONResponse({"detail": "Аккаунт с таким email уже существует."}, status_code=409)

    try:
        create_otp(email, "register", hash_password(password))
    except ValueError as exc:
        return JSONResponse({"detail": str(exc)}, status_code=429)
    except Exception:
        return JSONResponse({"detail": "Не удалось отправить код на email."}, status_code=500)

    return {"ok": True}


# =========================================================
# REGISTER VERIFY
# =========================================================

@app.post("/auth/register/verify")
def register_verify(request: Request, email: str = Form(...), code: str = Form(...)):
    email = clean_email(email)
    try:
        pending = verify_otp(email, code)
    except ValueError as exc:
        return JSONResponse({"detail": str(exc)}, status_code=400)

    if not pending or pending["purpose"] != "register":
        return JSONResponse({"detail": "Сессия регистрации истекла. Запросите новый код."}, status_code=400)

    existing = get_user(email)
    if existing:
        c = conn()
        c.execute(
            "UPDATE users SET password_hash=? WHERE id=?",
            (pending["password_hash"], existing["id"]),
        )
        c.commit()
        c.close()
        user = get_user(email)
    else:
        user = create_user(email, pending["password_hash"])

    device = create_trusted_device(user["id"], request)
    response = JSONResponse({"ok": True, "redirect": "/"})
    response.set_cookie(
        "motohub_session",
        serializer.dumps({"email": email}),
        httponly=True,
        samesite="lax",
        max_age=SESSION_MAX_AGE,
    )
    response.set_cookie(
        DEVICE_COOKIE,
        device,
        httponly=True,
        samesite="lax",
        max_age=DEVICE_MAX_AGE,
    )
    return response


# =========================================================
# LOGIN
# =========================================================

@app.post("/auth/login")
def auth_login(request: Request, email: str = Form(...), password: str = Form(...)):
    email = clean_email(email)
    user = get_user(email)

    if not valid_email(email):
        return RedirectResponse("/login?error=Введите корректный email", 303)
    if not user:
        return RedirectResponse("/login?error=Аккаунт с таким email не найден", 303)
    if user["is_banned"]:
        return RedirectResponse("/login?error=Аккаунт заблокирован", 303)
    if not user["password_hash"]:
        return RedirectResponse("/login?error=Для этого аккаунта нужно зарегистрировать пароль", 303)
    if not verify_password(password, user["password_hash"]):
        return RedirectResponse("/login?error=Неверный email или пароль", 303)

    device = request.cookies.get(DEVICE_COOKIE)
    if trusted_device_user(email, device):
        return make_session_response(email)

    try:
        create_otp(email, "login", None)
    except ValueError as exc:
        return RedirectResponse(f"/login?error={str(exc)}", 303)
    except Exception:
        return RedirectResponse("/login?error=Не удалось отправить код на email", 303)

    return RedirectResponse(f"/verify?email={email}&purpose=login", 303)


# =========================================================
# COMPATIBILITY: OLD OTP REQUEST
# =========================================================

@app.post("/auth/request")
def request_code(email: str = Form(...)):
    email = clean_email(email)
    if not valid_email(email):
        return RedirectResponse("/login?error=Неверный email", 303)
    if not get_user(email):
        return RedirectResponse("/login?error=Аккаунт не найден", 303)
    try:
        create_otp(email, "login", None)
    except ValueError as exc:
        return RedirectResponse(f"/login?error={str(exc)}", 303)
    except Exception:
        return RedirectResponse("/login?error=Не удалось отправить код на email", 303)
    return RedirectResponse(f"/verify?email={email}&purpose=login", 303)


# =========================================================
# VERIFY PAGE
# =========================================================

@app.get("/verify", response_class=HTMLResponse)
def verify_page(request: Request, email: str, purpose: str = "login"):
    return templates.TemplateResponse(
        "verify.html",
        {
            "request": request,
            "email": clean_email(email),
            "error": request.query_params.get("error"),
            "purpose": purpose,
        },
    )


# =========================================================
# VERIFY LOGIN / COMPATIBILITY
# =========================================================

@app.post("/auth/verify")
def verify(request: Request, email: str = Form(...), code: str = Form(...)):
    email = clean_email(email)
    try:
        pending = verify_otp(email, code)
    except ValueError as exc:
        return RedirectResponse(
            f"/verify?email={email}&purpose=login&error={str(exc)}",
            303,
        )

    if not pending or pending["purpose"] != "login":
        return RedirectResponse(
            f"/login?error=Код предназначен для другого действия",
            303,
        )

    user = get_user(email)
    if not user:
        return RedirectResponse("/login?error=Аккаунт не найден", 303)
    if user["is_banned"]:
        return RedirectResponse("/login?error=Аккаунт заблокирован", 303)

    device = create_trusted_device(user["id"], request)
    return make_session_response(email, "/", device)


# =========================================================
# FORGOT PASSWORD PAGE
# =========================================================

@app.get("/forgot", response_class=HTMLResponse)
def forgot_page(request: Request):
    return templates.TemplateResponse(
        "forgot.html",
        {
            "request": request,
            "error": request.query_params.get("error"),
        },
    )


# =========================================================
# FORGOT PASSWORD REQUEST
# =========================================================

@app.post("/auth/forgot")
def forgot_request(email: str = Form(...)):
    email = clean_email(email)
    user = get_user(email)
    if not user:
        return RedirectResponse("/forgot?error=Аккаунт с таким email не найден", 303)
    try:
        create_otp(email, "reset", None)
    except ValueError as exc:
        return RedirectResponse(f"/forgot?error={str(exc)}", 303)
    except Exception:
        return RedirectResponse("/forgot?error=Не удалось отправить код на email", 303)
    return RedirectResponse(f"/verify?email={email}&purpose=reset", 303)


# =========================================================
# LOGOUT
# =========================================================

@app.post("/logout")
def logout():
    response = RedirectResponse("/", 303)
    response.delete_cookie("motohub_session")
    response.delete_cookie(DEVICE_COOKIE)
    return response


# =========================================================
# LOGOUT ALL DEVICES
# =========================================================

@app.post("/auth/logout-all")
def logout_all(request: Request):
    user = session_user(request)
    if not user:
        return RedirectResponse("/login", 303)
    c = conn()
    c.execute("DELETE FROM trusted_devices WHERE user_id=?", (user["id"],))
    c.commit()
    c.close()
    response = RedirectResponse("/profile", 303)
    response.delete_cookie("motohub_session")
    response.delete_cookie(DEVICE_COOKIE)
    return response


# =========================================================
# PROFILE REDIRECT
# =========================================================

@app.get(
    "/profile",
    response_class=HTMLResponse
)
def my_profile(
    request: Request
):

    user = session_user(
        request
    )

    if not user:

        return RedirectResponse(
            "/login",
            303
        )

    return RedirectResponse(
        f"/profile/{user['id']}",
        303
    )


# =========================================================
# PROFILE PAGE
# =========================================================

@app.get(
    "/profile/{user_id}",
    response_class=HTMLResponse
)
def profile_page(
    request: Request,
    user_id: int
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
            303
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
        )
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
        )
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
        }
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
            303
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
                303
            )


        if (
            avatar.content_type
            and not avatar.content_type.startswith(
                "image/"
            )
        ):

            return RedirectResponse(
                "/profile?error=Это не изображение",
                303
            )


        data = await avatar.read()


        if len(data) > MAX_AVATAR_SIZE:

            return RedirectResponse(
                "/profile?error=Фото больше 4 МБ",
                303
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
        )
    )


    c.commit()
    c.close()


    return RedirectResponse(
        f"/profile/{user['id']}",
        303
    )


# =========================================================
# CHAT PAGE
# =========================================================

@app.get(
    "/chat",
    response_class=HTMLResponse
)
def chat_page(
    request: Request
):

    user = session_user(
        request
    )


    if not user:

        return RedirectResponse(
            "/login",
            303
        )


    return templates.TemplateResponse(
        "chat.html",
        {
            "request": request,
            "user": user,
        }
    )


# =========================================================
# CHAT USERS
# =========================================================

@app.get(
    "/api/chat/users"
)
def chat_users(
    request: Request
):

    user = session_user(
        request
    )


    if not user:

        return JSONResponse(
            {
                "error": "auth"
            },
            status_code=401
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
        )
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
    other_id: int
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
                "error": "auth"
            },
            status_code=401
        )


    if not other:

        return JSONResponse(
            {
                "error": "user_not_found"
            },
            status_code=404
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
        )
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
    other_id: int
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
                "error": "auth"
            },
            status_code=401
        )


    if not other:

        return JSONResponse(
            {
                "error": "user_not_found"
            },
            status_code=404
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
        )
    )


    c.commit()
    c.close()


    return {
        "ok": True
    }


# =========================================================
# UNREAD
# =========================================================

@app.get(
    "/api/chat/unread"
)
def unread(
    request: Request
):

    user = session_user(
        request
    )


    if not user:

        return JSONResponse(
            {
                "error": "auth"
            },
            status_code=401
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
        )
    ).fetchall()


    c.close()


    return [
        dict(row)
        for row in rows
    ]


# =========================================================
# CHAT FILE UPLOAD
#
# PHOTO  = 300 MB
# VIDEO  = 500 MB
# =========================================================

@app.post(
    "/api/chat/upload"
)
async def chat_upload(
    request: Request,
    file: UploadFile = File(...)
):

    user = session_user(
        request
    )


    if not user:

        return JSONResponse(
            {
                "error": "auth"
            },
            status_code=401
        )


    if user["is_banned"]:

        return JSONResponse(
            {
                "error": "Аккаунт заблокирован"
            },
            status_code=403
        )


    if not file.filename:

        raise HTTPException(
            status_code=400,
            detail="Файл не выбран"
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
            )
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
            detail="Расширение файла не поддерживается"
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
    #
    # Не читаем 500 МБ целиком в RAM.
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


                # -----------------------------------------
                # SIZE CHECK
                # -----------------------------------------

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
                            )
                        )

                    else:

                        raise HTTPException(
                            status_code=413,
                            detail=(
                                "Видео не должно "
                                "быть больше 500 МБ"
                            )
                        )


                output.write(
                    chunk
                )


    except HTTPException:

        raise


    except Exception as exc:

        try:

            destination.unlink(
                missing_ok=True
            )

        except Exception:
            pass


        raise HTTPException(
            status_code=500,
            detail="Ошибка сохранения файла"
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
    response_class=HTMLResponse
)
def admin(
    request: Request
):

    user = session_user(
        request
    )


    if not is_staff(
        user
    ):

        return RedirectResponse(
            "/",
            303
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
        }
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
    body: str = Form(...)
):

    user = session_user(
        request
    )


    if not is_staff(
        user
    ):

        return RedirectResponse(
            "/",
            303
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
        )
    )


    c.commit()
    c.close()


    return RedirectResponse(
        "/admin",
        303
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
    location: str = Form("")
):

    user = session_user(
        request
    )


    if not is_staff(
        user
    ):

        return RedirectResponse(
            "/",
            303
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
        )
    )


    c.commit()
    c.close()


    return RedirectResponse(
        "/admin",
        303
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
    role: str = Form(...)
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
            303
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
        )
    )


    c.commit()
    c.close()


    return RedirectResponse(
        "/admin",
        303
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
    banned: int = Form(...)
):

    actor = session_user(
        request
    )


    if not is_admin(
        actor
    ):

        return RedirectResponse(
            "/admin",
            303
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
        )
    )


    c.commit()
    c.close()


    return RedirectResponse(
        "/admin",
        303
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
    city: str = Form("")
):

    actor = session_user(
        request
    )


    if not is_staff(
        actor
    ):

        return RedirectResponse(
            "/admin",
            303
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
        )
    )


    c.commit()
    c.close()


    return RedirectResponse(
        "/admin",
        303
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
    note: str = Form("")
):

    actor = session_user(
        request
    )


    if not is_staff(
        actor
    ):

        return RedirectResponse(
            "/admin",
            303
        )


    # -----------------------------------------------------
    # EVENT ID
    #
    # Исправлено:
    # HTML select может отправлять ""
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
        )
    )


    c.commit()
    c.close()


    return RedirectResponse(
        "/admin",
        303
    )


# =========================================================
# DELETE ACHIEVEMENT
# =========================================================

@app.post(
    "/admin/achievement/delete"
)
def admin_achievement_delete(
    request: Request,
    achievement_id: int = Form(...)
):

    actor = session_user(
        request
    )


    if not is_staff(
        actor
    ):

        return RedirectResponse(
            "/admin",
            303
        )


    c = conn()


    c.execute(
        """
        DELETE FROM achievements
        WHERE id=?
        """,
        (
            achievement_id,
        )
    )


    c.commit()
    c.close()


    return RedirectResponse(
        "/admin",
        303
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
        ws
    ):

        await ws.accept()

        self.connections.setdefault(
            user_id,
            set()
        ).add(
            ws
        )


    def disconnect(
        self,
        user_id,
        ws
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
        payload
    ):

        dead = []


        for ws in list(
            self.connections.get(
                user_id,
                set()
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
                ws
            )


    async def broadcast_public(
        self,
        payload
    ):

        for user_id in list(
            self.connections
        ):

            await self.send_user(
                user_id,
                payload
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
    ws: WebSocket
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
        ws
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
                    ""
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
                        str
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
                )
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
                    payload
                )


                await manager.send_user(
                    recipient["id"],
                    payload
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
            ws
        )


    except Exception:

        manager.disconnect(
            user["id"],
            ws
        )
