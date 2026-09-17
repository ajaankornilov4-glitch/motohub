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

    return refresh_user_restrictions(get_user(email))


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

        return refresh_user_restrictions(get_user(email))

    except BadSignature:

        return None


def clean_email(
    email: str
):

    return email.strip().lower()


def create_notification(user_id: int, kind: str, title: str, body: str):
    c = conn()
    c.execute(
        """INSERT INTO notifications(user_id,kind,title,body,created_at)
           VALUES(?,?,?,?,?)""",
        (user_id, kind, title[:200], body[:2000], now().isoformat()),
    )
    c.commit()
    c.close()


def refresh_user_restrictions(user):
    if not user:
        return None
    current = dict(user)
    now_iso = now().isoformat()
    c = conn()
    if current.get("muted_until") and current["muted_until"] <= now_iso:
        c.execute("UPDATE users SET muted_until=NULL WHERE id=?", (current["id"],))
        current["muted_until"] = None
    if current.get("is_banned"):
        permanent = c.execute(
            "SELECT 1 FROM punishments WHERE user_id=? AND kind='ban' ORDER BY id DESC LIMIT 1",
            (current["id"],),
        ).fetchone()
        active_temp = c.execute(
            "SELECT 1 FROM punishments WHERE user_id=? AND kind='temporary_ban' AND expires_at>? ORDER BY id DESC LIMIT 1",
            (current["id"], now_iso),
        ).fetchone()
        if not permanent and not active_temp:
            c.execute("UPDATE users SET is_banned=0 WHERE id=?", (current["id"],))
            current["is_banned"] = 0
    c.commit()
    c.close()
    return get_user_by_id(current["id"])


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
def home(request: Request):
    current_user = session_user(request)
    c = conn()
    now_iso = now().isoformat()

    upcoming_events = c.execute(
        "SELECT * FROM events WHERE starts_at >= ? ORDER BY starts_at ASC LIMIT 6",
        (now_iso,),
    ).fetchall()
    past_events = c.execute(
        "SELECT * FROM events WHERE starts_at < ? ORDER BY starts_at DESC LIMIT 8",
        (now_iso,),
    ).fetchall()
    news = c.execute(
        "SELECT * FROM news ORDER BY id DESC LIMIT 8"
    ).fetchall()
    past_news = c.execute(
        "SELECT * FROM news ORDER BY id DESC LIMIT 20"
    ).fetchall()

    def with_photos(rows, table):
        out = []
        photo_table = "event_photos" if table == "events" else "news_photos"
        key = "event_id" if table == "events" else "news_id"
        for row in rows:
            item = dict(row)
            item["photos"] = [dict(x) for x in c.execute(
                f"SELECT * FROM {photo_table} WHERE {key}=? ORDER BY is_cover DESC, id ASC",
                (row["id"],),
            ).fetchall()]
            out.append(item)
        return out

    upcoming_events = with_photos(upcoming_events, "events")
    past_events = with_photos(past_events, "events")
    news = with_photos(news, "news")
    past_news = with_photos(past_news, "news")
    c.close()

    unread = 0
    if current_user:
        c = conn()
        unread = c.execute(
            "SELECT COUNT(*) FROM notifications WHERE user_id=? AND read_at IS NULL",
            (current_user["id"],),
        ).fetchone()[0]
        c.close()

    return templates.TemplateResponse(
        "index.html",
        {
            "request": request,
            "user": current_user,
            "upcoming_events": upcoming_events,
            "past_events": past_events,
            "news": news,
            "past_news": past_news,
            "unread_notifications": unread,
            "now_iso": now_iso,
        },
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
# NOTIFICATIONS
# =========================================================

@app.get("/notifications", response_class=HTMLResponse)
def notifications_page(request: Request):
    user = session_user(request)
    if not user:
        return RedirectResponse("/login", 303)
    c = conn()
    rows = c.execute(
        "SELECT * FROM notifications WHERE user_id=? ORDER BY id DESC LIMIT 100",
        (user["id"],),
    ).fetchall()
    c.execute(
        "UPDATE notifications SET read_at=? WHERE user_id=? AND read_at IS NULL",
        (now().isoformat(), user["id"]),
    )
    c.commit()
    c.close()
    return templates.TemplateResponse(
        "notifications.html",
        {"request": request, "user": user, "notifications": rows},
    )


# =========================================================
# SETTINGS / THEME
# =========================================================

@app.get("/settings", response_class=HTMLResponse)
def settings_page(request: Request):
    user = session_user(request)
    if not user:
        return RedirectResponse("/login", 303)
    return templates.TemplateResponse("settings.html", {"request": request, "user": user})


@app.post("/settings/theme")
def settings_theme(
    request: Request,
    accent: str = Form("#ff2636"),
    mode: str = Form("dark"),
):
    user = session_user(request)
    if not user:
        return RedirectResponse("/login", 303)
    allowed = {"#ff2636", "#b8ff00", "#2f8cff", "#9b5cff", "#ff7a00", "#f2f4f5"}
    if accent not in allowed:
        accent = "#ff2636"
    if mode not in {"dark", "light"}:
        mode = "dark"
    c = conn()
    c.execute("UPDATE users SET theme_accent=?, theme_mode=? WHERE id=?", (accent, mode, user["id"]))
    c.commit()
    c.close()
    return RedirectResponse("/settings", 303)


# =========================================================
# ADMIN PUNISHMENTS / MODERATION
# =========================================================

@app.post("/admin/punishment")
def admin_punishment(
    request: Request,
    user_id: int = Form(...),
    reason: str = Form(...),
    duration: str = Form(""),
    kind: str = Form("warning"),
):
    actor = session_user(request)
    if not is_admin(actor):
        return RedirectResponse("/admin", 303)
    target = get_user_by_id(user_id)
    if not target:
        return RedirectResponse("/admin", 303)

    try:
        duration_minutes = int(duration) if duration.strip() else None
    except ValueError:
        duration_minutes = None
    if duration_minutes is not None and duration_minutes <= 0:
        duration_minutes = None

    kind = kind if kind in {"warning", "mute", "temporary_ban", "ban"} else "warning"
    created = now()
    expires = None
    if duration_minutes:
        expires = created + timedelta(minutes=duration_minutes)

    c = conn()
    c.execute(
        """INSERT INTO punishments(user_id,admin_id,kind,reason,duration_minutes,created_at,expires_at)
           VALUES(?,?,?,?,?,?,?)""",
        (user_id, actor["id"], kind, reason.strip()[:500], duration_minutes, created.isoformat(), expires.isoformat() if expires else None),
    )
    if kind == "mute":
        c.execute("UPDATE users SET muted_until=? WHERE id=?", (expires.isoformat() if expires else None, user_id))
    elif kind in {"temporary_ban", "ban"}:
        c.execute("UPDATE users SET is_banned=1 WHERE id=?", (user_id,))
    c.commit()
    c.close()

    labels = {"warning": "Предупреждение", "mute": "Мут", "temporary_ban": "Временная блокировка", "ban": "Постоянная блокировка"}
    end_text = expires.isoformat(sep=" ", timespec="minutes") if expires else "бессрочно"
    create_notification(
        user_id,
        "punishment",
        f"{labels[kind]} в MotoHub",
        f"Причина: {reason.strip()}. Выдано: {created.isoformat(sep=' ', timespec='minutes')}. Окончание: {end_text}.",
    )
    return RedirectResponse("/admin", 303)


@app.post("/admin/punishment/remove")
def admin_punishment_remove(request: Request, user_id: int = Form(...)):
    actor = session_user(request)
    if not is_admin(actor):
        return RedirectResponse("/admin", 303)
    target = get_user_by_id(user_id)
    if not target:
        return RedirectResponse("/admin", 303)
    c = conn()
    c.execute("UPDATE users SET is_banned=0, muted_until=NULL WHERE id=?", (user_id,))
    c.commit()
    c.close()
    create_notification(
        user_id,
        "unblock",
        "Наказание снято",
        f"Ограничения сняты администратором {now().isoformat(sep=' ', timespec='minutes')}.",
    )
    return RedirectResponse("/admin", 303)


# =========================================================
# ADMIN NEWS / EVENTS EDIT + DELETE
# =========================================================

@app.post("/admin/news/update")
def admin_news_update(
    request: Request,
    news_id: int = Form(...),
    title: str = Form(...),
    body: str = Form(...),
):
    actor = session_user(request)
    if not is_staff(actor):
        return RedirectResponse("/", 303)
    c = conn()
    c.execute("UPDATE news SET title=?, body=?, updated_at=? WHERE id=?", (title.strip()[:200], body.strip()[:5000], now().isoformat(), news_id))
    c.commit(); c.close()
    return RedirectResponse("/admin", 303)


@app.post("/admin/news/delete")
def admin_news_delete(request: Request, news_id: int = Form(...)):
    actor = session_user(request)
    if not is_staff(actor):
        return RedirectResponse("/", 303)
    c = conn()
    c.execute("DELETE FROM news_photos WHERE news_id=?", (news_id,))
    c.execute("DELETE FROM news WHERE id=?", (news_id,))
    c.commit(); c.close()
    return RedirectResponse("/admin", 303)


@app.post("/admin/events/update")
def admin_event_update(
    request: Request,
    event_id: int = Form(...),
    title: str = Form(...),
    description: str = Form(...),
    starts_at: str = Form(...),
    location: str = Form(""),
):
    actor = session_user(request)
    if not is_staff(actor):
        return RedirectResponse("/", 303)
    c = conn()
    c.execute("UPDATE events SET title=?, description=?, starts_at=?, location=?, updated_at=? WHERE id=?", (title.strip()[:200], description.strip()[:5000], starts_at, location.strip()[:200], now().isoformat(), event_id))
    c.commit(); c.close()
    return RedirectResponse("/admin", 303)


@app.post("/admin/events/delete")
def admin_event_delete(request: Request, event_id: int = Form(...)):
    actor = session_user(request)
    if not is_staff(actor):
        return RedirectResponse("/", 303)
    c = conn()
    c.execute("DELETE FROM event_photos WHERE event_id=?", (event_id,))
    c.execute("DELETE FROM achievements WHERE event_id=?", (event_id,))
    c.execute("DELETE FROM events WHERE id=?", (event_id,))
    c.commit(); c.close()
    return RedirectResponse("/admin", 303)


async def _save_content_photos(files, folder: str):
    target = UPLOADS / folder
    target.mkdir(parents=True, exist_ok=True)
    urls = []
    for upload in files or []:
        if not upload or not upload.filename:
            continue
        content_type = upload.content_type or ""
        if content_type not in ALLOWED_IMAGE_TYPES:
            continue
        data = await upload.read()
        if len(data) > MAX_AVATAR_SIZE * 4:
            continue
        ext = Path(upload.filename).suffix.lower() or ".jpg"
        name = f"{uuid.uuid4().hex}{ext}"
        path = target / name
        path.write_bytes(data)
        urls.append(f"/static/uploads/{folder}/{name}")
    return urls


@app.post("/admin/news/photos")
async def admin_news_photos(request: Request, news_id: int = Form(...), photos: list[UploadFile] = File(default=[])):
    actor = session_user(request)
    if not is_staff(actor):
        return RedirectResponse("/", 303)
    urls = await _save_content_photos(photos, "news")
    c = conn()
    for url in urls:
        c.execute("INSERT INTO news_photos(news_id,url,created_at) VALUES(?,?,?)", (news_id, url, now().isoformat()))
    c.commit(); c.close()
    return RedirectResponse("/admin", 303)


@app.post("/admin/events/photos")
async def admin_event_photos(request: Request, event_id: int = Form(...), photos: list[UploadFile] = File(default=[])):
    actor = session_user(request)
    if not is_staff(actor):
        return RedirectResponse("/", 303)
    urls = await _save_content_photos(photos, "events")
    c = conn()
    for url in urls:
        c.execute("INSERT INTO event_photos(event_id,url,created_at) VALUES(?,?,?)", (event_id, url, now().isoformat()))
    c.commit(); c.close()
    return RedirectResponse("/admin", 303)


@app.post("/admin/news/photo/delete")
def admin_news_photo_delete(request: Request, photo_id: int = Form(...)):
    actor = session_user(request)
    if not is_staff(actor): return RedirectResponse("/admin", 303)
    c = conn(); row = c.execute("SELECT url FROM news_photos WHERE id=?", (photo_id,)).fetchone()
    if row: c.execute("DELETE FROM news_photos WHERE id=?", (photo_id,))
    c.commit(); c.close(); return RedirectResponse("/admin", 303)


@app.post("/admin/events/photo/delete")
def admin_event_photo_delete(request: Request, photo_id: int = Form(...)):
    actor = session_user(request)
    if not is_staff(actor): return RedirectResponse("/admin", 303)
    c = conn(); row = c.execute("SELECT url FROM event_photos WHERE id=?", (photo_id,)).fetchone()
    if row: c.execute("DELETE FROM event_photos WHERE id=?", (photo_id,))
    c.commit(); c.close(); return RedirectResponse("/admin", 303)


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

    punishments = c.execute(
        "SELECT * FROM punishments ORDER BY id DESC LIMIT 500"
    ).fetchall()

    enriched_users = []
    for row in users:
        item = dict(row)
        item["achievement_count"] = c.execute(
            "SELECT COUNT(*) FROM achievements WHERE user_id=?", (row["id"],)
        ).fetchone()[0]
        item["achievements"] = c.execute(
            """SELECT a.*, e.title AS event_title FROM achievements a
               LEFT JOIN events e ON e.id=a.event_id WHERE a.user_id=? ORDER BY a.id DESC LIMIT 20""",
            (row["id"],),
        ).fetchall()
        item["message_count"] = c.execute(
            "SELECT COUNT(*) FROM messages WHERE email=? OR recipient_id=?", (row["email"], row["id"])
        ).fetchone()[0]
        item["trusted_count"] = c.execute(
            "SELECT COUNT(*) FROM trusted_devices WHERE user_id=?", (row["id"],)
        ).fetchone()[0]
        enriched_users.append(item)

    users = enriched_users

    for i, item in enumerate(users):
        # refresh display-only expired restrictions without deleting history
        if item["muted_until"] and item["muted_until"] <= now().isoformat():
            c.execute("UPDATE users SET muted_until=NULL WHERE id=?", (item["id"],))

    c.commit()
    c.close()

    return templates.TemplateResponse(
        "admin.html",
        {
            "request": request,
            "user": user,
            "users": users,
            "news": news,
            "events": events,
            "punishments": punishments,
            "now_iso": now().isoformat(),
        }
    )


# =========================================================
# ADMIN NEWS
# =========================================================

@app.post("/admin/news")
async def add_news(request: Request, title: str = Form(...), body: str = Form(...), photos: list[UploadFile] = File(default=[])):
    user = session_user(request)
    if not is_staff(user):
        return RedirectResponse("/", 303)
    c = conn()
    c.execute("INSERT INTO news(title,body,created_at) VALUES(?,?,?)", (title.strip()[:200], body.strip()[:5000], now().isoformat()))
    news_id = c.execute("SELECT last_insert_rowid()").fetchone()[0]
    c.commit(); c.close()
    urls = await _save_content_photos(photos, "news")
    if urls:
        c = conn()
        for i, url in enumerate(urls):
            c.execute("INSERT INTO news_photos(news_id,url,is_cover,created_at) VALUES(?,?,?,?)", (news_id, url, 1 if i == 0 else 0, now().isoformat()))
        c.commit(); c.close()
    return RedirectResponse("/admin", 303)


# =========================================================
# ADMIN EVENTS
# =========================================================

@app.post("/admin/events")
async def add_event(request: Request, title: str = Form(...), description: str = Form(...), starts_at: str = Form(...), location: str = Form(""), photos: list[UploadFile] = File(default=[])):
    user = session_user(request)
    if not is_staff(user):
        return RedirectResponse("/", 303)
    c = conn()
    c.execute("INSERT INTO events(title,description,starts_at,location,created_at) VALUES(?,?,?,?,?)", (title.strip()[:200], description.strip()[:5000], starts_at, location.strip()[:200], now().isoformat()))
    event_id = c.execute("SELECT last_insert_rowid()").fetchone()[0]
    c.commit(); c.close()
    urls = await _save_content_photos(photos, "events")
    if urls:
        c = conn()
        for i, url in enumerate(urls):
            c.execute("INSERT INTO event_photos(event_id,url,is_cover,created_at) VALUES(?,?,?,?)", (event_id, url, 1 if i == 0 else 0, now().isoformat()))
        c.commit(); c.close()
    return RedirectResponse("/admin", 303)


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

@app.post("/admin/ban")
def ban(request: Request, user_id: int = Form(...), banned: int = Form(...)):
    actor = session_user(request)
    if not is_admin(actor):
        return RedirectResponse("/admin", 303)
    target = get_user_by_id(user_id)
    if not target:
        return RedirectResponse("/admin", 303)
    c = conn()
    if banned:
        created = now()
        c.execute("UPDATE users SET is_banned=1 WHERE id=?", (user_id,))
        c.execute("INSERT INTO punishments(user_id,admin_id,kind,reason,duration_minutes,created_at,expires_at) VALUES(?,?,?,?,?,?,?)", (user_id, actor["id"], "ban", "Постоянная блокировка", None, created.isoformat(), None))
        c.commit(); c.close()
        create_notification(user_id, "punishment", "Постоянная блокировка", f"Аккаунт заблокирован {created.isoformat(sep=' ', timespec='minutes')}. Ограничение бессрочное.")
    else:
        c.execute("UPDATE users SET is_banned=0, muted_until=NULL WHERE id=?", (user_id,))
        c.commit(); c.close()
        create_notification(user_id, "unblock", "Блокировка снята", f"Ограничение снято {now().isoformat(sep=' ', timespec='minutes')}.")
    return RedirectResponse("/admin", 303)


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
