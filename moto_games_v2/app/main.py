import hashlib
import os
import secrets
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
)
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from itsdangerous import URLSafeSerializer, BadSignature

from .db import (
    init_db,
    conn,
    get_user,
    get_user_by_id,
    create_user,
    now,
)
from .emailer import send_otp


load_dotenv()

BASE = Path(__file__).resolve().parent.parent

UPLOADS = BASE / "static" / "uploads"
UPLOADS.mkdir(parents=True, exist_ok=True)

app = FastAPI(title="MotoHub")

templates = Jinja2Templates(
    directory=str(Path(__file__).parent / "templates")
)

app.mount(
    "/static",
    StaticFiles(directory=str(BASE / "static")),
    name="static",
)

serializer = URLSafeSerializer(
    os.getenv("SECRET_KEY", "dev-secret")
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

def clean_email(email):
    return email.strip().lower()


def hash_password(password):
    salt = secrets.token_bytes(16)

    digest = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        180000,
    )

    return salt.hex() + ":" + digest.hex()


def verify_password(password, stored):
    try:
        salt_hex, digest_hex = stored.split(":", 1)

        digest = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            bytes.fromhex(salt_hex),
            180000,
        )

        return secrets.compare_digest(
            digest.hex(),
            digest_hex,
        )

    except Exception:
        return False


def device_token():
    return secrets.token_urlsafe(48)


def device_hash(token):
    return hashlib.sha256(
        token.encode("utf-8")
    ).hexdigest()


def device_name(request):
    ua = request.headers.get("user-agent", "")

    if "iPhone" in ua:
        return "iPhone"

    if "iPad" in ua:
        return "iPad"

    if "Android" in ua:
        return "Android"

    if "Windows" in ua:
        return "Windows"

    if "Macintosh" in ua:
        return "Mac"

    if "Linux" in ua:
        return "Linux"

    return "Браузер"


def trusted_user(request, user):
    token = request.cookies.get("motohub_device")

    if not token or not user:
        return False

    c = conn()

    row = c.execute(
        """
        SELECT id
        FROM trusted_devices
        WHERE user_id=? AND token_hash=?
        """,
        (
            user["id"],
            device_hash(token),
        ),
    ).fetchone()

    if row:
        c.execute(
            """
            UPDATE trusted_devices
            SET last_used_at=?
            WHERE id=?
            """,
            (
                now().isoformat(),
                row["id"],
            ),
        )

        c.commit()

    c.close()

    return bool(row)


def trust_device(response, request, user):
    token = device_token()

    c = conn()

    c.execute(
        """
        INSERT OR IGNORE INTO trusted_devices(
            user_id,
            token_hash,
            device_name,
            created_at,
            last_used_at
        )
        VALUES(?,?,?,?,?)
        """,
        (
            user["id"],
            device_hash(token),
            device_name(request),
            now().isoformat(),
            now().isoformat(),
        ),
    )

    c.commit()
    c.close()

    response.set_cookie(
        "motohub_device",
        token,
        httponly=True,
        samesite="lax",
        max_age=60 * 60 * 24 * 180,
    )


def make_session(response, email):
    response.set_cookie(
        "motohub_session",
        serializer.dumps({
            "email": email
        }),
        httponly=True,
        samesite="lax",
        max_age=604800,
    )


def session_email(request):
    token = request.cookies.get("motohub_session")

    if not token:
        return None

    try:
        return serializer.loads(token).get("email")

    except BadSignature:
        return None


def session_user(request):
    email = session_email(request)

    return get_user(email) if email else None


def ws_user(ws):
    token = ws.cookies.get("motohub_session")

    if not token:
        return None

    try:
        email = serializer.loads(token).get("email")

        return get_user(email)

    except BadSignature:
        return None


def public_user(row):
    d = dict(row)

    d.pop("muted_until", None)
    d.pop("is_banned", None)

    return d


# =========================================================
# OTP
# =========================================================

def send_auth_code(email, password_hash, purpose):
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
                now() - timedelta(seconds=60)
            ).isoformat(),
        ),
    ).fetchone()

    if recent:
        c.close()

        return False, "Подождите 60 секунд"

    code = f"{secrets.randbelow(1000000):06d}"

    code_hash = hashlib.sha256(
        code.encode()
    ).hexdigest()

    created = now()

    expires = created + timedelta(
        minutes=10
    )

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
            expires.isoformat(),
            created.isoformat(),
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
            purpose,
            expires.isoformat(),
            created.isoformat(),
        ),
    )

    c.commit()
    c.close()

    send_otp(email, code)

    return True, None


def consume_code(email, code):
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
        (email,),
    ).fetchone()

    if not row:
        c.close()

        return None, "Код не найден"

    if datetime.fromisoformat(
        row["expires_at"]
    ) < now():

        c.close()

        return None, "Код истёк"

    if row["attempts"] >= 5:
        c.close()

        return None, "Слишком много попыток"

    code_hash = hashlib.sha256(
        code.strip().encode()
    ).hexdigest()

    if code_hash != row["code_hash"]:

        c.execute(
            """
            UPDATE otp
            SET attempts=attempts+1
            WHERE id=?
            """,
            (row["id"],),
        )

        c.commit()
        c.close()

        return None, "Неверный код"

    c.execute(
        """
        UPDATE otp
        SET consumed=1
        WHERE id=?
        """,
        (row["id"],),
    )

    pending = c.execute(
        """
        SELECT *
        FROM pending_auth
        WHERE email=?
        AND expires_at>?
        ORDER BY id DESC
        LIMIT 1
        """,
        (
            email,
            now().isoformat(),
        ),
    ).fetchone()

    c.commit()
    c.close()

    return pending, None


# =========================================================
# HOME
# =========================================================

@app.get("/", response_class=HTMLResponse)
def home(request: Request):
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
            "user": session_user(request),
        },
    )


# =========================================================
# LOGIN
# =========================================================

@app.get("/login", response_class=HTMLResponse)
def login(request: Request):
    return templates.TemplateResponse(
        "login.html",
        {
            "request": request,
            "error": request.query_params.get("error"),
        },
    )


@app.post("/auth/login")
def auth_login(
    request: Request,
    email: str = Form(...),
    password: str = Form(...),
):
    email = clean_email(email)

    if (
        "@" not in email
        or "." not in email.split("@")[-1]
    ):
        return RedirectResponse(
            "/login?error=Неверный email",
            303,
        )

    if len(password) < 6:
        return RedirectResponse(
            "/login?error=Пароль должен быть не короче 6 символов",
            303,
        )

    user = get_user(email)

    # -----------------------------------------------------
    # НОВАЯ РЕГИСТРАЦИЯ
    # -----------------------------------------------------

    if not user:

        password_hash = hash_password(
            password
        )

        ok, error = send_auth_code(
            email,
            password_hash,
            "register",
        )

        if not ok:
            return RedirectResponse(
                "/login?error=" + error,
                303,
            )

        return RedirectResponse(
            f"/verify?email={email}&mode=register",
            303,
        )

    # -----------------------------------------------------
    # БАН
    # -----------------------------------------------------

    if user["is_banned"]:
        return RedirectResponse(
            "/login?error=Аккаунт заблокирован",
            303,
        )

    # -----------------------------------------------------
    # СТАРЫЙ АККАУНТ БЕЗ ПАРОЛЯ
    # -----------------------------------------------------

    if not user["password_hash"]:

        password_hash = hash_password(
            password
        )

        ok, error = send_auth_code(
            email,
            password_hash,
            "set_password",
        )

        if not ok:
            return RedirectResponse(
                "/login?error=" + error,
                303,
            )

        return RedirectResponse(
            f"/verify?email={email}&mode=set_password",
            303,
        )

    # -----------------------------------------------------
    # ПРОВЕРКА ПАРОЛЯ
    # -----------------------------------------------------

    if not verify_password(
        password,
        user["password_hash"],
    ):
        return RedirectResponse(
            "/login?error=Неверный email или пароль",
            303,
        )

    # -----------------------------------------------------
    # ДОВЕРЕННОЕ УСТРОЙСТВО
    # -----------------------------------------------------

    if trusted_user(request, user):

        response = RedirectResponse(
            "/",
            303,
        )

        make_session(
            response,
            email,
        )

        return response

    # -----------------------------------------------------
    # НОВОЕ УСТРОЙСТВО
    # -----------------------------------------------------

    ok, error = send_auth_code(
        email,
        None,
        "new_device",
    )

    if not ok:
        return RedirectResponse(
            "/login?error=" + error,
            303,
        )

    return RedirectResponse(
        f"/verify?email={email}&mode=new_device",
        303,
    )


# =========================================================
# VERIFY
# =========================================================

@app.get("/verify", response_class=HTMLResponse)
def verify_page(
    request: Request,
    email: str,
    mode: str = "",
):
    return templates.TemplateResponse(
        "verify.html",
        {
            "request": request,
            "email": clean_email(email),
            "mode": mode,
            "error": request.query_params.get("error"),
        },
    )


@app.post("/auth/verify")
def verify(
    request: Request,
    email: str = Form(...),
    code: str = Form(...),
):
    email = clean_email(email)

    pending, error = consume_code(
        email,
        code,
    )

    if error:
        return RedirectResponse(
            f"/verify?email={email}&error={error}",
            303,
        )

    purpose = (
        pending["purpose"]
        if pending
        else "new_device"
    )

    user = get_user(email)

    # -----------------------------------------------------
    # РЕГИСТРАЦИЯ / УСТАНОВКА ПАРОЛЯ
    # -----------------------------------------------------

    if purpose in (
        "register",
        "set_password",
    ):

        password_hash = (
            pending["password_hash"]
            if pending
            else None
        )

        if not password_hash:
            return RedirectResponse(
                "/login?error=Сессия регистрации истекла",
                303,
            )

        user = create_user(
            email,
            password_hash,
        )

        c = conn()

        c.execute(
            """
            UPDATE users
            SET password_hash=?
            WHERE id=?
            """,
            (
                password_hash,
                user["id"],
            ),
        )

        c.execute(
            """
            DELETE FROM pending_auth
            WHERE email=?
            """,
            (email,),
        )

        c.commit()
        c.close()

        user = get_user(email)

    # -----------------------------------------------------
    # НОВОЕ УСТРОЙСТВО
    # -----------------------------------------------------

    elif purpose == "new_device":

        if not user:
            return RedirectResponse(
                "/login?error=Пользователь не найден",
                303,
            )

        c = conn()

        c.execute(
            """
            DELETE FROM pending_auth
            WHERE email=?
            """,
            (email,),
        )

        c.commit()
        c.close()

    # -----------------------------------------------------
    # ВХОД
    # -----------------------------------------------------

    response = RedirectResponse(
        "/",
        303,
    )

    make_session(
        response,
        email,
    )

    if user:
        trust_device(
            response,
            request,
            user,
        )

    return response


# =========================================================
# FORGOT PASSWORD
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


@app.post("/auth/forgot")
def forgot(
    request: Request,
    email: str = Form(...),
):
    email = clean_email(email)

    user = get_user(email)

    if not user:
        return RedirectResponse(
            "/forgot?error=Пользователь не найден",
            303,
        )

    ok, error = send_auth_code(
        email,
        None,
        "reset_password",
    )

    if not ok:
        return RedirectResponse(
            "/forgot?error=" + error,
            303,
        )

    return RedirectResponse(
        f"/reset?email={email}",
        303,
    )


@app.get("/reset", response_class=HTMLResponse)
def reset_page(
    request: Request,
    email: str,
):
    return templates.TemplateResponse(
        "reset.html",
        {
            "request": request,
            "email": clean_email(email),
            "error": request.query_params.get("error"),
        },
    )


@app.post("/auth/reset")
def reset_password(
    request: Request,
    email: str = Form(...),
    code: str = Form(...),
    password: str = Form(...),
):
    email = clean_email(email)

    if len(password) < 6:
        return RedirectResponse(
            f"/reset?email={email}&error=Пароль должен быть не короче 6 символов",
            303,
        )

    pending, error = consume_code(
        email,
        code,
    )

    if error:
        return RedirectResponse(
            f"/reset?email={email}&error={error}",
            303,
        )

    if (
        not pending
        or pending["purpose"] != "reset_password"
    ):
        return RedirectResponse(
            f"/reset?email={email}&error=Код сброса не найден",
            303,
        )

    user = get_user(email)

    if not user:
        return RedirectResponse(
            "/login?error=Пользователь не найден",
            303,
        )

    password_hash = hash_password(
        password
    )

    c = conn()

    c.execute(
        """
        UPDATE users
        SET password_hash=?
        WHERE id=?
        """,
        (
            password_hash,
            user["id"],
        ),
    )

    # Старые устройства отключаем
    c.execute(
        """
        DELETE FROM trusted_devices
        WHERE user_id=?
        """,
        (user["id"],),
    )

    c.execute(
        """
        DELETE FROM pending_auth
        WHERE email=?
        """,
        (email,),
    )

    c.commit()
    c.close()

    user = get_user(email)

    response = RedirectResponse(
        "/",
        303,
    )

    make_session(
        response,
        email,
    )

    trust_device(
        response,
        request,
        user,
    )

    return response


# =========================================================
# LOGOUT
# =========================================================

@app.post("/logout")
def logout():
    response = RedirectResponse(
        "/",
        303,
    )

    response.delete_cookie(
        "motohub_session"
    )

    return response


@app.post("/logout-all")
def logout_all(request: Request):
    user = session_user(request)

    if user:
        c = conn()

        c.execute(
            """
            DELETE FROM trusted_devices
            WHERE user_id=?
            """,
            (user["id"],),
        )

        c.commit()
        c.close()

    response = RedirectResponse(
        "/login?error=Все устройства отключены",
        303,
    )

    response.delete_cookie(
        "motohub_session"
    )

    response.delete_cookie(
        "motohub_device"
    )

    return response


# =========================================================
# PROFILE
# =========================================================

@app.get("/profile", response_class=HTMLResponse)
def my_profile(request: Request):
    user = session_user(request)

    if not user:
        return RedirectResponse(
            "/login",
            303,
        )

    return RedirectResponse(
        f"/profile/{user['id']}",
        303,
    )


@app.get("/profile/{user_id}", response_class=HTMLResponse)
def profile_page(
    request: Request,
    user_id: int,
):
    viewer = session_user(request)

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
            ON e.id=a.event_id
        WHERE a.user_id=?
        ORDER BY
            COALESCE(
                e.starts_at,
                a.created_at
            ) DESC,
            a.id DESC
        """,
        (user_id,),
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
        (user_id,),
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


@app.post("/profile/update")
async def profile_update(
    request: Request,
    display_name: str = Form(""),
    bio: str = Form(""),
    motorcycle: str = Form(""),
    city: str = Form(""),
    avatar: UploadFile | None = File(None),
):
    user = session_user(request)

    if not user:
        return RedirectResponse(
            "/login",
            303,
        )

    avatar_url = user["avatar_url"]

    if avatar and avatar.filename:

        ext = Path(
            avatar.filename
        ).suffix.lower()

        if ext not in {
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
            and not avatar.content_type.startswith("image/")
        ):
            return RedirectResponse(
                "/profile?error=Это не изображение",
                303,
            )

        data = await avatar.read()

        if len(data) > 4 * 1024 * 1024:
            return RedirectResponse(
                "/profile?error=Фото больше 4 МБ",
                303,
            )

        filename = (
            f"user_{user['id']}{ext}"
        )

        (
            UPLOADS / filename
        ).write_bytes(data)

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
            display_name.strip()[:80] or None,
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
# CHAT
# =========================================================

@app.get("/chat", response_class=HTMLResponse)
def chat_page(request: Request):
    user = session_user(request)

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


@app.get("/api/chat/users")
def chat_users(request: Request):
    user = session_user(request)

    if not user:
        return JSONResponse(
            {"error": "auth"},
            401,
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
        WHERE id!=?
        ORDER BY
            COALESCE(
                display_name,
                email
            )
        """,
        (user["id"],),
    ).fetchall()

    c.close()

    return [
        public_user(row)
        for row in rows
        if not row["is_banned"]
    ]


@app.get("/api/chat/messages/{other_id}")
def chat_history(
    request: Request,
    other_id: int,
):
    user = session_user(request)

    other = get_user_by_id(
        other_id
    )

    if not user:
        return JSONResponse(
            {"error": "auth"},
            401,
        )

    if not other:
        return JSONResponse(
            {"error": "user_not_found"},
            404,
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
            is_read
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


@app.post("/api/chat/read/{other_id}")
def mark_read(
    request: Request,
    other_id: int,
):
    user = session_user(request)

    other = get_user_by_id(
        other_id
    )

    if not user:
        return JSONResponse(
            {"error": "auth"},
            401,
        )

    if not other:
        return JSONResponse(
            {"error": "user_not_found"},
            404,
        )

    c = conn()

    c.execute(
        """
        UPDATE messages
        SET is_read=1
        WHERE email=?
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
        "ok": True
    }


@app.get("/api/chat/unread")
def unread(request: Request):
    user = session_user(request)

    if not user:
        return JSONResponse(
            {"error": "auth"},
            401,
        )

    c = conn()

    rows = c.execute(
        """
        SELECT
            email,
            COUNT(*) count

        FROM messages

        WHERE recipient_id=?
        AND is_read=0

        GROUP BY email
        """,
        (user["id"],),
    ).fetchall()

    c.close()

    return [
        dict(row)
        for row in rows
    ]


# =========================================================
# ADMIN
# =========================================================

def is_staff(user):
    return (
        user
        and user["role"]
        in (
            "ADMIN",
            "MODERATOR",
        )
    )


def is_admin(user):
    return (
        user
        and user["role"] == "ADMIN"
    )


@app.get("/admin", response_class=HTMLResponse)
def admin(request: Request):
    user = session_user(request)

    if not is_staff(user):
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


@app.get("/api/admin/users/search")
def admin_users_search(
    request: Request,
    q: str = "",
):
    actor = session_user(request)

    if not is_staff(actor):
        return JSONResponse(
            {"error": "forbidden"},
            403,
        )

    q = q.strip()

    c = conn()

    if q:

        like = f"%{q}%"

        rows = c.execute(
            """
            SELECT
                id,
                email,
                display_name,
                role,
                is_banned,
                muted_until,
                avatar_url,
                city,
                motorcycle

            FROM users

            WHERE
                email LIKE ?
                OR display_name LIKE ?
                OR city LIKE ?
                OR motorcycle LIKE ?

            ORDER BY id DESC

            LIMIT 50
            """,
            (
                like,
                like,
                like,
                like,
            ),
        ).fetchall()

    else:

        rows = c.execute(
            """
            SELECT
                id,
                email,
                display_name,
                role,
                is_banned,
                muted_until,
                avatar_url,
                city,
                motorcycle

            FROM users

            ORDER BY id DESC

            LIMIT 50
            """
        ).fetchall()

    c.close()

    return [
        dict(row)
        for row in rows
    ]


@app.post("/admin/news")
def add_news(
    request: Request,
    title: str = Form(...),
    body: str = Form(...),
):
    user = session_user(request)

    if not is_staff(user):
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


@app.post("/admin/events")
def add_event(
    request: Request,
    title: str = Form(...),
    description: str = Form(...),
    starts_at: str = Form(...),
    location: str = Form(""),
):
    user = session_user(request)

    if not is_staff(user):
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


@app.post("/admin/role")
def role(
    request: Request,
    user_id: int = Form(...),
    role: str = Form(...),
):
    actor = session_user(request)

    if (
        not is_admin(actor)
        or role not in (
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


@app.post("/admin/ban")
def ban(
    request: Request,
    user_id: int = Form(...),
    banned: int = Form(...),
):
    actor = session_user(request)

    if not is_admin(actor):
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


@app.post("/admin/profile")
def admin_profile(
    request: Request,
    user_id: int = Form(...),
    display_name: str = Form(""),
    bio: str = Form(""),
    motorcycle: str = Form(""),
    city: str = Form(""),
):
    actor = session_user(request)

    if not is_staff(actor):
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
# PUNISHMENT
# =========================================================

@app.post("/admin/punishment")
def admin_punishment(
    request: Request,
    user_id: int = Form(...),
    reason: str = Form(""),
    duration_minutes: str = Form(""),
):
    actor = session_user(request)

    if not is_staff(actor):
        return RedirectResponse(
            "/admin",
            303,
        )

    reason = reason.strip()[:500]

    if not reason:
        return RedirectResponse(
            "/admin?error=Укажите причину наказания",
            303,
        )

    duration_value = None
    expires_at = None

    if duration_minutes.strip():

        try:
            minutes = int(
                duration_minutes
            )

            if minutes < 1:
                raise ValueError

            duration_value = minutes

            expires_at = (
                now()
                + timedelta(
                    minutes=minutes
                )
            ).isoformat()

        except ValueError:

            return RedirectResponse(
                "/admin?error=Некорректный срок наказания",
                303,
            )

    c = conn()

    c.execute(
        """
        UPDATE users
        SET muted_until=?
        WHERE id=?
        """,
        (
            expires_at,
            user_id,
        ),
    )

    c.execute(
        """
        INSERT INTO punishments(
            user_id,
            admin_id,
            reason,
            duration_minutes,
            created_at,
            expires_at
        )
        VALUES(?,?,?,?,?,?)
        """,
        (
            user_id,
            actor["id"],
            reason,
            duration_value,
            now().isoformat(),
            expires_at,
        ),
    )

    c.commit()
    c.close()

    return RedirectResponse(
        "/admin",
        303,
    )


# =========================================================
# ACHIEVEMENTS
# =========================================================

@app.post("/admin/achievement")
def admin_achievement(
    request: Request,
    user_id: int = Form(...),
    event_id: str = Form(""),
    place: str = Form(""),
    award: str = Form(""),
    note: str = Form(""),
):
    actor = session_user(request)

    if not is_staff(actor):
        return RedirectResponse(
            "/admin",
            303,
        )

    place_num = None

    if place.strip():

        try:
            place_num = int(place)

        except ValueError:
            place_num = None

    event_id_value = None

    if event_id.strip():

        try:
            event_id_value = int(
                event_id
            )

        except ValueError:
            event_id_value = None

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
            event_id_value,
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


@app.post("/admin/achievement/delete")
def admin_achievement_delete(
    request: Request,
    achievement_id: int = Form(...),
):
    actor = session_user(request)

    if not is_staff(actor):
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
        (achievement_id,),
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
        ).add(ws)

    def disconnect(
        self,
        user_id,
        ws,
    ):
        if user_id in self.connections:

            self.connections[user_id].discard(
                ws
            )

            if not self.connections[user_id]:
                del self.connections[user_id]

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
                dead.append(ws)

        for ws in dead:
            self.disconnect(
                user_id,
                ws,
            )

    async def broadcast_public(
        self,
        payload,
    ):
        for uid in list(
            self.connections
        ):
            await self.send_user(
                uid,
                payload,
            )

    def online_ids(self):
        return list(
            self.connections
        )


manager = ChatManager()


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
            recipient_id

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

@app.websocket("/ws/chat")
async def chat(ws: WebSocket):

    user = ws_user(ws)

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

        await ws.send_json(
            {
                "type": "presence",
                "online": manager.online_ids(),
            }
        )

        for message in public_history():

            await ws.send_json(
                {
                    "type": "public",
                    "message": message,
                }
            )

        while True:

            data = await ws.receive_json()

            text = str(
                data.get(
                    "text",
                    "",
                )
            ).strip()

            if (
                not text
                or len(text) > 2000
            ):
                continue

            # Проверяем временный мут
            muted_until = user["muted_until"]

            if muted_until:

                try:
                    if datetime.fromisoformat(
                        muted_until
                    ) > now():

                        continue

                except Exception:
                    pass

            target = data.get(
                "recipient_id"
            )

            recipient = None

            if target not in (
                None,
                "",
                0,
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
                    is_read
                )
                VALUES(?,?,?,?,?,?)
                """,
                (
                    user["email"],

                    user["display_name"]
                    or user["email"].split("@")[0],

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
                    is_read

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

            if recipient:

                await manager.send_user(
                    user["id"],
                    payload,
                )

                await manager.send_user(
                    recipient["id"],
                    payload,
                )

            else:

                await manager.broadcast_public(
                    payload
                )

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
