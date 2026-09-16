import hashlib, os, secrets, shutil
from datetime import datetime, timedelta
from pathlib import Path

from dotenv import load_dotenv
from fastapi import FastAPI, Request, Form, WebSocket, WebSocketDisconnect, UploadFile, File
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from itsdangerous import URLSafeSerializer, BadSignature

from .db import init_db, conn, get_user, get_user_by_id, create_user, now
from .emailer import send_otp

load_dotenv()
BASE = Path(__file__).resolve().parent.parent
UPLOADS = BASE / "static" / "uploads"
UPLOADS.mkdir(parents=True, exist_ok=True)

app=FastAPI(title="MotoHub")
templates=Jinja2Templates(directory=str(Path(__file__).parent/"templates"))
app.mount("/static", StaticFiles(directory=str(BASE/"static")), name="static")
serializer=URLSafeSerializer(os.getenv("SECRET_KEY","dev-secret"))

@app.on_event("startup")
def startup(): init_db()

def session_email(request):
    token=request.cookies.get("motohub_session")
    if not token: return None
    try: return serializer.loads(token).get("email")
    except BadSignature: return None

def session_user(request):
    email=session_email(request)
    return get_user(email) if email else None

def ws_user(ws):
    token = ws.cookies.get("motohub_session")
    if not token: return None
    try: return get_user(serializer.loads(token).get("email"))
    except BadSignature: return None

def clean_email(email): return email.strip().lower()

def public_user(row):
    d = dict(row)
    d.pop("muted_until", None)
    d.pop("is_banned", None)
    return d

@app.get("/", response_class=HTMLResponse)
def home(request: Request):
    c=conn()
    news=c.execute("SELECT * FROM news ORDER BY id DESC LIMIT 6").fetchall()
    events=c.execute("SELECT * FROM events ORDER BY starts_at ASC LIMIT 6").fetchall()
    c.close()
    return templates.TemplateResponse("index.html", {"request":request,"news":news,"events":events,"user":session_user(request)})

@app.get("/login", response_class=HTMLResponse)
def login(request: Request):
    return templates.TemplateResponse("login.html", {"request":request,"error":None})

@app.post("/auth/request")
def request_code(email: str=Form(...)):
    email=clean_email(email)
    if "@" not in email or "." not in email.split("@")[-1]:
        return RedirectResponse("/login?error=Неверный email",303)
    c=conn()
    recent=c.execute("SELECT id FROM otp WHERE email=? AND created_at>?",(email,(now()-timedelta(seconds=60)).isoformat())).fetchone()
    if recent:
        c.close()
        return RedirectResponse("/login?error=Подождите 60 секунд",303)
    code=f"{secrets.randbelow(1000000):06d}"
    h=hashlib.sha256(code.encode()).hexdigest()
    c.execute("INSERT INTO otp(email,code_hash,expires_at,created_at) VALUES(?,?,?,?)",(email,h,(now()+timedelta(minutes=10)).isoformat(),now().isoformat()))
    c.commit(); c.close()
    send_otp(email,code)
    return RedirectResponse(f"/verify?email={email}",303)

@app.get("/verify", response_class=HTMLResponse)
def verify_page(request: Request, email: str):
    return templates.TemplateResponse("verify.html", {"request":request,"email":email,"error":None})

@app.post("/auth/verify")
def verify(email: str=Form(...), code: str=Form(...)):
    email=clean_email(email)
    c=conn()
    row=c.execute("SELECT * FROM otp WHERE email=? AND consumed=0 ORDER BY id DESC LIMIT 1",(email,)).fetchone()
    if not row:
        c.close(); return RedirectResponse(f"/verify?email={email}&error=Код не найден",303)
    if datetime.fromisoformat(row["expires_at"]) < now():
        c.close(); return RedirectResponse(f"/verify?email={email}&error=Код истёк",303)
    if row["attempts"]>=5:
        c.close(); return RedirectResponse(f"/verify?email={email}&error=Слишком много попыток",303)
    if hashlib.sha256(code.strip().encode()).hexdigest() != row["code_hash"]:
        c.execute("UPDATE otp SET attempts=attempts+1 WHERE id=?",(row["id"],))
        c.commit(); c.close()
        return RedirectResponse(f"/verify?email={email}&error=Неверный код",303)
    c.execute("UPDATE otp SET consumed=1 WHERE id=?",(row["id"],)); c.commit(); c.close()
    create_user(email)
    response=RedirectResponse("/",303)
    response.set_cookie("motohub_session",serializer.dumps({"email":email}),httponly=True,samesite="lax",max_age=604800)
    return response

@app.post("/logout")
def logout():
    r=RedirectResponse("/",303); r.delete_cookie("motohub_session"); return r

@app.get("/profile", response_class=HTMLResponse)
def my_profile(request: Request):
    user=session_user(request)
    if not user: return RedirectResponse("/login",303)
    return RedirectResponse(f"/profile/{user['id']}",303)

@app.get("/profile/{user_id}", response_class=HTMLResponse)
def profile_page(request: Request, user_id:int):
    viewer=session_user(request)
    profile=get_user_by_id(user_id)
    if not profile: return RedirectResponse("/",303)
    c=conn()
    achievements=c.execute("""
      SELECT a.*, e.title AS event_title, e.starts_at, e.location
      FROM achievements a LEFT JOIN events e ON e.id=a.event_id
      WHERE a.user_id=? ORDER BY COALESCE(e.starts_at,a.created_at) DESC, a.id DESC
    """,(user_id,)).fetchall()
    stats=c.execute("""
      SELECT COUNT(*) total,
             SUM(CASE WHEN place=1 THEN 1 ELSE 0 END) firsts,
             SUM(CASE WHEN place=2 THEN 1 ELSE 0 END) seconds,
             SUM(CASE WHEN place=3 THEN 1 ELSE 0 END) thirds
      FROM achievements WHERE user_id=?
    """,(user_id,)).fetchone()
    c.close()
    return templates.TemplateResponse("profile.html", {
        "request":request,"user":viewer,"profile":profile,
        "achievements":achievements,"stats":stats
    })

@app.post("/profile/update")
async def profile_update(request: Request,
                         display_name: str=Form(""),
                         bio: str=Form(""),
                         motorcycle: str=Form(""),
                         city: str=Form(""),
                         avatar: UploadFile | None = File(None)):
    user=session_user(request)
    if not user: return RedirectResponse("/login",303)
    avatar_url=user["avatar_url"]
    if avatar and avatar.filename:
        ext=Path(avatar.filename).suffix.lower()
        if ext not in {".jpg",".jpeg",".png",".webp"}:
            return RedirectResponse("/profile?error=Формат фото не поддерживается",303)
        if avatar.content_type and not avatar.content_type.startswith("image/"):
            return RedirectResponse("/profile?error=Это не изображение",303)
        data=await avatar.read()
        if len(data)>4*1024*1024:
            return RedirectResponse("/profile?error=Фото больше 4 МБ",303)
        filename=f"user_{user['id']}{ext}"
        (UPLOADS/filename).write_bytes(data)
        avatar_url=f"/static/uploads/{filename}"
    c=conn()
    c.execute("""UPDATE users SET display_name=?,bio=?,motorcycle=?,city=?,avatar_url=? WHERE id=?""",
              (display_name.strip()[:80] or None,bio.strip()[:500],motorcycle.strip()[:100],city.strip()[:100],avatar_url,user["id"]))
    c.commit(); c.close()
    return RedirectResponse(f"/profile/{user['id']}",303)

@app.get("/chat", response_class=HTMLResponse)
def chat_page(request: Request):
    user=session_user(request)
    if not user: return RedirectResponse("/login",303)
    return templates.TemplateResponse("chat.html", {"request":request,"user":user})

@app.get("/api/chat/users")
def chat_users(request: Request):
    user=session_user(request)
    if not user: return JSONResponse({"error":"auth"},401)
    c=conn()
    rows=c.execute("SELECT id,email,display_name,role,is_banned,avatar_url,motorcycle,city FROM users WHERE id!=? ORDER BY COALESCE(display_name,email)",(user["id"],)).fetchall()
    c.close()
    return [public_user(r) for r in rows if not r["is_banned"]]

@app.get("/api/chat/messages/{other_id}")
def chat_history(request: Request, other_id:int):
    user=session_user(request); other=get_user_by_id(other_id)
    if not user: return JSONResponse({"error":"auth"},401)
    if not other: return JSONResponse({"error":"user_not_found"},404)
    c=conn()
    rows=c.execute("""SELECT id,email,display_name,text,created_at,recipient_id,is_read
      FROM messages WHERE recipient_id IS NOT NULL
      AND ((email=? AND recipient_id=?) OR (email=? AND recipient_id=?))
      ORDER BY id DESC LIMIT 100""",(user["email"],other_id,other["email"],user["id"])).fetchall()
    c.close()
    return [dict(r) for r in reversed(rows)]

@app.post("/api/chat/read/{other_id}")
def mark_read(request: Request, other_id:int):
    user=session_user(request); other=get_user_by_id(other_id)
    if not user: return JSONResponse({"error":"auth"},401)
    if not other: return JSONResponse({"error":"user_not_found"},404)
    c=conn(); c.execute("UPDATE messages SET is_read=1 WHERE email=? AND recipient_id=?",(other["email"],user["id"]))
    c.commit(); c.close(); return {"ok":True}

@app.get("/api/chat/unread")
def unread(request: Request):
    user=session_user(request)
    if not user: return JSONResponse({"error":"auth"},401)
    c=conn(); rows=c.execute("SELECT email,COUNT(*) count FROM messages WHERE recipient_id=? AND is_read=0 GROUP BY email",(user["id"],)).fetchall()
    c.close(); return [dict(r) for r in rows]

# ----- Admin -----
def is_staff(user): return user and user["role"] in ("ADMIN","MODERATOR")
def is_admin(user): return user and user["role"]=="ADMIN"

@app.get("/admin", response_class=HTMLResponse)
def admin(request: Request):
    user=session_user(request)
    if not is_staff(user): return RedirectResponse("/",303)
    c=conn()
    users=c.execute("SELECT * FROM users ORDER BY id DESC").fetchall()
    news=c.execute("SELECT * FROM news ORDER BY id DESC").fetchall()
    events=c.execute("SELECT * FROM events ORDER BY starts_at ASC").fetchall()
    c.close()
    return templates.TemplateResponse("admin.html",{"request":request,"user":user,"users":users,"news":news,"events":events})

@app.post("/admin/news")
def add_news(request: Request, title:str=Form(...), body:str=Form(...)):
    user=session_user(request)
    if not is_staff(user): return RedirectResponse("/",303)
    c=conn(); c.execute("INSERT INTO news(title,body,created_at) VALUES(?,?,?)",(title,body,now().isoformat())); c.commit(); c.close()
    return RedirectResponse("/admin",303)

@app.post("/admin/events")
def add_event(request: Request, title:str=Form(...), description:str=Form(...), starts_at:str=Form(...), location:str=Form("")):
    user=session_user(request)
    if not is_staff(user): return RedirectResponse("/",303)
    c=conn(); c.execute("INSERT INTO events(title,description,starts_at,location,created_at) VALUES(?,?,?,?,?)",(title,description,starts_at,location,now().isoformat())); c.commit(); c.close()
    return RedirectResponse("/admin",303)

@app.post("/admin/role")
def role(request: Request, user_id:int=Form(...), role:str=Form(...)):
    actor=session_user(request)
    if not is_admin(actor) or role not in ("USER","MODERATOR","ADMIN"): return RedirectResponse("/admin",303)
    c=conn(); c.execute("UPDATE users SET role=? WHERE id=?",(role,user_id)); c.commit(); c.close()
    return RedirectResponse("/admin",303)

@app.post("/admin/ban")
def ban(request: Request, user_id:int=Form(...), banned:int=Form(...)):
    actor=session_user(request)
    if not is_admin(actor): return RedirectResponse("/admin",303)
    c=conn(); c.execute("UPDATE users SET is_banned=? WHERE id=?",(1 if banned else 0,user_id)); c.commit(); c.close()
    return RedirectResponse("/admin",303)

@app.post("/admin/profile")
def admin_profile(request: Request, user_id:int=Form(...), display_name:str=Form(""), bio:str=Form(""), motorcycle:str=Form(""), city:str=Form("")):
    actor=session_user(request)
    if not is_staff(actor): return RedirectResponse("/admin",303)
    c=conn(); c.execute("UPDATE users SET display_name=?,bio=?,motorcycle=?,city=? WHERE id=?",
                         (display_name.strip()[:80] or None,bio.strip()[:500],motorcycle.strip()[:100],city.strip()[:100],user_id))
    c.commit(); c.close(); return RedirectResponse("/admin",303)

@app.post("/admin/achievement")
def admin_achievement(request: Request, user_id:int=Form(...), event_id:int|None=Form(None),
                      place:str=Form(""), award:str=Form(""), note:str=Form("")):
    actor=session_user(request)
    if not is_staff(actor): return RedirectResponse("/admin",303)
    place_num=None
    if place.strip():
        try: place_num=int(place)
        except ValueError: place_num=None
    c=conn()
    c.execute("INSERT INTO achievements(user_id,event_id,place,award,note,created_at) VALUES(?,?,?,?,?,?)",
              (user_id,event_id or None,place_num,award.strip()[:120],note.strip()[:500],now().isoformat()))
    c.commit(); c.close(); return RedirectResponse("/admin",303)

@app.post("/admin/achievement/delete")
def admin_achievement_delete(request: Request, achievement_id:int=Form(...)):
    actor=session_user(request)
    if not is_staff(actor): return RedirectResponse("/admin",303)
    c=conn(); c.execute("DELETE FROM achievements WHERE id=?",(achievement_id,)); c.commit(); c.close()
    return RedirectResponse("/admin",303)

class ChatManager:
    def __init__(self): self.connections={}
    async def connect(self,user_id,ws):
        await ws.accept(); self.connections.setdefault(user_id,set()).add(ws)
    def disconnect(self,user_id,ws):
        if user_id in self.connections:
            self.connections[user_id].discard(ws)
            if not self.connections[user_id]: del self.connections[user_id]
    async def send_user(self,user_id,payload):
        dead=[]
        for ws in list(self.connections.get(user_id,set())):
            try: await ws.send_json(payload)
            except Exception: dead.append(ws)
        for ws in dead: self.disconnect(user_id,ws)
    async def broadcast_public(self,payload):
        for uid in list(self.connections): await self.send_user(uid,payload)
    def online_ids(self): return list(self.connections)

manager=ChatManager()

def public_history():
    c=conn(); rows=c.execute("SELECT id,email,display_name,text,created_at,recipient_id FROM messages WHERE recipient_id IS NULL ORDER BY id DESC LIMIT 60").fetchall(); c.close()
    return [dict(r) for r in reversed(rows)]

@app.websocket("/ws/chat")
async def chat(ws: WebSocket):
    user=ws_user(ws)
    if not user or user["is_banned"]: await ws.close(code=1008); return
    await manager.connect(user["id"],ws)
    try:
        await ws.send_json({"type":"presence","online":manager.online_ids()})
        for m in public_history(): await ws.send_json({"type":"public","message":m})
        while True:
            data=await ws.receive_json()
            text=str(data.get("text","")).strip()
            if not text or len(text)>2000: continue
            if user["muted_until"] and user["muted_until"]>now().isoformat(): continue
            target=data.get("recipient_id")
            recipient=None
            if target not in (None,"",0):
                try: target=int(target)
                except ValueError: continue
                recipient=get_user_by_id(target)
                if not recipient or recipient["is_banned"] or recipient["id"]==user["id"]: continue
            c=conn(); created=now().isoformat()
            c.execute("""INSERT INTO messages(email,display_name,text,created_at,recipient_id,is_read)
                         VALUES(?,?,?,?,?,?)""",
                      (user["email"],user["display_name"] or user["email"].split("@")[0],
                       text,created,recipient["id"] if recipient else None,0 if recipient else 1))
            c.commit()
            row=c.execute("SELECT id,email,display_name,text,created_at,recipient_id,is_read FROM messages WHERE id=last_insert_rowid()").fetchone()
            c.close()
            payload={"type":"dm" if recipient else "public","message":dict(row)}
            if recipient:
                await manager.send_user(user["id"],payload)
                await manager.send_user(recipient["id"],payload)
            else:
                await manager.broadcast_public(payload)
            await manager.broadcast_public({"type":"presence","online":manager.online_ids()})
    except WebSocketDisconnect:
        manager.disconnect(user["id"],ws)
    except Exception:
        manager.disconnect(user["id"],ws)
