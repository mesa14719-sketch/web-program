# language: Python 3.11+, file: server.py
# Bot Hosting Platform — FastAPI (fixed)
# Made By @SUNIOxRICH | @Firstoget (Code Stride)

import os
import re
import io
import json
import uuid
import sqlite3
import asyncio
import subprocess
import secrets
import hashlib
import zipfile
import shutil
import tempfile
import sys
from pathlib import Path
from datetime import datetime, timedelta
from typing import Optional

from fastapi import FastAPI, HTTPException, Depends, UploadFile, File, Form, Request, status
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import jwt

# ============================================================
# CONFIG
# ============================================================
BASE_DIR     = Path(__file__).parent.resolve()
DATA_DIR     = BASE_DIR / "data"
BOTS_DIR     = DATA_DIR / "bots"
UPLOADS_DIR  = DATA_DIR / "uploads"
DB_PATH      = DATA_DIR / "app.db"
HTML_FILE    = BASE_DIR / "index.html"

DATA_DIR.mkdir(exist_ok=True)
BOTS_DIR.mkdir(exist_ok=True)
UPLOADS_DIR.mkdir(exist_ok=True)

JWT_SECRET   = os.environ.get("JWT_SECRET", secrets.token_urlsafe(48))
JWT_ALGO     = "HS256"
JWT_EXP_DAYS = 7

ADMIN_EMAIL  = os.environ.get("ADMIN_EMAIL", "admin@local").lower().strip()

MAX_UPLOAD_MB = 50
MAX_BOTS_PER_USER = 20

# ============================================================
# DATABASE
# ============================================================
def db():
    conn = sqlite3.connect(DB_PATH, timeout=15)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def init_db():
    with db() as conn:
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TEXT NOT NULL,
            is_admin INTEGER DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS bots (
            id TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            type TEXT NOT NULL,
            entry_file TEXT NOT NULL,
            status TEXT DEFAULT 'stopped',
            created_at TEXT NOT NULL,
            last_start TEXT,
            pid INTEGER,
            FOREIGN KEY (user_id) REFERENCES users(id)
        );
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            bot_id TEXT NOT NULL,
            line TEXT NOT NULL,
            type TEXT NOT NULL,
            ts TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_logs_bot ON logs(bot_id, id DESC);
        """)


init_db()

# ============================================================
# AUTH
# ============================================================
def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    h = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 200_000)
    return salt.hex() + "$" + h.hex()


def verify_password(password: str, stored: str) -> bool:
    try:
        salt_hex, h_hex = stored.split("$")
        salt = bytes.fromhex(salt_hex)
        h = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 200_000)
        return secrets.compare_digest(h.hex(), h_hex)
    except Exception:
        return False


def make_token(user_id: int, email: str) -> str:
    payload = {
        "uid": user_id,
        "email": email,
        "exp": datetime.utcnow() + timedelta(days=JWT_EXP_DAYS),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGO)


def decode_token(token: str) -> Optional[dict]:
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGO])
    except Exception:
        return None


def get_current_user(request: Request) -> dict:
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Missing token")
    data = decode_token(auth[7:])
    if not data:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid token")
    with db() as conn:
        row = conn.execute("SELECT id, email, is_admin FROM users WHERE id = ?", (data["uid"],)).fetchone()
    if not row:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "User not found")
    return dict(row)


# ============================================================
# APP
# ============================================================
app = FastAPI(title="Bot Hosting Platform")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# قائمة العمليات الحية: bot_id -> Popen
PROCS: dict = {}


# ============================================================
# MODELS
# ============================================================
class AuthPayload(BaseModel):
    email: str
    password: str


class RenamePayload(BaseModel):
    name: str


# ============================================================
# AUTH ROUTES
# ============================================================
@app.post("/api/auth/register")
def register(p: AuthPayload):
    email = p.email.lower().strip()
    if not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email):
        raise HTTPException(400, "بريد غير صالح")
    if len(p.password) < 6:
        raise HTTPException(400, "كلمة المرور قصيرة (6 أحرف على الأقل)")

    with db() as conn:
        if conn.execute("SELECT id FROM users WHERE email = ?", (email,)).fetchone():
            raise HTTPException(400, "البريد مستخدم مسبقاً")
        is_admin = 1 if email == ADMIN_EMAIL else 0
        cur = conn.execute(
            "INSERT INTO users (email, password_hash, created_at, is_admin) VALUES (?, ?, ?, ?)",
            (email, hash_password(p.password), datetime.utcnow().isoformat(), is_admin),
        )
        uid = cur.lastrowid

    return {"ok": True, "token": make_token(uid, email), "user": {"id": uid, "email": email, "is_admin": bool(is_admin)}}


@app.post("/api/auth/login")
def login(p: AuthPayload):
    email = p.email.lower().strip()
    with db() as conn:
        row = conn.execute("SELECT id, email, password_hash, is_admin FROM users WHERE email = ?", (email,)).fetchone()
    if not row or not verify_password(p.password, row["password_hash"]):
        raise HTTPException(401, "بيانات غير صحيحة")
    return {"ok": True, "token": make_token(row["id"], row["email"]), "user": {"id": row["id"], "email": row["email"], "is_admin": bool(row["is_admin"])}}


@app.get("/api/auth/me")
def me(user: dict = Depends(get_current_user)):
    return {"ok": True, "user": {"id": user["id"], "email": user["email"], "is_admin": bool(user["is_admin"])}}


# ============================================================
# HELPERS
# ============================================================
def detect_bot_type(entry_file: str) -> Optional[str]:
    lf = entry_file.lower()
    if lf.endswith(".py"): return "python"
    if lf.endswith(".php"): return "php"
    return None


def bot_log(bot_id: str, type_: str, line: str):
    with db() as conn:
        conn.execute(
            "INSERT INTO logs (bot_id, line, type, ts) VALUES (?, ?, ?, ?)",
            (bot_id, line[:2000], type_, datetime.utcnow().isoformat()),
        )
        conn.execute("""
            DELETE FROM logs WHERE bot_id = ? AND id NOT IN (
                SELECT id FROM logs WHERE bot_id = ? ORDER BY id DESC LIMIT 500
            )
        """, (bot_id, bot_id))


def extract_zip_to_bot(zip_path: Path, dest_dir: Path) -> tuple:
    with zipfile.ZipFile(zip_path, "r") as z:
        names = z.namelist()
        files = [n for n in names if not n.endswith("/") and "__MACOSX" not in n and not n.startswith(".")]

        prefixes = set(n.split("/")[0] for n in files if "/" in n)
        single_prefix = None
        if len(prefixes) == 1:
            p = list(prefixes)[0]
            if all(n.startswith(p + "/") for n in files):
                single_prefix = p + "/"

        py_files = [n for n in files if n.lower().endswith(".py")]
        php_files = [n for n in files if n.lower().endswith(".php")]
        candidates = ["bot.py", "main.py", "app.py", "index.py"] + py_files + php_files

        entry = None
        for c in candidates:
            for n in files:
                stripped = n[len(single_prefix):] if single_prefix else n
                if stripped == c or n == c:
                    entry = n; break
            if entry: break

        if not entry and (py_files or php_files):
            entry = (py_files or php_files)[0]

        if not entry:
            raise ValueError("لا يوجد ملف .py أو .php في الـ ZIP")

        for n in files:
            src = z.open(n)
            rel = n[len(single_prefix):] if (single_prefix and n.startswith(single_prefix)) else n
            out = dest_dir / rel
            out.parent.mkdir(parents=True, exist_ok=True)
            with out.open("wb") as f:
                shutil.copyfileobj(src, f)

        entry_rel = entry[len(single_prefix):] if (single_prefix and entry.startswith(single_prefix)) else entry
        return entry_rel, {"files": files, "total": len(files)}


def install_requirements(bot_dir: Path, bot_id: str):
    req = bot_dir / "requirements.txt"
    if not req.exists():
        bot_log(bot_id, "sys", "[pip] لا يوجد requirements.txt")
        return True

    bot_log(bot_id, "sys", "[pip] جارٍ تثبيت المكتبات...")
    try:
        result = subprocess.run(
            [sys.executable, "-m", "pip", "install", "--no-cache-dir", "--disable-pip-version-check", "-r", str(req)],
            cwd=str(bot_dir),
            capture_output=True,
            text=True,
            timeout=600,
        )
        if result.returncode == 0:
            bot_log(bot_id, "sys", "[pip] ✅ تم التثبيت بنجاح")
            return True
        else:
            for line in (result.stderr or "").splitlines()[-15:]:
                bot_log(bot_id, "err", "[pip] " + line)
            return False
    except subprocess.TimeoutExpired:
        bot_log(bot_id, "err", "[pip] انتهت المهلة (10 دقائق)")
        return False
    except Exception as e:
        bot_log(bot_id, "err", f"[pip] {e}")
        return False


# ============================================================
# BOT ROUTES
# ============================================================
@app.get("/api/bots")
def list_bots(user: dict = Depends(get_current_user)):
    with db() as conn:
        rows = conn.execute(
            "SELECT id, name, type, entry_file, status, created_at, last_start FROM bots WHERE user_id = ? ORDER BY created_at DESC",
            (user["id"],),
        ).fetchall()
    return {"ok": True, "bots": [dict(r) for r in rows]}


@app.post("/api/bots")
async def create_bot(
    name: str = Form(...),
    file: UploadFile = File(...),
    user: dict = Depends(get_current_user),
):
    name = name.strip()[:60]
    if not name:
        raise HTTPException(400, "الاسم مطلوب")

    with db() as conn:
        cnt = conn.execute("SELECT COUNT(*) AS c FROM bots WHERE user_id = ?", (user["id"],)).fetchone()["c"]
    if cnt >= MAX_BOTS_PER_USER:
        raise HTTPException(400, f"الحد الأقصى {MAX_BOTS_PER_USER} بوت")

    content = await file.read()
    if len(content) > MAX_UPLOAD_MB * 1024 * 1024:
        raise HTTPException(400, f"الملف أكبر من {MAX_UPLOAD_MB} MB")

    bot_id = uuid.uuid4().hex[:12]
    bot_dir = BOTS_DIR / bot_id
    bot_dir.mkdir(parents=True, exist_ok=True)

    try:
        if file.filename.lower().endswith(".zip"):
            tmp = UPLOADS_DIR / f"{bot_id}.zip"
            tmp.write_bytes(content)
            try:
                entry, meta = extract_zip_to_bot(tmp, bot_dir)
            finally:
                tmp.unlink(missing_ok=True)
        elif file.filename.lower().endswith((".py", ".php")):
            entry = file.filename
            (bot_dir / entry).write_bytes(content)
        else:
            shutil.rmtree(bot_dir, ignore_errors=True)
            raise HTTPException(400, "يُقبل فقط: ZIP، PY، PHP")

        bot_type = detect_bot_type(entry)
        if not bot_type:
            shutil.rmtree(bot_dir, ignore_errors=True)
            raise HTTPException(400, "نوع الملف غير مدعوم")

    except HTTPException:
        raise
    except Exception as e:
        shutil.rmtree(bot_dir, ignore_errors=True)
        raise HTTPException(400, f"فشل الاستخراج: {e}")

    with db() as conn:
        conn.execute(
            "INSERT INTO bots (id, user_id, name, type, entry_file, status, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (bot_id, user["id"], name, bot_type, entry, "stopped", datetime.utcnow().isoformat()),
        )

    # تثبيت المكتبات (blocking سريع كفاية، أو نخليه async)
    await asyncio.to_thread(install_requirements, bot_dir, bot_id)

    return {"ok": True, "id": bot_id, "name": name, "type": bot_type}


@app.post("/api/bots/{bot_id}/rename")
def rename_bot(bot_id: str, p: RenamePayload, user: dict = Depends(get_current_user)):
    name = p.name.strip()[:60]
    if not name:
        raise HTTPException(400, "الاسم مطلوب")
    with db() as conn:
        row = conn.execute("SELECT id FROM bots WHERE id = ? AND user_id = ?", (bot_id, user["id"])).fetchone()
        if not row:
            raise HTTPException(404, "غير موجود")
        conn.execute("UPDATE bots SET name = ? WHERE id = ?", (name, bot_id))
    return {"ok": True}


@app.delete("/api/bots/{bot_id}")
def delete_bot(bot_id: str, user: dict = Depends(get_current_user)):
    with db() as conn:
        row = conn.execute("SELECT id FROM bots WHERE id = ? AND user_id = ?", (bot_id, user["id"])).fetchone()
        if not row:
            raise HTTPException(404, "غير موجود")
        conn.execute("DELETE FROM bots WHERE id = ?", (bot_id,))
        conn.execute("DELETE FROM logs WHERE bot_id = ?", (bot_id,))
    # أوقف العملية إن كانت تعمل
    proc = PROCS.pop(bot_id, None)
    if proc and proc.poll() is None:
        try: proc.terminate()
        except Exception: pass
    shutil.rmtree(BOTS_DIR / bot_id, ignore_errors=True)
    return {"ok": True}


@app.post("/api/bots/{bot_id}/start")
def start_bot(bot_id: str, user: dict = Depends(get_current_user)):
    with db() as conn:
        row = conn.execute("SELECT * FROM bots WHERE id = ? AND user_id = ?", (bot_id, user["id"])).fetchone()
    if not row:
        raise HTTPException(404, "غير موجود")

    # إذا كانت العملية موجودة وتعمل، أرجع فوراً
    existing = PROCS.get(bot_id)
    if existing and existing.poll() is None:
        return {"ok": True, "msg": "يعمل مسبقاً", "pid": existing.pid}

    bot_dir = BOTS_DIR / bot_id
    entry = bot_dir / row["entry_file"]
    if not entry.exists():
        raise HTTPException(400, f"ملف الدخول مفقود: {row['entry_file']}")

    try:
        if row["type"] == "python":
            cmd = [sys.executable, "-u", str(entry)]
        elif row["type"] == "php":
            cmd = ["php", str(entry)]
        else:
            raise HTTPException(400, "نوع غير مدعوم")

        proc = subprocess.Popen(
            cmd,
            cwd=str(bot_dir),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )
    except FileNotFoundError as e:
        raise HTTPException(500, f"المشغّل غير متوفر: {e}")

    PROCS[bot_id] = proc

    with db() as conn:
        conn.execute(
            "UPDATE bots SET status = 'running', pid = ?, last_start = ? WHERE id = ?",
            (proc.pid, datetime.utcnow().isoformat(), bot_id),
        )

    # بدء قارئات stdout/stderr في الخلفية
    asyncio.create_task(_stream_output(bot_id, proc))

    return {"ok": True, "pid": proc.pid}


async def _stream_output(bot_id: str, proc: subprocess.Popen):
    def read_stream(stream, type_):
        try:
            for line in iter(stream.readline, ""):
                if line:
                    bot_log(bot_id, type_, line.rstrip("\n"))
        except Exception:
            pass
        finally:
            try: stream.close()
            except Exception: pass

    await asyncio.gather(
        asyncio.to_thread(read_stream, proc.stdout, "out"),
        asyncio.to_thread(read_stream, proc.stderr, "err"),
    )

    code = await asyncio.to_thread(proc.wait)
    bot_log(bot_id, "sys", f"[exit] code={code}")
    PROCS.pop(bot_id, None)
    with db() as conn:
        conn.execute("UPDATE bots SET status = 'stopped', pid = NULL WHERE id = ?", (bot_id,))


@app.post("/api/bots/{bot_id}/stop")
def stop_bot(bot_id: str, user: dict = Depends(get_current_user)):
    with db() as conn:
        row = conn.execute("SELECT * FROM bots WHERE id = ? AND user_id = ?", (bot_id, user["id"])).fetchone()
    if not row:
        raise HTTPException(404, "غير موجود")

    proc = PROCS.get(bot_id)
    if proc and proc.poll() is None:
        try: proc.terminate()
        except Exception: pass
        try: proc.wait(timeout=5)
        except Exception:
            try: proc.kill()
            except Exception: pass
    PROCS.pop(bot_id, None)

    with db() as conn:
        conn.execute("UPDATE bots SET status = 'stopped', pid = NULL WHERE id = ?", (bot_id,))

    bot_log(bot_id, "sys", "[stopped by user]")
    return {"ok": True}


@app.get("/api/bots/{bot_id}/logs")
def get_logs(bot_id: str, since: int = 0, user: dict = Depends(get_current_user)):
    with db() as conn:
        row = conn.execute("SELECT id FROM bots WHERE id = ? AND user_id = ?", (bot_id, user["id"])).fetchone()
        if not row:
            raise HTTPException(404, "غير موجود")
        rows = conn.execute(
            "SELECT id, line, type, ts FROM logs WHERE bot_id = ? AND id > ? ORDER BY id ASC LIMIT 500",
            (bot_id, since),
        ).fetchall()
    return {"ok": True, "logs": [dict(r) for r in rows]}


@app.get("/api/bots/{bot_id}/stream")
async def stream_logs(bot_id: str, request: Request, user: dict = Depends(get_current_user)):
    with db() as conn:
        row = conn.execute("SELECT id FROM bots WHERE id = ? AND user_id = ?", (bot_id, user["id"])).fetchone()
        if not row:
            raise HTTPException(404, "غير موجود")

    async def gen():
        last_id = 0
        while True:
            if await request.is_disconnected():
                break
            with db() as conn:
                rows = conn.execute(
                    "SELECT id, line, type, ts FROM logs WHERE bot_id = ? AND id > ? ORDER BY id ASC LIMIT 100",
                    (bot_id, last_id),
                ).fetchall()
            for r in rows:
                last_id = r["id"]
                yield f"data: {json.dumps({'id': r['id'], 'line': r['line'], 'type': r['type'], 'ts': r['ts']})}\n\n"
            await asyncio.sleep(1)

    return StreamingResponse(gen(), media_type="text/event-stream")


# ============================================================
# CRON / WAKEUP — لإعادة تشغيل البوتات بعد نوم Render
# ============================================================
@app.get("/api/cron/resume")
def cron_resume(request: Request):
    """يُستدعى دورياً (cron-job.org مثلاً) لتشغيل البوتات المتوقفة."""
    # تحقق بسيط: مفتاح في الرابط أو أن كل البوتات تُعاد
    restarted = []
    with db() as conn:
        rows = conn.execute("SELECT id, user_id FROM bots").fetchall()
    for r in rows:
        if r["id"] not in PROCS or PROCS[r["id"]].poll() is not None:
            # أنشئ طلب start يدوياً (بدون auth — endpoint داخلي)
            try:
                class FakeReq:
                    def __init__(self, uid, email):
                        self.uid = uid; self.email = email
                # بديل: نستخدم منطق start_bot مباشرة
                with db() as conn:
                    bot = conn.execute("SELECT * FROM bots WHERE id = ?", (r["id"],)).fetchone()
                if not bot: continue
                bot_dir = BOTS_DIR / r["id"]
                entry = bot_dir / bot["entry_file"]
                if not entry.exists(): continue
                cmd = [sys.executable, "-u", str(entry)] if bot["type"] == "python" else ["php", str(entry)]
                proc = subprocess.Popen(cmd, cwd=str(bot_dir), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1)
                PROCS[r["id"]] = proc
                with db() as conn:
                    conn.execute("UPDATE bots SET status='running', pid=?, last_start=? WHERE id=?",
                                 (proc.pid, datetime.utcnow().isoformat(), r["id"]))
                asyncio.create_task(_stream_output(r["id"], proc))
                restarted.append(r["id"])
            except Exception as e:
                bot_log(r["id"], "err", f"[cron] {e}")

    return {"ok": True, "restarted": restarted}


@app.get("/health")
def health():
    return {"ok": True, "running": len([p for p in PROCS.values() if p.poll() is None])}


# ============================================================
# ROOT
# ============================================================
@app.get("/", response_class=HTMLResponse)
def root():
    if not HTML_FILE.exists():
        return HTMLResponse("<h1>index.html مفقود</h1>", status_code=500)
    return HTMLResponse(HTML_FILE.read_text(encoding="utf-8"))


if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run("server:app", host="0.0.0.0", port=port, reload=False)
