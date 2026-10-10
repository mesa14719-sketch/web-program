# language: Python 3.11+, file: server.py
# Bot Hosting Platform — no email verification
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
import sys
import random
import string
import urllib.request
from pathlib import Path
from datetime import datetime, timedelta
from typing import Optional

from fastapi import FastAPI, HTTPException, Depends, UploadFile, File, Form, Request, status
from fastapi.responses import HTMLResponse, StreamingResponse
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
            is_admin INTEGER DEFAULT 0,
            terms_accepted TEXT
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
            source TEXT DEFAULT 'upload',
            github_url TEXT,
            github_branch TEXT,
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
        CREATE TABLE IF NOT EXISTS file_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            bot_id TEXT NOT NULL,
            path TEXT NOT NULL,
            content TEXT NOT NULL,
            ts TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_hist_bot ON file_history(bot_id, id DESC);
        """)

        # migrations — أعمدة جديدة لو الجدول قديم
        ucols = [r["name"] for r in conn.execute("PRAGMA table_info(users)").fetchall()]
        for col, ddl in [
            ("is_admin", "ALTER TABLE users ADD COLUMN is_admin INTEGER DEFAULT 0"),
            ("terms_accepted", "ALTER TABLE users ADD COLUMN terms_accepted TEXT"),
        ]:
            if col not in ucols:
                try: conn.execute(ddl)
                except Exception: pass

        bcols = [r["name"] for r in conn.execute("PRAGMA table_info(bots)").fetchall()]
        for col, ddl in [
            ("source", "ALTER TABLE bots ADD COLUMN source TEXT DEFAULT 'upload'"),
            ("github_url", "ALTER TABLE bots ADD COLUMN github_url TEXT"),
            ("github_branch", "ALTER TABLE bots ADD COLUMN github_branch TEXT"),
        ]:
            if col not in bcols:
                try: conn.execute(ddl)
                except Exception: pass


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
    payload = {"uid": user_id, "email": email, "exp": datetime.utcnow() + timedelta(days=JWT_EXP_DAYS)}
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
    allow_origins=["*"], allow_credentials=True,
    allow_methods=["*"], allow_headers=["*"],
)

PROCS: dict = {}


# ============================================================
# MODELS
# ============================================================
class RegisterPayload(BaseModel):
    email: str
    password: str
    terms: bool


class AuthPayload(BaseModel):
    email: str
    password: str


class RenamePayload(BaseModel):
    name: str


class FileSave(BaseModel):
    path: str
    content: str


class FileCreate(BaseModel):
    path: str
    is_dir: bool = False


class GitHubImport(BaseModel):
    name: str
    url: str
    branch: str = "main"


# ============================================================
# AUTH ROUTES
# ============================================================
@app.post("/api/auth/register")
def register(p: RegisterPayload):
    if not p.terms:
        raise HTTPException(400, "يجب الموافقة على الشروط والأحكام")

    email = p.email.lower().strip()
    if not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email):
        raise HTTPException(400, "بريد غير صالح")
    if len(p.password) < 8:
        raise HTTPException(400, "كلمة المرور 8 أحرف على الأقل")
    if not re.search(r"[A-Za-z]", p.password) or not re.search(r"\d", p.password):
        raise HTTPException(400, "كلمة المرور يجب أن تحتوي حرفاً ورقماً على الأقل")

    with db() as conn:
        if conn.execute("SELECT id FROM users WHERE email = ?", (email,)).fetchone():
            raise HTTPException(400, "البريد مسجّل مسبقاً")

        is_admin = 1 if email == ADMIN_EMAIL else 0
        cur = conn.execute(
            "INSERT INTO users (email, password_hash, created_at, is_admin, terms_accepted) VALUES (?, ?, ?, ?, ?)",
            (email, hash_password(p.password), datetime.utcnow().isoformat(), is_admin, datetime.utcnow().isoformat())
        )
        uid = cur.lastrowid

    return {"ok": True, "token": make_token(uid, email),
            "user": {"id": uid, "email": email, "is_admin": bool(is_admin)}}


@app.post("/api/auth/login")
def login(p: AuthPayload):
    email = p.email.lower().strip()
    with db() as conn:
        row = conn.execute(
            "SELECT id, email, password_hash, is_admin FROM users WHERE email = ?", (email,)
        ).fetchone()
    if not row or not verify_password(p.password, row["password_hash"]):
        raise HTTPException(401, "بيانات غير صحيحة")
    return {"ok": True, "token": make_token(row["id"], row["email"]),
            "user": {"id": row["id"], "email": row["email"], "is_admin": bool(row["is_admin"])}}


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


def find_entry_file(bot_dir: Path) -> Optional[str]:
    priority = ["bot.py", "main.py", "app.py", "index.py", "index.php", "bot.php"]
    all_files = []
    for f in bot_dir.rglob("*"):
        if f.is_file():
            rel = f.relative_to(bot_dir).as_posix()
            if "__MACOSX" in rel or rel.startswith("."): continue
            all_files.append(rel)

    for name in priority:
        for f in all_files:
            if f == name or f.endswith("/" + name):
                return f

    py = [f for f in all_files if f.lower().endswith(".py")]
    php = [f for f in all_files if f.lower().endswith(".php")]
    if py: return py[0]
    if php: return php[0]
    return None


def install_requirements(bot_dir: Path, bot_id: str):
    req = None
    for candidate in bot_dir.rglob("requirements.txt"):
        req = candidate; break
    if not req:
        return True

    bot_log(bot_id, "sys", "[pip] جارٍ التثبيت...")
    try:
        result = subprocess.run(
            [sys.executable, "-m", "pip", "install", "--no-cache-dir", "--disable-pip-version-check", "-r", str(req)],
            cwd=str(req.parent), capture_output=True, text=True, timeout=600,
        )
        if result.returncode == 0:
            bot_log(bot_id, "sys", "[pip] ✅ تم التثبيت")
            return True
        for line in (result.stderr or "").splitlines()[-15:]:
            bot_log(bot_id, "err", "[pip] " + line)
        return False
    except Exception as e:
        bot_log(bot_id, "err", f"[pip] {e}")
        return False


def extract_zip_safe(zip_path: Path, dest_dir: Path):
    with zipfile.ZipFile(zip_path, "r") as z:
        files = [n for n in z.namelist()
                 if not n.endswith("/") and "__MACOSX" not in n and not n.startswith(".")]
        prefixes = set(n.split("/")[0] for n in files if "/" in n)
        single = None
        if len(prefixes) == 1:
            p = list(prefixes)[0]
            if all(n.startswith(p + "/") for n in files):
                single = p + "/"

        for n in files:
            src = z.open(n)
            rel = n[len(single):] if (single and n.startswith(single)) else n
            out = dest_dir / rel
            out.parent.mkdir(parents=True, exist_ok=True)
            with out.open("wb") as f:
                shutil.copyfileobj(src, f)


def _download_file(url: str, dest: Path):
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    with urllib.request.urlopen(req, timeout=60) as r, open(dest, "wb") as f:
        shutil.copyfileobj(r, f)


# ============================================================
# BOTS
# ============================================================
@app.get("/api/bots")
def list_bots(user: dict = Depends(get_current_user)):
    with db() as conn:
        rows = conn.execute(
            "SELECT id, name, type, entry_file, status, created_at, last_start, source, github_url "
            "FROM bots WHERE user_id = ? ORDER BY created_at DESC",
            (user["id"],)
        ).fetchall()
    return {"ok": True, "bots": [dict(r) for r in rows]}


@app.post("/api/bots/upload-files")
async def upload_files(
    name: str = Form(...),
    main_file: UploadFile = File(...),
    requirements: Optional[UploadFile] = File(None),
    extras: list[UploadFile] = File(default=[]),
    user: dict = Depends(get_current_user),
):
    name = name.strip()[:60]
    if not name:
        raise HTTPException(400, "الاسم مطلوب")

    with db() as conn:
        cnt = conn.execute("SELECT COUNT(*) AS c FROM bots WHERE user_id = ?", (user["id"],)).fetchone()["c"]
    if cnt >= MAX_BOTS_PER_USER:
        raise HTTPException(400, f"الحد الأقصى {MAX_BOTS_PER_USER} بوت")

    bot_id = uuid.uuid4().hex[:12]
    bot_dir = BOTS_DIR / bot_id
    bot_dir.mkdir(parents=True, exist_ok=True)

    try:
        main_name = Path(main_file.filename).name
        main_content = await main_file.read()
        if len(main_content) > MAX_UPLOAD_MB * 1024 * 1024:
            raise HTTPException(400, "الملف الرئيسي كبير جداً")
        (bot_dir / main_name).write_bytes(main_content)

        if requirements and requirements.filename:
            req_content = await requirements.read()
            (bot_dir / "requirements.txt").write_bytes(req_content)

        for ex in (extras or []):
            if not ex.filename: continue
            safe_name = Path(ex.filename).name
            content = await ex.read()
            (bot_dir / safe_name).write_bytes(content)

        if main_name.lower().endswith(".zip"):
            try:
                extract_zip_safe(bot_dir / main_name, bot_dir)
                (bot_dir / main_name).unlink(missing_ok=True)
            except Exception as e:
                raise HTTPException(400, f"فشل فك ZIP: {e}")

        entry = find_entry_file(bot_dir)
        if not entry:
            raise HTTPException(400, "لم يُعثر على ملف .py أو .php")
        bot_type = detect_bot_type(entry)
        if not bot_type:
            raise HTTPException(400, "نوع غير مدعوم")

    except HTTPException:
        shutil.rmtree(bot_dir, ignore_errors=True)
        raise
    except Exception as e:
        shutil.rmtree(bot_dir, ignore_errors=True)
        raise HTTPException(400, f"فشل: {e}")

    with db() as conn:
        conn.execute(
            "INSERT INTO bots (id, user_id, name, type, entry_file, status, created_at, source) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, 'upload')",
            (bot_id, user["id"], name, bot_type, entry, "stopped", datetime.utcnow().isoformat())
        )

    await asyncio.to_thread(install_requirements, bot_dir, bot_id)
    return {"ok": True, "id": bot_id, "type": bot_type, "entry_file": entry}


@app.post("/api/bots/import-github")
async def import_github(p: GitHubImport, user: dict = Depends(get_current_user)):
    name = p.name.strip()[:60]
    if not name:
        raise HTTPException(400, "الاسم مطلوب")

    m = re.match(r"^https?://github\.com/([^/]+)/([^/]+?)(?:\.git)?/?(?:tree/([^/]+))?/?$", p.url.strip())
    if not m:
        raise HTTPException(400, "رابط GitHub غير صالح")
    owner, repo = m.group(1), m.group(2)
    branch = p.branch.strip() or m.group(3) or "main"

    with db() as conn:
        cnt = conn.execute("SELECT COUNT(*) AS c FROM bots WHERE user_id = ?", (user["id"],)).fetchone()["c"]
    if cnt >= MAX_BOTS_PER_USER:
        raise HTTPException(400, f"الحد الأقصى {MAX_BOTS_PER_USER} بوت")

    bot_id = uuid.uuid4().hex[:12]
    bot_dir = BOTS_DIR / bot_id
    bot_dir.mkdir(parents=True, exist_ok=True)

    zip_url = f"https://codeload.github.com/{owner}/{repo}/zip/refs/heads/{branch}"
    tmp_zip = UPLOADS_DIR / f"{bot_id}.zip"

    try:
        await asyncio.to_thread(_download_file, zip_url, tmp_zip)
        extract_zip_safe(tmp_zip, bot_dir)
    except Exception as e:
        shutil.rmtree(bot_dir, ignore_errors=True)
        tmp_zip.unlink(missing_ok=True)
        raise HTTPException(400, f"فشل الاستيراد: {e}")
    finally:
        tmp_zip.unlink(missing_ok=True)

    entry = find_entry_file(bot_dir)
    if not entry:
        shutil.rmtree(bot_dir, ignore_errors=True)
        raise HTTPException(400, "لم يُعثر على ملف .py أو .php في المستودع")
    bot_type = detect_bot_type(entry)
    if not bot_type:
        shutil.rmtree(bot_dir, ignore_errors=True)
        raise HTTPException(400, "نوع غير مدعوم")

    with db() as conn:
        conn.execute(
            "INSERT INTO bots (id, user_id, name, type, entry_file, status, created_at, source, github_url, github_branch) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, 'github', ?, ?)",
            (bot_id, user["id"], name, bot_type, entry, "stopped",
             datetime.utcnow().isoformat(), p.url.strip(), branch)
        )

    await asyncio.to_thread(install_requirements, bot_dir, bot_id)
    return {"ok": True, "id": bot_id, "type": bot_type, "entry_file": entry}


@app.post("/api/bots/{bot_id}/update-from-github")
async def update_from_github(bot_id: str, user: dict = Depends(get_current_user)):
    with db() as conn:
        row = conn.execute("SELECT * FROM bots WHERE id = ? AND user_id = ?", (bot_id, user["id"])).fetchone()
    if not row: raise HTTPException(404, "غير موجود")
    if row["source"] != "github" or not row["github_url"]:
        raise HTTPException(400, "هذا البوت لم يُستورد من GitHub")

    m = re.match(r"^https?://github\.com/([^/]+)/([^/]+?)(?:\.git)?/?$", row["github_url"])
    if not m: raise HTTPException(400, "رابط GitHub غير صالح")
    owner, repo = m.group(1), m.group(2)
    branch = row["github_branch"] or "main"

    bot_dir = BOTS_DIR / bot_id
    new_dir = BOTS_DIR / f"{bot_id}_new"

    proc = PROCS.pop(bot_id, None)
    if proc and proc.poll() is None:
        try: proc.terminate()
        except Exception: pass

    zip_url = f"https://codeload.github.com/{owner}/{repo}/zip/refs/heads/{branch}"
    tmp_zip = UPLOADS_DIR / f"{bot_id}_upd.zip"

    try:
        if new_dir.exists(): shutil.rmtree(new_dir, ignore_errors=True)
        new_dir.mkdir(parents=True)
        await asyncio.to_thread(_download_file, zip_url, tmp_zip)
        extract_zip_safe(tmp_zip, new_dir)
    except Exception as e:
        if new_dir.exists(): shutil.rmtree(new_dir, ignore_errors=True)
        raise HTTPException(400, f"فشل التحديث: {e}")
    finally:
        tmp_zip.unlink(missing_ok=True)

    if bot_dir.exists(): shutil.rmtree(bot_dir)
    new_dir.rename(bot_dir)

    bot_log(bot_id, "sys", "[update] تم التحديث من GitHub")
    await asyncio.to_thread(install_requirements, bot_dir, bot_id)

    with db() as conn:
        conn.execute("UPDATE bots SET status='stopped', pid=NULL WHERE id=?", (bot_id,))

    return {"ok": True}


@app.post("/api/bots/{bot_id}/rename")
def rename_bot(bot_id: str, p: RenamePayload, user: dict = Depends(get_current_user)):
    name = p.name.strip()[:60]
    if not name: raise HTTPException(400, "الاسم مطلوب")
    with db() as conn:
        if not conn.execute("SELECT id FROM bots WHERE id = ? AND user_id = ?", (bot_id, user["id"])).fetchone():
            raise HTTPException(404, "غير موجود")
        conn.execute("UPDATE bots SET name = ? WHERE id = ?", (name, bot_id))
    return {"ok": True}


@app.delete("/api/bots/{bot_id}")
def delete_bot(bot_id: str, user: dict = Depends(get_current_user)):
    with db() as conn:
        if not conn.execute("SELECT id FROM bots WHERE id = ? AND user_id = ?", (bot_id, user["id"])).fetchone():
            raise HTTPException(404, "غير موجود")
        conn.execute("DELETE FROM bots WHERE id = ?", (bot_id,))
        conn.execute("DELETE FROM logs WHERE bot_id = ?", (bot_id,))
        conn.execute("DELETE FROM file_history WHERE bot_id = ?", (bot_id,))
    proc = PROCS.pop(bot_id, None)
    if proc and proc.poll() is None:
        try: proc.terminate()
        except Exception: pass
    shutil.rmtree(BOTS_DIR / bot_id, ignore_errors=True)
    return {"ok": True}


# ============================================================
# START / STOP / LOGS
# ============================================================
@app.post("/api/bots/{bot_id}/start")
def start_bot(bot_id: str, user: dict = Depends(get_current_user)):
    with db() as conn:
        row = conn.execute("SELECT * FROM bots WHERE id = ? AND user_id = ?", (bot_id, user["id"])).fetchone()
    if not row: raise HTTPException(404, "غير موجود")

    existing = PROCS.get(bot_id)
    if existing and existing.poll() is None:
        return {"ok": True, "pid": existing.pid}

    bot_dir = BOTS_DIR / bot_id
    entry = bot_dir / row["entry_file"]
    if not entry.exists():
        raise HTTPException(400, f"ملف الدخول مفقود: {row['entry_file']}")

    cmd = [sys.executable, "-u", str(entry)] if row["type"] == "python" else ["php", str(entry)]
    try:
        proc = subprocess.Popen(cmd, cwd=str(bot_dir),
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                text=True, bufsize=1)
    except FileNotFoundError as e:
        raise HTTPException(500, f"المشغّل غير متوفر: {e}")

    PROCS[bot_id] = proc
    with db() as conn:
        conn.execute("UPDATE bots SET status='running', pid=?, last_start=? WHERE id=?",
                     (proc.pid, datetime.utcnow().isoformat(), bot_id))
    asyncio.create_task(_stream_output(bot_id, proc))
    return {"ok": True, "pid": proc.pid}


async def _stream_output(bot_id: str, proc: subprocess.Popen):
    def reader(stream, t):
        try:
            for line in iter(stream.readline, ""):
                if line: bot_log(bot_id, t, line.rstrip("\n"))
        except Exception: pass
        finally:
            try: stream.close()
            except Exception: pass

    await asyncio.gather(
        asyncio.to_thread(reader, proc.stdout, "out"),
        asyncio.to_thread(reader, proc.stderr, "err"),
    )
    code = await asyncio.to_thread(proc.wait)
    bot_log(bot_id, "sys", f"[exit] code={code}")
    PROCS.pop(bot_id, None)
    with db() as conn:
        conn.execute("UPDATE bots SET status='stopped', pid=NULL WHERE id=?", (bot_id,))


@app.post("/api/bots/{bot_id}/stop")
def stop_bot(bot_id: str, user: dict = Depends(get_current_user)):
    with db() as conn:
        if not conn.execute("SELECT id FROM bots WHERE id = ? AND user_id = ?", (bot_id, user["id"])).fetchone():
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
        conn.execute("UPDATE bots SET status='stopped', pid=NULL WHERE id=?", (bot_id,))
    bot_log(bot_id, "sys", "[stopped by user]")
    return {"ok": True}


@app.post("/api/bots/{bot_id}/restart")
def restart_bot(bot_id: str, user: dict = Depends(get_current_user)):
    stop_bot(bot_id, user)
    import time as _t; _t.sleep(0.5)
    return start_bot(bot_id, user)


@app.get("/api/bots/{bot_id}/logs")
def get_logs(bot_id: str, since: int = 0, user: dict = Depends(get_current_user)):
    with db() as conn:
        if not conn.execute("SELECT id FROM bots WHERE id = ? AND user_id = ?", (bot_id, user["id"])).fetchone():
            raise HTTPException(404, "غير موجود")
        rows = conn.execute(
            "SELECT id, line, type, ts FROM logs WHERE bot_id = ? AND id > ? ORDER BY id ASC LIMIT 500",
            (bot_id, since)
        ).fetchall()
    return {"ok": True, "logs": [dict(r) for r in rows]}


@app.get("/api/bots/{bot_id}/stream")
async def stream_logs(bot_id: str, request: Request, user: dict = Depends(get_current_user)):
    with db() as conn:
        if not conn.execute("SELECT id FROM bots WHERE id = ? AND user_id = ?", (bot_id, user["id"])).fetchone():
            raise HTTPException(404, "غير موجود")

    async def gen():
        last_id = 0
        while True:
            if await request.is_disconnected(): break
            with db() as conn:
                rows = conn.execute(
                    "SELECT id, line, type, ts FROM logs WHERE bot_id = ? AND id > ? ORDER BY id ASC LIMIT 100",
                    (bot_id, last_id)
                ).fetchall()
            for r in rows:
                last_id = r["id"]
                yield f"data: {json.dumps({'id': r['id'], 'line': r['line'], 'type': r['type'], 'ts': r['ts']})}\n\n"
            await asyncio.sleep(1)

    return StreamingResponse(gen(), media_type="text/event-stream")


# ============================================================
# FILE EDITOR
# ============================================================
def _safe_path(base: Path, rel: str) -> Path:
    base = base.resolve()
    p = (base / rel).resolve()
    if not str(p).startswith(str(base)):
        raise HTTPException(400, "مسار غير مسموح")
    return p


def _check_bot_owner(bot_id: str, user: dict) -> dict:
    with db() as conn:
        row = conn.execute("SELECT * FROM bots WHERE id = ? AND user_id = ?", (bot_id, user["id"])).fetchone()
    if not row: raise HTTPException(404, "غير موجود")
    return dict(row)


@app.get("/api/bots/{bot_id}/files")
def list_files(bot_id: str, user: dict = Depends(get_current_user)):
    _check_bot_owner(bot_id, user)
    bot_dir = BOTS_DIR / bot_id
    if not bot_dir.exists(): return {"ok": True, "files": []}

    files = []
    for p in sorted(bot_dir.rglob("*")):
        rel = p.relative_to(bot_dir).as_posix()
        if "__MACOSX" in rel: continue
        if p.is_dir():
            files.append({"path": rel + "/", "type": "dir", "size": 0})
        else:
            try: size = p.stat().st_size
            except Exception: size = 0
            files.append({"path": rel, "type": "file", "size": size})

    return {"ok": True, "files": files}


@app.get("/api/bots/{bot_id}/file")
def read_file(bot_id: str, path: str, user: dict = Depends(get_current_user)):
    _check_bot_owner(bot_id, user)
    fp = _safe_path(BOTS_DIR / bot_id, path)
    if not fp.exists() or not fp.is_file():
        raise HTTPException(404, "الملف غير موجود")
    if fp.stat().st_size > 2 * 1024 * 1024:
        raise HTTPException(400, "الملف كبير جداً (2 MB)")
    try:
        content = fp.read_text(encoding="utf-8", errors="replace")
    except Exception as e:
        raise HTTPException(400, f"فشل القراءة: {e}")
    return {"ok": True, "path": path, "content": content}


@app.put("/api/bots/{bot_id}/file")
def write_file(bot_id: str, p: FileSave, user: dict = Depends(get_current_user)):
    _check_bot_owner(bot_id, user)
    fp = _safe_path(BOTS_DIR / bot_id, p.path)
    if not fp.parent.exists():
        raise HTTPException(400, "المجلد غير موجود")
    if fp.exists():
        try:
            old = fp.read_text(encoding="utf-8", errors="replace")
            with db() as conn:
                conn.execute(
                    "INSERT INTO file_history (bot_id, path, content, ts) VALUES (?, ?, ?, ?)",
                    (bot_id, p.path, old, datetime.utcnow().isoformat())
                )
        except Exception: pass
    try:
        fp.write_text(p.content, encoding="utf-8")
    except Exception as e:
        raise HTTPException(400, f"فشل الحفظ: {e}")
    bot_log(bot_id, "sys", f"[edit] {p.path}")
    return {"ok": True}


@app.post("/api/bots/{bot_id}/file/create")
def create_file(bot_id: str, p: FileCreate, user: dict = Depends(get_current_user)):
    _check_bot_owner(bot_id, user)
    fp = _safe_path(BOTS_DIR / bot_id, p.path)
    if fp.exists(): raise HTTPException(400, "الموجود مسبقاً")
    if p.is_dir:
        fp.mkdir(parents=True, exist_ok=True)
    else:
        fp.parent.mkdir(parents=True, exist_ok=True)
        fp.write_text("", encoding="utf-8")
    return {"ok": True}


@app.delete("/api/bots/{bot_id}/file")
def delete_file(bot_id: str, path: str, user: dict = Depends(get_current_user)):
    _check_bot_owner(bot_id, user)
    fp = _safe_path(BOTS_DIR / bot_id, path)
    if not fp.exists(): raise HTTPException(404, "غير موجود")
    try:
        if fp.is_dir(): shutil.rmtree(fp)
        else: fp.unlink()
    except Exception as e:
        raise HTTPException(400, f"فشل الحذف: {e}")
    return {"ok": True}


# ============================================================
# CRON
# ============================================================
@app.get("/api/cron/resume")
def cron_resume():
    restarted = []
    with db() as conn:
        rows = conn.execute("SELECT id FROM bots").fetchall()
    for r in rows:
        bid = r["id"]
        if bid in PROCS and PROCS[bid].poll() is None: continue
        bot_dir = BOTS_DIR / bid
        with db() as conn:
            b = conn.execute("SELECT * FROM bots WHERE id=?", (bid,)).fetchone()
        if not b: continue
        entry = bot_dir / b["entry_file"]
        if not entry.exists(): continue
        cmd = [sys.executable, "-u", str(entry)] if b["type"] == "python" else ["php", str(entry)]
        try:
            proc = subprocess.Popen(cmd, cwd=str(bot_dir),
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                    text=True, bufsize=1)
            PROCS[bid] = proc
            with db() as conn:
                conn.execute("UPDATE bots SET status='running', pid=?, last_start=? WHERE id=?",
                             (proc.pid, datetime.utcnow().isoformat(), bid))
            asyncio.create_task(_stream_output(bid, proc))
            restarted.append(bid)
        except Exception as e:
            bot_log(bid, "err", f"[cron] {e}")
    return {"ok": True, "restarted": restarted}


# ============================================================
# ROOT
# ============================================================
@app.get("/", response_class=HTMLResponse)
def root():
    if not HTML_FILE.exists():
        return HTMLResponse("<h1>index.html مفقود</h1>", status_code=500)
    return HTMLResponse(HTML_FILE.read_text(encoding="utf-8"))


@app.get("/health")
def health():
    return {"ok": True, "running": len([p for p in PROCS.values() if p.poll() is None])}


if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run("server:app", host="0.0.0.0", port=port, reload=False)
