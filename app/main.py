import os
import random
import string
import secrets
import sqlite3
import base64
import json
import logging
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Optional

import httpx
from fastapi import FastAPI, HTTPException, Depends, Request, UploadFile, File, Form
from fastapi.responses import HTMLResponse, JSONResponse, Response, FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.security import APIKeyHeader
from pydantic import BaseModel, Field
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from apscheduler.schedulers.background import BackgroundScheduler

from .words import ADJECTIVES, NOUNS
from .storage import get_backend, LocalBackend
from .eml_parser import parse_eml, render_eml_report

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# --- Rate limiter ---
limiter = Limiter(key_func=get_remote_address)
app = FastAPI(title="Glimpse")
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# --- Config ---
APP_API_KEY       = os.environ["APP_API_KEY"]
DB_PATH           = os.environ.get("DB_PATH", "/data/glimpse.db")
GLIMPSE_PUBLIC_URL = os.environ.get("GLIMPSE_PUBLIC_URL", "https://glimpseadmin.mck.la")
DEFAULT_EXPIRY    = 7
MAX_EXPIRY        = 90
MAX_FILE_SIZE_MB  = int(os.environ.get("MAX_FILE_SIZE_MB", "50"))
MAX_FILE_BYTES    = MAX_FILE_SIZE_MB * 1024 * 1024

# Initialise storage backend once at module load
storage = get_backend()

# --- Recipient page template ---
RECIPIENT_TEMPLATE = """\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Glimpse</title>
<link rel="icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><text y='.9em' font-size='90'>👁</text></svg>">
<style>
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@300;400;600&family=Syne:wght@700;800&display=swap');
:root{{--bg:#0a0a0c;--surface:#111116;--border:#1e1e28;--accent:#00e5ff;--text:#c8ccd8;--dim:#555570;--danger:#ff4455}}
*{{box-sizing:border-box;margin:0;padding:0}}
body{{background:var(--bg);color:var(--text);font-family:'JetBrains Mono',monospace;min-height:100vh;display:flex;flex-direction:column;align-items:center;justify-content:center;padding:24px}}
body::before{{content:'';position:fixed;inset:0;background:repeating-linear-gradient(0deg,transparent,transparent 2px,rgba(0,0,0,0.04) 2px,rgba(0,0,0,0.04) 4px);pointer-events:none;z-index:0}}
.card{{position:relative;z-index:1;width:100%;max-width:420px;background:var(--surface);border:1px solid var(--border);border-radius:6px;padding:40px 36px;animation:rise 0.4s ease}}
@keyframes rise{{from{{opacity:0;transform:translateY(12px)}}to{{opacity:1;transform:translateY(0)}}}}
.logo{{text-align:center;margin-bottom:32px}}
.logo-word{{font-family:'Syne',sans-serif;font-size:26px;font-weight:800;color:#fff}}
.logo-word span{{color:var(--accent)}}
.logo-sub{{font-size:10px;letter-spacing:3px;text-transform:uppercase;color:var(--dim);margin-top:6px}}
.divider{{height:1px;background:var(--border);margin-bottom:28px}}
label{{display:block;font-size:10px;letter-spacing:2px;text-transform:uppercase;color:var(--dim);margin-bottom:10px}}
input[type=password]{{width:100%;background:var(--bg);border:1px solid var(--border);border-radius:3px;color:var(--text);font-family:'JetBrains Mono',monospace;font-size:14px;padding:12px 16px;outline:none;transition:border-color 0.15s;letter-spacing:2px}}
input[type=password]:focus{{border-color:var(--accent)}}
button{{width:100%;margin-top:16px;padding:13px;background:var(--accent);color:#000;border:none;border-radius:3px;font-family:'JetBrains Mono',monospace;font-size:11px;font-weight:600;letter-spacing:2px;text-transform:uppercase;cursor:pointer;transition:filter 0.15s}}
button:hover{{filter:brightness(1.1)}}
button:disabled{{opacity:0.5;cursor:not-allowed;filter:none}}
#msg{{margin-top:14px;font-size:11px;color:var(--danger);text-align:center;min-height:18px}}
.footer{{margin-top:28px;text-align:center;font-size:10px;color:var(--dim);letter-spacing:1px}}
</style>
</head>
<body>
<div class="card">
  <div class="logo">
    <div class="logo-word">Gl<span>i</span>mpse</div>
    <div class="logo-sub">Private &middot; Encrypted &middot; Shared</div>
  </div>
  <div class="divider"></div>
  <label for="pw">Enter password to unlock</label>
  <input type="password" id="pw" placeholder="············" autofocus>
  <button id="btn" onclick="decrypt()">Unlock</button>
  <div id="msg"></div>
  <div class="footer">encrypted with AES-256-GCM</div>
</div>
<script>
const PAYLOAD    = {payload_json};
const TRACK_BASE = '{public_url}/api/track/{slug}';
function beacon(event) {{ try {{ fetch(TRACK_BASE+'/'+event,{{method:'POST',keepalive:true}}); }} catch(e) {{}} }}
beacon('view');
async function decrypt() {{
  const btn=document.getElementById('btn'),msg=document.getElementById('msg'),pw=document.getElementById('pw').value;
  if(!pw){{msg.textContent='Enter the password.';return;}}
  btn.disabled=true;btn.textContent='Decrypting...';msg.textContent='';
  try {{
    const salt=b64ToBytes(PAYLOAD.salt),iv=b64ToBytes(PAYLOAD.iv),ct=b64ToBytes(PAYLOAD.ct);
    const km=await crypto.subtle.importKey('raw',new TextEncoder().encode(pw),'PBKDF2',false,['deriveKey']);
    const key=await crypto.subtle.deriveKey({{name:'PBKDF2',salt,iterations:600000,hash:'SHA-256'}},km,{{name:'AES-GCM',length:256}},false,['decrypt']);
    const plain=await crypto.subtle.decrypt({{name:'AES-GCM',iv}},key,ct);
    beacon('decrypt');
    const html=new TextDecoder().decode(plain);
    document.open();document.write(html);document.close();
  }} catch(e) {{
    beacon('decrypt_fail');
    msg.textContent='Incorrect password or corrupted file.';
    btn.disabled=false;btn.textContent='Unlock';
    document.getElementById('pw').value='';document.getElementById('pw').focus();
  }}
}}
document.getElementById('pw').addEventListener('keydown',e=>{{if(e.key==='Enter')decrypt();}});
function b64ToBytes(b64){{const bin=atob(b64);const buf=new Uint8Array(bin.length);for(let i=0;i<bin.length;i++)buf[i]=bin.charCodeAt(i);return buf;}}
</script>
</body>
</html>"""

# --- DB ---
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = get_db()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS published (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            slug         TEXT UNIQUE NOT NULL,
            created_at   TEXT NOT NULL,
            github_path  TEXT,
            sha          TEXT,
            comment      TEXT,
            expires_at   TEXT,
            deleted_at   TEXT,
            portal_key   TEXT,
            backend      TEXT
        );
        CREATE TABLE IF NOT EXISTS access_log (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            slug       TEXT NOT NULL,
            event      TEXT NOT NULL,
            timestamp  TEXT NOT NULL,
            ip         TEXT,
            user_agent TEXT
        );
        CREATE TABLE IF NOT EXISTS portal_log (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp  TEXT NOT NULL,
            ip         TEXT,
            user_agent TEXT,
            portal_key TEXT
        );
    """)
    conn.commit()
    conn.close()

# --- Auth ---
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)

def verify_key(api_key: str = Depends(api_key_header)):
    if api_key != APP_API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API key")
    return api_key

def get_client_ip(request: Request) -> str:
    cf = request.headers.get("CF-Connecting-IP")
    if cf: return cf
    fwd = request.headers.get("X-Forwarded-For")
    if fwd: return fwd.split(",")[0].strip()
    return request.client.host if request.client else "unknown"

# --- Slug ---
def generate_slug(conn) -> str:
    adj_pool  = list(dict.fromkeys(ADJECTIVES))
    noun_pool = list(dict.fromkeys(NOUNS))
    for _ in range(100):
        adj1 = random.choice(adj_pool)
        adj2 = random.choice(adj_pool)
        while adj2 == adj1: adj2 = random.choice(adj_pool)
        noun   = random.choice(noun_pool)
        suffix = ''.join(random.choices(string.ascii_lowercase + string.digits, k=3))
        slug   = f"{adj1}-{adj2}-{noun}-{suffix}"
        if not conn.execute("SELECT 1 FROM published WHERE slug=?", (slug,)).fetchone():
            return slug
    raise RuntimeError("Could not generate unique slug after 100 attempts")

# --- Recipient page builder ---
def build_recipient_page(ciphertext_b64: str, salt_b64: str, iv_b64: str, slug: str) -> str:
    payload = json.dumps({"ct": ciphertext_b64, "salt": salt_b64, "iv": iv_b64})
    return RECIPIENT_TEMPLATE.format(
        payload_json=payload,
        public_url=GLIMPSE_PUBLIC_URL,
        slug=slug,
    )

# --- Expiry sweep ---
def expiry_sweep():
    now = datetime.now(timezone.utc).isoformat()
    conn = get_db()
    try:
        rows = conn.execute(
            "SELECT slug, github_path, sha, backend FROM published WHERE expires_at <= ? AND deleted_at IS NULL",
            (now,)
        ).fetchall()
        for row in rows:
            try:
                storage.delete(row["slug"], dict(row))
            except Exception as e:
                logger.warning(f"Expiry delete failed for {row['slug']}: {e}")
            conn.execute("UPDATE published SET deleted_at=? WHERE slug=?", (now, row["slug"]))
        if rows:
            conn.commit()
            logger.info(f"Expiry sweep: deleted {len(rows)} slugs")
    finally:
        conn.close()

# --- Request model ---
class PublishRequest(BaseModel):
    slug:         str
    ciphertext:   str
    salt:         str
    iv:           str
    comment:      Optional[str] = Field(None, max_length=250)
    expires_days: int = Field(DEFAULT_EXPIRY, ge=1, le=MAX_EXPIRY)

# --- Startup ---
@app.on_event("startup")
def startup():
    init_db()
    scheduler = BackgroundScheduler()
    scheduler.add_job(expiry_sweep, "interval", hours=1)
    scheduler.start()
    logger.info(f"Glimpse started. Storage: {storage.__class__.__name__}. Max file size: {MAX_FILE_SIZE_MB}MB")

# --- Static routes ---
@app.get("/", response_class=HTMLResponse)
def index():
    with open("/app/app/static/index.html", "r") as f:
        return f.read()

# Local vault file serving
@app.get("/vault/{slug}.html")
@limiter.limit("30/minute")
async def serve_vault(slug: str, request: Request):
    """Serve locally stored encrypted pages. Rate limited, silent 404."""
    if not isinstance(storage, LocalBackend):
        return Response(status_code=404)
    conn = get_db()
    try:
        row = conn.execute(
            "SELECT deleted_at FROM published WHERE slug=?", (slug,)
        ).fetchone()
        if not row or row["deleted_at"]:
            return Response(status_code=404)
        path = storage.file_path(slug)
        if not path.exists():
            return Response(status_code=404)
        return FileResponse(str(path), media_type="text/html")
    finally:
        conn.close()

# --- Public config ---
@app.get("/api/config")
def config():
    backend_name = storage.__class__.__name__.replace("Backend", "").lower()
    return JSONResponse({
        "public_url":   GLIMPSE_PUBLIC_URL,
        "backend":      backend_name,
        "max_file_mb":  MAX_FILE_SIZE_MB,
    })

# --- Words ---
@app.get("/api/words")
def words(_key: str = Depends(verify_key)):
    return JSONResponse({
        "adjectives": list(dict.fromkeys(ADJECTIVES)),
        "nouns":      list(dict.fromkeys(NOUNS)),
    })

# --- Auth probe ---
@app.post("/api/auth")
@limiter.limit("5/minute")
async def auth_check(request: Request, _key: str = Depends(verify_key)):
    return JSONResponse({"ok": True})

# --- Login audit ---
@app.post("/api/login_audit")
async def login_audit(request: Request, _key: str = Depends(verify_key)):
    conn = get_db()
    try:
        conn.execute(
            "INSERT INTO portal_log (timestamp, ip, user_agent, portal_key) VALUES (?,?,?,?)",
            (datetime.now(timezone.utc).isoformat(),
             get_client_ip(request),
             request.headers.get("user-agent", ""),
             _key[-6:])
        )
        conn.commit()
    finally:
        conn.close()
    return Response(status_code=204)

# --- EML parse endpoint ---
@app.post("/api/parse_eml")
async def parse_eml_endpoint(
    request: Request,
    file: UploadFile = File(...),
    do_dns: bool = Form(False),
    _key: str = Depends(verify_key),
):
    raw = await file.read()
    if len(raw) > MAX_FILE_BYTES:
        raise HTTPException(status_code=413, detail=f"File exceeds {MAX_FILE_SIZE_MB}MB limit")
    try:
        data    = parse_eml(raw, do_dns=do_dns)
        html    = render_eml_report(data)
        return JSONResponse({"html": html})
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"EML parse error: {str(e)}")

# --- Publish ---
@app.post("/api/publish")
def publish(body: PublishRequest, request: Request, _key: str = Depends(verify_key)):
    # Validate base64
    try:
        ct_bytes = base64.b64decode(body.ciphertext)
        base64.b64decode(body.salt)
        base64.b64decode(body.iv)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid base64 in payload")

    # File size check (ciphertext is slightly larger than plaintext)
    if len(ct_bytes) > MAX_FILE_BYTES:
        raise HTTPException(status_code=413, detail=f"File exceeds {MAX_FILE_SIZE_MB}MB limit")

    conn = get_db()
    try:
        # Slug uniqueness
        if conn.execute("SELECT 1 FROM published WHERE slug=?", (body.slug,)).fetchone():
            raise HTTPException(status_code=409, detail="Slug collision, please retry")

        page = build_recipient_page(body.ciphertext, body.salt, body.iv, body.slug)
        result = storage.write(body.slug, page)

        now = datetime.now(timezone.utc)
        expires_at = (now + timedelta(days=body.expires_days)).isoformat()

        conn.execute(
            "INSERT INTO published (slug, created_at, github_path, sha, comment, expires_at, portal_key, backend) VALUES (?,?,?,?,?,?,?,?)",
            (body.slug, now.isoformat(), result.get("github_path"),
             result.get("sha"), body.comment, expires_at,
             _key[-6:], storage.__class__.__name__)
        )
        conn.commit()
        return JSONResponse({"url": result["url"], "slug": body.slug})
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        conn.close()

# --- Delete ---
@app.delete("/api/delete/{slug}")
def delete_slug(slug: str, _key: str = Depends(verify_key)):
    conn = get_db()
    try:
        row = conn.execute(
            "SELECT github_path, sha, deleted_at FROM published WHERE slug=?", (slug,)
        ).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Slug not found")
        if row["deleted_at"]:
            raise HTTPException(status_code=410, detail="Already deleted")
        storage.delete(slug, dict(row))
        conn.execute("UPDATE published SET deleted_at=? WHERE slug=?",
                     (datetime.now(timezone.utc).isoformat(), slug))
        conn.commit()
        return JSONResponse({"deleted": True})
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        conn.close()

# --- List ---
@app.get("/api/list")
def list_published(_key: str = Depends(verify_key)):
    conn = get_db()
    rows = conn.execute("""
        SELECT p.slug, p.created_at, p.comment, p.expires_at, p.deleted_at,
               p.portal_key, p.github_path, p.backend,
               COUNT(CASE WHEN a.event='view'         THEN 1 END) as views,
               COUNT(CASE WHEN a.event='decrypt'      THEN 1 END) as decrypts,
               COUNT(CASE WHEN a.event='decrypt_fail' THEN 1 END) as fails,
               MAX(a.timestamp) as last_seen
        FROM published p
        LEFT JOIN access_log a ON a.slug = p.slug
        GROUP BY p.slug
        ORDER BY p.created_at DESC
    """).fetchall()
    conn.close()
    return [dict(r) for r in rows]

# --- Access log ---
@app.get("/api/access_log/{slug}")
def access_log(slug: str, _key: str = Depends(verify_key)):
    conn = get_db()
    rows = conn.execute(
        "SELECT event, timestamp, ip, user_agent FROM access_log WHERE slug=? ORDER BY timestamp DESC LIMIT 200",
        (slug,)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]

# --- Portal log ---
@app.get("/api/portal_log")
def portal_log(_key: str = Depends(verify_key)):
    conn = get_db()
    rows = conn.execute(
        "SELECT timestamp, ip, user_agent, portal_key FROM portal_log ORDER BY timestamp DESC LIMIT 500"
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]

# --- Tracking beacon ---
MAX_LOG_ROWS = 500

@app.post("/api/track/{slug}/{event}")
@limiter.limit("10/minute")
async def track(slug: str, event: str, request: Request):
    if event not in ("view", "decrypt", "decrypt_fail"):
        return Response(status_code=204)
    conn = get_db()
    try:
        row = conn.execute(
            "SELECT 1 FROM published WHERE slug=? AND deleted_at IS NULL", (slug,)
        ).fetchone()
        if not row:
            return Response(status_code=204)
        count = conn.execute(
            "SELECT COUNT(*) FROM access_log WHERE slug=?", (slug,)
        ).fetchone()[0]
        if count >= MAX_LOG_ROWS:
            return Response(status_code=204)
        ip = get_client_ip(request)
        conn.execute(
            "INSERT INTO access_log (slug, event, timestamp, ip, user_agent) VALUES (?,?,?,?,?)",
            (slug, event, datetime.now(timezone.utc).isoformat(),
             ip, request.headers.get("user-agent", ""))
        )
        conn.commit()
    finally:
        conn.close()
    return Response(status_code=204)

app.mount("/static", StaticFiles(directory="/app/app/static"), name="static")
