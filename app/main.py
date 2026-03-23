import os
import random
import string
import secrets
import sqlite3
import base64
from datetime import datetime
from typing import Optional

import httpx
from fastapi import FastAPI, HTTPException, Depends
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.security import APIKeyHeader
from pydantic import BaseModel

from .words import ADJECTIVES, NOUNS

app = FastAPI(title="Glimpse")

# --- Config ---
GITHUB_TOKEN  = os.environ["GITHUB_TOKEN"]
GITHUB_REPO   = os.environ["GITHUB_REPO"]
GITHUB_BRANCH = os.environ.get("GITHUB_BRANCH", "main")
APP_API_KEY   = os.environ["APP_API_KEY"]
DB_PATH       = os.environ.get("DB_PATH", "/data/glimpse.db")
PAGES_BASE_URL = os.environ.get("PAGES_BASE_URL", f"https://{GITHUB_REPO.split('/')[0]}.github.io")
VAULT_SUBDIR  = os.environ.get("VAULT_SUBDIR", "vault")

# --- Recipient page template ---
# Embedded into every published file. Pure self-contained HTML + inline JS.
# Decryption uses AES-256-GCM via Web Crypto API, same primitives used by the sender.
RECIPIENT_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Glimpse</title>
<link rel="icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><text y='.9em' font-size='90'>👁</text></svg>">
<style>
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@300;400;600&family=Syne:wght@700;800&display=swap');
:root {{
  --bg:#0a0a0c; --surface:#111116; --border:#1e1e28;
  --accent:#00e5ff; --text:#c8ccd8; --dim:#555570; --danger:#ff4455;
}}
*{{box-sizing:border-box;margin:0;padding:0}}
body{{background:var(--bg);color:var(--text);font-family:'JetBrains Mono',monospace;
  min-height:100vh;display:flex;flex-direction:column;align-items:center;
  justify-content:center;padding:24px}}
body::before{{content:'';position:fixed;inset:0;
  background:repeating-linear-gradient(0deg,transparent,transparent 2px,rgba(0,0,0,0.04) 2px,rgba(0,0,0,0.04) 4px);
  pointer-events:none;z-index:0}}
.card{{position:relative;z-index:1;width:100%;max-width:420px;
  background:var(--surface);border:1px solid var(--border);border-radius:6px;
  padding:40px 36px;animation:rise 0.4s ease}}
@keyframes rise{{from{{opacity:0;transform:translateY(12px)}}to{{opacity:1;transform:translateY(0)}}}}
.logo{{text-align:center;margin-bottom:32px}}
.logo-word{{font-family:'Syne',sans-serif;font-size:26px;font-weight:800;color:#fff}}
.logo-word span{{color:var(--accent)}}
.logo-sub{{font-size:10px;letter-spacing:3px;text-transform:uppercase;color:var(--dim);margin-top:6px}}
.divider{{height:1px;background:var(--border);margin-bottom:28px}}
label{{display:block;font-size:10px;letter-spacing:2px;text-transform:uppercase;color:var(--dim);margin-bottom:10px}}
input[type=password]{{width:100%;background:var(--bg);border:1px solid var(--border);border-radius:3px;
  color:var(--text);font-family:'JetBrains Mono',monospace;font-size:14px;
  padding:12px 16px;outline:none;transition:border-color 0.15s;letter-spacing:2px}}
input[type=password]:focus{{border-color:var(--accent)}}
button{{width:100%;margin-top:16px;padding:13px;background:var(--accent);color:#000;border:none;
  border-radius:3px;font-family:'JetBrains Mono',monospace;font-size:11px;font-weight:600;
  letter-spacing:2px;text-transform:uppercase;cursor:pointer;transition:filter 0.15s}}
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
const PAYLOAD = {payload_json};

async function decrypt() {{
  const btn = document.getElementById('btn');
  const msg = document.getElementById('msg');
  const pw  = document.getElementById('pw').value;
  if (!pw) {{ msg.textContent = 'Enter the password.'; return; }}

  btn.disabled = true;
  btn.textContent = 'Decrypting...';
  msg.textContent = '';

  try {{
    const salt       = b64ToBytes(PAYLOAD.salt);
    const iv         = b64ToBytes(PAYLOAD.iv);
    const ciphertext = b64ToBytes(PAYLOAD.ct);

    const keyMaterial = await crypto.subtle.importKey(
      'raw', new TextEncoder().encode(pw), 'PBKDF2', false, ['deriveKey']
    );
    const key = await crypto.subtle.deriveKey(
      {{ name:'PBKDF2', salt, iterations:600000, hash:'SHA-256' }},
      keyMaterial,
      {{ name:'AES-GCM', length:256 }},
      false,
      ['decrypt']
    );
    const plain = await crypto.subtle.decrypt({{ name:'AES-GCM', iv }}, key, ciphertext);
    const html  = new TextDecoder().decode(plain);

    // Replace entire page with decrypted content
    document.open(); document.write(html); document.close();
  }} catch(e) {{
    msg.textContent = 'Incorrect password or corrupted file.';
    btn.disabled = false;
    btn.textContent = 'Unlock';
    document.getElementById('pw').value = '';
    document.getElementById('pw').focus();
  }}
}}

document.getElementById('pw').addEventListener('keydown', e => {{
  if (e.key === 'Enter') decrypt();
}});

function b64ToBytes(b64) {{
  const bin = atob(b64);
  const buf = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) buf[i] = bin.charCodeAt(i);
  return buf;
}}
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
    conn.execute("""
        CREATE TABLE IF NOT EXISTS published (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            slug TEXT UNIQUE NOT NULL,
            created_at TEXT NOT NULL,
            github_path TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()

# --- Auth ---
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)

def verify_key(api_key: str = Depends(api_key_header)):
    if api_key != APP_API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API key")
    return api_key

# --- Slug generation ---
def generate_slug(conn) -> str:
    adj_pool  = list(dict.fromkeys(ADJECTIVES))
    noun_pool = list(dict.fromkeys(NOUNS))
    for _ in range(100):
        adj1 = random.choice(adj_pool)
        adj2 = random.choice(adj_pool)
        while adj2 == adj1:
            adj2 = random.choice(adj_pool)
        noun   = random.choice(noun_pool)
        suffix = ''.join(random.choices(string.ascii_lowercase + string.digits, k=3))
        slug   = f"{adj1}-{adj2}-{noun}-{suffix}"
        if not conn.execute("SELECT 1 FROM published WHERE slug=?", (slug,)).fetchone():
            return slug
    raise RuntimeError("Could not generate unique slug after 100 attempts")

# --- Build recipient HTML ---
def build_recipient_page(ciphertext_b64: str, salt_b64: str, iv_b64: str) -> str:
    import json
    payload = json.dumps({"ct": ciphertext_b64, "salt": salt_b64, "iv": iv_b64})
    return RECIPIENT_TEMPLATE.format(payload_json=payload)

# --- GitHub push ---
def push_to_github(slug: str, html: str) -> str:
    path_in_repo = f"{VAULT_SUBDIR}/{slug}.html"
    url = f"https://api.github.com/repos/{GITHUB_REPO}/contents/{path_in_repo}"
    headers = {
        "Authorization": f"Bearer {GITHUB_TOKEN}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    content_b64 = base64.b64encode(html.encode("utf-8")).decode("ascii")
    payload = {
        "message": f"glimpse: add {slug}",
        "content": content_b64,
        "branch": GITHUB_BRANCH,
    }
    resp = httpx.put(url, headers=headers, json=payload, timeout=30)
    if resp.status_code not in (200, 201):
        raise RuntimeError(f"GitHub API error {resp.status_code}: {resp.text}")
    return path_in_repo

# --- Request model ---
class PublishRequest(BaseModel):
    ciphertext: str   # base64 AES-256-GCM ciphertext
    salt: str         # base64 PBKDF2 salt (16 bytes)
    iv: str           # base64 AES-GCM IV (12 bytes)

# --- Routes ---
@app.on_event("startup")
def startup():
    init_db()

@app.get("/", response_class=HTMLResponse)
def index():
    with open("/app/app/static/index.html", "r") as f:
        return f.read()

@app.post("/api/publish")
def publish(body: PublishRequest, _key: str = Depends(verify_key)):
    if not body.ciphertext or not body.salt or not body.iv:
        raise HTTPException(status_code=400, detail="Missing ciphertext, salt or iv")

    # Validate base64
    try:
        base64.b64decode(body.ciphertext)
        base64.b64decode(body.salt)
        base64.b64decode(body.iv)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid base64 in payload")

    conn = get_db()
    try:
        slug = generate_slug(conn)
        page = build_recipient_page(body.ciphertext, body.salt, body.iv)
        github_path = push_to_github(slug, page)

        conn.execute(
            "INSERT INTO published (slug, created_at, github_path) VALUES (?,?,?)",
            (slug, datetime.utcnow().isoformat(), github_path),
        )
        conn.commit()

        public_url = f"{PAGES_BASE_URL}/{VAULT_SUBDIR}/{slug}.html"
        return JSONResponse({"url": public_url, "slug": slug})
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        conn.close()

@app.get("/api/list")
def list_published(_key: str = Depends(verify_key)):
    conn = get_db()
    rows = conn.execute(
        "SELECT slug, created_at, github_path FROM published ORDER BY created_at DESC"
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]

app.mount("/static", StaticFiles(directory="/app/app/static"), name="static")
