# Glimpse

Self-hosted portal for encrypting and privately sharing files via password-protected links. Supports HTML pages, JSX components, raw email forensics (EML), and any binary file (ZIP, DOCX, PDF, images, etc). Encryption happens entirely in the browser — the server never sees your content.

## Inspiration

Glimpse is inspired by [StatiCrypt](https://github.com/robinmoisson/staticrypt), an excellent tool that encrypts HTML pages for client-side decryption. StatiCrypt is the right tool for many use cases and well worth looking at.

Glimpse takes a different approach for a specific scenario: a self-hosted publishing workflow where content should be encrypted before it leaves the browser, so it is never visible in transit even on an untrusted or sniffable network. Rather than running StatiCrypt's Node.js CLI server-side (which means plaintext HTML travels unencrypted from browser to server), Glimpse moves encryption entirely into the browser using the Web Crypto API. The server receives only ciphertext. Node.js is not required anywhere in the stack.

---

## How it works

1. Open the Glimpse portal and enter your portal key
2. Paste or upload a file (HTML, JSX, EML, or any binary file)
3. Optionally set a comment, expiry, and burn-on-read
4. Your browser generates a random password, encrypts the content with AES-256-GCM, and computes a proof verifier
5. Only the encrypted blob, salt, IV, metadata, and verifier are sent to the server — plaintext never leaves the browser
6. The server writes the encrypted recipient page to your chosen storage backend
7. You receive a URL and a one-time password — the password is never stored anywhere
8. Share the URL and password with your recipient

The recipient opens the URL, enters the password, and their browser decrypts and renders the content. No server is involved at decrypt time.

---

## Features

### File types

| Type | Behaviour |
|------|-----------|
| `.html` / `.htm` | Decrypts and renders directly in the browser |
| `.jsx` | Stripped of ES module imports, wrapped in a Babel + React CDN scaffold, rendered in browser |
| `.eml` | Parsed server-side into a full forensic report before encryption (see below) |
| Any other file | Encrypted as binary, recipient gets a download button after decryption |

### EML forensic analysis

Upload a `.eml` raw email file and Glimpse parses it into a detailed forensic report before encrypting. The report includes:

- Risk summary with colour-coded indicators for SPF/DKIM/DMARC failures, From/Reply-To/Return-Path mismatches, and display name spoofing against known brands
- Authentication results (SPF, DKIM with selector and domain, DMARC, ARC chain)
- Received chain with per-hop timestamps, time deltas between hops, and optional PTR/MX DNS lookups
- HTML body rendered in a sandboxed iframe with raw source toggle
- Link extraction with display text vs href mismatch detection
- Tracking pixel candidates identified
- Attachment listing with MD5 and SHA-256 hashes linked to VirusTotal
- Full MIME structure tree and all raw headers

DNS lookups are optional per upload via a toggle in the UI. They add a few seconds to the publish flow.

### Burn on read

Check the "Burn on read" option at publish time. After the first successful decrypt, the file is automatically deleted from storage and marked as burnt in the database. Subsequent attempts to open the URL will get a 404. The access log is retained.

A race condition guard ensures only one deletion fires even if two recipients decrypt simultaneously.

### Recipient-triggered destroy

For EML and binary files, a 🔥 Destroy this file button appears after successful decryption. Clicking it calls a one-time token endpoint that permanently deletes the file from storage. The token is embedded in the recipient page at publish time and is single-use.

HTML and JSX files do not have a destroy button since they render inline and there is no persistent file to destroy from the recipient's perspective.

### Proof of decryption

At publish time the browser computes `SHA256(password + slug)` as a verifier and sends it to the server. When the recipient decrypts successfully, their browser computes the same value and sends it with the decrypt beacon. The server verifies the proof. Without the correct password, the proof cannot be computed, so fake decrypt beacons from external parties are logged as `decrypt_fail` instead.

### Tracking

Each published page embeds three beacon events:

| Event | When it fires |
|-------|--------------|
| `view` | When the recipient page loads (before password entry) |
| `decrypt` | After successful decryption with valid proof |
| `decrypt_fail` | On wrong password or invalid proof |

Each event is logged with timestamp, IP address (real IP via `CF-Connecting-IP` if behind Cloudflare), and user-agent. The admin panel shows per-slug stats and an expandable log drawer.

### Expiry

Each published page has a configurable expiry of 1–90 days (default 7). A background sweep runs hourly, deletes expired files from storage, and marks them as deleted in SQLite. The access log is retained.

### Session and security

- Portal key is required to access the admin UI
- Session expires after 30 minutes of inactivity (cookie-based, resets on user activity)
- Login is rate limited: 10 failed attempts within 15 minutes triggers a 30-minute lockout, 3 lockouts triggers a 24-hour hard lockout
- All lockout thresholds are configurable via environment variables
- The Security tab in admin shows active lockouts and recent failed attempts

### Storage backends

Three backends are supported, selected via `STORAGE_BACKEND`:

| Backend | How it works |
|---------|-------------|
| `local` | Files stored in the container volume at `LOCAL_VAULT_DIR`, served directly by Glimpse at `/vault/<slug>.html`. Rate limited, silent 404 on unknown slugs. |
| `github` | Files pushed to a GitHub Pages repo via the GitHub API. Served by GitHub Pages CDN. |
| `r2` | Files written to a Cloudflare R2 bucket via S3-compatible API. Served via R2 public URL or custom domain. |

Unknown `STORAGE_BACKEND` values log a warning and fall back to `local`.

---

## Stack

- **FastAPI** — Python API server
- **Web Crypto API** — browser-native AES-256-GCM encryption, no external crypto libraries
- **SQLite** — slug tracking, access logs, portal logs, brute force records
- **Docker** — single container, no Node.js required
- **slowapi** — rate limiting
- **APScheduler** — background expiry sweep
- **dnspython** — optional DNS lookups for EML forensics
- **boto3** — Cloudflare R2 support via S3-compatible API

---

## Environment variables

### Required

| Variable | Description |
|----------|-------------|
| `APP_API_KEY` | Portal key required to access the admin UI. Generate with `openssl rand -base64 24`. |
| `GLIMPSE_PUBLIC_URL` | Public URL of your Glimpse instance, e.g. `https://glimpseadmin.yourdomain.com`. Embedded in recipient pages as the beacon and destroy endpoint base URL. |
| `VAULT_ORIGIN` | Origin of your vault/recipient pages, e.g. `https://glimpsevault.yourdomain.com`. Required for CORS when the admin and vault are on different domains. Can be the same as `GLIMPSE_PUBLIC_URL` if on one domain. |

### Storage — select one

| Variable | Description | Default |
|----------|-------------|---------|
| `STORAGE_BACKEND` | `local`, `github`, or `r2` | `local` |

#### Local backend

| Variable | Description | Default |
|----------|-------------|---------|
| `LOCAL_VAULT_DIR` | Directory inside the container for stored files | `/data/vault` |

#### GitHub backend

| Variable | Description |
|----------|-------------|
| `GITHUB_TOKEN` | Fine-grained PAT with Contents read/write on the target repo |
| `GITHUB_REPO` | `owner/repo` format |
| `GITHUB_BRANCH` | Branch to push to (default: `main`) |
| `VAULT_SUBDIR` | Subfolder in repo for published files (default: `vault`) |
| `PAGES_BASE_URL` | Base URL of your GitHub Pages site, e.g. `https://smck83.github.io/glimpse` |

#### Cloudflare R2 backend

| Variable | Description |
|----------|-------------|
| `R2_ACCOUNT_ID` | Cloudflare account ID (32-char hex, found in dashboard sidebar) |
| `R2_ACCESS_KEY_ID` | R2 API token access key |
| `R2_SECRET_ACCESS_KEY` | R2 API token secret key |
| `R2_BUCKET_NAME` | R2 bucket name |
| `R2_PUBLIC_URL` | Public base URL for the bucket, e.g. `https://vault.yourdomain.com` |
| `VAULT_SUBDIR` | Subfolder within the bucket (default: `vault`) |

### General

| Variable | Description | Default |
|----------|-------------|---------|
| `DB_PATH` | SQLite database path inside the container | `/data/glimpse.db` |
| `MAX_FILE_SIZE_MB` | Maximum upload size in megabytes | `50` |

### Security and brute force protection

| Variable | Description | Default |
|----------|-------------|---------|
| `TRUSTED_PROXY_MODE` | Read `CF-Connecting-IP` for real client IP (set `true` when behind Cloudflare) | `true` |
| `BF_MAX_ATTEMPTS` | Failed login attempts before lockout | `10` |
| `BF_WINDOW_MINUTES` | Window in minutes to count failed attempts | `15` |
| `BF_LOCKOUT_MINUTES` | Lockout duration in minutes after first threshold | `30` |
| `BF_LOCKOUT_THRESHOLD` | Number of lockouts before hard lockout applies | `3` |
| `BF_HARD_LOCKOUT_MINUTES` | Hard lockout duration in minutes | `1440` (24h) |

---

## Setup

### 1. Generate a portal key

```bash
openssl rand -base64 24
```

### 2. Choose and configure your storage backend

**Local (no external accounts needed):**
```dotenv
STORAGE_BACKEND=local
LOCAL_VAULT_DIR=/data/vault
GLIMPSE_PUBLIC_URL=https://glimpseadmin.yourdomain.com
VAULT_ORIGIN=https://glimpseadmin.yourdomain.com
```

**GitHub Pages:**

Create a fine-grained personal access token at GitHub > Settings > Developer Settings > Personal Access Tokens > Fine-grained tokens. Scope it to your target repo only with Contents — Read and Write.

```dotenv
STORAGE_BACKEND=github
GITHUB_TOKEN=github_pat_...
GITHUB_REPO=yourusername/yourrepo
GITHUB_BRANCH=main
VAULT_SUBDIR=vault
PAGES_BASE_URL=https://yourusername.github.io/yourrepo
GLIMPSE_PUBLIC_URL=https://glimpseadmin.yourdomain.com
VAULT_ORIGIN=https://yourusername.github.io
```

**Cloudflare R2:**

Create a bucket in the R2 dashboard. Under R2 > Manage R2 API Tokens create a token with Object Read & Write on that bucket. Enable public access or attach a custom domain.

```dotenv
STORAGE_BACKEND=r2
R2_ACCOUNT_ID=your_account_id
R2_ACCESS_KEY_ID=your_access_key
R2_SECRET_ACCESS_KEY=your_secret_key
R2_BUCKET_NAME=glimpse-vault
R2_PUBLIC_URL=https://vault.yourdomain.com
VAULT_SUBDIR=vault
GLIMPSE_PUBLIC_URL=https://glimpseadmin.yourdomain.com
VAULT_ORIGIN=https://vault.yourdomain.com
```

### 3. Build and run

```bash
docker compose up -d --build
```

Access the portal at `http://your-host:8765`.

Glimpse requires HTTPS or localhost for the Web Crypto API. Put it behind a Cloudflare Tunnel or reverse proxy with TLS for production use.

### 4. Portainer deployment

Paste `docker-compose.yml` into a new Portainer stack and set environment variables in Portainer's environment editor.

```yaml
services:
  glimpse:
    image: glimpse:latest
    container_name: glimpse
    restart: unless-stopped
    ports:
      - "8765:8000"
    volumes:
      - glimpse_data:/data
    environment:
      - APP_API_KEY=your_key_here
      - GLIMPSE_PUBLIC_URL=https://glimpseadmin.yourdomain.com
      - VAULT_ORIGIN=https://vault.yourdomain.com
      - STORAGE_BACKEND=r2
      - R2_ACCOUNT_ID=...
      - R2_ACCESS_KEY_ID=...
      - R2_SECRET_ACCESS_KEY=...
      - R2_BUCKET_NAME=glimpse-vault
      - R2_PUBLIC_URL=https://vault.yourdomain.com
      - VAULT_SUBDIR=vault
      - DB_PATH=/data/glimpse.db
      - MAX_FILE_SIZE_MB=50
      - TRUSTED_PROXY_MODE=true

volumes:
  glimpse_data:
```

Build the image on the host first:

```bash
docker build -t glimpse:latest .
```

---

## Database migrations

If upgrading from an earlier version, run this inside the container to add any missing columns:

```bash
python3 -c "
import sqlite3
conn = sqlite3.connect('/data/glimpse.db')
cols = [r[0] for r in conn.execute(\"SELECT name FROM pragma_table_info('published')\").fetchall()]
needed = [
    ('sha', 'TEXT'), ('comment', 'TEXT'), ('expires_at', 'TEXT'),
    ('deleted_at', 'TEXT'), ('portal_key', 'TEXT'), ('backend', 'TEXT'),
    ('burn_on_read', 'INTEGER DEFAULT 0'), ('burnt_at', 'TEXT'),
    ('destroy_token', 'TEXT'), ('decrypt_verifier', 'TEXT'), ('content_type', 'TEXT'),
]
for col, typedef in needed:
    if col not in cols:
        conn.execute(f'ALTER TABLE published ADD COLUMN {col} {typedef}')
        print(f'Added: {col}')
    else:
        print(f'OK: {col}')
conn.commit()
conn.close()
"
```

If you see `NOT NULL constraint failed: published.sha` or `published.github_path`, run this to remove old constraints:

```bash
python3 -c "
import sqlite3
conn = sqlite3.connect('/data/glimpse.db')
conn.executescript('''
BEGIN;
ALTER TABLE published RENAME TO published_old;
CREATE TABLE published (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    slug             TEXT UNIQUE NOT NULL,
    created_at       TEXT NOT NULL,
    github_path      TEXT,
    sha              TEXT,
    comment          TEXT,
    expires_at       TEXT,
    deleted_at       TEXT,
    portal_key       TEXT,
    backend          TEXT,
    burn_on_read     INTEGER DEFAULT 0,
    burnt_at         TEXT,
    destroy_token    TEXT,
    decrypt_verifier TEXT,
    content_type     TEXT
);
INSERT INTO published SELECT
    id, slug, created_at, github_path, sha, comment, expires_at,
    deleted_at, portal_key, backend,
    COALESCE(burn_on_read, 0), burnt_at, destroy_token, decrypt_verifier, content_type
FROM published_old;
DROP TABLE published_old;
COMMIT;
''')
print('Migration complete')
conn.close()
"
```

---

## Slug format

Each published page gets a unique slug generated client-side from a server-provided word list:

```
adjective-adjective-noun-xxx
```

Where `xxx` is 3 random alphanumeric characters (a-z, 0-9). On collision the browser retries up to 5 times. Example:

```
frozen-radiant-citadel-4k2
```

---

## Security notes

- Plaintext content is encrypted in the browser before the POST — never visible in server logs or in transit
- The password is generated client-side and never sent to or stored by the server
- Decrypt proof (`SHA256(password + slug)`) is verified server-side — fake beacon requests without the password are logged as failures
- Burn on read uses a SQLite write guard (`WHERE burnt_at IS NULL`) to prevent race condition double-deletions
- Destroy tokens are 32-byte random URL-safe strings, single-use, embedded in the recipient page only
- Binary file metadata (filename, MIME, size) is stored separately from the ciphertext and is unencrypted — only the file content is encrypted
- The Web Crypto API requires HTTPS or localhost. Plain HTTP will cause encryption to fail in the browser
- R2 requires `boto3` — installed in the container but only imported when `STORAGE_BACKEND=r2`
- `dnspython` is installed for EML DNS lookups — if not needed it can be removed from `requirements.txt` and the parser degrades gracefully
- JSX support uses Babel standalone for runtime transpilation. Complex canvas-based or heavily stateful apps may not render correctly — for those, pre-bundle with Vite and upload the compiled HTML instead
