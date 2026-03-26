# Glimpse

Self-hosted portal for encrypting and privately sharing HTML, JSX, and email (EML) files via password-protected links. Encrypt in your browser, publish to your chosen storage backend, share a URL and password.

## Inspiration

Glimpse is inspired by [StatiCrypt](https://github.com/robinmoisson/staticrypt) — an excellent tool that encrypts HTML pages so they can be hosted anywhere and decrypted client-side with a password. StatiCrypt is the right tool for many use cases and well worth looking at.

Glimpse takes a different approach for a specific scenario: a self-hosted publishing workflow where the HTML content should be encrypted before it leaves the browser, so it is never visible in transit even on an untrusted or sniffable network. Rather than rely on StatiCrypt's Node.js CLI running server-side (which means the plaintext HTML travels from the browser to the server unencrypted), Glimpse moves the encryption step entirely into the browser using the Web Crypto API. The server receives only ciphertext and never sees your content. Node.js is not required anywhere in the stack.

## How it works

1. You open the Glimpse portal and enter your portal key to unlock it
2. You paste or upload a file (HTML, JSX, or EML)
3. For EML files, the server parses the email into a forensic HTML report — the plaintext is never stored
4. Your browser generates a random password and encrypts the content using AES-256-GCM with PBKDF2 key derivation (600,000 iterations, SHA-256) — entirely client-side
5. Only the encrypted blob, salt, and IV are sent to the FastAPI server
6. The server wraps the payload in a self-contained recipient page and writes it to your chosen storage backend
7. You receive a public URL and a one-time password — the password was generated in your browser and is never sent to or stored by the server
8. Share the URL and password with your recipient

The recipient opens the URL, enters the password, their browser decrypts and renders the page. No server is involved at decryption time.

## Security properties

- Plaintext content is encrypted in the browser before the POST — not visible in transit or in server logs
- The password never leaves the browser and is never stored anywhere
- The server stores only: slug, timestamp, storage path, comment, and expiry — no passwords, no content
- Encryption uses AES-256-GCM (authenticated — detects tampering) with PBKDF2-SHA256 at 600,000 iterations (OWASP recommended)
- Login attempts are rate limited (5 per minute per IP)
- Beacon tracking endpoints are rate limited (10 per minute per IP) with silent 404 on unknown slugs
- Session expires after 30 minutes of inactivity
- To revoke access, delete the slug from the admin portal

## Features

### File types supported
- **HTML / HTM** — paste directly or upload a file
- **JSX** — upload a `.jsx` file; Glimpse strips ES module imports and wraps in a Babel + React scaffold for runtime transpilation in the recipient's browser
- **EML** — upload a raw email file for forensic analysis (see below)

### EML forensic analysis
Upload a `.eml` file and Glimpse parses it into a full forensic report before encrypting:
- Risk summary with colour-coded indicators for SPF/DKIM/DMARC failures, From/Reply-To/Return-Path mismatches, and display name spoofing
- Authentication results (SPF, DKIM with selector and domain, DMARC, ARC chain)
- Received chain with per-hop timestamps, time deltas, and optional PTR/MX DNS lookups
- HTML body rendered in a sandboxed iframe with raw source toggle
- Link extraction with display text vs href mismatch detection
- Tracking pixel detection
- Attachment listing with MD5 and SHA-256 hashes linked to VirusTotal
- Full MIME structure tree and all raw headers

### Storage backends
Three backends are supported, selected via `STORAGE_BACKEND` env var:

| Backend | Description |
|---------|-------------|
| `local` | Files stored in the container volume, served directly by Glimpse at `/vault/<slug>.html` |
| `github` | Files pushed to a GitHub Pages repo via the GitHub API |
| `r2` | Files stored in a Cloudflare R2 bucket and served via its public URL |

Unknown values fall back to `local` with a warning logged at startup.

### Admin portal
- Published pages table with slug, comment, created timestamp, view/decrypt/fail counts, last seen, expiry, and delete button
- Per-slug access log drawer showing each beacon event with timestamp, IP, and user-agent
- Search/filter by slug or comment
- Portal login history showing timestamp, IP, user-agent, and last 6 characters of the portal key
- Soft delete — files are removed from storage but the access log is retained

### Tracking
Each published page embeds two beacons:
- **View** — fires when the recipient page loads (before password entry)
- **Decrypt** — fires on successful decryption
- **Decrypt fail** — fires on incorrect password attempt

All three are logged per slug with IP and user-agent.

### Expiry
Each published page has a configurable expiry (1–90 days, default 7). A background sweep runs hourly, deletes expired files from the storage backend, and marks them as deleted in SQLite. The access log is retained.

## Stack

- **FastAPI** — Python API server
- **Web Crypto API** — browser-native AES-256-GCM encryption, no external crypto libraries
- **SQLite** — slug tracking, access logs, portal logs
- **Docker** — single container, no Node.js, no build tools
- **slowapi** — rate limiting
- **APScheduler** — background expiry sweep
- **dnspython** — optional DNS lookups for EML forensics
- **boto3** — Cloudflare R2 support via S3-compatible API

## Requirements

- Docker
- One of: a GitHub Pages repo + token, a Cloudflare R2 bucket, or just the container volume (local)

## Environment variables

### Required for all backends

| Variable | Description |
|----------|-------------|
| `APP_API_KEY` | Portal key required to access the admin UI |
| `GLIMPSE_PUBLIC_URL` | Public base URL of your Glimpse instance, e.g. `https://glimpseadmin.yourdomain.com` — used for beacon URLs embedded in published pages |
| `DB_PATH` | SQLite database path inside the container (default: `/data/glimpse.db`) |

### Storage selection

| Variable | Description | Default |
|----------|-------------|---------|
| `STORAGE_BACKEND` | `local`, `github`, or `r2` | `local` |

### Local backend

| Variable | Description | Default |
|----------|-------------|---------|
| `LOCAL_VAULT_DIR` | Directory inside the container where files are stored | `/data/vault` |

### GitHub backend

| Variable | Description |
|----------|-------------|
| `GITHUB_TOKEN` | Fine-grained personal access token with Contents read/write on the target repo |
| `GITHUB_REPO` | Repository in `owner/repo` format |
| `GITHUB_BRANCH` | Branch to push to (default: `main`) |
| `VAULT_SUBDIR` | Subfolder in the repo for published files (default: `vault`) |
| `PAGES_BASE_URL` | Base URL of your GitHub Pages site, e.g. `https://smck83.github.io/glimpse` |

### Cloudflare R2 backend

| Variable | Description |
|----------|-------------|
| `R2_ACCOUNT_ID` | Cloudflare account ID (32 character hex, found in the dashboard sidebar) |
| `R2_ACCESS_KEY_ID` | R2 API token access key |
| `R2_SECRET_ACCESS_KEY` | R2 API token secret key |
| `R2_BUCKET_NAME` | Name of your R2 bucket |
| `R2_PUBLIC_URL` | Public base URL for the bucket, e.g. `https://vault.yourdomain.com` |
| `VAULT_SUBDIR` | Subfolder within the bucket (default: `vault`) |

### General

| Variable | Description | Default |
|----------|-------------|---------|
| `MAX_FILE_SIZE_MB` | Maximum upload size in megabytes | `50` |

## Setup

### 1. Generate a portal key

```bash
openssl rand -base64 24
```

### 2. Configure your storage backend

**Local (simplest — no external accounts needed):**
```dotenv
STORAGE_BACKEND=local
LOCAL_VAULT_DIR=/data/vault
GLIMPSE_PUBLIC_URL=https://glimpseadmin.yourdomain.com
```

**GitHub:**

Go to GitHub > Settings > Developer Settings > Personal Access Tokens > Fine-grained tokens. Create a token scoped to your target repo only with Contents — Read and Write. Nothing else.

```dotenv
STORAGE_BACKEND=github
GITHUB_TOKEN=github_pat_...
GITHUB_REPO=yourusername/yourrepo
GITHUB_BRANCH=main
VAULT_SUBDIR=vault
PAGES_BASE_URL=https://yourusername.github.io/yourrepo
GLIMPSE_PUBLIC_URL=https://glimpseadmin.yourdomain.com
```

**Cloudflare R2:**

Create a bucket in the Cloudflare dashboard. Under R2 > Manage R2 API Tokens create a token with Object Read & Write on that bucket. Enable public access on the bucket or attach a custom domain.

```dotenv
STORAGE_BACKEND=r2
R2_ACCOUNT_ID=your_account_id
R2_ACCESS_KEY_ID=your_access_key
R2_SECRET_ACCESS_KEY=your_secret_key
R2_BUCKET_NAME=glimpse-vault
R2_PUBLIC_URL=https://vault.yourdomain.com
VAULT_SUBDIR=vault
GLIMPSE_PUBLIC_URL=https://glimpseadmin.yourdomain.com
```

### 3. Run with Docker

```bash
docker compose up -d --build
```

Access the portal at `http://your-host:8765`. For production, put it behind a Cloudflare Tunnel or reverse proxy with TLS — the Web Crypto API requires HTTPS or localhost.

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
      - STORAGE_BACKEND=local
      - LOCAL_VAULT_DIR=/data/vault
      - DB_PATH=/data/glimpse.db
      - MAX_FILE_SIZE_MB=50

volumes:
  glimpse_data:
```

Build the image on the host first:

```bash
docker build -t glimpse:latest .
```

## Database migrations

If upgrading from an earlier version, the SQLite schema may be missing newer columns. Run this inside the container to safely add any missing columns:

```bash
python3 -c "
import sqlite3
conn = sqlite3.connect('/data/glimpse.db')
cols = [r[0] for r in conn.execute(\"SELECT name FROM pragma_table_info('published')\").fetchall()]
needed = ['sha','comment','expires_at','deleted_at','portal_key','backend',
          'burn_on_read','burnt_at','destroy_token','decrypt_verifier','content_type']
for col in needed:
    if col not in cols:
        default = ' DEFAULT 0' if col == 'burn_on_read' else ''
        conn.execute(f'ALTER TABLE published ADD COLUMN {col} TEXT{default}')
        print(f'Added: {col}')
    else:
        print(f'Already exists: {col}')
conn.commit()
conn.close()
"
```

```bash
python3 -c "
import sqlite3
conn = sqlite3.connect('/data/glimpse.db')
cols = [r[0] for r in conn.execute(\"SELECT name FROM pragma_table_info('published')\").fetchall()]
needed = ['sha', 'comment', 'expires_at', 'deleted_at', 'portal_key', 'backend']
for col in needed:
    if col not in cols:
        conn.execute(f'ALTER TABLE published ADD COLUMN {col} TEXT')
        print(f'Added: {col}')
    else:
        print(f'Already exists: {col}')
conn.commit()
conn.close()
"
```

If you see `NOT NULL constraint failed: published.sha` or `published.github_path`, run this migration to remove the constraints from older schema versions:

```bash
python3 -c "
import sqlite3
conn = sqlite3.connect('/data/glimpse.db')
conn.executescript('''
BEGIN;
ALTER TABLE published RENAME TO published_old;
CREATE TABLE published (
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
INSERT INTO published SELECT id, slug, created_at, github_path, sha, comment, expires_at, deleted_at, portal_key, backend FROM published_old;
DROP TABLE published_old;
COMMIT;
''')
print('Migration complete')
conn.close()
"
```

## Slug format

Each published page gets a unique slug:

```
adjective-adjective-noun-xxx
```

Where `xxx` is 3 random alphanumeric characters (a-z, 0-9). Slug generation happens client-side from a word list served by the API. On collision the browser retries up to 5 times.

Example: `frozen-radiant-citadel-4k2`

## Notes

- Glimpse requires HTTPS or localhost for the Web Crypto API. Plain HTTP will cause encryption to fail in the browser.
- JSX support uses Babel standalone for runtime transpilation. Complex apps (canvas-based games, heavy stateful components) may not render correctly — for those, pre-bundle with Vite or similar and upload the compiled HTML instead.
- EML DNS lookups (PTR, MX) are optional per upload and add a few seconds to the publish flow.
- The password is generated fresh in the browser for each publish and is never sent to the server. If you lose it, the content cannot be recovered.
- R2 requires `boto3` which is installed in the container. It is only imported when `STORAGE_BACKEND=r2` is set.
- `dnspython` is installed for EML DNS lookups. If not needed, it can be removed from `requirements.txt` — the parser will skip DNS gracefully.
