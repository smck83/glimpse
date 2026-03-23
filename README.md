# Glimpse

Self-hosted portal for sharing HTML pages privately via password-protected links. Paste or upload HTML, get back a URL and a one-time password. Share both with whoever needs to see it.

## Inspiration

Glimpse is inspired by [StatiCrypt](https://github.com/robinmoisson/staticrypt) — an excellent tool that encrypts HTML pages so they can be hosted anywhere and decrypted client-side with a password. StatiCrypt is the right tool for many use cases and well worth looking at.

Glimpse takes a different approach for a specific scenario: a self-hosted publishing workflow where the HTML content should be encrypted before it leaves the browser, so it is never visible in transit even on an untrusted or sniffable network. Rather than rely on StatiCrypt's Node.js CLI running server-side (which means the plaintext HTML travels from your browser to your server unencrypted), Glimpse moves the encryption step entirely into the browser using the Web Crypto API. The server receives only ciphertext and never sees your content. Node.js is not required anywhere in the stack.

## How it works

1. You open the Glimpse portal and enter your portal key to unlock it
2. You paste or upload an HTML file
3. Your browser generates a random password and encrypts the HTML using AES-256-GCM with PBKDF2 key derivation (600,000 iterations, SHA-256) — entirely client-side
4. Only the encrypted blob, salt, and IV are sent to the FastAPI server
5. The server wraps the encrypted payload in a self-contained recipient HTML page and pushes it to your GitHub Pages repo via the GitHub API
6. You receive the public URL and the password — the password was generated in your browser and is never sent to or stored by the server
7. Share the URL and password with your recipient however you like

The recipient opens the URL, enters the password, their browser decrypts the page and renders it. No server is involved at decryption time.

## Security properties

- Plaintext HTML is encrypted in the browser before the POST request — not visible in transit or in server logs
- The password never leaves the browser and is never stored anywhere
- The server stores only: slug, timestamp, and GitHub file path (SQLite) — no passwords, no content
- Encrypted files on GitHub Pages are publicly reachable but unreadable without the password
- Encryption uses AES-256-GCM (authenticated encryption — detects tampering) with PBKDF2-SHA256 at 600,000 iterations (OWASP recommended)
- To revoke access to a published page, delete the file from your GitHub repo

## Stack

- **FastAPI** — lightweight Python API server
- **Web Crypto API** — browser-native encryption, no external crypto libraries
- **GitHub API** — pushes encrypted files directly to your GitHub Pages repo
- **SQLite** — tracks published slugs and timestamps
- **Docker** — single container, no Node.js, no build tools

## Requirements

- Docker
- A GitHub account with a Pages-enabled repo (e.g. `username/username.github.io` or any repo with Pages enabled)
- A GitHub fine-grained personal access token with Contents read/write on that repo

## Setup

### 1. GitHub Personal Access Token

Go to **GitHub > Settings > Developer Settings > Personal Access Tokens > Fine-grained tokens**.

Create a token scoped to your target repo only, with a single permission:

- **Contents** — Read and Write

Everything else should be set to No access.

### 2. Prepare your GitHub Pages repo

Create a subfolder for Glimpse to publish into. The easiest way is to add a `vault/.gitkeep` file via the GitHub web UI. The app will push encrypted files there as `vault/slug.html`.

If your repo is `smck83/glimpse`, files will be served at:
```
https://smck83.github.io/glimpse/vault/slug.html
```

### 3. Configure environment

Copy the example env file and fill in your values:

```bash
cp .env.example .env
```

```dotenv
GITHUB_TOKEN=github_pat_...
GITHUB_REPO=yourusername/yourrepo
GITHUB_BRANCH=main
VAULT_SUBDIR=vault
PAGES_BASE_URL=https://yourusername.github.io/yourrepo
APP_API_KEY=your-strong-secret
DB_PATH=/data/glimpse.db
```

Generate a strong portal key:

```bash
openssl rand -base64 24
```

### 4. Run with Docker

```bash
docker compose up -d --build
```

Access the portal at `http://your-host:8765`.

### 5. Portainer deployment

Paste the contents of `docker-compose.yml` into a new Portainer stack. Set environment variables using Portainer's environment editor rather than a `.env` file if you prefer to avoid storing secrets on disk.

The Portainer stack YAML with environment variables inlined:

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
      - GITHUB_TOKEN=your_token_here
      - GITHUB_REPO=yourusername/yourrepo
      - GITHUB_BRANCH=main
      - VAULT_SUBDIR=vault
      - PAGES_BASE_URL=https://yourusername.github.io/yourrepo
      - APP_API_KEY=your_key_here
      - DB_PATH=/data/glimpse.db

volumes:
  glimpse_data:
```

Build the image first on the host before deploying via Portainer:

```bash
docker build -t glimpse:latest .
```

## Usage

1. Open the portal and enter your portal key — you are not prompted again for the session
2. Paste HTML into the text area or drag and drop an `.html` / `.htm` file
3. Click **Encrypt & Publish**
4. The browser encrypts your HTML, the server publishes it, you receive a URL and password
5. Click **Copy Both** to copy the URL and password as a single block ready to paste into a message
6. GitHub Pages typically serves the new file within 30-90 seconds of publishing

## Slug format

Each published page gets a unique slug in the format:

```
adjective-adjective-noun-xxx
```

Where `xxx` is 3 random alphanumeric characters (a-z, 0-9). Example:

```
https://yourusername.github.io/yourrepo/vault/frozen-radiant-citadel-4k2.html
```

The slug is the only public identifier for the page. Combined with the password requirement, a guessable URL alone grants no access.

## Notes

- Glimpse requires a secure context (HTTPS or localhost) for the Web Crypto API. If accessing over plain HTTP on your LAN, encryption will fail. Put the app behind a Cloudflare Tunnel or reverse proxy with TLS for production use.
- The `python-multipart` package is included in requirements for potential future form handling but the publish endpoint currently uses JSON.
- There is no built-in expiry or access counting. To revoke a published page, delete the file from GitHub via the web UI or API.
