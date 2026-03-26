"""
Storage backend abstraction for Glimpse.
Supports: github, local, r2
Selected via STORAGE_BACKEND env var (default: local).
"""
import os
import base64
import logging
from abc import ABC, abstractmethod
from pathlib import Path

import httpx

logger = logging.getLogger(__name__)

# -------------------------------------------------------
# Base class
# -------------------------------------------------------
class StorageBackend(ABC):
    @abstractmethod
    def write(self, slug: str, html: str) -> dict:
        """
        Write encrypted HTML for slug.
        Returns dict with at least 'url' and optionally 'sha'.
        """

    @abstractmethod
    def delete(self, slug: str, meta: dict) -> None:
        """
        Delete file for slug.
        meta contains the row from published table (github_path, sha etc).
        """

    @abstractmethod
    def public_url(self, slug: str) -> str:
        """Return the public-facing URL for a slug."""


# -------------------------------------------------------
# GitHub backend
# -------------------------------------------------------
class GitHubBackend(StorageBackend):
    def __init__(self):
        self.token       = os.environ["GITHUB_TOKEN"]
        self.repo        = os.environ["GITHUB_REPO"]
        self.branch      = os.environ.get("GITHUB_BRANCH", "main")
        self.vault_subdir = os.environ.get("VAULT_SUBDIR", "vault")
        self.pages_base  = os.environ["PAGES_BASE_URL"]

    def _path(self, slug: str) -> str:
        return f"{self.vault_subdir}/{slug}.html"

    def _headers(self) -> dict:
        return {
            "Authorization": f"Bearer {self.token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }

    def write(self, slug: str, html: str) -> dict:
        path = self._path(slug)
        url  = f"https://api.github.com/repos/{self.repo}/contents/{path}"
        content_b64 = base64.b64encode(html.encode("utf-8")).decode("ascii")
        resp = httpx.put(url, headers=self._headers(), json={
            "message": f"glimpse: add {slug}",
            "content": content_b64,
            "branch": self.branch,
        }, timeout=30)
        if resp.status_code not in (200, 201):
            raise RuntimeError(f"GitHub write error {resp.status_code}: {resp.text}")
        sha = resp.json()["content"]["sha"]
        return {"url": self.public_url(slug), "github_path": path, "sha": sha}

    def delete(self, slug: str, meta: dict) -> None:
        import json as _json
        path = meta.get("github_path") or self._path(slug)
        sha  = meta.get("sha")
        if not sha:
            raise RuntimeError(f"No SHA stored for slug {slug}, cannot delete from GitHub")
        url = f"https://api.github.com/repos/{self.repo}/contents/{path}"
        hdrs = {**self._headers(), "Content-Type": "application/json"}
        body = _json.dumps({
            "message": f"glimpse: delete {slug}",
            "sha": sha,
            "branch": self.branch,
        }).encode("utf-8")
        resp = httpx.request("DELETE", url, headers=hdrs, content=body, timeout=30)
        if resp.status_code not in (200, 204):
            raise RuntimeError(f"GitHub delete error {resp.status_code}: {resp.text}")

    def public_url(self, slug: str) -> str:
        vault = os.environ.get("VAULT_SUBDIR", "vault")
        return f"{self.pages_base}/{vault}/{slug}.html"


# -------------------------------------------------------
# Local backend
# -------------------------------------------------------
class LocalBackend(StorageBackend):
    def __init__(self):
        self.vault_dir  = Path(os.environ.get("LOCAL_VAULT_DIR", "/data/vault"))
        self.public_base = os.environ["GLIMPSE_PUBLIC_URL"]
        self.vault_dir.mkdir(parents=True, exist_ok=True)

    def write(self, slug: str, html: str) -> dict:
        path = self.vault_dir / f"{slug}.html"
        path.write_text(html, encoding="utf-8")
        return {"url": self.public_url(slug), "github_path": None, "sha": None}

    def delete(self, slug: str, meta: dict) -> None:
        path = self.vault_dir / f"{slug}.html"
        if path.exists():
            path.unlink()

    def public_url(self, slug: str) -> str:
        return f"{self.public_base}/vault/{slug}.html"

    def file_path(self, slug: str) -> Path:
        return self.vault_dir / f"{slug}.html"


# -------------------------------------------------------
# Cloudflare R2 backend
# -------------------------------------------------------
class R2Backend(StorageBackend):
    def __init__(self):
        self.account_id  = os.environ["R2_ACCOUNT_ID"]
        self.access_key  = os.environ["R2_ACCESS_KEY_ID"]
        self.secret_key  = os.environ["R2_SECRET_ACCESS_KEY"]
        self.bucket      = os.environ["R2_BUCKET_NAME"]
        self.public_base = os.environ["R2_PUBLIC_URL"].rstrip("/")
        self.vault_subdir = os.environ.get("VAULT_SUBDIR", "vault")
        self._endpoint   = f"https://{self.account_id}.r2.cloudflarestorage.com"

    def _client(self):
        try:
            import boto3
            return boto3.client(
                "s3",
                endpoint_url=self._endpoint,
                aws_access_key_id=self.access_key,
                aws_secret_access_key=self.secret_key,
                region_name="auto",
            )
        except ImportError:
            raise RuntimeError("boto3 is required for R2 backend. Add boto3 to requirements.txt.")

    def _key(self, slug: str) -> str:
        return f"{self.vault_subdir}/{slug}.html"

    def write(self, slug: str, html: str) -> dict:
        client = self._client()
        key    = self._key(slug)
        client.put_object(
            Bucket=self.bucket,
            Key=key,
            Body=html.encode("utf-8"),
            ContentType="text/html; charset=utf-8",
        )
        return {"url": self.public_url(slug), "github_path": key, "sha": None}

    def delete(self, slug: str, meta: dict) -> None:
        client = self._client()
        key    = meta.get("github_path") or self._key(slug)
        client.delete_object(Bucket=self.bucket, Key=key)

    def public_url(self, slug: str) -> str:
        return f"{self.public_base}/{self.vault_subdir}/{slug}.html"


# -------------------------------------------------------
# Factory
# -------------------------------------------------------
def get_backend() -> StorageBackend:
    backend = os.environ.get("STORAGE_BACKEND", "local").lower().strip()
    if backend == "github":
        logger.info("Storage backend: GitHub Pages")
        return GitHubBackend()
    elif backend == "local":
        logger.info("Storage backend: local filesystem")
        return LocalBackend()
    elif backend == "r2":
        logger.info("Storage backend: Cloudflare R2")
        return R2Backend()
    else:
        logger.warning(
            f"Unknown STORAGE_BACKEND '{backend}', falling back to local filesystem"
        )
        return LocalBackend()
