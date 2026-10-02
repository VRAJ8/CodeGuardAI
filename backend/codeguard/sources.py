"""Loading source code from ZIP archives, GitHub repositories, and local folders.

Archives are read in-memory with hard limits on member count, per-file size and
total bytes (zip-bomb protection); path-traversal entries are rejected.
"""
from __future__ import annotations

import fnmatch
import io
import os
import re
import zipfile
from pathlib import Path, PurePosixPath
from typing import Iterable, List, Optional, Tuple

import httpx

from .models import SourceFile

LANGUAGES = {
    ".py": "python", ".js": "javascript", ".jsx": "javascript", ".mjs": "javascript", ".cjs": "javascript",
    ".ts": "typescript", ".tsx": "typescript", ".java": "java", ".go": "go", ".rs": "rust", ".cpp": "cpp",
    ".cc": "cpp", ".c": "c", ".h": "c", ".rb": "ruby", ".php": "php", ".cs": "csharp", ".swift": "swift",
    ".kt": "kotlin", ".json": "json", ".yml": "config", ".yaml": "config", ".toml": "config", ".ini": "config",
    ".cfg": "config", ".env": "config", ".properties": "config",
}
SPECIAL_NAMES = {"requirements.txt": "config", "go.mod": "config", "dockerfile": "config", ".env": "config"}
SKIP_DIRS = {"node_modules", ".git", "dist", "build", "vendor", "venv", ".venv", "env", "__pycache__", ".next",
             "coverage", "site-packages", ".tox", ".mypy_cache", ".pytest_cache", "target", "bin", "obj", ".idea"}
SKIP_FILES = {"package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock", "Pipfile.lock", "go.sum", "composer.lock"}

MAX_FILES = int(os.environ.get("CODEGUARD_MAX_FILES", 400))
MAX_FILE_BYTES = 512 * 1024
MAX_TOTAL_BYTES = 30 * 1024 * 1024
MAX_MEMBERS = 20000
MAX_DOWNLOAD_BYTES = 60 * 1024 * 1024


class SourceError(Exception):
    """User-facing error while loading sources."""


def detect_language(path: str) -> Optional[str]:
    name = PurePosixPath(path).name.lower()
    if name in SPECIAL_NAMES or name.startswith(".env"):
        return SPECIAL_NAMES.get(name, "config")
    if re.match(r"requirements[-_.\w]*\.txt$", name):
        return "config"
    if name.endswith((".min.js", ".bundle.js", ".map")):
        return None
    return LANGUAGES.get(PurePosixPath(path).suffix.lower())


def should_skip(path: str) -> bool:
    p = PurePosixPath(path)
    return p.name in SKIP_FILES or any(part in SKIP_DIRS for part in p.parts[:-1])


def _strip_common_prefix(paths: List[str]) -> str:
    """GitHub zipballs wrap everything in `owner-repo-sha/`; drop a single shared top folder."""
    tops = {p.split("/", 1)[0] for p in paths if "/" in p}
    if len(tops) == 1 and all("/" in p for p in paths):
        return tops.pop() + "/"
    return ""


def _make(path: str, raw: bytes) -> Optional[SourceFile]:
    lang = detect_language(path)
    if not lang:
        return None
    text = raw.decode("utf-8", errors="ignore")
    if "\x00" in text[:1024]:
        return None
    return SourceFile(path=path, content=text, language=lang, lines=text.count("\n") + 1)


def load_zip(data: bytes) -> List[SourceFile]:
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile as e:
        raise SourceError("That file isn't a valid ZIP archive.") from e
    infos = zf.infolist()
    if len(infos) > MAX_MEMBERS:
        raise SourceError(f"Archive has too many entries ({len(infos)}).")
    names = [i.filename for i in infos if not i.is_dir()]
    prefix = _strip_common_prefix(names)
    files: List[SourceFile] = []
    total = 0
    for info in infos:
        if info.is_dir() or info.filename.startswith("__MACOSX/"):
            continue
        p = PurePosixPath(info.filename)
        if p.is_absolute() or ".." in p.parts:
            continue  # path traversal attempt
        rel = info.filename[len(prefix):] if prefix and info.filename.startswith(prefix) else info.filename
        if should_skip(rel) or not detect_language(rel) or info.file_size > MAX_FILE_BYTES:
            continue
        total += info.file_size
        if total > MAX_TOTAL_BYTES:
            break
        with zf.open(info) as fh:
            raw = fh.read(MAX_FILE_BYTES + 1)
        if len(raw) > MAX_FILE_BYTES:
            continue
        f = _make(rel, raw)
        if f:
            files.append(f)
        if len(files) >= MAX_FILES:
            break
    return files


def load_directory(root: str, exclude: Iterable[str] = ()) -> List[SourceFile]:
    exclude = list(exclude)
    files: List[SourceFile] = []
    base = Path(root).resolve()
    for dirpath, dirnames, filenames in os.walk(base):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for name in sorted(filenames):
            full = Path(dirpath, name)
            rel = full.relative_to(base).as_posix()
            if should_skip(rel) or not detect_language(rel):
                continue
            if any(fnmatch.fnmatch(rel, pat) or rel.startswith(pat.rstrip("/*") + "/") for pat in exclude):
                continue
            try:
                if full.stat().st_size > MAX_FILE_BYTES:
                    continue
                f = _make(rel, full.read_bytes())
            except OSError:
                continue
            if f:
                files.append(f)
            if len(files) >= MAX_FILES:
                return files
    return files


GITHUB_URL = re.compile(r"^https?://(www\.)?github\.com/([\w.-]+)/([\w.-]+?)(\.git)?(/tree/([^?#]+))?/?(?:[?#].*)?$")


def parse_github_url(url: str) -> Tuple[str, str, Optional[str]]:
    m = GITHUB_URL.match(url.strip())
    if not m:
        raise SourceError("Enter a repository URL like https://github.com/owner/repo")
    return m.group(2), m.group(3), m.group(6)


def _github_headers() -> dict:
    headers = {"Accept": "application/vnd.github+json", "User-Agent": "codeguard-ai"}
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


async def load_github(url: str) -> Tuple[List[SourceFile], dict]:
    owner, repo, ref = parse_github_url(url)
    async with httpx.AsyncClient(timeout=60, follow_redirects=True, headers=_github_headers()) as client:
        meta = await client.get(f"https://api.github.com/repos/{owner}/{repo}")
        if meta.status_code == 404:
            raise SourceError("Repository not found — it must be public (or set GITHUB_TOKEN for private repos).")
        if meta.status_code == 403:
            raise SourceError("GitHub API rate limit reached. Set GITHUB_TOKEN on the server to raise it.")
        meta.raise_for_status()
        info = meta.json()
        ref = ref or info.get("default_branch", "main")
        buf = bytearray()
        async with client.stream("GET", f"https://api.github.com/repos/{owner}/{repo}/zipball/{ref}") as resp:
            if resp.status_code != 200:
                raise SourceError(f"Couldn't download branch '{ref}' (HTTP {resp.status_code}).")
            async for chunk in resp.aiter_bytes():
                buf.extend(chunk)
                if len(buf) > MAX_DOWNLOAD_BYTES:
                    raise SourceError("Repository archive is larger than 60 MB — try uploading a trimmed ZIP.")
    repo_meta = {
        "owner": owner, "repo": repo, "ref": ref, "stars": info.get("stargazers_count"),
        "description": info.get("description"), "language": info.get("language"),
    }
    return load_zip(bytes(buf)), repo_meta


def iter_code(files: Iterable[SourceFile]) -> Iterable[SourceFile]:
    return (f for f in files if f.language not in {"json", "config"})
