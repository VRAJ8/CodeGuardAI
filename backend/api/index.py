"""Vercel entrypoint: Vercel's Python runtime serves the ASGI `app` exported here (routing in ../vercel.json)."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from server import app  # noqa: E402,F401
