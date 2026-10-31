"""Small shared helpers: the .env file, HTTP calls and waiting for services.

Standard library only, so the scripts run on any Python 3.10+ without a venv.
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parent
ENV_FILE = ROOT / ".env"

DOJO_URL = "http://localhost:8180"
SONAR_URL = "http://localhost:9100"
DEVLAKE_URL = "http://localhost:8183"
DEVLAKE_UI_URL = "http://localhost:4000"


def load_env() -> dict[str, str]:
    env: dict[str, str] = {}
    if ENV_FILE.exists():
        for line in ENV_FILE.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                key, value = line.split("=", 1)
                env[key.strip()] = value.strip()
    return env


def save_env(updates: dict[str, str]) -> None:
    """Sets keys in .env, keeping its other lines and comments as they are."""
    lines = ENV_FILE.read_text(encoding="utf-8").splitlines() if ENV_FILE.exists() else []
    pending = dict(updates)
    for i, line in enumerate(lines):
        key = line.split("=", 1)[0].strip()
        if "=" in line and not line.lstrip().startswith("#") and key in pending:
            lines[i] = f"{key}={pending.pop(key)}"
    lines += [f"{key}={value}" for key, value in pending.items()]
    ENV_FILE.write_text("\n".join(lines) + "\n", encoding="utf-8")


class HttpError(Exception):
    def __init__(self, status: int, body: str):
        super().__init__(f"HTTP {status}: {body[:500]}")
        self.status = status
        self.body = body


def request(
    method: str,
    url: str,
    *,
    json_body=None,
    form: dict | None = None,
    files: dict[str, tuple[str, bytes]] | None = None,
    headers: dict[str, str] | None = None,
    timeout: float = 120,
):
    """One HTTP call. Returns parsed JSON when the response is JSON, else text."""
    headers = dict(headers or {})
    data = None
    if files is not None:
        boundary = uuid.uuid4().hex
        parts = []
        for name, value in (form or {}).items():
            parts.append(
                f'--{boundary}\r\nContent-Disposition: form-data; name="{name}"\r\n\r\n{value}\r\n'.encode()
            )
        for name, (filename, content) in files.items():
            parts.append(
                f'--{boundary}\r\nContent-Disposition: form-data; name="{name}"; filename="{filename}"\r\n'
                f"Content-Type: application/octet-stream\r\n\r\n".encode()
                + content
                + b"\r\n"
            )
        data = b"".join(parts) + f"--{boundary}--\r\n".encode()
        headers["Content-Type"] = f"multipart/form-data; boundary={boundary}"
    elif form is not None:
        data = urllib.parse.urlencode(form).encode()
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    elif json_body is not None:
        data = json.dumps(json_body).encode()
        headers["Content-Type"] = "application/json"

    req = urllib.request.Request(url, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8", errors="replace")
            ctype = resp.headers.get("Content-Type", "")
    except urllib.error.HTTPError as e:
        raise HttpError(e.code, e.read().decode("utf-8", errors="replace")) from None
    if "json" in ctype and body:
        return json.loads(body)
    return body


def wait_for(name: str, check, timeout: float = 900, interval: float = 5) -> None:
    """Calls check() until it returns truthy without raising."""
    deadline = time.monotonic() + timeout
    print(f"[..] waiting for {name}", flush=True)
    while True:
        try:
            if check():
                print(f"[ok] {name} is up", flush=True)
                return
        except (OSError, HttpError, ValueError):
            pass
        if time.monotonic() > deadline:
            raise SystemExit(f"[!!] {name} did not come up within {timeout:.0f}s")
        time.sleep(interval)
