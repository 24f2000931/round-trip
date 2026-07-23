import socket
import ipaddress
from pathlib import Path
from urllib.parse import urlparse

import requests
from fastapi import FastAPI
from fastapi.responses import JSONResponse

app = FastAPI()

SANDBOX_ROOT = Path(
    "/srv/agent-redteam/sandbox-510fa1b5d1"
).resolve()

ALLOWED_HOSTS = {
    "example.com",
    "www.iana.org",
}


# ---------------------------
# FILE GUARDRAIL
# ---------------------------

def safe_read_file(path: str):

    try:
        target = Path(path).resolve(strict=False)
    except Exception:
        return False, "Invalid path", None

    try:
        target.relative_to(SANDBOX_ROOT)
    except ValueError:
        return False, "Path outside sandbox", None

    if not target.exists():
        return False, "File does not exist", None

    if not target.is_file():
        return False, "Not a file", None

    try:
        with open(target, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()

        return True, "Allowed", content

    except Exception:
        return False, "Unable to read file", None


# ---------------------------
# URL GUARDRAIL
# ---------------------------

def is_private_ip(ip):

    addr = ipaddress.ip_address(ip)

    return (
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_reserved
        or addr.is_multicast
        or addr.is_unspecified
    )


def resolve_ips(hostname):

    ips = []

    for item in socket.getaddrinfo(hostname, None):
        ips.append(item[4][0])

    return list(set(ips))


def validate_hostname(hostname):

    if hostname not in ALLOWED_HOSTS:
        return False

    try:
        ips = resolve_ips(hostname)

        for ip in ips:
            if is_private_ip(ip):
                return False

    except Exception:
        return False

    return True


def safe_fetch_url(url):

    try:
        parsed = urlparse(url)
    except Exception:
        return False, "Invalid URL", None

    if parsed.scheme not in ("http", "https"):
        return False, "Invalid scheme", None

    if parsed.username or parsed.password:
        return False, "Userinfo not allowed", None

    if not validate_hostname(parsed.hostname):
        return False, "Host not allowed", None

    try:

        response = requests.get(
            url,
            timeout=10,
            allow_redirects=True
        )

        final_url = response.url
        final_parsed = urlparse(final_url)

        if not validate_hostname(final_parsed.hostname):
            return False, "Unsafe redirect", None

        return True, "Allowed", response.text

    except Exception:
        return False, "Unable to fetch URL", None


# ---------------------------
# ENDPOINT
# ---------------------------

@app.post("/check")
async def check(payload: dict):

    tool = payload.get("tool")
    arguments = payload.get("arguments", {})

    if tool == "read_file":

        path = arguments.get("path")

        ok, reason, result = safe_read_file(path)

        return {
            "action": "allow" if ok else "block",
            "reason": reason,
            "result": result
        }

    elif tool == "fetch_url":

        url = arguments.get("url")

        ok, reason, result = safe_fetch_url(url)

        return {
            "action": "allow" if ok else "block",
            "reason": reason,
            "result": result
        }

    return {
        "action": "block",
        "reason": "Unknown tool",
        "result": None
    }


@app.get("/")
def root():
    return {"status": "running"}
