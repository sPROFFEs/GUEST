"""Small helpers shared across routers."""
from __future__ import annotations

import ipaddress
from urllib.parse import urlsplit

from fastapi import HTTPException, Request


_SAFE_PATH = ("/peers", "/hosts", "/lan-egress", "/users", "/settings", "/audit", "/")


def safe_redirect_back(request: Request, fallback: str = "/") -> str:
    """Pick a safe redirect target based on the Referer header.

    Returns the path-only portion of the request's Referer if it points to a
    page within the panel; otherwise `fallback`. We refuse anything with a
    different host or scheme so a crafted Referer can't bounce us off-site.
    """
    ref = request.headers.get("referer", "")
    if not ref:
        return fallback
    try:
        parts = urlsplit(ref)
    except ValueError:
        return fallback
    # Same host — accept. Different host (or empty for relative) — only the
    # path portion is used, but we still require it to start with one of our
    # known prefixes so we don't bounce to /static or anywhere unexpected.
    if parts.netloc and parts.netloc != request.url.netloc:
        return fallback
    path = parts.path or fallback
    if not any(path == p or path.startswith(p + "/") or path == p for p in _SAFE_PATH):
        return fallback
    # Preserve query string if present (audit log filters, etc).
    return f"{path}?{parts.query}" if parts.query else path


def normalize_cidr(value: str) -> str:
    """Accept a bare IPv4 (treated as /32) or a CIDR; return canonical form.

    Examples:
        "192.168.100.211"        -> "192.168.100.211/32"
        "192.168.100.211/32"     -> "192.168.100.211/32"
        "192.168.100.0/24"       -> "192.168.100.0/24"
        "192.168.100.211/24"     -> HTTPException (host bits set)
        "not-an-ip"              -> HTTPException
    """
    s = (value or "").strip()
    if not s:
        raise HTTPException(400, "Empty IP/CIDR.")
    if "/" in s:
        try:
            return str(ipaddress.IPv4Network(s, strict=True))
        except ValueError as e:
            raise HTTPException(400, f"Invalid CIDR ({e}). Tip: for a single host write the IP without a prefix.")
    try:
        return f"{ipaddress.IPv4Address(s)}/32"
    except ValueError:
        raise HTTPException(400, f"Invalid IP address: {s!r}")
