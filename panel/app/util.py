"""Small helpers shared across routers."""
from __future__ import annotations

import ipaddress

from fastapi import HTTPException


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
