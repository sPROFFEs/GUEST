#!/usr/bin/env python3
"""Flatten a TOML file into shell-sourceable KEY='value' lines.

Nested tables become underscore-joined uppercase keys:
    [gateway] wan_iface = "eth0"   -> GATEWAY_WAN_IFACE='eth0'
    [modules] wireguard = true     -> MODULES_WIREGUARD='true'
    [dhcp]    range = "a,b,c"      -> DHCP_RANGE='a,b,c'

Lists are joined with commas. Booleans become 'true'/'false' strings.
"""
from __future__ import annotations

import sys

try:
    import tomllib  # py3.11+
except ModuleNotFoundError:
    import tomli as tomllib  # type: ignore


def flatten(d: dict, prefix: str = ""):
    for k, v in d.items():
        key = f"{prefix}{k}".upper().replace("-", "_")
        if isinstance(v, dict):
            yield from flatten(v, f"{key}_")
        elif isinstance(v, bool):
            yield key, "true" if v else "false"
        elif isinstance(v, (int, float, str)):
            yield key, str(v)
        elif isinstance(v, list):
            yield key, ",".join(str(x) for x in v)
        else:
            print(f"warn: unsupported type for {key}: {type(v).__name__}", file=sys.stderr)


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: toml-to-env.py FILE", file=sys.stderr)
        return 2
    with open(sys.argv[1], "rb") as f:
        data = tomllib.load(f)
    for key, value in flatten(data):
        escaped = value.replace("'", "'\\''")
        print(f"{key}='{escaped}'")
    return 0


if __name__ == "__main__":
    sys.exit(main())
