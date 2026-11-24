"""Match validators: confirm that a match is REAL data.

They cut false positives by telling, for example, a real IP (`192.168.1.10`)
from an IP-looking but impossible string (`999.1.2.3`) or a version number
(`1.2.3.4.5`).

Each validator takes the matched value and returns ``True`` if it is valid.
They are referenced by name (string) from detectors, so functions never need
to be serialized across processes.
"""
from __future__ import annotations

import ipaddress
from urllib.parse import urlparse

from .entropy import luhn_valid

# Internal hosts/TLDs that do NOT count as a "public URL"
_INTERNAL_TLDS = (".local", ".internal", ".intranet", ".corp", ".lan", ".home", ".test")


def _valid_ipv4(value: str) -> ipaddress.IPv4Address | None:
    try:
        return ipaddress.IPv4Address(value.strip())
    except ValueError:
        return None


def is_ipv4_private(value: str) -> bool:
    ip = _valid_ipv4(value)
    return bool(ip and (ip.is_private or ip.is_loopback or ip.is_link_local))


def is_ipv4_public(value: str) -> bool:
    ip = _valid_ipv4(value)
    if ip is None:
        return False
    # Public = global and routable; excludes private, loopback, reserved...
    return ip.is_global and not ip.is_multicast


def is_ipv6(value: str) -> bool:
    try:
        ip = ipaddress.IPv6Address(value.strip())
    except ValueError:
        return False
    # Avoid trivial false positives like a lone "::"
    return not ip.is_unspecified


def _host_of(value: str) -> str:
    try:
        return (urlparse(value).hostname or "").lower()
    except ValueError:
        return ""


def is_url_public(value: str) -> bool:
    """http(s) URL with a real, non-internal host (internal ones have their own detector)."""
    host = _host_of(value)
    if not host:
        return False
    if host == "localhost" or host.endswith(_INTERNAL_TLDS):
        return False
    ip = _valid_ipv4(host)
    if ip is not None:
        return bool(ip.is_global)
    labels = host.split(".")
    return len(labels) >= 2 and labels[-1].isalpha() and len(labels[-1]) >= 2


def is_luhn(value: str) -> bool:
    return luhn_valid(value)


VALIDATORS = {
    "ipv4_private": is_ipv4_private,
    "ipv4_public": is_ipv4_public,
    "ipv6": is_ipv6,
    "url_public": is_url_public,
    "luhn": is_luhn,
}
