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


def is_card(value: str) -> bool:
    """Luhn-valid AND not an obvious dummy/test number (4100000000000004...)."""
    digits = "".join(c for c in value if c.isdigit())
    if not luhn_valid(value):
        return False
    return digits.count("0") < 7


_IBAN_LEN = {"ES": 24, "FR": 27, "DE": 22, "GB": 22, "IT": 27, "PT": 25, "NL": 18, "BE": 16,
             "CH": 21, "AT": 20, "IE": 22, "LU": 20, "AD": 24}


def is_iban(value: str) -> bool:
    """ISO 13616: known country length + mod-97 checksum."""
    v = value.replace(" ", "").upper()
    if not (15 <= len(v) <= 34) or not v.isalnum():
        return False
    want = _IBAN_LEN.get(v[:2])
    if want is not None and len(v) != want:
        return False
    rearranged = v[4:] + v[:4]
    num = "".join(str(int(c, 36)) for c in rearranged)
    return int(num) % 97 == 1


_DNI_LETTERS = "TRWAGMYFPDXBNJZSQVHLCKE"


def is_dni(value: str) -> bool:
    v = value.replace(" ", "").replace("-", "").upper()
    return len(v) == 9 and v[:8].isdigit() and _DNI_LETTERS[int(v[:8]) % 23] == v[8]


def is_nie(value: str) -> bool:
    v = value.replace(" ", "").replace("-", "").upper()
    if len(v) != 9 or v[0] not in "XYZ" or not v[1:8].isdigit():
        return False
    return _DNI_LETTERS[int("XYZ".index(v[0]).__str__() + v[1:8]) % 23] == v[8]


VALIDATORS = {
    "iban": is_iban,
    "dni": is_dni,
    "nie": is_nie,
    "card": is_card,
    "ipv4_private": is_ipv4_private,
    "ipv4_public": is_ipv4_public,
    "ipv6": is_ipv6,
    "url_public": is_url_public,
    "luhn": is_luhn,
}
