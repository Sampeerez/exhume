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
import re
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
    return check_card(value)[0]


def check_card(value: str) -> tuple[bool, str]:
    """Luhn + brand; flags obvious dummy numbers."""
    digits = "".join(c for c in value if c.isdigit())
    if not luhn_valid(value):
        return False, "Luhn check failed"
    if digits.count("0") >= 7:
        return False, "dummy/test number (mostly zeros)"
    brand = ("Visa" if digits[0] == "4" else "Mastercard" if digits[0] == "5" else
             "Amex" if digits[0] == "3" else "Discover/UnionPay")
    return True, f"{brand}, Luhn OK"


_IBAN_LEN = {"ES": 24, "FR": 27, "DE": 22, "GB": 22, "IT": 27, "PT": 25, "NL": 18, "BE": 16,
             "CH": 21, "AT": 20, "IE": 22, "LU": 20, "AD": 24}


_CCC_W = (1, 2, 4, 8, 5, 10, 9, 7, 3, 6)


def _ccc_dc(digits: str) -> int:
    r = 11 - sum(int(d) * w for d, w in zip(digits, _CCC_W)) % 11
    return {11: 0, 10: 1}.get(r, r)


def check_iban(value: str) -> tuple[bool, str]:
    """ISO 13616 (country length + mod-97); for ES also the bank/branch/account check digits."""
    v = value.replace(" ", "").upper()
    if not (15 <= len(v) <= 34) or not v.isalnum():
        return False, "bad length"
    want = _IBAN_LEN.get(v[:2])
    if want is not None and len(v) != want:
        return False, f"wrong length for {v[:2]} (expected {want})"
    num = "".join(str(int(c, 36)) for c in v[4:] + v[:4])
    if int(num) % 97 != 1:
        return False, "IBAN checksum (mod-97) failed"
    if v[:2] == "ES":
        bank_branch, dc, acct = v[4:12], v[12:14], v[14:]
        if not (bank_branch.isdigit() and dc.isdigit() and acct.isdigit()):
            return False, "malformed Spanish account"
        if f"{_ccc_dc('00' + bank_branch)}{_ccc_dc(acct)}" != dc:
            return False, "Spanish account control digits failed"
        return True, f"valid Spanish IBAN (bank {bank_branch[:4]})"
    return True, f"valid IBAN ({v[:2]})"


def is_iban(value: str) -> bool:
    return check_iban(value)[0]


_DNI_LETTERS = "TRWAGMYFPDXBNJZSQVHLCKE"


def is_dni(value: str) -> bool:
    v = value.replace(" ", "").replace("-", "").upper()
    return len(v) == 9 and v[:8].isdigit() and _DNI_LETTERS[int(v[:8]) % 23] == v[8]


def check_dni(value: str) -> tuple[bool, str]:
    return (True, "control letter OK") if is_dni(value) else (False, "control letter does not match")


def is_nie(value: str) -> bool:
    v = value.replace(" ", "").replace("-", "").upper()
    if len(v) != 9 or v[0] not in "XYZ" or not v[1:8].isdigit():
        return False
    return _DNI_LETTERS[int("XYZ".index(v[0]).__str__() + v[1:8]) % 23] == v[8]


def check_nie(value: str) -> tuple[bool, str]:
    return (True, "control letter OK") if is_nie(value) else (False, "control letter does not match")


# Offline "is it real?" checks: name -> fn(value) -> (ok, detail)
def check_phone(value: str) -> tuple[bool, str]:
    """Plausible phone number: right digit count, not all the same digit, not a calendar date
    (a date like 20240115 matches the loose "digits next to a label" shape too easily)."""
    digits = re.sub(r"\D", "", value)
    if not (7 <= len(digits) <= 15):
        return False, "wrong digit count for a phone number"
    if len(set(digits)) <= 2:
        return False, "repeated-digit pattern, not a real number"
    if len(digits) == 8:
        year, month, day = digits[:4], digits[4:6], digits[6:8]
        if 1900 <= int(year) <= 2099 and 1 <= int(month) <= 12 and 1 <= int(day) <= 31:
            return False, "looks like a calendar date (YYYYMMDD)"
    return True, "plausible phone number"


CHECKS = {"iban": check_iban, "card": check_card, "dni": check_dni, "nie": check_nie,
         "phone": check_phone}

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
