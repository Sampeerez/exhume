"""Host liveness check for discovered IP addresses.

For authorized audits only: it opens short TCP connections to a handful of
common ports and, if nothing answers, asks DNS for a reverse (PTR) record.
A host that accepts OR actively refuses a connection (RST) certainly exists;
a PTR record means the address is assigned. Firewalled hosts that silently
drop everything are reported as "no response" (they may still be real).

Private/link-local addresses (RFC1918, 169.254.0.0/16) are a special case: this probe
always runs from the scanning machine, which is normally OUTSIDE the target's internal
network. A private IP found in a log or config is still a real, worth-reporting fact even
when nothing answers from here — that failure proves nothing about whether the address is
real, only that this machine can't reach that network. So an unreachable private address is
reported UNKNOWN (shown normally, not hidden), never INVALID; only a genuinely bogus PUBLIC
IP (one that answers from nowhere on the real Internet) is flagged invalid. Loopback
addresses are never probed at all — probing one would just test the scanning host itself.
"""
from __future__ import annotations

import concurrent.futures as cf
import errno
import ipaddress
import select
import socket
import time

from ..models import Verified

_PORTS = (443, 80, 22, 445, 3389, 8080)
_TIMEOUT = 1.5
_PTR_TIMEOUT = 2.0
_ptr_pool = cf.ThreadPoolExecutor(max_workers=16)

_REFUSED = {errno.ECONNREFUSED, getattr(errno, "WSAECONNREFUSED", -1)}


def raise_fd_limit(want: int = 4096) -> None:
    """Many concurrent probes need more file descriptors than macOS' default 256."""
    try:
        import resource
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        target = want if hard == resource.RLIM_INFINITY else min(want, hard)
        if soft < target:
            resource.setrlimit(resource.RLIMIT_NOFILE, (target, hard))
    except Exception:
        pass


def _tcp_probe(ip: str) -> str | None:
    """Return a description if the host answers on any probed port, else None."""
    pending: dict[socket.socket, int] = {}
    refused: int | None = None
    try:
        for port in _PORTS:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setblocking(False)
            err = s.connect_ex((ip, port))
            if err == 0:
                s.close()
                return f"port {port} open"
            if err in _REFUSED:
                s.close()
                refused = refused or port
                continue
            pending[s] = port
        deadline = time.monotonic() + _TIMEOUT
        while pending:
            left = deadline - time.monotonic()
            if left <= 0:
                break
            _, writable, _ = select.select([], list(pending), [], left)
            if not writable:
                break
            for s in writable:
                port = pending.pop(s)
                code = s.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
                s.close()
                if code == 0:
                    return f"port {port} open"
                if code in _REFUSED:
                    refused = refused or port
    except OSError:
        pass
    finally:
        for s in pending:
            try:
                s.close()
            except OSError:
                pass
    return f"host answered (port {refused} closed)" if refused else None


def _ptr(ip: str) -> str | None:
    try:
        return _ptr_pool.submit(lambda: socket.gethostbyaddr(ip)[0]).result(timeout=_PTR_TIMEOUT)
    except Exception:
        return None


# Major cloud providers auto-assign a reverse-DNS (PTR) record to EVERY public IP in these ranges
# the moment it's allocated to the pool, whether or not anyone has ever deployed anything on it. A
# PTR here is proof the number is real, allocated IP space — not proof the specific IP was ever
# actually referenced as infrastructure. A `3.4.4.2` sitting in a PDF's numbered section list will
# resolve exactly like this, which previously made it look network-"VALID" on no real evidence.
_AUTO_PTR_SUFFIXES = (
    ".compute.amazonaws.com", ".compute-1.amazonaws.com", ".compute.internal",
    ".cloudapp.azure.com", ".cloudapp.net", ".azure.com",
    ".bc.googleusercontent.com", ".googleusercontent.com", ".googleapis.com",
)


def is_auto_assigned_ptr(hostname: str) -> bool:
    h = hostname.lower()
    return any(h.endswith(suf) for suf in _AUTO_PTR_SUFFIXES)


def verify_ip(ip: str) -> tuple[Verified, str]:
    ip = ip.strip()
    try:
        addr = ipaddress.IPv4Address(ip)
    except ValueError:
        return Verified.UNKNOWN, "not a parseable IPv4 address"
    if addr.is_loopback:
        return Verified.VALID, "loopback address (always refers to the scanning host itself)"
    hit = _tcp_probe(ip)
    if hit:
        return Verified.VALID, hit
    name = _ptr(ip)
    if name:
        if is_auto_assigned_ptr(name):
            return (Verified.UNKNOWN, f"reverse DNS: {name} (auto-assigned by the cloud provider to "
                                      "every IP in this range — not proof this specific address was "
                                      "ever actually used, since no port answered)")
        return Verified.VALID, f"reverse DNS: {name}"
    if addr.is_private or addr.is_link_local:
        return (Verified.UNKNOWN, "private address: not reachable from this machine, which is expected "
                                  "when scanning from outside its network — this does not mean it's fake")
    return Verified.INVALID, "no response on common ports and no reverse DNS"


NETWORK_VERIFIERS = {"ip": verify_ip}
