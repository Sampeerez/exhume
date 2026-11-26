"""SMB source: recursive download of an unmounted share (via impacket)."""
from __future__ import annotations

import os
import re
import tempfile

from ..extractors.archives import safe_join
from ..extractors.magic import DEFAULT_SKIP_DIRS


def is_smb_target(target: str) -> bool:
    return target.startswith("smb://") or target.startswith("\\\\")


def parse(target: str) -> tuple[str, str, str]:
    t = target.replace("\\", "/")
    t = re.sub(r"^smb:/+", "", t)
    t = re.sub(r"^/+", "", t)
    parts = [p for p in t.split("/") if p]
    if len(parts) < 2:
        raise ValueError("Formato esperado: smb://host/share[/subruta]")
    return parts[0], parts[1], "/".join(parts[2:])


def download(target: str, cfg) -> tuple[str, str]:
    """Descarga el share a un temporal local. Devuelve (dir_temporal, prefijo_visual)."""
    try:
        from impacket.smbconnection import SMBConnection  # type: ignore
    except ImportError as exc:
        raise RuntimeError("Falta impacket (pip install impacket) o monta el share y pasa la ruta.") from exc

    host, share, sub = parse(target)
    conn = SMBConnection(host, host, sess_port=cfg.smb_port, timeout=15)
    conn.login(cfg.smb_user or "", cfg.smb_pass or "", cfg.smb_domain or "")
    tmp = tempfile.mkdtemp(prefix="exhume_smb_")
    prefix = f"smb://{host}/{share}"
    max_bytes = cfg.max_bytes

    def walk(remote_dir: str) -> None:
        try:
            entries = conn.listPath(share, (remote_dir.rstrip("/") + "/*") if remote_dir else "*")
        except Exception:
            return
        for e in entries:
            name = e.get_longname()
            if name in (".", ".."):
                continue
            rpath = (remote_dir + "/" + name) if remote_dir else name
            if e.is_directory():
                if name not in DEFAULT_SKIP_DIRS:
                    walk(rpath)
                continue
            if max_bytes is not None and e.get_filesize() > max_bytes and not cfg.smb_all:
                continue
            local = safe_join(tmp, rpath.replace("/", os.sep))
            if not local:
                continue
            os.makedirs(os.path.dirname(local), exist_ok=True)
            try:
                with open(local, "wb") as fh:
                    conn.getFile(share, rpath, fh.write)
            except Exception:
                try:
                    os.remove(local)
                except OSError:
                    pass

    walk(sub)
    try:
        conn.close()
    except Exception:
        pass
    return tmp, prefix
