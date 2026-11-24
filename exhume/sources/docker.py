"""Fuente Docker: exporta una imagen a un tar y la trata como archivo anidado.

`docker save` produce un tar que contiene las capas (cada una, a su vez, un tar).
Exhume's recursive archive extractor descends through all of them, so
scanning an image = scanning that tar. A pre-saved tarball also works.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import tempfile


def is_docker_target(target: str) -> bool:
    return target.startswith("docker://")


def image_name(target: str) -> str:
    return target[len("docker://"):]


def save_image(target: str, timeout: int = 600) -> tuple[str, str]:
    """Ejecuta `docker save` de la imagen a un tar temporal.

    Devuelve (ruta_tar, prefijo_visual). Lanza RuntimeError si no hay docker CLI
    or the export fails.
    """
    if not shutil.which("docker"):
        raise RuntimeError("Falta el CLI de docker. Alternativa: `docker save img -o img.tar` y escanea el tar.")
    image = image_name(target)
    tmpdir = tempfile.mkdtemp(prefix="exhume_docker_")
    tar_path = os.path.join(tmpdir, "image.tar")
    try:
        r = subprocess.run(["docker", "save", "-o", tar_path, image],
                           capture_output=True, text=True, timeout=timeout)
    except Exception as exc:
        shutil.rmtree(tmpdir, ignore_errors=True)
        raise RuntimeError(f"docker save failed: {exc}") from exc
    if r.returncode != 0:
        shutil.rmtree(tmpdir, ignore_errors=True)
        raise RuntimeError(f"docker save failed: {r.stderr.strip()[:200]}")
    return tar_path, f"docker://{image}"
