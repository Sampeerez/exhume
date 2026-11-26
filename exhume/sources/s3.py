"""S3 source: downloads objects from a bucket (via boto3) for scanning.

Uses credentials from the environment/AWS profile (standard boto3 chain).
"""
from __future__ import annotations

import os
import tempfile

from ..extractors.archives import safe_join


def is_s3_target(target: str) -> bool:
    return target.startswith("s3://")


def parse(target: str) -> tuple[str, str]:
    body = target[len("s3://"):]
    bucket, _, prefix = body.partition("/")
    if not bucket:
        raise ValueError("Formato esperado: s3://bucket[/prefijo]")
    return bucket, prefix


def download(target: str, cfg) -> tuple[str, str]:
    """Descarga objetos del bucket a un temporal. Devuelve (dir_temporal, prefijo_visual)."""
    try:
        import boto3  # type: ignore
    except ImportError as exc:
        raise RuntimeError("Falta boto3 (pip install boto3).") from exc

    bucket, prefix = parse(target)
    kwargs = {"region_name": cfg.s3_region} if cfg.s3_region else {}
    s3 = boto3.client("s3", **kwargs)
    tmp = tempfile.mkdtemp(prefix="exhume_s3_")
    visual = f"s3://{bucket}"
    max_bytes = cfg.max_bytes

    paginator = s3.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=bucket, Prefix=prefix):
        for obj in page.get("Contents", []) or []:
            key = obj["Key"]
            if key.endswith("/"):
                continue
            if max_bytes is not None and obj.get("Size", 0) > max_bytes and not cfg.s3_all:
                continue
            local = safe_join(tmp, key.replace("/", os.sep))
            if not local:
                continue
            os.makedirs(os.path.dirname(local), exist_ok=True)
            try:
                s3.download_file(bucket, key, local)
            except Exception:
                try:
                    os.remove(local)
                except OSError:
                    pass
    return tmp, visual
