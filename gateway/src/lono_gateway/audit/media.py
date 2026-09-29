"""Content-addressed media storage (local filesystem or MinIO)."""

from __future__ import annotations

import asyncio
import base64
import binascii
import copy
import hashlib
import logging
import re
import time
from pathlib import Path
from typing import Any

import httpx

from lono_gateway.audit.store import AuditStore
from lono_gateway.settings import MediaConfig

logger = logging.getLogger(__name__)

_DATA_URL_RE = re.compile(r"^data:(?P<mime>[^;,]+)?;base64,(?P<data>.+)$", re.S)


class MediaStore:
    def __init__(self, cfg: MediaConfig, store: AuditStore) -> None:
        self.cfg = cfg
        self.store = store
        self._minio = None
        self._ready = False

    async def ensure_ready(self) -> None:
        if not self.cfg.enabled:
            return
        if self.cfg.backend == "minio":
            await asyncio.to_thread(self._ensure_minio_with_retry)
        else:
            Path(self.cfg.local_path).mkdir(parents=True, exist_ok=True)
        self._ready = True

    def _ensure_minio_with_retry(self, attempts: int = 15, delay_s: float = 2.0) -> None:
        last: Exception | None = None
        for _ in range(attempts):
            try:
                self._ensure_minio()
                return
            except Exception as exc:  # noqa: BLE001 - MinIO may still be starting
                last = exc
                time.sleep(delay_s)
        raise RuntimeError(f"could not initialise the MinIO media store: {last}")

    def _ensure_minio(self) -> None:
        try:
            from minio import Minio
        except ImportError as exc:  # pragma: no cover - optional dependency
            raise RuntimeError(
                "minio backend selected but the 'minio' package is not installed; "
                "install lono-gateway[minio] or switch audit.media.backend to local"
            ) from exc
        self._minio = Minio(
            self.cfg.endpoint,
            access_key=self.cfg.access_key,
            secret_key=self.cfg.secret_key,
            secure=self.cfg.secure,
        )
        if not self._minio.bucket_exists(self.cfg.bucket):
            self._minio.make_bucket(self.cfg.bucket)

    @staticmethod
    def object_key(sha256: str) -> str:
        return f"sha256/{sha256[:2]}/{sha256[2:4]}/{sha256}"

    async def store_bytes(
        self, data: bytes, mime: str, request_id: str | None, kind: str = "image"
    ) -> dict[str, Any]:
        sha256 = hashlib.sha256(data).hexdigest()
        ref: dict[str, Any] = {
            "sha256": sha256,
            "mime": mime,
            "size": len(data),
            "backend": self.cfg.backend,
            "object": self.object_key(sha256),
            "kind": kind,
        }
        if not self.cfg.enabled:
            ref["stored"] = False
            return ref
        if len(data) > self.cfg.max_store_bytes:
            logger.warning("media object %s exceeds max_store_bytes; not stored", sha256)
            ref["stored"] = False
            return ref
        if self.cfg.backend == "minio":
            await asyncio.to_thread(self._put_minio, ref, data)
        else:
            await asyncio.to_thread(self._put_local, ref, data)
        self.store.record_media(ref, request_id)
        return ref

    def _put_local(self, ref: dict[str, Any], data: bytes) -> None:
        path = Path(self.cfg.local_path) / ref["object"]
        if path.exists():
            return
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(".tmp")
        tmp.write_bytes(data)
        tmp.replace(path)

    def _put_minio(self, ref: dict[str, Any], data: bytes) -> None:
        from io import BytesIO

        assert self._minio is not None
        self._minio.put_object(
            self.cfg.bucket,
            ref["object"],
            BytesIO(data),
            length=len(data),
            content_type=ref.get("mime") or "application/octet-stream",
        )

    async def store_data_url(self, url: str, request_id: str | None) -> dict[str, Any] | None:
        match = _DATA_URL_RE.match(url.strip())
        if not match:
            return None
        try:
            data = base64.b64decode(match.group("data"), validate=False)
        except (binascii.Error, ValueError):
            return None
        mime = match.group("mime") or "application/octet-stream"
        return await self.store_bytes(data, mime, request_id, kind="image")

    async def store_remote_url(self, url: str, request_id: str | None) -> dict[str, Any]:
        ref: dict[str, Any] = {
            "sha256": hashlib.sha256(url.encode("utf-8")).hexdigest(),
            "mime": None,
            "size": 0,
            "backend": self.cfg.backend,
            "object": url,
            "kind": "remote_url",
            "remote": True,
        }
        if self.cfg.fetch_remote_images and url.lower().startswith(("http://", "https://")):
            try:
                async with httpx.AsyncClient(timeout=15.0, follow_redirects=True) as client:
                    response = await client.get(url)
                    response.raise_for_status()
                    if len(response.content) <= self.cfg.max_store_bytes:
                        return await self.store_bytes(
                            response.content,
                            response.headers.get("content-type", "application/octet-stream"),
                            request_id,
                            kind="image",
                        )
            except Exception as exc:  # noqa: BLE001 - remote fetch is best-effort
                logger.debug("could not fetch remote image %s: %s", url, exc.__class__.__name__)
        self.store.record_media(ref, request_id)
        return ref

    def read_sync(self, ref: dict[str, Any]) -> bytes | None:
        if not self.cfg.enabled or ref.get("remote") or not ref.get("object"):
            return None
        if self.cfg.backend == "minio":
            return self._get_minio(ref)
        path = Path(self.cfg.local_path) / str(ref["object"])
        return path.read_bytes() if path.exists() else None

    async def fetch(self, ref: dict[str, Any]) -> bytes | None:
        return await asyncio.to_thread(self.read_sync, ref)

    def _get_minio(self, ref: dict[str, Any]) -> bytes | None:
        assert self._minio is not None
        response = None
        try:
            response = self._minio.get_object(self.cfg.bucket, ref["object"])
            return response.read()
        except Exception as exc:  # noqa: BLE001
            logger.warning("minio read failed for %s: %s", ref.get("sha256"), exc.__class__.__name__)
            return None
        finally:
            if response is not None:
                response.close()
                response.release_conn()


async def externalize_media(
    payload: Any, media: MediaStore, request_id: str | None
) -> tuple[Any, list[dict[str, Any]]]:
    """Return a deep copy of the payload with inline media replaced by CAS refs.

    Never mutates the original payload: the bytes actually sent to and received
    from a provider are untouched; only the audit copy is externalized.
    """
    if not isinstance(payload, (dict, list)):
        return payload, []
    clone = copy.deepcopy(payload)
    refs: list[dict[str, Any]] = []
    await _walk(clone, media, request_id, refs)
    return clone, refs


async def _walk(node: Any, media: MediaStore, request_id: str | None, refs: list[dict[str, Any]]) -> None:
    if isinstance(node, dict):
        node_type = node.get("type")
        image_url = node.get("image_url")
        if node_type == "image_url" and isinstance(image_url, dict) and isinstance(image_url.get("url"), str):
            url = image_url["url"]
            if url.startswith("data:"):
                ref = await media.store_data_url(url, request_id)
                if ref:
                    refs.append(ref)
                    image_url["url"] = f"lono-media://sha256/{ref['sha256']}"
                    image_url["lono_media"] = _compact(ref)
            elif url.lower().startswith(("http://", "https://")):
                ref = await media.store_remote_url(url, request_id)
                refs.append(ref)
                image_url["lono_media"] = _compact(ref)
        elif node_type == "input_image" and isinstance(image_url, str):
            if image_url.startswith("data:"):
                ref = await media.store_data_url(image_url, request_id)
                if ref:
                    refs.append(ref)
                    node["image_url"] = f"lono-media://sha256/{ref['sha256']}"
                    node["lono_media"] = _compact(ref)
        elif node_type == "image" and isinstance(node.get("source"), dict):
            source = node["source"]
            if source.get("type") == "base64" and isinstance(source.get("data"), str):
                ref = await media.store_data_url(
                    f"data:{source.get('media_type') or 'application/octet-stream'};base64,{source['data']}",
                    request_id,
                )
                if ref:
                    refs.append(ref)
                    source["data"] = ""
                    source["lono_media"] = _compact(ref)
        for value in node.values():
            await _walk(value, media, request_id, refs)
    elif isinstance(node, list):
        for item in node:
            await _walk(item, media, request_id, refs)


def _compact(ref: dict[str, Any]) -> dict[str, Any]:
    keys = ("sha256", "mime", "size", "object", "kind", "remote")
    return {key: ref[key] for key in keys if key in ref}