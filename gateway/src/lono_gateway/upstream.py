"""Upstream client: LiteLLM (or any OpenAI-compatible endpoint)."""

from __future__ import annotations

from collections.abc import Mapping

import httpx

from lono_gateway.settings import UpstreamConfig


class UpstreamClient:
    def __init__(self, cfg: UpstreamConfig, transport: httpx.AsyncBaseTransport | None = None) -> None:
        self.cfg = cfg
        self._client = httpx.AsyncClient(
            base_url=cfg.base_url.rstrip("/"),
            timeout=httpx.Timeout(cfg.timeout_s, connect=cfg.connect_timeout_s),
            transport=transport,
            follow_redirects=False,
        )

    def filter_headers(self, headers: Mapping[str, str]) -> dict[str, str]:
        allowed = {name.lower() for name in self.cfg.forward_headers}
        forwarded = {key: value for key, value in headers.items() if key.lower() in allowed}
        forwarded.setdefault("content-type", "application/json")
        return forwarded

    async def send(
        self,
        method: str,
        path: str,
        *,
        headers: Mapping[str, str] | None = None,
        content: bytes | None = None,
        stream: bool = False,
    ) -> httpx.Response:
        request = self._client.build_request(method, path, headers=headers, content=content)
        return await self._client.send(request, stream=stream)

    async def aclose(self) -> None:
        await self._client.aclose()

    @property
    def base_url(self) -> str:
        return str(self._client.base_url)