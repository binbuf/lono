"""Upstream routing: forward to one of several provider proxies.

The gateway can talk to multiple upstreams concurrently — a LiteLLM proxy plus
any number of additional provider proxies. Each request is routed to one:

1. the ``x-lono-upstream`` request header (explicit selection), else
2. the first enabled upstream whose ``models`` glob matches the request model, else
3. the first enabled upstream whose ``path_prefixes`` matches the URL path, else
4. the default upstream (``upstream`` in security.yaml).
"""

from __future__ import annotations

import fnmatch
import logging
import re
from collections.abc import Mapping

import httpx

from lono_gateway.settings import SecurityConfig, UpstreamConfig

logger = logging.getLogger(__name__)

_HOP_BY_HOP = {"x-lono-upstream"}


class UpstreamClient:
    def __init__(self, cfg: UpstreamConfig, transport: httpx.AsyncBaseTransport | None = None) -> None:
        self.cfg = cfg
        self.name = cfg.name
        self._client = httpx.AsyncClient(
            base_url=cfg.base_url.rstrip("/"),
            timeout=httpx.Timeout(cfg.timeout_s, connect=cfg.connect_timeout_s),
            transport=transport,
            follow_redirects=False,
        )

    def filter_headers(self, headers: Mapping[str, str]) -> dict[str, str]:
        allowed = {name.lower() for name in self.cfg.forward_headers}
        forwarded = {
            key: value
            for key, value in headers.items()
            if key.lower() in allowed and key.lower() not in _HOP_BY_HOP
        }
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


class UpstreamRegistry:
    """Owns every upstream client and picks one per request."""

    def __init__(
        self,
        cfg: SecurityConfig,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self._transport = transport
        self._clients: dict[str, UpstreamClient] = {}
        self._order: list[str] = []
        self.cfg: SecurityConfig = cfg
        self.reload(cfg)

    def reload(self, cfg: SecurityConfig | None = None) -> None:
        if cfg is not None:
            self.cfg = cfg
        existing = self._clients
        clients: dict[str, UpstreamClient] = {}
        order: list[str] = []
        for upstream in self.cfg.all_upstreams():
            if not upstream.enabled:
                continue
            client = existing.get(upstream.name)
            if client is not None and client.cfg.base_url == upstream.base_url:
                client.cfg = upstream
            else:
                if client is not None:
                    # base_url changed: the httpx client must be rebuilt.
                    import asyncio

                    try:
                        asyncio.get_running_loop().create_task(client.aclose())
                    except RuntimeError:
                        pass
                client = UpstreamClient(upstream, transport=self._transport)
            clients[upstream.name] = client
            order.append(upstream.name)
        for name, client in existing.items():
            if name not in clients:
                import asyncio

                try:
                    asyncio.get_running_loop().create_task(client.aclose())
                except RuntimeError:
                    pass
        self._clients = clients
        self._order = order
        if "default" not in clients and clients:
            logger.warning("no default upstream is enabled; routing falls back to the first entry")

    @property
    def default(self) -> UpstreamClient:
        if "default" in self._clients:
            return self._clients["default"]
        if not self._clients:
            raise RuntimeError("no upstreams configured")
        return self._clients[self._order[0]]

    def names(self) -> list[str]:
        return list(self._order)

    def get(self, name: str) -> UpstreamClient | None:
        return self._clients.get(name)

    def select(
        self,
        *,
        path: str = "",
        model: str | None = None,
        headers: Mapping[str, str] | None = None,
    ) -> UpstreamClient:
        if headers:
            requested = (headers.get("x-lono-upstream") or "").strip()
            if requested:
                client = self._clients.get(requested)
                if client is not None:
                    return client
                logger.warning("requested upstream %r not found; falling back", requested)

        candidates = [self._clients[name] for name in self._order if name != "default"]
        candidates.append(self.default)

        if model:
            for client in candidates:
                for pattern in client.cfg.models:
                    if _match_pattern(pattern, model):
                        return client
        if path:
            for client in candidates:
                for prefix in client.cfg.path_prefixes:
                    if path.startswith(prefix):
                        return client
        return self.default

    async def aclose(self) -> None:
        for client in self._clients.values():
            await client.aclose()


def _match_pattern(pattern: str, value: str) -> bool:
    pattern = pattern.strip()
    if not pattern:
        return False
    if any(char in pattern for char in "*?["):
        return fnmatch.fnmatchcase(value, pattern)
    if pattern.endswith("/"):
        return value.startswith(pattern)
    # Bare prefix is treated as a glob prefix ("deepseek" matches "deepseek-...").
    return bool(re.match(rf"^{re.escape(pattern)}(?:$|[/.:-])", value))