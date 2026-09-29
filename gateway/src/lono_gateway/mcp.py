"""MCP (Model Context Protocol) proxy registry.

Forwards JSON-RPC traffic to configured MCP servers so it lands inside the same
audit boundary as LLM traffic. Each call becomes an audit request and one or
more ``mcp_events`` linked back to that request.
"""

from __future__ import annotations

import logging

import httpx

from lono_gateway.settings import McpConfig, McpServerConfig

logger = logging.getLogger(__name__)


class McpRegistry:
    def __init__(
        self, cfg: McpConfig, transport: httpx.AsyncBaseTransport | None = None
    ) -> None:
        self.cfg = cfg
        self._transport = transport
        self._clients: dict[str, httpx.AsyncClient] = {}
        self._servers: dict[str, McpServerConfig] = {}
        self.reload(cfg)

    def reload(self, cfg: McpConfig | None = None) -> None:
        if cfg is not None:
            self.cfg = cfg
        servers = {server.name: server for server in self.cfg.servers if server.enabled}
        # Drop clients for removed/changed servers.
        for name in list(self._clients):
            if name not in servers:
                import asyncio

                try:
                    asyncio.get_running_loop().create_task(self._clients[name].aclose())
                except RuntimeError:
                    pass
                del self._clients[name]
        for name, server in servers.items():
            if name not in self._clients:
                self._clients[name] = httpx.AsyncClient(
                    base_url=server.url.rstrip("/"),
                    timeout=httpx.Timeout(self.cfg.timeout_s),
                    transport=self._transport,
                    follow_redirects=False,
                )
        self._servers = servers

    def names(self) -> list[str]:
        return list(self._servers)

    def get(self, name: str) -> tuple[McpServerConfig, httpx.AsyncClient] | None:
        server = self._servers.get(name)
        if server is None:
            return None
        return server, self._clients[name]

    def default_name(self) -> str | None:
        if not self._servers:
            return None
        return next(iter(self._servers))

    async def aclose(self) -> None:
        for client in self._clients.values():
            await client.aclose()