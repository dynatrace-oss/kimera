# Copyright 2025 Dynatrace LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import json
from typing import Any


class DynatraceMCPClient:
    """Client for the Dynatrace hosted MCP gateway.

    Uses the MCP SDK to connect via Streamable HTTP transport with bearer
    token authentication. All queries go through the ``execute_dql`` tool
    exposed by the Dynatrace MCP server.
    """

    def __init__(self, dt_environment: str, bearer_token: str) -> None:
        """Initialize with Dynatrace environment URL and bearer token.

        Args:
            dt_environment: Dynatrace environment URL
                (e.g. ``https://abc12345.apps.dynatrace.com``).
            bearer_token: Platform token or OAuth bearer token.
        """
        self._gateway_url = self._build_gateway_url(dt_environment)
        self._token = bearer_token
        self._session: Any = None
        self._transport_ctx: Any = None
        self._cached_tools: list[dict[str, Any]] | None = None

    @staticmethod
    def _build_gateway_url(dt_environment: str) -> str:
        """Build the MCP gateway URL from a Dynatrace environment URL."""
        base = dt_environment.rstrip("/")
        if not base.startswith("https://"):
            base = f"https://{base}"
        return f"{base}/platform-reserved/mcp-gateway/v0.1/servers/dynatrace-mcp/mcp"

    async def connect(self) -> None:
        """Establish connection to the DT MCP gateway.

        Attempts Streamable HTTP transport first, falls back to SSE.
        The exact MCP SDK transport API depends on the installed version.
        """
        try:
            from mcp import ClientSession  # noqa: PLC0415
        except ImportError as exc:
            raise ImportError(
                "MCP SDK is required for DT MCP integration. "
                "Install with: uv pip install 'kimera[dt-mcp]'"
            ) from exc

        headers = {"Authorization": f"Bearer {self._token}"}
        transport_factory = self._resolve_transport()
        self._transport_ctx = transport_factory(self._gateway_url, headers=headers)
        read_stream, write_stream, *_ = await self._transport_ctx.__aenter__()
        self._session = ClientSession(read_stream, write_stream)
        await self._session.__aenter__()
        await self._session.initialize()

    @staticmethod
    def _resolve_transport() -> Any:
        """Find an available MCP HTTP transport from the installed SDK."""
        # Streamable HTTP (mcp >= 1.8)
        try:
            from mcp.client.streamable_http import streamablehttp_client  # noqa: PLC0415

            return streamablehttp_client
        except ImportError:
            pass

        # SSE transport (mcp >= 1.0)
        try:
            from mcp.client.sse import sse_client  # noqa: PLC0415

            return sse_client
        except ImportError:
            pass

        raise ImportError(
            "No MCP HTTP transport found. Install the MCP SDK: uv pip install 'kimera[dt-mcp]'"
        )

    async def close(self) -> None:
        """Close the MCP session and transport."""
        if self._session:
            await self._session.__aexit__(None, None, None)
            self._session = None
        if self._transport_ctx:
            await self._transport_ctx.__aexit__(None, None, None)
            self._transport_ctx = None

    async def execute_dql(self, query: str) -> list[dict[str, Any]]:
        """Execute a DQL query via the DT MCP gateway.

        Args:
            query: DQL query string.

        Returns:
            List of result records as dicts.
        """
        if not self._session:
            raise RuntimeError("Not connected. Call connect() first.")

        result = await self._session.call_tool("execute-dql", {"dqlQueryString": query})
        return self._parse_response_records(result.content)

    async def list_tools(self) -> list[dict[str, Any]]:
        """List available tools on the MCP server.

        Results are cached for the lifetime of this client session.

        Returns:
            List of tool descriptors with name, description, and schema.
        """
        if not self._session:
            raise RuntimeError("Not connected. Call connect() first.")

        if self._cached_tools is not None:
            return self._cached_tools

        result = await self._session.list_tools()
        self._cached_tools = [
            {
                "name": t.name,
                "description": getattr(t, "description", ""),
                "schema": getattr(t, "inputSchema", {}),
            }
            for t in result.tools
        ]
        return self._cached_tools

    async def call_tool(self, tool_name: str, arguments: dict[str, Any]) -> list[dict[str, Any]]:
        """Call any MCP tool by name and parse the response.

        Args:
            tool_name: MCP tool name.
            arguments: Tool arguments dict.

        Returns:
            Parsed records from the tool response.
        """
        if not self._session:
            raise RuntimeError("Not connected. Call connect() first.")

        result = await self._session.call_tool(tool_name, arguments)
        return self._parse_response_records(result.content)

    def _parse_response_records(self, content_blocks: list[Any]) -> list[dict[str, Any]]:
        r"""Parse MCP response content blocks into record dicts.

        The DT MCP gateway returns text blocks with prefixes like
        ``"Query result records:\n[{...}]"`` or ``"Query metadata:\n{...}"``.
        This extracts JSON from each block and filters out metadata.
        """
        records: list[dict[str, Any]] = []
        for block in content_blocks:
            if not hasattr(block, "text"):
                continue
            json_str = self._extract_json(block.text)
            if not json_str:
                continue
            try:
                parsed = json.loads(json_str)
                if isinstance(parsed, list):
                    records.extend(r for r in parsed if isinstance(r, dict))
                elif isinstance(parsed, dict) and "records" in parsed:
                    records.extend(parsed["records"])
                elif isinstance(parsed, dict):
                    if "grail" not in parsed and "scannedRecords" not in parsed:
                        records.append(parsed)
            except json.JSONDecodeError:
                continue
        return records

    @staticmethod
    def _extract_json(text: str) -> str | None:
        r"""Extract JSON from MCP response text that may have a prefix.

        Finds the first ``[`` or ``{`` and returns everything from that point.
        """
        for i, ch in enumerate(text):
            if ch in ("[", "{"):
                return text[i:]
        return None
