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

import asyncio
import os

from ....core.enrichment import EnrichmentContext
from ...core.logger import SecurityLogger


class DynatraceEnrichmentProvider:
    """Fetches KSPM findings and Smartscape topology from Dynatrace via MCP.

    Requires:
      - DT_ENVIRONMENT and DT_PLATFORM_TOKEN environment variables
      - mcp optional dependency: uv pip install 'kimera[mcp-server]'
    """

    def __init__(self, strategy_name: str = "targeted", **kwargs: str) -> None:  # noqa: D107
        self._strategy_name = strategy_name
        self._kwargs = kwargs

    @property
    def name(self) -> str:  # noqa: D102
        return "dynatrace"

    def fetch(  # noqa: D102
        self,
        logger: SecurityLogger,
        namespace: str,
        cluster_name: str,
        exploit_type: str,
        **kwargs: str,
    ) -> EnrichmentContext | None:
        dt_env = os.environ.get("DT_ENVIRONMENT", "")
        dt_token = os.environ.get("DT_PLATFORM_TOKEN", "")

        if not dt_env or not dt_token:
            logger.warning(
                "DT MCP requires DT_ENVIRONMENT and DT_PLATFORM_TOKEN. "
                "Skipping DT enrichment."
            )
            return None

        try:
            from .data_models import DtContext
            from .mcp_client import DynatraceMCPClient
            from .query_strategies import create_strategy
        except ImportError as e:
            logger.warning(f"DT MCP client not available: {e}. Skipping enrichment.")
            return None

        strategy_kwargs: dict[str, str] = {**self._kwargs, **kwargs}
        try:
            strategy = create_strategy(self._strategy_name, **strategy_kwargs)
        except (ValueError, ImportError) as e:
            logger.error(f"Failed to create DT strategy '{self._strategy_name}': {e}")
            return None

        async def _fetch() -> DtContext | None:
            mcp_client = DynatraceMCPClient(dt_env, dt_token)
            try:
                await mcp_client.connect()
                logger.info(f"Connected to DT MCP gateway (strategy: {strategy.name})")
                ctx = await strategy.fetch(mcp_client, exploit_type, namespace, cluster_name)
                logger.info(ctx.summary)
                return ctx
            except Exception as e:
                logger.warning(f"DT MCP enrichment failed: {e}")
                return None
            finally:
                await mcp_client.close()

        dt_context = asyncio.run(_fetch())
        if not dt_context:
            return None

        return EnrichmentContext(
            compliance_context=dt_context.raw_kspm or None,
            topology_context=dt_context.raw_smartscape or None,
            source="dynatrace",
            queries_executed=dt_context.queries_executed,
        )
