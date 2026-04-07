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
import yaml
import logging
from abc import ABC, abstractmethod
from functools import lru_cache
from pathlib import Path
from typing import Any

from .dt_data_models import DtContext, KspmFinding, SmartscapeEdge

logger = logging.getLogger(__name__)

_PROMPTS_DIR = Path(__file__).parent.parent.parent / "prompts"


@lru_cache(maxsize=1)
def _load_dql_reference() -> dict[str, Any]:
    """Load the DQL reference YAML (cached)."""

    data: dict[str, Any] = yaml.safe_load((_PROMPTS_DIR / "dql_reference.yaml").read_text())
    return data


# ---------------------------------------------------------------------------
# Exploit-type → query parameter mappings
# ---------------------------------------------------------------------------

# KSPM: CIS rule IDs for precise filtering, with title keywords as fallback
EXPLOIT_KSPM_FILTERS: dict[str, dict[str, Any]] = {
    "missing-network-policies": {
        "rule_id": "CIS-78711",
        "title_keywords": ["network polic"],
    },
    "privileged-containers": {
        "rule_id": None,
        "title_keywords": ["privileged", "root"],
    },
    "dangerous-capabilities": {
        "rule_id": None,
        "title_keywords": ["capabilit"],
    },
    "host-namespace-sharing": {
        "rule_id": None,
        "title_keywords": ["host"],
    },
    "missing-resource-limits": {
        "rule_id": None,
        "title_keywords": ["resource", "limit"],
    },
    "all": {
        "rule_id": None,
        "title_keywords": [],
    },
}

# Smartscape scope per exploit type
EXPLOIT_SMARTSCAPE_SCOPE: dict[str, str] = {
    "missing-network-policies": "full",
    "privileged-containers": "minimal",
    "dangerous-capabilities": "minimal",
    "host-namespace-sharing": "minimal",
    "missing-resource-limits": "none",
    "all": "full",
}


# ---------------------------------------------------------------------------
# Shared utilities
# ---------------------------------------------------------------------------


def classify_records(
    records: list[dict[str, Any]],
) -> tuple[list[KspmFinding], list[SmartscapeEdge]]:
    """Classify raw MCP query records into KSPM findings and Smartscape edges."""
    findings: list[KspmFinding] = []
    edges: list[SmartscapeEdge] = []
    for r in records:
        if "compliance.rule.title" in r or "compliance.result.object.name" in r:
            findings.append(
                KspmFinding(
                    object_name=r.get("compliance.result.object.name", "?"),
                    rule_title=r.get("compliance.rule.title", "?"),
                    count=r.get("findings", 1),
                )
            )
        elif any(k in r for k in ("source_name", "source.name", "sourceId")):
            src = r.get("source_name") or r.get("source.name") or "?"
            tgt = r.get("target_name") or r.get("destination.name") or "?"
            src_wl = str(r.get("source_workload") or "")
            tgt_wl = str(r.get("target_workload") or "")
            edges.append(
                SmartscapeEdge(
                    source_name=src,
                    target_name=tgt,
                    source_workload=src_wl,
                    target_workload=tgt_wl,
                )
            )
    return findings, edges


def _format_kspm(findings: list[KspmFinding]) -> str:
    if not findings:
        return ""
    return "\n".join(f"  {f.object_name}: {f.rule_title} (count: {f.count})" for f in findings)


def _format_smartscape(edges: list[SmartscapeEdge]) -> str:
    if not edges:
        return ""
    lines = []
    for e in edges:
        src = f"{e.source_name} (k8s: {e.source_workload})" if e.source_workload else e.source_name
        tgt = f"{e.target_name} (k8s: {e.target_workload})" if e.target_workload else e.target_name
        lines.append(f"  {src} -> {tgt}")
    return "\n".join(lines)


def _build_summary(
    strategy_name: str,
    queries: list[str],
    findings: list[KspmFinding],
    edges: list[SmartscapeEdge],
    total_records: int,
    **extra: Any,
) -> str:
    parts = [
        f"Strategy: {strategy_name}",
        f"Queries: {len(queries)}",
        f"KSPM findings: {len(findings)}",
        f"Smartscape edges: {len(edges)}",
        f"Total records: {total_records}",
    ]
    for k, v in extra.items():
        parts.append(f"{k}: {v}")
    return " | ".join(parts)


# ---------------------------------------------------------------------------
# Abstract base
# ---------------------------------------------------------------------------


class DtDataStrategy(ABC):
    """Abstract base class for Dynatrace data fetching strategies."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Strategy identifier shown in logs and CLI output."""

    @abstractmethod
    async def fetch(
        self,
        mcp_client: Any,
        exploit_type: str,
        namespace: str,
        cluster_name: str,
    ) -> DtContext:
        """Fetch Dynatrace context for the given exploit type."""


# ---------------------------------------------------------------------------
# Strategy 1: Targeted queries
# ---------------------------------------------------------------------------


class TargetedQueryStrategy(DtDataStrategy):
    """Exploit-type-specific DQL queries using verified syntax."""

    @property
    def name(self) -> str:  # noqa: D102
        return "targeted"

    async def fetch(  # noqa: D102
        self,
        mcp_client: Any,
        exploit_type: str,
        namespace: str,
        cluster_name: str,
    ) -> DtContext:
        queries_executed: list[str] = []
        all_findings: list[KspmFinding] = []
        all_edges: list[SmartscapeEdge] = []
        total_records = 0

        # 1. KSPM findings
        kspm_query = self._build_kspm_query(namespace, cluster_name, exploit_type)
        if kspm_query:
            queries_executed.append(kspm_query)
            try:
                records = await mcp_client.execute_dql(kspm_query)
                logger.info("KSPM query returned %d records", len(records))
                total_records += len(records)
                findings, _ = classify_records(records)
                all_findings.extend(findings)
            except Exception as e:
                logger.warning("KSPM query failed: %s", e)

        # 2. Smartscape edges
        scope = EXPLOIT_SMARTSCAPE_SCOPE.get(exploit_type, "none")
        if scope != "none":
            ss_query = self._build_smartscape_query(scope, namespace)
            queries_executed.append(ss_query)
            try:
                records = await mcp_client.execute_dql(ss_query)
                logger.info("Smartscape query returned %d records", len(records))
                total_records += len(records)
                _, edges = classify_records(records)
                all_edges.extend(edges)
            except Exception as e:
                logger.warning("Smartscape query failed: %s", e)

        # 3. Process group instances (for full scope)
        if scope == "full" and cluster_name:
            pg_query = self._build_process_group_query(namespace, cluster_name)
            queries_executed.append(pg_query)
            try:
                records = await mcp_client.execute_dql(pg_query)
                logger.info("Process group query returned %d records", len(records))
                total_records += len(records)
            except Exception as e:
                logger.warning("Process group query failed: %s", e)

        return DtContext(
            strategy_name=self.name,
            kspm_findings=all_findings,
            smartscape_edges=all_edges,
            queries_executed=queries_executed,
            records_fetched=total_records,
            raw_kspm=_format_kspm(all_findings),
            raw_smartscape=_format_smartscape(all_edges),
            summary=_build_summary(
                self.name, queries_executed, all_findings, all_edges, total_records
            ),
        )

    # -- Query builders --------------------------------------------------------

    @staticmethod
    def _build_kspm_query(namespace: str, cluster_name: str, exploit_type: str) -> str:
        """Build a KSPM DQL query targeted to the exploit type."""
        filters = EXPLOIT_KSPM_FILTERS.get(exploit_type, EXPLOIT_KSPM_FILTERS["all"])

        lines = [
            "fetch security.events, from:-7d",
            '| filter dt.system.bucket == "default_securityevents_builtin"',
            '| filter event.type == "COMPLIANCE_FINDING"',
        ]
        if cluster_name:
            lines.append(f'| filter k8s.cluster.name == "{cluster_name}"')

        # Precise CIS rule ID when available
        if filters["rule_id"]:
            lines.append(f'| filter compliance.rule.id == "{filters["rule_id"]}"')
        elif filters["title_keywords"]:
            kw_clauses = [
                f'contains(lower(compliance.rule.title), "{kw}")'
                for kw in filters["title_keywords"]
            ]
            lines.append(f"| filter {' or '.join(kw_clauses)}")

        lines.append('| filter compliance.result.status.level == "FAILED"')
        lines.append(f'| filter k8s.namespace.name == "{namespace}"')
        lines.append(
            "| summarize findings = count(), "
            "by:{compliance.result.object.name, compliance.rule.title}"
        )
        lines.append("| sort findings desc")
        return "\n".join(lines)

    @staticmethod
    def _build_smartscape_query(scope: str, namespace: str = "") -> str:
        """Build a Smartscape DQL query based on scope level."""
        if scope == "full":
            lines = [
                "smartscapeEdges calls, from:-30m",
                '| fieldsAdd source_name = getNodeField(source_id, "name"),',
                '    target_name = getNodeField(target_id, "name"),',
                '    source_workload = getNodeField(source_id, "k8s.workload.name"),',
                '    target_workload = getNodeField(target_id, "k8s.workload.name")',
            ]
            if namespace:
                lines.append(
                    f'| filter contains(lower(source_name), "{namespace}") '
                    f'or contains(lower(target_name), "{namespace}")'
                )
            lines.append("| fields source_name, target_name, source_workload, target_workload")
            return "\n".join(lines)
        # minimal — edge count only
        return "smartscapeEdges calls, from:-30m\n| summarize total_edges = count()"

    @staticmethod
    def _build_process_group_query(namespace: str, cluster_name: str) -> str:
        """Build a process group instance query for the namespace."""
        return (
            "fetch dt.entity.process_group_instance\n"
            f'| filter k8s.namespace.name == "{namespace}"\n'
            f'| filter k8s.cluster.name == "{cluster_name}"'
        )


# ---------------------------------------------------------------------------
# Strategy 2: LLM-generated queries
# ---------------------------------------------------------------------------


class LlmQueryStrategy(DtDataStrategy):
    """Uses Claude to generate DQL queries from few-shot examples.

    Two-hop pipeline: Claude generates DQL → execute via MCP → parse results.
    Requires both ``kimera[llm]`` and ``kimera[dt-mcp]`` extras.
    """

    def __init__(self, model: str = "claude-sonnet-4-6") -> None:  # noqa: D107
        self._model = model

    @property
    def name(self) -> str:  # noqa: D102
        return "llm-query"

    async def fetch(  # noqa: D102
        self,
        mcp_client: Any,
        exploit_type: str,
        namespace: str,
        cluster_name: str,
    ) -> DtContext:
        # Generate DQL queries via LLM
        query_specs = self._generate_queries(exploit_type, namespace, cluster_name)
        if not query_specs:
            return DtContext(
                strategy_name=self.name,
                summary="LLM generated no valid queries",
            )

        queries_executed: list[str] = []
        all_findings: list[KspmFinding] = []
        all_edges: list[SmartscapeEdge] = []
        total_records = 0

        for spec in query_specs:
            query = spec.get("query", "")
            purpose = spec.get("purpose", "unknown")

            if not self._validate_query(query):
                logger.warning("Skipping invalid LLM-generated query (%s): %s", purpose, query)
                continue

            queries_executed.append(query)
            try:
                records = await mcp_client.execute_dql(query)
                total_records += len(records)
                findings, edges = classify_records(records)
                all_findings.extend(findings)
                all_edges.extend(edges)
            except Exception as e:
                logger.warning("LLM query failed (%s): %s", purpose, e)

        return DtContext(
            strategy_name=self.name,
            kspm_findings=all_findings,
            smartscape_edges=all_edges,
            queries_executed=queries_executed,
            records_fetched=total_records,
            raw_kspm=_format_kspm(all_findings),
            raw_smartscape=_format_smartscape(all_edges),
            summary=_build_summary(
                self.name,
                queries_executed,
                all_findings,
                all_edges,
                total_records,
            ),
        )

    def _generate_queries(
        self, exploit_type: str, namespace: str, cluster_name: str
    ) -> list[dict[str, str]]:
        """Call Anthropic Claude to generate DQL queries."""
        try:
            import anthropic  # noqa: PLC0415
        except ImportError as exc:
            raise ImportError(
                "Anthropic SDK is required for llm-query strategy. "
                "Install with: uv pip install 'kimera[llm]'"
            ) from exc

        try:
            from jinja2 import Environment, FileSystemLoader, select_autoescape  # noqa: PLC0415
        except ImportError as exc:
            raise ImportError(
                "Jinja2 is required for llm-query strategy. "
                "Install with: uv pip install 'kimera[llm]'"
            ) from exc

        env = Environment(
            loader=FileSystemLoader(str(_PROMPTS_DIR)),
            autoescape=select_autoescape([]),
            trim_blocks=True,
            lstrip_blocks=True,
        )

        dql_ref = _load_dql_reference()
        system_prompt = env.get_template("dql_query_system.j2").render(dql=dql_ref)
        user_prompt = env.get_template("dql_query_user.j2").render(
            exploit_type=exploit_type,
            namespace=namespace,
            cluster_name=cluster_name,
        )

        client = anthropic.Anthropic()
        message = client.messages.create(
            model=self._model,
            max_tokens=4096,
            system=system_prompt,
            messages=[{"role": "user", "content": user_prompt}],
        )

        raw = getattr(message.content[0], "text", "") if message.content else ""
        return self._parse_query_response(raw)

    @staticmethod
    def _parse_query_response(raw: str) -> list[dict[str, str]]:
        """Extract JSON array of {purpose, query} from LLM response."""
        text = raw.strip()
        # Strip markdown fences
        if text.startswith("```"):
            text = text.split("```", 2)[1]
            first_nl = text.find("\n")
            if first_nl != -1:
                lang = text[:first_nl].strip()
                if lang.isalpha():
                    text = text[first_nl:]
            text = text.rsplit("```", 1)[0].strip()

        try:
            parsed = json.loads(text)
            if isinstance(parsed, list):
                return [
                    s for s in parsed if isinstance(s, dict) and "query" in s and "purpose" in s
                ]
        except json.JSONDecodeError:
            logger.warning("Failed to parse LLM query response as JSON")
        return []

    @staticmethod
    def _validate_query(query: str) -> bool:
        """Lightweight validation of a DQL query string."""
        q = query.strip().lower()
        if not (q.startswith("fetch") or q.startswith("smartscape")):
            return False
        forbidden = ["delete", "insert", "update set", "create", "drop"]
        return not any(word in q for word in forbidden)


# ---------------------------------------------------------------------------
# Strategy 3: Davis CoPilot
# ---------------------------------------------------------------------------


class DavisStrategy(DtDataStrategy):
    """Queries Davis CoPilot via MCP if available, falls back to targeted."""

    @property
    def name(self) -> str:  # noqa: D102
        return "davis"

    async def fetch(  # noqa: D102
        self,
        mcp_client: Any,
        exploit_type: str,
        namespace: str,
        cluster_name: str,
    ) -> DtContext:
        davis_tools = await self._discover_davis_tools(mcp_client)

        if davis_tools:
            return await self._query_davis(
                mcp_client, davis_tools[0], exploit_type, namespace, cluster_name
            )

        # Fall back to targeted
        logger.info("No Davis tools found on MCP server. Falling back to targeted strategy.")
        fallback = TargetedQueryStrategy()
        ctx = await fallback.fetch(mcp_client, exploit_type, namespace, cluster_name)
        return DtContext(
            strategy_name="davis (fallback: targeted)",
            kspm_findings=ctx.kspm_findings,
            smartscape_edges=ctx.smartscape_edges,
            queries_executed=ctx.queries_executed,
            records_fetched=ctx.records_fetched,
            raw_kspm=ctx.raw_kspm,
            raw_smartscape=ctx.raw_smartscape,
            summary=ctx.summary.replace(
                f"Strategy: {fallback.name}",
                "Strategy: davis (fallback: targeted)",
            ),
        )

    @staticmethod
    async def _discover_davis_tools(mcp_client: Any) -> list[dict[str, Any]]:
        """Discover DT AI tools on the MCP server.

        Looks for ``create-dql`` (natural language to DQL), Davis CoPilot,
        or similar AI-powered tools.
        """
        try:
            tools = await mcp_client.list_tools()
            ai_keywords = ("davis", "copilot", "intelligent", "nl2dql", "create-dql")
            ai_tools = [
                t for t in tools if any(kw in t.get("name", "").lower() for kw in ai_keywords)
            ]
            if not ai_tools:
                tool_names = [t.get("name", "?") for t in tools]
                logger.info("Available MCP tools: %s", tool_names)
            else:
                logger.info("Found AI tools: %s", [t.get("name") for t in ai_tools])
            return ai_tools
        except Exception as e:
            logger.warning("Failed to list MCP tools: %s", e)
            return []

    @staticmethod
    async def _query_davis(
        mcp_client: Any,
        tool: dict[str, Any],
        exploit_type: str,
        namespace: str,
        cluster_name: str,
    ) -> DtContext:
        """Query via a DT AI tool (create-dql or Davis CoPilot)."""
        tool_name = tool.get("name", "")
        logger.info("Using DT AI tool: '%s'", tool_name)

        queries_executed: list[str] = []
        all_findings: list[KspmFinding] = []
        all_edges: list[SmartscapeEdge] = []
        total_records = 0

        requests = _build_davis_requests(exploit_type, namespace, cluster_name)

        for purpose, request_text in requests:
            try:
                if tool_name == "create-dql":
                    query = await _execute_create_dql(mcp_client, purpose, request_text)
                    if query is None:
                        continue
                    queries_executed.append(query)
                    records = await mcp_client.execute_dql(query)
                    total_records += len(records)
                    findings, edges = classify_records(records)
                    all_findings.extend(findings)
                    all_edges.extend(edges)
                else:
                    records = await mcp_client.call_tool(tool_name, {"question": request_text})
                    total_records += len(records)
                    queries_executed.append(f"{tool_name}: {request_text}")
            except Exception as e:
                if "403" in str(e) or "missingScopes" in str(e):
                    logger.warning(
                        "AI tool '%s' requires 'davis-copilot:nl2dql:execute' scope.", tool_name
                    )
                    break
                logger.warning("AI tool query failed (%s): %s", purpose, e)

        if not queries_executed:
            logger.warning("No queries via AI tool. Falling back to targeted.")
            fallback = TargetedQueryStrategy()
            return await fallback.fetch(mcp_client, exploit_type, namespace, cluster_name)

        # Supplement with targeted Smartscape if Davis didn't produce edges
        scope = EXPLOIT_SMARTSCAPE_SCOPE.get(exploit_type, "none")
        if not all_edges and scope != "none":
            logger.info("Supplementing with targeted Smartscape query.")
            ss_query = TargetedQueryStrategy._build_smartscape_query(scope, namespace)
            queries_executed.append(ss_query)
            try:
                records = await mcp_client.execute_dql(ss_query)
                total_records += len(records)
                _, edges = classify_records(records)
                all_edges.extend(edges)
            except Exception as e:
                logger.warning("Smartscape supplement failed: %s", e)

        strategy_name = f"davis ({tool_name})"
        return DtContext(
            strategy_name=strategy_name,
            kspm_findings=all_findings,
            smartscape_edges=all_edges,
            queries_executed=queries_executed,
            records_fetched=total_records,
            raw_kspm=_format_kspm(all_findings),
            raw_smartscape=_format_smartscape(all_edges),
            summary=_build_summary(
                strategy_name, queries_executed, all_findings, all_edges, total_records
            ),
        )


async def _execute_create_dql(mcp_client: Any, purpose: str, request_text: str) -> str | None:
    """Execute a create-dql request. Returns the generated DQL or None on failure."""
    result = await mcp_client.call_tool("create-dql", {"request": request_text})
    if not result or not isinstance(result, list):
        logger.warning("create-dql returned empty for '%s'", purpose)
        return None

    resp = result[0] if isinstance(result[0], dict) else {}

    if "error" in resp:
        err = resp["error"]
        logger.warning(
            "create-dql error (code %s): %s. Missing scopes: %s",
            err.get("code"),
            err.get("message", "unknown"),
            err.get("details", {}).get("missingScopes", "unknown"),
        )
        return None

    gen_query: str = resp.get("dql", "") or resp.get("query", "")
    if resp.get("status") == "FAILED" or not gen_query:
        notifications = resp.get("metadata", {}).get("notifications", [])
        msg = notifications[0].get("message", "") if notifications else "unknown"
        logger.warning("create-dql failed for '%s': %s", purpose, msg)
        return None

    logger.info("create-dql generated (%s): %s", purpose, gen_query[:120])
    return gen_query


def _build_davis_requests(
    exploit_type: str, namespace: str, cluster_name: str
) -> list[tuple[str, str]]:
    """Build DQL-hint-enriched natural language requests for DT AI tools.

    Includes explicit DQL field names to help Davis generate correct queries.
    """
    ref = _load_dql_reference()
    kspm_rules = ref["syntax_rules"]["kspm"]
    bucket_filter = kspm_rules["required_filters"][0]
    status_filter = kspm_rules["required_filters"][2]

    cluster_hint = f", k8s.cluster.name == '{cluster_name}'" if cluster_name else ""

    # KSPM request with DQL field hints
    kspm_filters = EXPLOIT_KSPM_FILTERS.get(exploit_type, EXPLOIT_KSPM_FILTERS["all"])
    if kspm_filters["rule_id"]:
        rule_hint = f", compliance.rule.id == '{kspm_filters['rule_id']}'"
    elif kspm_filters["title_keywords"]:
        kw = kspm_filters["title_keywords"][0]
        rule_hint = f", compliance.rule.title containing '{kw}'"
    else:
        rule_hint = ""

    kspm_request = (
        "kspm",
        f"Query {kspm_rules['data_source']} for FAILED compliance findings "
        f"({status_filter}) with {bucket_filter}{rule_hint}{cluster_hint}, "
        f"k8s.namespace.name == '{namespace}'. "
        f"Group by compliance.result.object.name and compliance.rule.title.",
    )

    requests: list[tuple[str, str]] = [kspm_request]

    # Smartscape request (only for exploit types that need it)
    scope = EXPLOIT_SMARTSCAPE_SCOPE.get(exploit_type, "none")
    if scope == "full":
        requests.append(
            (
                "smartscape",
                f"Query smartscapeEdges calls to show service-to-service communication "
                f"edges involving namespace '{namespace}'. "
                f"Resolve display names with getNodeField(source_id, 'name') and getNodeField(target_id, 'name'). "
                f"Also retrieve K8s workload names with getNodeField(source_id, 'k8s.workload.name') "
                f"and getNodeField(target_id, 'k8s.workload.name') to correlate Smartscape nodes with KSPM findings.",
            )
        )

    return requests


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------

_STRATEGIES: dict[str, type[DtDataStrategy]] = {
    "targeted": TargetedQueryStrategy,
    "llm-query": LlmQueryStrategy,
    "davis": DavisStrategy,
}


def create_strategy(name: str, **kwargs: Any) -> DtDataStrategy:
    """Create a DT data strategy by name.

    Args:
        name: One of ``targeted``, ``llm-query``, ``davis``.
        **kwargs: Passed to the strategy constructor.

    Returns:
        A concrete ``DtDataStrategy`` instance.

    Raises:
        ValueError: If the strategy name is unknown.
    """
    cls = _STRATEGIES.get(name)
    if cls is None:
        valid = ", ".join(sorted(_STRATEGIES))
        raise ValueError(f"Unknown DT strategy: {name!r}. Choose from: {valid}")
    return cls(**kwargs)
