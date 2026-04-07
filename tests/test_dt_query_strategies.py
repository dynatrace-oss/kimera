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
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from kimera.container.infrastructure.dt_data_models import (
    DtContext,
    KspmFinding,
    SmartscapeEdge,
)
from kimera.container.infrastructure.dt_query_strategies import (
    EXPLOIT_KSPM_FILTERS,
    EXPLOIT_SMARTSCAPE_SCOPE,
    DavisStrategy,
    LlmQueryStrategy,
    TargetedQueryStrategy,
    classify_records,
    create_strategy,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _run(coro):
    """Run an async coroutine in a new event loop."""
    return asyncio.run(coro)


def _mock_mcp_client(dql_results: list[dict] | None = None) -> MagicMock:
    """Create a mock DynatraceMCPClient."""
    client = MagicMock()
    client.execute_dql = AsyncMock(return_value=dql_results or [])
    client.list_tools = AsyncMock(
        return_value=[{"name": "execute-dql", "description": "Execute DQL", "schema": {}}]
    )
    client.call_tool = AsyncMock(return_value=[])
    return client


# ===========================================================================
# DtContext tests
# ===========================================================================


class TestDtContext:
    """Tests for the DtContext dataclass."""

    def test_creation(self) -> None:
        ctx = DtContext(strategy_name="test", summary="test summary")
        assert ctx.strategy_name == "test"
        assert ctx.kspm_findings == []
        assert ctx.smartscape_edges == []
        assert ctx.queries_executed == []
        assert ctx.records_fetched == 0
        assert ctx.raw_kspm == ""
        assert ctx.raw_smartscape == ""

    def test_frozen(self) -> None:
        ctx = DtContext(strategy_name="test")
        with pytest.raises(AttributeError):
            ctx.strategy_name = "changed"  # type: ignore[misc]

    def test_with_data(self) -> None:
        findings = [KspmFinding(object_name="pod-1", rule_title="CIS-78711", count=3)]
        edges = [SmartscapeEdge(source_name="svc-a", target_name="svc-b")]
        ctx = DtContext(
            strategy_name="targeted",
            kspm_findings=findings,
            smartscape_edges=edges,
            queries_executed=["q1", "q2"],
            records_fetched=5,
            raw_kspm="pod-1: CIS-78711",
            raw_smartscape="svc-a -> svc-b",
            summary="test",
        )
        assert len(ctx.kspm_findings) == 1
        assert len(ctx.smartscape_edges) == 1
        assert ctx.records_fetched == 5


class TestKspmFinding:
    """Tests for the KspmFinding dataclass."""

    def test_creation(self) -> None:
        f = KspmFinding(object_name="deployment-x", rule_title="rule-1", count=5)
        assert f.object_name == "deployment-x"
        assert f.rule_title == "rule-1"
        assert f.count == 5

    def test_default_count(self) -> None:
        f = KspmFinding(object_name="x", rule_title="y")
        assert f.count == 1

    def test_frozen(self) -> None:
        f = KspmFinding(object_name="x", rule_title="y")
        with pytest.raises(AttributeError):
            f.object_name = "z"  # type: ignore[misc]


class TestSmartscapeEdge:
    """Tests for the SmartscapeEdge dataclass."""

    def test_creation(self) -> None:
        e = SmartscapeEdge(source_name="php-cli", target_name="unguard-auth-pod")
        assert e.source_name == "php-cli"
        assert e.target_name == "unguard-auth-pod"


# ===========================================================================
# TargetedQueryStrategy tests
# ===========================================================================


class TestTargetedQueryStrategy:
    """Tests for the TargetedQueryStrategy."""

    def test_name(self) -> None:
        assert TargetedQueryStrategy().name == "targeted"

    def test_builds_kspm_query_with_cis_rule_id(self) -> None:
        query = TargetedQueryStrategy._build_kspm_query(
            "unguard", "my-cluster", "missing-network-policies"
        )
        assert 'compliance.rule.id == "CIS-78711"' in query
        assert 'k8s.namespace.name == "unguard"' in query
        assert 'k8s.cluster.name == "my-cluster"' in query
        assert 'compliance.result.status.level == "FAILED"' in query

    def test_builds_kspm_query_with_title_keywords(self) -> None:
        query = TargetedQueryStrategy._build_kspm_query(
            "unguard", "my-cluster", "privileged-containers"
        )
        assert "privileged" in query
        assert "root" in query
        assert "compliance.rule.id" not in query

    def test_builds_kspm_query_all_type(self) -> None:
        query = TargetedQueryStrategy._build_kspm_query("unguard", "my-cluster", "all")
        assert "compliance.rule.id ==" not in query
        assert "contains(lower(compliance.rule.title)" not in query
        assert 'compliance.result.status.level == "FAILED"' in query

    def test_builds_kspm_query_without_cluster(self) -> None:
        query = TargetedQueryStrategy._build_kspm_query("unguard", "", "missing-network-policies")
        assert "k8s.cluster.name" not in query

    def test_builds_smartscape_full_scope(self) -> None:
        query = TargetedQueryStrategy._build_smartscape_query("full", "unguard")
        assert "getNodeField(source_id" in query
        assert "getNodeField(target_id" in query
        assert "source_name" in query
        assert "target_name" in query
        assert "unguard" in query

    def test_builds_smartscape_minimal_scope(self) -> None:
        query = TargetedQueryStrategy._build_smartscape_query("minimal")
        assert "summarize total_edges = count()" in query

    def test_builds_process_group_query(self) -> None:
        query = TargetedQueryStrategy._build_process_group_query("unguard", "my-cluster")
        assert "dt.entity.process_group_instance" in query
        assert 'k8s.namespace.name == "unguard"' in query

    def test_fetch_returns_valid_context(self) -> None:
        mock_records = [
            {
                "compliance.result.object.name": "pod-1",
                "compliance.rule.title": "CIS-78711",
                "findings": 2,
            },
        ]
        client = _mock_mcp_client(mock_records)
        strategy = TargetedQueryStrategy()
        ctx = _run(strategy.fetch(client, "missing-network-policies", "unguard", "my-cluster"))
        assert ctx.strategy_name == "targeted"
        assert len(ctx.queries_executed) >= 1
        assert ctx.records_fetched >= 1

    def test_fetch_handles_empty_results(self) -> None:
        client = _mock_mcp_client([])
        strategy = TargetedQueryStrategy()
        ctx = _run(strategy.fetch(client, "missing-network-policies", "unguard", "my-cluster"))
        assert ctx.strategy_name == "targeted"
        assert len(ctx.kspm_findings) == 0

    def test_fetch_handles_mcp_error(self) -> None:
        client = _mock_mcp_client()
        client.execute_dql = AsyncMock(side_effect=RuntimeError("connection lost"))
        strategy = TargetedQueryStrategy()
        ctx = _run(strategy.fetch(client, "missing-network-policies", "unguard", ""))
        assert ctx.strategy_name == "targeted"
        assert ctx.records_fetched == 0

    def test_smartscape_none_scope_skips_query(self) -> None:
        client = _mock_mcp_client([])
        strategy = TargetedQueryStrategy()
        ctx = _run(strategy.fetch(client, "missing-resource-limits", "unguard", ""))
        # Should only have KSPM query, no Smartscape
        has_smartscape = any("smartscape" in q.lower() for q in ctx.queries_executed)
        assert not has_smartscape


# ===========================================================================
# LlmQueryStrategy tests
# ===========================================================================


class TestLlmQueryStrategy:
    """Tests for the LlmQueryStrategy."""

    def test_name(self) -> None:
        assert LlmQueryStrategy().name == "llm-query"

    def test_validate_query_accepts_fetch(self) -> None:
        assert LlmQueryStrategy._validate_query("fetch security.events, from:-24h")

    def test_validate_query_accepts_smartscape(self) -> None:
        assert LlmQueryStrategy._validate_query("smartscapeEdges calls, from:-30m")

    def test_validate_query_rejects_mutation(self) -> None:
        assert not LlmQueryStrategy._validate_query("delete from security.events")
        assert not LlmQueryStrategy._validate_query("create table foo")

    def test_validate_query_rejects_invalid(self) -> None:
        assert not LlmQueryStrategy._validate_query("SELECT * FROM foo")

    def test_parse_query_response_valid_json(self) -> None:
        raw = '[{"purpose": "test", "query": "fetch security.events"}]'
        result = LlmQueryStrategy._parse_query_response(raw)
        assert len(result) == 1
        assert result[0]["purpose"] == "test"

    def test_parse_query_response_with_fences(self) -> None:
        raw = '```json\n[{"purpose": "test", "query": "fetch x"}]\n```'
        result = LlmQueryStrategy._parse_query_response(raw)
        assert len(result) == 1

    def test_parse_query_response_invalid_json(self) -> None:
        result = LlmQueryStrategy._parse_query_response("not json at all")
        assert result == []

    def test_parse_query_response_filters_incomplete(self) -> None:
        raw = '[{"purpose": "test"}, {"purpose": "ok", "query": "fetch x"}]'
        result = LlmQueryStrategy._parse_query_response(raw)
        assert len(result) == 1

    def test_parse_query_response_empty_array(self) -> None:
        result = LlmQueryStrategy._parse_query_response("[]")
        assert result == []

    def test_parse_query_response_single_object(self) -> None:
        raw = '{"purpose": "test", "query": "fetch x"}'
        result = LlmQueryStrategy._parse_query_response(raw)
        assert result == []

    @patch("kimera.container.infrastructure.dt_query_strategies.LlmQueryStrategy._generate_queries")
    def test_fetch_pipeline(self, mock_generate: MagicMock) -> None:
        mock_generate.return_value = [
            {"purpose": "kspm", "query": "fetch security.events, from:-24h"},
        ]
        client = _mock_mcp_client(
            [{"compliance.result.object.name": "x", "compliance.rule.title": "y"}]
        )
        strategy = LlmQueryStrategy()
        ctx = _run(strategy.fetch(client, "missing-network-policies", "unguard", "my-cluster"))
        assert ctx.strategy_name == "llm-query"
        assert len(ctx.queries_executed) == 1

    @patch("kimera.container.infrastructure.dt_query_strategies.LlmQueryStrategy._generate_queries")
    def test_fetch_skips_invalid_queries(self, mock_generate: MagicMock) -> None:
        mock_generate.return_value = [
            {"purpose": "bad", "query": "SELECT * FROM foo"},
            {"purpose": "good", "query": "fetch security.events, from:-24h"},
        ]
        client = _mock_mcp_client([])
        strategy = LlmQueryStrategy()
        ctx = _run(strategy.fetch(client, "all", "unguard", ""))
        assert len(ctx.queries_executed) == 1  # Only valid query executed

    @patch("kimera.container.infrastructure.dt_query_strategies.LlmQueryStrategy._generate_queries")
    def test_fetch_handles_no_queries(self, mock_generate: MagicMock) -> None:
        mock_generate.return_value = []
        client = _mock_mcp_client()
        strategy = LlmQueryStrategy()
        ctx = _run(strategy.fetch(client, "all", "unguard", ""))
        assert "no valid queries" in ctx.summary.lower()


# ===========================================================================
# DavisStrategy tests
# ===========================================================================


class TestDavisStrategy:
    """Tests for the DavisStrategy."""

    def test_name(self) -> None:
        assert DavisStrategy().name == "davis"

    def test_falls_back_when_no_davis_tools(self) -> None:
        client = _mock_mcp_client([])
        strategy = DavisStrategy()
        ctx = _run(strategy.fetch(client, "missing-network-policies", "unguard", ""))
        assert "fallback" in ctx.strategy_name.lower()

    def test_uses_create_dql_when_available(self) -> None:
        client = _mock_mcp_client()
        client.list_tools = AsyncMock(
            return_value=[
                {"name": "create-dql", "description": "Generate DQL", "schema": {}},
            ]
        )
        # create-dql returns a generated query as text
        client.call_tool = AsyncMock(return_value=[{"query": "fetch security.events"}])
        # execute_dql returns records
        client.execute_dql = AsyncMock(
            return_value=[{"compliance.result.object.name": "x", "compliance.rule.title": "y"}]
        )
        strategy = DavisStrategy()
        ctx = _run(strategy.fetch(client, "missing-network-policies", "unguard", "my-cluster"))
        assert "davis" in ctx.strategy_name
        assert "create-dql" in ctx.strategy_name
        client.call_tool.assert_called()

    def test_falls_back_on_davis_error(self) -> None:
        client = _mock_mcp_client([])
        client.list_tools = AsyncMock(
            return_value=[
                {"name": "davis-copilot", "description": "Davis", "schema": {}},
            ]
        )
        client.call_tool = AsyncMock(side_effect=RuntimeError("Davis unavailable"))
        strategy = DavisStrategy()
        # Should fall back to targeted, not raise
        ctx = _run(strategy.fetch(client, "all", "unguard", ""))
        assert ctx is not None

    def test_logs_available_tools_on_fallback(self) -> None:
        client = _mock_mcp_client()
        client.list_tools = AsyncMock(
            return_value=[
                {"name": "execute-dql", "description": "DQL", "schema": {}},
                {"name": "other-tool", "description": "Other", "schema": {}},
            ]
        )
        strategy = DavisStrategy()
        ctx = _run(strategy.fetch(client, "all", "unguard", ""))
        assert "fallback" in ctx.strategy_name.lower()


# ===========================================================================
# Factory tests
# ===========================================================================


class TestCreateStrategy:
    """Tests for the create_strategy factory function."""

    def test_creates_targeted(self) -> None:
        s = create_strategy("targeted")
        assert isinstance(s, TargetedQueryStrategy)

    def test_creates_llm_query(self) -> None:
        s = create_strategy("llm-query", model="claude-haiku-4-5-20251001")
        assert isinstance(s, LlmQueryStrategy)

    def test_creates_davis(self) -> None:
        s = create_strategy("davis")
        assert isinstance(s, DavisStrategy)

    def test_unknown_raises(self) -> None:
        with pytest.raises(ValueError, match="Unknown DT strategy"):
            create_strategy("nonexistent")


# ===========================================================================
# Exploit-type mapping coverage
# ===========================================================================


class TestExploitMappings:
    """Verify all exploit types have query mappings."""

    def test_all_exploit_types_have_kspm_filters(self) -> None:
        expected = {
            "missing-network-policies",
            "privileged-containers",
            "dangerous-capabilities",
            "host-namespace-sharing",
            "missing-resource-limits",
            "all",
        }
        assert set(EXPLOIT_KSPM_FILTERS.keys()) == expected

    def test_all_exploit_types_have_smartscape_scope(self) -> None:
        assert set(EXPLOIT_SMARTSCAPE_SCOPE.keys()) == set(EXPLOIT_KSPM_FILTERS.keys())

    def test_smartscape_scopes_are_valid(self) -> None:
        valid_scopes = {"full", "minimal", "none"}
        for scope in EXPLOIT_SMARTSCAPE_SCOPE.values():
            assert scope in valid_scopes


# ===========================================================================
# classify_records tests
# ===========================================================================


class TestClassifyRecords:
    """Tests for the module-level classify_records utility."""

    def test_classifies_kspm_records(self) -> None:
        records = [
            {
                "compliance.result.object.name": "pod-1",
                "compliance.rule.title": "rule-1",
                "findings": 3,
            },
        ]
        findings, edges = classify_records(records)
        assert len(findings) == 1
        assert findings[0].count == 3
        assert len(edges) == 0

    def test_classifies_smartscape_records(self) -> None:
        records = [{"source_name": "svc-a", "target_name": "svc-b"}]
        findings, edges = classify_records(records)
        assert len(findings) == 0
        assert len(edges) == 1
        assert edges[0].source_name == "svc-a"

    def test_handles_mixed_records(self) -> None:
        records = [
            {"compliance.result.object.name": "pod-1", "compliance.rule.title": "r1"},
            {"source_name": "a", "target_name": "b"},
            {"unrelated_field": "ignored"},
        ]
        findings, edges = classify_records(records)
        assert len(findings) == 1
        assert len(edges) == 1

    def test_handles_empty_records(self) -> None:
        findings, edges = classify_records([])
        assert findings == []
        assert edges == []

    def test_handles_alternative_field_names(self) -> None:
        records = [{"source.name": "a", "destination.name": "b"}]
        _, edges = classify_records(records)
        assert len(edges) == 1
        assert edges[0].source_name == "a"
        assert edges[0].target_name == "b"


# ===========================================================================
# Davis create-dql response tests
# ===========================================================================


class TestDavisCreateDql:
    """Tests for Davis create-dql response handling."""

    def test_create_dql_success_response(self) -> None:
        client = _mock_mcp_client()
        client.list_tools = AsyncMock(
            return_value=[{"name": "create-dql", "description": "NL2DQL", "schema": {}}]
        )
        client.call_tool = AsyncMock(
            return_value=[{"dql": "fetch security.events", "status": "SUCCESSFUL", "metadata": {}}]
        )
        client.execute_dql = AsyncMock(
            return_value=[{"compliance.result.object.name": "x", "compliance.rule.title": "y"}]
        )
        strategy = DavisStrategy()
        ctx = _run(strategy.fetch(client, "missing-network-policies", "unguard", "my-cluster"))
        assert "davis" in ctx.strategy_name
        assert len(ctx.kspm_findings) >= 1

    def test_create_dql_failed_status(self) -> None:
        client = _mock_mcp_client()
        client.list_tools = AsyncMock(
            return_value=[{"name": "create-dql", "description": "NL2DQL", "schema": {}}]
        )
        client.call_tool = AsyncMock(
            return_value=[
                {
                    "dql": "",
                    "status": "FAILED",
                    "metadata": {"notifications": [{"message": "Cannot generate"}]},
                }
            ]
        )
        strategy = DavisStrategy()
        # Falls back to targeted when all create-dql requests fail
        ctx = _run(strategy.fetch(client, "missing-network-policies", "unguard", ""))
        assert ctx is not None

    def test_create_dql_permission_error(self) -> None:
        client = _mock_mcp_client()
        client.list_tools = AsyncMock(
            return_value=[{"name": "create-dql", "description": "NL2DQL", "schema": {}}]
        )
        client.call_tool = AsyncMock(
            return_value=[
                {
                    "error": {
                        "code": 403,
                        "message": "Forbidden",
                        "details": {"missingScopes": ["davis-copilot:nl2dql:execute"]},
                    },
                }
            ]
        )
        strategy = DavisStrategy()
        # Falls back to targeted
        ctx = _run(strategy.fetch(client, "missing-network-policies", "unguard", ""))
        assert ctx is not None

    def test_smartscape_supplement_when_no_edges(self) -> None:
        client = _mock_mcp_client()
        client.list_tools = AsyncMock(
            return_value=[{"name": "create-dql", "description": "NL2DQL", "schema": {}}]
        )
        # create-dql returns KSPM query successfully
        client.call_tool = AsyncMock(
            return_value=[{"dql": "fetch security.events", "status": "SUCCESSFUL", "metadata": {}}]
        )
        # First call (KSPM) returns findings, second call (Smartscape supplement) returns edges
        client.execute_dql = AsyncMock(
            side_effect=[
                [{"compliance.result.object.name": "x", "compliance.rule.title": "y"}],
                [{"source_name": "a", "target_name": "b"}],
            ]
        )
        strategy = DavisStrategy()
        ctx = _run(strategy.fetch(client, "missing-network-policies", "unguard", "my-cluster"))
        assert len(ctx.kspm_findings) >= 1
        assert len(ctx.smartscape_edges) >= 1
