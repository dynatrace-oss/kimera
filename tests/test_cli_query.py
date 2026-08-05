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

"""Tests for the provider-neutral `kimera query` command."""

import json
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner, Result

from kimera.cli.query import query


def _invoke(args: list[str], provider: Any = None) -> Result:
    obj: dict[str, Any] = {"k8s": MagicMock(), "logger": MagicMock()}
    with patch("kimera.cli.query._create_query_provider") as factory:
        factory.return_value = provider
        return CliRunner().invoke(query, args, obj=obj)


def _provider(records: list[dict[str, str]] | None = None, error: Exception | None = None) -> Any:
    stub = MagicMock()
    stub.name = "stubprovider"
    stub.query_language = "STUBQL"
    if error is not None:
        stub.execute_query.side_effect = error
    else:
        stub.execute_query.return_value = records or []
    return stub


class TestProviderSelection:
    def test_named_provider_executes_the_query(self) -> None:
        provider = _provider([{"svc": "a"}])
        result = _invoke(["fetch things", "--provider", "stubprovider"], provider)
        assert result.exit_code == 0
        provider.execute_query.assert_called_once_with("fetch things")

    def test_unknown_provider_exits_non_zero_and_runs_nothing(self) -> None:
        result = _invoke(["fetch things", "--provider", "nope"], provider=None)
        assert result.exit_code != 0
        assert "nope" in result.output

    def test_neutral_modules_carry_no_platform_specifics(self) -> None:
        # A provider name in the factory is unavoidable and matches how
        # `generate` already selects one. What must not leak upward is the
        # platform's query language, entity model, or endpoints.
        root = Path(__file__).resolve().parent.parent
        for relative in ("kimera/cli/query.py", "kimera/core/enrichment.py"):
            text = (root / relative).read_text(encoding="utf-8").lower()
            for term in ("dql", "smartscape", "grail", "dt_platform_token", "apps.dynatrace.com"):
                assert term not in text, f"{relative} names {term}"


class TestResultReporting:
    def test_records_appear_in_output(self) -> None:
        result = _invoke(["q", "--provider", "stubprovider"], _provider([{"svc": "payments"}]))
        assert "payments" in result.output

    def test_json_output_carries_the_records(self) -> None:
        records = [{"svc": "a"}, {"svc": "b"}]
        result = _invoke(["q", "--provider", "stubprovider", "--json"], _provider(records))
        assert json.loads(result.output) == records

    def test_empty_result_is_success_not_failure(self) -> None:
        # Absence is often the decisive answer; it must not look like a broken query.
        result = _invoke(["q", "--provider", "stubprovider"], _provider([]))
        assert result.exit_code == 0
        assert "no records" in result.output.lower()


class TestDynatraceQueryProvider:
    """The provider is where platform specifics belong, so guidance is tested here."""

    def test_missing_credentials_name_the_variables(self, monkeypatch) -> None:  # type: ignore[no-untyped-def]
        from kimera.container.integrations.dynatrace.enrichment import DynatraceQueryProvider

        monkeypatch.delenv("DT_ENVIRONMENT", raising=False)
        monkeypatch.delenv("DT_PLATFORM_TOKEN", raising=False)

        with pytest.raises(ValueError) as exc:
            DynatraceQueryProvider().execute_query("fetch spans")

        assert "DT_ENVIRONMENT" in str(exc.value)
        assert "DT_PLATFORM_TOKEN" in str(exc.value)

    def test_missing_dependency_names_the_extra(self, monkeypatch) -> None:  # type: ignore[no-untyped-def]
        from kimera.container.integrations.dynatrace.enrichment import DynatraceQueryProvider

        monkeypatch.setenv("DT_ENVIRONMENT", "https://abc.apps.dynatrace.com")
        monkeypatch.setenv("DT_PLATFORM_TOKEN", "dt0s16.test")
        with patch.dict(
            "sys.modules", {"kimera.container.integrations.dynatrace.mcp_client": None}
        ):
            with pytest.raises(ImportError) as exc:
                DynatraceQueryProvider().execute_query("fetch spans")

        assert "mcp-server" in str(exc.value)

    def test_reports_its_query_language(self) -> None:
        from kimera.container.integrations.dynatrace.enrichment import DynatraceQueryProvider

        assert DynatraceQueryProvider().query_language == "DQL"


class TestUnusableProvider:
    def test_provider_guidance_reaches_the_operator_verbatim(self) -> None:
        # The CLI must not swallow or reword what the provider says is missing —
        # only the provider knows which extra or which credentials it needs.
        provider = _provider(error=ImportError("No module named 'mcp'. Install the X extra."))
        result = _invoke(["q", "--provider", "stubprovider"], provider)
        assert result.exit_code != 0
        assert "Install the X extra." in result.output

    def test_missing_credentials_are_named(self) -> None:
        provider = _provider(error=ValueError("DT_ENVIRONMENT and DT_PLATFORM_TOKEN are required"))
        result = _invoke(["q", "--provider", "stubprovider"], provider)
        assert result.exit_code != 0
        assert "DT_ENVIRONMENT" in result.output

    def test_failed_query_does_not_report_an_empty_result(self) -> None:
        provider = _provider(error=RuntimeError("gateway refused"))
        result = _invoke(["q", "--provider", "stubprovider"], provider)
        assert result.exit_code != 0
        assert "no records" not in result.output.lower()
