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

"""Tests for DynatraceMCPClient parsers and URL building."""

from unittest.mock import MagicMock

import pytest

from kimera.container.infrastructure.dt_mcp_client import DynatraceMCPClient

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_text_block(text: str) -> MagicMock:
    """Create a mock content block with a .text attribute."""
    block = MagicMock()
    block.text = text
    return block


def _make_non_text_block() -> MagicMock:
    """Create a mock content block without a .text attribute."""
    block = MagicMock(spec=[])  # no attributes
    return block


@pytest.fixture()
def client() -> DynatraceMCPClient:
    """Create a client instance (no connection needed for parser tests)."""
    return DynatraceMCPClient("https://abc.apps.dynatrace.com", "test-token")


# ===========================================================================
# _extract_json tests
# ===========================================================================


class TestExtractJson:
    """Tests for the _extract_json static method."""

    def test_extracts_from_prefixed_text(self) -> None:
        text = 'Query result records:\n[{"name": "pod-1"}]'
        result = DynatraceMCPClient._extract_json(text)
        assert result == '[{"name": "pod-1"}]'

    def test_extracts_from_plain_json_array(self) -> None:
        text = '[{"a": 1}]'
        result = DynatraceMCPClient._extract_json(text)
        assert result == '[{"a": 1}]'

    def test_extracts_from_plain_json_object(self) -> None:
        text = '{"key": "value"}'
        result = DynatraceMCPClient._extract_json(text)
        assert result == '{"key": "value"}'

    def test_returns_none_for_no_json(self) -> None:
        assert DynatraceMCPClient._extract_json("No results found") is None

    def test_returns_none_for_empty_string(self) -> None:
        assert DynatraceMCPClient._extract_json("") is None

    def test_handles_nested_braces(self) -> None:
        text = 'Metadata:\n{"a": {"b": 1}}'
        result = DynatraceMCPClient._extract_json(text)
        assert result == '{"a": {"b": 1}}'

    def test_handles_whitespace_prefix(self) -> None:
        text = '   [{"a": 1}]'
        result = DynatraceMCPClient._extract_json(text)
        assert result == '[{"a": 1}]'


# ===========================================================================
# _parse_response_records tests
# ===========================================================================


class TestParseResponseRecords:
    """Tests for the _parse_response_records method."""

    def test_parses_record_list(self, client: DynatraceMCPClient) -> None:
        blocks = [_make_text_block('[{"name": "a"}, {"name": "b"}]')]
        result = client._parse_response_records(blocks)
        assert len(result) == 2
        assert result[0]["name"] == "a"

    def test_parses_dict_with_records_key(self, client: DynatraceMCPClient) -> None:
        blocks = [_make_text_block('{"records": [{"x": 1}]}')]
        result = client._parse_response_records(blocks)
        assert len(result) == 1
        assert result[0]["x"] == 1

    def test_skips_metadata_blocks(self, client: DynatraceMCPClient) -> None:
        blocks = [
            _make_text_block('Query metadata:\n{"grail": {}, "scannedRecords": 100}'),
            _make_text_block('Query result records:\n[{"name": "pod-1"}]'),
        ]
        result = client._parse_response_records(blocks)
        assert len(result) == 1
        assert result[0]["name"] == "pod-1"

    def test_skips_grail_metadata(self, client: DynatraceMCPClient) -> None:
        blocks = [_make_text_block('{"grail": {"query": "..."}}')]
        result = client._parse_response_records(blocks)
        assert len(result) == 0

    def test_skips_scanned_records_metadata(self, client: DynatraceMCPClient) -> None:
        blocks = [_make_text_block('{"scannedRecords": 500}')]
        result = client._parse_response_records(blocks)
        assert len(result) == 0

    def test_includes_regular_dict(self, client: DynatraceMCPClient) -> None:
        blocks = [_make_text_block('{"dql": "fetch x", "status": "SUCCESSFUL"}')]
        result = client._parse_response_records(blocks)
        assert len(result) == 1
        assert result[0]["status"] == "SUCCESSFUL"

    def test_handles_non_dict_items_in_list(self, client: DynatraceMCPClient) -> None:
        blocks = [_make_text_block('[1, "string", {"valid": true}]')]
        result = client._parse_response_records(blocks)
        assert len(result) == 1
        assert result[0]["valid"] is True

    def test_handles_json_decode_error(self, client: DynatraceMCPClient) -> None:
        blocks = [_make_text_block("not json at all")]
        result = client._parse_response_records(blocks)
        assert result == []

    def test_handles_no_text_attribute(self, client: DynatraceMCPClient) -> None:
        blocks = [_make_non_text_block()]
        result = client._parse_response_records(blocks)
        assert result == []

    def test_handles_multiple_content_blocks(self, client: DynatraceMCPClient) -> None:
        blocks = [
            _make_text_block('Query metadata:\n{"grail": {}}'),
            _make_text_block('Query result records:\n[{"a": 1}, {"a": 2}]'),
        ]
        result = client._parse_response_records(blocks)
        assert len(result) == 2

    def test_handles_empty_blocks(self, client: DynatraceMCPClient) -> None:
        result = client._parse_response_records([])
        assert result == []

    def test_handles_prefixed_text_with_records(self, client: DynatraceMCPClient) -> None:
        blocks = [_make_text_block('Some prefix text:\n[{"name": "x"}]')]
        result = client._parse_response_records(blocks)
        assert len(result) == 1


# ===========================================================================
# _build_gateway_url tests
# ===========================================================================


class TestBuildGatewayUrl:
    """Tests for the _build_gateway_url static method."""

    def test_standard_url(self) -> None:
        url = DynatraceMCPClient._build_gateway_url("https://abc.apps.dynatrace.com")
        assert url == (
            "https://abc.apps.dynatrace.com"
            "/platform-reserved/mcp-gateway/v0.1/servers/dynatrace-mcp/mcp"
        )

    def test_url_without_scheme(self) -> None:
        url = DynatraceMCPClient._build_gateway_url("abc.apps.dynatrace.com")
        assert url.startswith("https://abc.apps.dynatrace.com/platform-reserved/")

    def test_url_with_trailing_slash(self) -> None:
        url = DynatraceMCPClient._build_gateway_url("https://abc.apps.dynatrace.com/")
        assert "//" not in url.split("://", 1)[1]  # no double slashes in path
