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

"""Unit tests for S5/S6/S7 stealth defense-tool version detection."""

from unittest.mock import MagicMock

import pytest
from kubernetes.client import ApiException

from kimera.core.api_executor import (
    _handle_detect_tool_version,
    _parse_image_version,
    _version_is_vulnerable,
)
from kimera.core.findings import TechniqueResult
from kimera.core.technique_registry import TechniqueRegistry

# ── _version_is_vulnerable ────────────────────────────────────────────


class TestVersionIsVulnerable:
    @pytest.mark.parametrize(
        "current,fixed,expected",
        [
            ("1.12.5", "1.13.1", True),  # older minor
            ("1.13.0", "1.13.1", True),  # older patch
            ("1.13.1", "1.13.1", False),  # exactly fixed
            ("1.13.2", "1.13.1", False),  # newer patch
            ("2.0.0", "1.13.1", False),  # newer major
            ("1.12.14", "1.13.1", True),  # older minor, high patch
            ("3.5.9", "3.6.0", True),  # Gatekeeper CVE boundary
            ("3.6.0", "3.6.0", False),  # Gatekeeper exactly fixed
            ("1.13.0", "1.13.0", False),  # Kyverno exactly fixed
            ("1.12.6", "1.13.0", True),  # Kyverno older
        ],
    )
    def test_version_comparison(self, current: str, fixed: str, expected: bool) -> None:
        assert _version_is_vulnerable(current, fixed) is expected

    def test_strips_leading_v(self) -> None:
        assert _version_is_vulnerable("v1.12.5", "1.13.1") is True
        assert _version_is_vulnerable("v1.13.1", "1.13.1") is False

    def test_malformed_version_does_not_crash(self) -> None:
        # Non-parseable parts treated as 0
        assert isinstance(_version_is_vulnerable("unknown", "1.13.1"), bool)


# ── _parse_image_version ──────────────────────────────────────────────


class TestParseImageVersion:
    def _make_container(self, image: str) -> MagicMock:
        c = MagicMock()
        c.image = image
        return c

    def test_extracts_tag_matching_tool_name(self) -> None:
        containers = [self._make_container("quay.io/cilium/cilium:v1.12.5")]
        assert _parse_image_version(containers, "cilium") == "1.12.5"

    def test_strips_v_prefix(self) -> None:
        containers = [self._make_container("ghcr.io/kyverno/kyverno:v1.10.3")]
        assert _parse_image_version(containers, "kyverno") == "1.10.3"

    def test_no_v_prefix(self) -> None:
        containers = [self._make_container("openpolicyagent/gatekeeper:3.13.0")]
        assert _parse_image_version(containers, "gatekeeper") == "3.13.0"

    def test_falls_back_to_first_container_if_no_tool_match(self) -> None:
        containers = [self._make_container("some-other-image:v2.0.0")]
        # fallback: returns first container tag even without name match
        assert _parse_image_version(containers, "cilium") == "2.0.0"

    def test_returns_empty_when_no_tag(self) -> None:
        containers = [self._make_container("cilium/cilium")]  # no tag
        assert _parse_image_version(containers, "cilium") == ""

    def test_empty_containers(self) -> None:
        assert _parse_image_version([], "cilium") == ""

    def test_multiple_containers_picks_matching_one(self) -> None:
        containers = [
            self._make_container("busybox:1.36"),
            self._make_container("cilium/cilium:v1.14.2"),
        ]
        assert _parse_image_version(containers, "cilium") == "1.14.2"


# ── _handle_detect_tool_version ───────────────────────────────────────


def _make_k8s() -> MagicMock:
    k8s = MagicMock()
    k8s.namespace = "demo"
    return k8s


def _make_result() -> TechniqueResult:
    return TechniqueResult(
        technique_id="S5",
        technique_name="test",
        target="demo",
        success=False,
    )


def _make_daemonset(name: str, image: str) -> MagicMock:
    ds = MagicMock()
    ds.metadata.name = name
    container = MagicMock()
    container.image = image
    ds.spec.template.spec.containers = [container]
    return ds


def _make_deployment(name: str, image: str) -> MagicMock:
    dep = MagicMock()
    dep.metadata.name = name
    container = MagicMock()
    container.image = image
    dep.spec.template.spec.containers = [container]
    return dep


class TestHandleDetectToolVersion:
    def test_cilium_vulnerable_version_detected(self) -> None:
        k8s = _make_k8s()
        k8s.apps_v1.list_namespaced_daemon_set.return_value.items = [
            _make_daemonset("cilium", "quay.io/cilium/cilium:v1.12.5"),
        ]
        result = _make_result()
        api_call = {
            "tool": "cilium",
            "namespace": "kube-system",
            "resource_kind": "daemonset",
            "name_prefix": "cilium",
            "fixed_version": "1.13.1",
            "cve": "CVE-2023-27595",
        }

        _handle_detect_tool_version(k8s, api_call, result)

        assert result.success is True
        assert any("TOOL_FOUND" in e for e in result.evidence)
        assert any("TOOL_VULNERABLE" in e for e in result.evidence)
        assert any("1.12.5" in e for e in result.evidence)
        assert any("CVE-2023-27595" in e for e in result.impact)

    def test_cilium_patched_version_reported(self) -> None:
        k8s = _make_k8s()
        k8s.apps_v1.list_namespaced_daemon_set.return_value.items = [
            _make_daemonset("cilium", "quay.io/cilium/cilium:v1.14.2"),
        ]
        result = _make_result()
        api_call = {
            "tool": "cilium",
            "namespace": "kube-system",
            "resource_kind": "daemonset",
            "name_prefix": "cilium",
            "fixed_version": "1.13.1",
            "cve": "CVE-2023-27595",
        }

        _handle_detect_tool_version(k8s, api_call, result)

        assert result.success is True
        assert any("TOOL_PATCHED" in e for e in result.evidence)
        assert not any("TOOL_VULNERABLE" in e for e in result.evidence)

    def test_tool_not_found(self) -> None:
        k8s = _make_k8s()
        k8s.apps_v1.list_namespaced_daemon_set.return_value.items = []
        result = _make_result()
        api_call = {
            "tool": "cilium",
            "namespace": "kube-system",
            "resource_kind": "daemonset",
            "name_prefix": "cilium",
            "fixed_version": "1.13.1",
            "cve": "CVE-2023-27595",
        }

        _handle_detect_tool_version(k8s, api_call, result)

        assert result.success is False
        assert any("TOOL_NOT_FOUND" in e for e in result.evidence)

    def test_gatekeeper_deployment_lookup(self) -> None:
        k8s = _make_k8s()
        k8s.apps_v1.list_namespaced_deployment.return_value.items = [
            _make_deployment(
                "gatekeeper-controller-manager",
                "openpolicyagent/gatekeeper:v3.5.0",
            ),
        ]
        result = _make_result()
        api_call = {
            "tool": "gatekeeper",
            "namespace": "gatekeeper-system",
            "resource_kind": "deployment",
            "name_prefix": "gatekeeper-controller-manager",
            "fixed_version": "3.6.0",
            "cve": "CVE-2021-43979",
        }

        _handle_detect_tool_version(k8s, api_call, result)

        assert result.success is True
        assert any("TOOL_VULNERABLE" in e for e in result.evidence)

    def test_kyverno_deployment_vulnerable(self) -> None:
        k8s = _make_k8s()
        k8s.apps_v1.list_namespaced_deployment.return_value.items = [
            _make_deployment("kyverno", "ghcr.io/kyverno/kyverno:v1.12.6"),
        ]
        result = _make_result()
        api_call = {
            "tool": "kyverno",
            "namespace": "kyverno",
            "resource_kind": "deployment",
            "name_prefix": "kyverno",
            "fixed_version": "1.13.0",
            "cve": "CVE-2024-48921",
        }

        _handle_detect_tool_version(k8s, api_call, result)

        assert result.success is True
        assert any("TOOL_VULNERABLE" in e for e in result.evidence)
        assert any("CVE-2024-48921" in e for e in result.impact)

    def test_kyverno_deployment_patched(self) -> None:
        k8s = _make_k8s()
        k8s.apps_v1.list_namespaced_deployment.return_value.items = [
            _make_deployment("kyverno", "ghcr.io/kyverno/kyverno:v1.13.0"),
        ]
        result = _make_result()
        api_call = {
            "tool": "kyverno",
            "namespace": "kyverno",
            "resource_kind": "deployment",
            "name_prefix": "kyverno",
            "fixed_version": "1.13.0",
            "cve": "CVE-2024-48921",
        }

        _handle_detect_tool_version(k8s, api_call, result)

        assert result.success is True
        assert any("TOOL_PATCHED" in e for e in result.evidence)

    def test_api_exception_recorded_not_raised(self) -> None:
        k8s = _make_k8s()
        k8s.apps_v1.list_namespaced_daemon_set.side_effect = ApiException(status=403)
        result = _make_result()
        api_call = {
            "tool": "cilium",
            "namespace": "kube-system",
            "resource_kind": "daemonset",
            "name_prefix": "cilium",
            "fixed_version": "1.13.1",
            "cve": "CVE-2023-27595",
        }

        _handle_detect_tool_version(k8s, api_call, result)

        assert result.success is False
        assert any("ACCESS_DENIED" in e for e in result.evidence)

    def test_no_parseable_version_reported(self) -> None:
        k8s = _make_k8s()
        ds = _make_daemonset("cilium", "quay.io/cilium/cilium:latest")
        k8s.apps_v1.list_namespaced_daemon_set.return_value.items = [ds]
        result = _make_result()
        api_call = {
            "tool": "cilium",
            "namespace": "kube-system",
            "resource_kind": "daemonset",
            "name_prefix": "cilium",
            "fixed_version": "1.13.1",
            "cve": "CVE-2023-27595",
        }

        _handle_detect_tool_version(k8s, api_call, result)

        assert result.success is True  # tool found
        assert any("VERSION_UNKNOWN" in e for e in result.evidence)


# ── Registry integration ──────────────────────────────────────────────


class TestStealthTechniqueRegistry:
    def test_s5_s6_s7_load_from_registry(self) -> None:
        registry = TechniqueRegistry()
        ids = {t["id"] for t in registry.list_techniques()}
        assert {"S5", "S6", "S7"} <= ids

    def test_s5_is_in_defense_validation_phase(self) -> None:
        registry = TechniqueRegistry()
        defense_ids = set(registry.list_by_phase("defense-validation"))
        assert "S5" in defense_ids
        assert "S6" in defense_ids
        assert "S7" in defense_ids

    def test_s5_technique_definition_valid(self) -> None:
        registry = TechniqueRegistry()
        tech = registry.get("S5")
        assert tech is not None
        assert tech.mode == "api"
        assert len(tech.api_calls) == 1
        assert tech.api_calls[0]["verb"] == "detect_tool_version"
        assert tech.api_calls[0]["tool"] == "cilium"

    def test_s7_technique_definition_valid(self) -> None:
        registry = TechniqueRegistry()
        tech = registry.get("S7")
        assert tech is not None
        assert tech.api_calls[0]["tool"] == "kyverno"
        assert tech.api_calls[0]["fixed_version"] == "1.13.0"
