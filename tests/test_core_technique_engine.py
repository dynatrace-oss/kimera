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


from pathlib import Path
from unittest.mock import MagicMock

import pytest
import yaml

from kimera.core.technique_engine import (
    TechniqueRegistry,
    _resolve_probe_params,
    execute_technique,
)


@pytest.fixture
def technique_dir(tmp_path: Path) -> Path:
    """Registry with T1 (has YAML) and T2 (missing YAML) to test skip behavior."""
    tech_dir = tmp_path / "techniques"
    tech_dir.mkdir()

    registry = {
        "techniques": {
            "T1": {
                "name": "Test technique",
                "file": "T1-test.yaml",
                "phase": "credential-access",
                "noise": "low",
            },
            "T2": {
                "name": "Missing file technique",
                "file": "T2-missing.yaml",
                "phase": "discovery",
                "noise": "low",
            },
        },
    }
    (tech_dir / "registry.yaml").write_text(yaml.dump(registry))

    technique = {
        "id": "T1",
        "name": "Test technique",
        "enabled": True,
        "mitre": {
            "technique_id": "T1552.007",
            "technique_name": "Container API",
            "tactic": "credential-access",
        },
        "execution": {
            "mode": "exec",
            "requires_target_pod": True,
            "probes": [
                {"type": "command", "run": 'echo "TEST_MARKER:found"'},
            ],
            "evidence_markers": [
                {
                    "marker": "TEST_MARKER",
                    "evidence": "Test evidence collected",
                    "impact": "Test impact",
                },
            ],
        },
        "success_indicators": ["TEST_MARKER"],
    }
    (tech_dir / "T1-test.yaml").write_text(yaml.dump(technique))
    return tech_dir


class TestTechniqueRegistry:
    def test_loads_present_files_skips_missing(self, technique_dir: Path) -> None:
        """T1 loads (file exists), T2 skipped (file missing). No crash."""
        registry = TechniqueRegistry(config_dir=technique_dir)
        assert registry.technique_count == 1
        assert "T1" in registry
        assert "T2" not in registry

    def test_list_techniques_returns_mcp_compatible_metadata(self, technique_dir: Path) -> None:
        """MCP list_techniques tool depends on this structure."""
        registry = TechniqueRegistry(config_dir=technique_dir)
        techniques = registry.list_techniques()
        assert len(techniques) == 1
        t = techniques[0]
        assert t["id"] == "T1"
        assert t["phase"] == "credential-access"
        assert t["mitre_id"] == "T1552.007"

    def test_list_by_phase_filters_correctly(self, technique_dir: Path) -> None:
        registry = TechniqueRegistry(config_dir=technique_dir)
        assert "T1" in registry.list_by_phase("credential-access")
        assert registry.list_by_phase("lateral-movement") == []

    def test_reload_picks_up_new_technique(self, technique_dir: Path) -> None:
        """Runtime extension: drop YAML, call reload(), technique appears."""
        registry = TechniqueRegistry(config_dir=technique_dir)
        assert registry.technique_count == 1

        technique2 = {
            "id": "T2",
            "name": "New technique",
            "enabled": True,
            "mitre": {"technique_id": "T1046", "tactic": "discovery"},
            "execution": {"mode": "api"},
        }
        (technique_dir / "T2-missing.yaml").write_text(yaml.dump(technique2))
        registry.reload()
        assert registry.technique_count == 2
        assert "T2" in registry

    def test_empty_directory_does_not_crash(self, tmp_path: Path) -> None:
        empty_dir = tmp_path / "empty"
        empty_dir.mkdir()
        registry = TechniqueRegistry(config_dir=empty_dir)
        assert registry.technique_count == 0

    def test_real_registry_loads_expected_techniques(self) -> None:
        """Integration: config/techniques/registry.yaml has expected techniques."""
        registry = TechniqueRegistry()
        assert registry.technique_count >= 5
        ids = {t["id"] for t in registry.list_techniques()}
        assert {"C1", "C5", "L1"} <= ids


class TestExecuteTechnique:
    def test_exec_matches_evidence_markers(self, technique_dir: Path) -> None:
        """Output containing marker → success=True, evidence populated."""
        registry = TechniqueRegistry(config_dir=technique_dir)
        k8s = MagicMock()
        k8s.namespace = "demo"
        k8s.exec_in_pod.return_value = "TEST_MARKER:found\nsome output"

        result = execute_technique(k8s, registry, "T1", target_pod="test-pod")

        assert result.success is True
        assert result.mitre_id == "T1552.007"
        assert any("Test evidence" in e for e in result.evidence)

    def test_exec_no_marker_means_failure(self, technique_dir: Path) -> None:
        """Output without marker → success=False, no false positives."""
        registry = TechniqueRegistry(config_dir=technique_dir)
        k8s = MagicMock()
        k8s.namespace = "demo"
        k8s.exec_in_pod.return_value = "nothing interesting here"

        result = execute_technique(k8s, registry, "T1", target_pod="test-pod")

        assert result.success is False
        assert result.evidence == []

    def test_exec_exception_returns_structured_error(self, technique_dir: Path) -> None:
        """Connection error → structured result, not a crash."""
        registry = TechniqueRegistry(config_dir=technique_dir)
        k8s = MagicMock()
        k8s.namespace = "demo"
        k8s.exec_in_pod.side_effect = Exception("Connection refused")

        result = execute_technique(k8s, registry, "T1", target_pod="test-pod")

        assert result.success is False
        assert any("Exec failed" in e for e in result.evidence)

    @pytest.mark.parametrize(
        "technique_id,target_pod,expected_evidence_fragment",
        [
            ("T1", None, "No target pod"),  # exec technique without pod
            ("NONEXISTENT", "pod", "not found"),  # unknown technique ID
        ],
    )
    def test_error_paths_return_structured_failure(
        self,
        technique_dir: Path,
        technique_id: str,
        target_pod: str | None,
        expected_evidence_fragment: str,
    ) -> None:
        registry = TechniqueRegistry(config_dir=technique_dir)
        k8s = MagicMock()
        k8s.namespace = "demo"

        result = execute_technique(k8s, registry, technique_id, target_pod=target_pod)

        assert result.success is False
        assert any(expected_evidence_fragment in e for e in result.evidence)


class TestResolveProbeParams:
    @pytest.mark.parametrize(
        "template,params,namespace,expected_fragment",
        [
            (
                "nc -z {{ host }} {{ port }}",
                {"host": "redis", "port": "6379"},
                "demo",
                "nc -z redis 6379",
            ),
            ("echo {{ namespace }}", {}, "production", "echo production"),
            ("echo {{ unknown_param }}", {}, "demo", "{{ unknown_param }}"),  # unresolved stays
        ],
    )
    def test_template_substitution(
        self,
        template: str,
        params: dict,
        namespace: str,
        expected_fragment: str,
    ) -> None:
        probe = {"type": "command", "run": template}
        resolved = _resolve_probe_params(probe, params, namespace)
        assert expected_fragment in resolved["run"]

    def test_non_string_values_preserved(self) -> None:
        """Integer probe params must not become strings."""
        probe = {"type": "port_open", "port": 8080, "timeout": 3}
        resolved = _resolve_probe_params(probe, {}, "demo")
        assert resolved["port"] == 8080
