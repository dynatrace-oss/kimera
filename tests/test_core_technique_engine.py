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

"""Tests for config-driven technique engine."""

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
    """Create a minimal technique registry and one technique for testing."""
    tech_dir = tmp_path / "techniques"
    tech_dir.mkdir()

    # Registry
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

    # Technique definition
    technique = {
        "id": "T1",
        "name": "Test technique",
        "enabled": True,
        "severity": "high",
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
        "impact": ["Test impact description"],
    }
    (tech_dir / "T1-test.yaml").write_text(yaml.dump(technique))

    return tech_dir


class TestTechniqueRegistry:
    def test_loads_techniques_from_directory(self, technique_dir: Path) -> None:
        registry = TechniqueRegistry(config_dir=technique_dir)
        assert registry.technique_count == 1  # T2 file is missing, so only T1 loads
        assert "T1" in registry

    def test_missing_file_skipped(self, technique_dir: Path) -> None:
        registry = TechniqueRegistry(config_dir=technique_dir)
        assert "T2" not in registry

    def test_list_techniques_returns_metadata(self, technique_dir: Path) -> None:
        registry = TechniqueRegistry(config_dir=technique_dir)
        techniques = registry.list_techniques()
        assert len(techniques) == 1
        assert techniques[0]["id"] == "T1"
        assert techniques[0]["phase"] == "credential-access"
        assert techniques[0]["mitre_id"] == "T1552.007"

    def test_list_by_phase(self, technique_dir: Path) -> None:
        registry = TechniqueRegistry(config_dir=technique_dir)
        cred_techs = registry.list_by_phase("credential-access")
        assert "T1" in cred_techs
        assert registry.list_by_phase("lateral-movement") == []

    def test_reload_picks_up_new_files(self, technique_dir: Path) -> None:
        registry = TechniqueRegistry(config_dir=technique_dir)
        assert registry.technique_count == 1

        # Add T2 file
        technique2 = {
            "id": "T2",
            "name": "Second technique",
            "enabled": True,
            "mitre": {"technique_id": "T1046", "tactic": "discovery"},
            "execution": {"mode": "api"},
        }
        (technique_dir / "T2-missing.yaml").write_text(yaml.dump(technique2))
        registry.reload()
        assert registry.technique_count == 2
        assert "T2" in registry

    def test_get_returns_definition(self, technique_dir: Path) -> None:
        registry = TechniqueRegistry(config_dir=technique_dir)
        tech = registry.get("T1")
        assert tech is not None
        assert tech.name == "Test technique"
        assert tech.mitre_id == "T1552.007"
        assert tech.mode == "exec"
        assert len(tech.probes) == 1

    def test_get_unknown_returns_none(self, technique_dir: Path) -> None:
        registry = TechniqueRegistry(config_dir=technique_dir)
        assert registry.get("NONEXISTENT") is None

    def test_empty_directory(self, tmp_path: Path) -> None:
        empty_dir = tmp_path / "empty"
        empty_dir.mkdir()
        registry = TechniqueRegistry(config_dir=empty_dir)
        assert registry.technique_count == 0

    def test_loads_real_registry(self) -> None:
        """Verify the actual config/techniques/registry.yaml loads correctly."""
        registry = TechniqueRegistry()
        assert registry.technique_count >= 5, (
            f"Expected at least 5 techniques, got {registry.technique_count}"
        )
        techniques = registry.list_techniques()
        ids = {t["id"] for t in techniques}
        assert "C1" in ids, "SA token theft technique should be registered"
        assert "C5" in ids, "Cloud metadata SSRF technique should be registered"
        assert "L1" in ids, "Network probe technique should be registered"


class TestExecuteTechnique:
    def test_exec_mode_success(self, technique_dir: Path) -> None:
        registry = TechniqueRegistry(config_dir=technique_dir)
        k8s = MagicMock()
        k8s.namespace = "demo"
        k8s.exec_in_pod.return_value = 'TEST_MARKER:found\nsome output'

        result = execute_technique(k8s, registry, "T1", target_pod="test-pod")

        assert result.success is True
        assert result.technique_id == "T1"
        assert result.mitre_id == "T1552.007"
        assert any("Test evidence" in e for e in result.evidence)
        k8s.exec_in_pod.assert_called_once()

    def test_exec_mode_no_match(self, technique_dir: Path) -> None:
        registry = TechniqueRegistry(config_dir=technique_dir)
        k8s = MagicMock()
        k8s.namespace = "demo"
        k8s.exec_in_pod.return_value = "nothing interesting"

        result = execute_technique(k8s, registry, "T1", target_pod="test-pod")

        assert result.success is False
        assert result.evidence == []

    def test_exec_fails_gracefully(self, technique_dir: Path) -> None:
        registry = TechniqueRegistry(config_dir=technique_dir)
        k8s = MagicMock()
        k8s.namespace = "demo"
        k8s.exec_in_pod.side_effect = Exception("Connection refused")

        result = execute_technique(k8s, registry, "T1", target_pod="test-pod")

        assert result.success is False
        assert any("Exec failed" in e for e in result.evidence)

    def test_missing_target_pod(self, technique_dir: Path) -> None:
        registry = TechniqueRegistry(config_dir=technique_dir)
        k8s = MagicMock()
        k8s.namespace = "demo"

        result = execute_technique(k8s, registry, "T1", target_pod=None)

        assert result.success is False
        assert any("No target pod" in e for e in result.evidence)

    def test_unknown_technique_id(self, technique_dir: Path) -> None:
        registry = TechniqueRegistry(config_dir=technique_dir)
        k8s = MagicMock()
        k8s.namespace = "demo"

        result = execute_technique(k8s, registry, "NONEXISTENT", target_pod="pod")

        assert result.success is False
        assert any("not found" in e for e in result.evidence)


class TestResolveProbeParams:
    def test_substitutes_parameters(self) -> None:
        probe = {"type": "command", "run": "nc -z {{ host }} {{ port }}"}
        params = {"host": "redis", "port": "6379"}
        resolved = _resolve_probe_params(probe, params, "demo")
        assert resolved["run"] == "nc -z redis 6379"

    def test_substitutes_namespace(self) -> None:
        probe = {"type": "command", "run": "echo {{ namespace }}"}
        resolved = _resolve_probe_params(probe, {}, "production")
        assert resolved["run"] == "echo production"

    def test_preserves_non_string_values(self) -> None:
        probe = {"type": "port_open", "port": 8080, "timeout": 3}
        resolved = _resolve_probe_params(probe, {}, "demo")
        assert resolved["port"] == 8080
        assert resolved["timeout"] == 3

    def test_unresolved_placeholder_left_intact(self) -> None:
        probe = {"type": "command", "run": "echo {{ unknown_param }}"}
        resolved = _resolve_probe_params(probe, {}, "demo")
        assert "{{ unknown_param }}" in resolved["run"]
