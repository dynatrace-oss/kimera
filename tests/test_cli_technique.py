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

"""Tests for the `kimera technique` command group."""

import json
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
import yaml
from click.testing import CliRunner, Result

from kimera.cli.technique import technique


@pytest.fixture
def technique_dir(tmp_path: Path) -> Path:
    """A two-technique registry, one per phase, with a parameterised probe."""
    tech_dir = tmp_path / "techniques"
    tech_dir.mkdir()
    (tech_dir / "registry.yaml").write_text(
        yaml.dump(
            {
                "techniques": {
                    "P1": {
                        "name": "Parameterised probe",
                        "file": "P1-param.yaml",
                        "phase": "credential-access",
                        "noise": "low",
                    },
                    "P2": {
                        "name": "Other phase",
                        "file": "P2-other.yaml",
                        "phase": "discovery",
                        "noise": "low",
                    },
                }
            }
        )
    )
    for tech_id, name in (("P1", "Parameterised probe"), ("P2", "Other phase")):
        (tech_dir / f"{tech_id}-{'param' if tech_id == 'P1' else 'other'}.yaml").write_text(
            yaml.dump(
                {
                    "id": tech_id,
                    "name": name,
                    "enabled": True,
                    "mitre": {"technique_id": "T1552", "tactic": "credential-access"},
                    "execution": {
                        "mode": "exec",
                        "probes": [{"type": "app_request", "url": "{{ url }}"}],
                        "evidence_markers": [{"marker": "FOUND", "evidence": "marker fired"}],
                    },
                    "success_indicators": ["FOUND"],
                }
            )
        )
    return tech_dir


def _invoke(args: list[str], technique_dir: Path, exec_output: str = "FOUND") -> Result:
    k8s = MagicMock()
    k8s.namespace = "demo"
    k8s.exec_in_pod.return_value = exec_output
    obj: dict[str, Any] = {"k8s": k8s, "logger": MagicMock()}
    with patch("kimera.cli.technique.TechniqueRegistry") as registry_cls:
        from kimera.core.technique_engine import TechniqueRegistry

        registry_cls.return_value = TechniqueRegistry(config_dir=technique_dir)
        result = CliRunner().invoke(technique, args, obj=obj)
    result.k8s = k8s  # type: ignore[attr-defined]
    return result


class TestTechniqueList:
    def test_lists_every_registered_technique(self, technique_dir: Path) -> None:
        result = _invoke(["list"], technique_dir)
        assert result.exit_code == 0
        assert "P1" in result.output
        assert "P2" in result.output

    def test_phase_filter_excludes_other_phases(self, technique_dir: Path) -> None:
        result = _invoke(["list", "--phase", "discovery"], technique_dir)
        assert result.exit_code == 0
        assert "P2" in result.output
        assert "P1" not in result.output


class TestTechniqueRun:
    def test_reports_evidence_on_success(self, technique_dir: Path) -> None:
        result = _invoke(["run", "P1", "--pod", "p", "--param", "url=http://x/"], technique_dir)
        assert result.exit_code == 0
        assert "marker fired" in result.output

    def test_unknown_id_exits_non_zero(self, technique_dir: Path) -> None:
        result = _invoke(["run", "NOPE", "--pod", "p"], technique_dir)
        assert result.exit_code != 0

    def test_parameter_substitutes_into_the_executed_probe(self, technique_dir: Path) -> None:
        result = _invoke(
            ["run", "P1", "--pod", "p", "--param", "url=http://target/path"], technique_dir
        )
        script = result.k8s.exec_in_pod.call_args.args[1]  # type: ignore[attr-defined]
        assert "http://target/path" in script
        assert "{{ url }}" not in script

    def test_every_parameter_is_forwarded(self, technique_dir: Path) -> None:
        with patch("kimera.cli.technique.execute_technique") as execute:
            execute.return_value = MagicMock(success=True, evidence=[], impact=[])
            _invoke(
                ["run", "P1", "--pod", "p", "--param", "url=u", "--param", "other=o"],
                technique_dir,
            )
        assert execute.call_args.kwargs["params"] == {"url": "u", "other": "o"}

    def test_malformed_parameter_is_rejected_and_nothing_runs(self, technique_dir: Path) -> None:
        # Dropping it silently would run the probe with an unresolved placeholder and
        # attribute the result to a target the operator never named.
        result = _invoke(["run", "P1", "--pod", "p", "--param", "no-equals-sign"], technique_dir)
        assert result.exit_code != 0
        result.k8s.exec_in_pod.assert_not_called()  # type: ignore[attr-defined]


class TestTechniqueDryRun:
    def test_dry_run_executes_nothing(self, technique_dir: Path) -> None:
        result = _invoke(
            ["run", "P1", "--pod", "p", "--param", "url=http://x/", "--dry-run"], technique_dir
        )
        assert result.exit_code == 0
        result.k8s.exec_in_pod.assert_not_called()  # type: ignore[attr-defined]

    def test_dry_run_reports_the_resolved_script(self, technique_dir: Path) -> None:
        result = _invoke(
            ["run", "P1", "--pod", "p", "--param", "url=http://resolved/", "--dry-run"],
            technique_dir,
        )
        assert "http://resolved/" in result.output
        assert "{{ url }}" not in result.output


class TestTechniqueJson:
    def test_json_output_carries_the_structured_result(self, technique_dir: Path) -> None:
        result = _invoke(
            ["run", "P1", "--pod", "p", "--param", "url=http://x/", "--json"], technique_dir
        )
        payload = json.loads(result.output)
        assert payload["technique_id"] == "P1"
        assert payload["success"] is True
        assert payload["evidence"] == ["marker fired"]
