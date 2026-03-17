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

"""Tests for the YAML test loader."""

from pathlib import Path

import yaml

from kimera.container.make_vulnerable.test_loader import load_exploit_tests


class TestLoadExploitTests:
    """Tests for the load_exploit_tests function."""

    def test_loads_from_yaml_with_probes(self, tmp_path: Path) -> None:
        """Test loading tests with structured probes from YAML."""
        yaml_content = {
            "tests": [
                {
                    "name": "Check access",
                    "probes": [
                        {"type": "writable", "path": "/sys"},
                        {"type": "path_exists", "path": "/dev/mem"},
                    ],
                    "evidence_markers": [
                        {
                            "marker": "VULNERABLE",
                            "evidence": "Found vuln",
                            "impact": "Bad",
                        }
                    ],
                }
            ],
            "summary_impact": ["Impact one", "Impact two"],
        }

        yaml_file = tmp_path / "test-exploit.yaml"
        yaml_file.write_text(yaml.dump(yaml_content))

        tests, summary = load_exploit_tests("test-exploit", config_dir=tmp_path)

        assert len(tests) == 1
        assert tests[0].name == "Check access"
        assert "/sys" in tests[0].script
        assert "/dev/mem" in tests[0].script
        assert len(tests[0].evidence_markers) == 1
        assert tests[0].evidence_markers[0].marker == "VULNERABLE"
        assert summary == ["Impact one", "Impact two"]

    def test_loads_from_yaml_with_script(self, tmp_path: Path) -> None:
        """Test loading tests with raw script field."""
        yaml_content = {
            "tests": [
                {
                    "name": "Raw script test",
                    "script": "echo hello\necho world",
                    "evidence_markers": [{"marker": "hello", "evidence": "Said hello"}],
                }
            ],
            "summary_impact": [],
        }

        yaml_file = tmp_path / "raw-test.yaml"
        yaml_file.write_text(yaml.dump(yaml_content))

        tests, _ = load_exploit_tests("raw-test", config_dir=tmp_path)

        assert len(tests) == 1
        assert "echo hello" in tests[0].script

    def test_missing_file_returns_empty(self, tmp_path: Path) -> None:
        """Test that a missing YAML file returns empty lists."""
        tests, summary = load_exploit_tests("nonexistent", config_dir=tmp_path)
        assert tests == []
        assert summary == []

    def test_skips_tests_without_probes_or_script(self, tmp_path: Path) -> None:
        """Test that tests with neither probes nor script are skipped."""
        yaml_content = {
            "tests": [
                {
                    "name": "Empty test",
                    "evidence_markers": [],
                }
            ],
            "summary_impact": [],
        }

        yaml_file = tmp_path / "empty-test.yaml"
        yaml_file.write_text(yaml.dump(yaml_content))

        tests, _ = load_exploit_tests("empty-test", config_dir=tmp_path)
        assert len(tests) == 0

    def test_marker_without_impact_defaults_empty(self, tmp_path: Path) -> None:
        """Test that markers without impact field default to empty string."""
        yaml_content = {
            "tests": [
                {
                    "name": "No impact",
                    "script": "echo test",
                    "evidence_markers": [{"marker": "test", "evidence": "Found test"}],
                }
            ],
            "summary_impact": [],
        }

        yaml_file = tmp_path / "no-impact.yaml"
        yaml_file.write_text(yaml.dump(yaml_content))

        tests, _ = load_exploit_tests("no-impact", config_dir=tmp_path)
        assert tests[0].evidence_markers[0].impact == ""

    def test_probes_take_precedence_over_script(self, tmp_path: Path) -> None:
        """Test that probes are used when both probes and script are present."""
        yaml_content = {
            "tests": [
                {
                    "name": "Both present",
                    "probes": [{"type": "writable", "path": "/test-path"}],
                    "script": "echo fallback",
                    "evidence_markers": [],
                }
            ],
            "summary_impact": [],
        }

        yaml_file = tmp_path / "both.yaml"
        yaml_file.write_text(yaml.dump(yaml_content))

        tests, _ = load_exploit_tests("both", config_dir=tmp_path)
        assert "/test-path" in tests[0].script
        assert "fallback" not in tests[0].script
