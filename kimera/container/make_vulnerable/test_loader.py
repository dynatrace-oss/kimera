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

"""Load SecurityTest definitions from exploit YAML configuration files.

Each file in ``config/exploits/`` can contain a ``tests`` section with
structured probe definitions and evidence markers. This module parses
that section into ``SecurityTest`` objects used by ``BaseExploit._run_tests()``.
"""

from pathlib import Path
from typing import Any

import yaml

from ...domain.models import EvidenceMarker, SecurityTest
from .probe_runner import ProbeRunner

_runner = ProbeRunner()

# Resolve config directory relative to project root
_CONFIG_DIR = Path(__file__).resolve().parents[3] / "config" / "exploits"


def load_exploit_tests(
    exploit_type: str,
    config_dir: Path | None = None,
) -> tuple[list[SecurityTest], list[str]]:
    """Load SecurityTest definitions and summary_impact from exploit YAML.

    Args:
        exploit_type: Exploit identifier matching the YAML filename
            (e.g., ``"privileged-containers"``).
        config_dir: Override for the config/exploits directory (used in tests).

    Returns:
        Tuple of (list of SecurityTest, list of summary impact strings).
    """
    base = config_dir or _CONFIG_DIR
    path = base / f"{exploit_type}.yaml"

    if not path.exists():
        return [], []

    with open(path) as f:
        data: dict[str, Any] = yaml.safe_load(f) or {}

    tests = _parse_tests(data.get("tests", []))
    summary_impact: list[str] = data.get("summary_impact", [])

    return tests, summary_impact


def _parse_tests(raw_tests: list[dict[str, Any]]) -> list[SecurityTest]:
    """Convert raw YAML test dicts into SecurityTest objects."""
    tests: list[SecurityTest] = []

    for raw in raw_tests:
        # Build script from probes or use raw script field
        probes = raw.get("probes", [])
        script = raw.get("script", "")

        if probes:
            script = _runner.build_script(probes)
        elif not script:
            continue  # skip tests with no probes and no script

        markers = [
            EvidenceMarker(
                marker=m["marker"],
                evidence=m["evidence"],
                impact=m.get("impact", ""),
            )
            for m in raw.get("evidence_markers", [])
        ]

        tests.append(
            SecurityTest(
                name=raw.get("name", "Unnamed test"),
                script=script,
                evidence_markers=markers,
            )
        )

    return tests
