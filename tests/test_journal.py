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
from pathlib import Path
from unittest.mock import patch

from kimera.container.core.journal import (
    clear_all,
    clear_operation,
    load_state,
    pending_operations,
    record_operation,
    save_state,
)


class TestJournal:
    """Test operation journal for tracking exploit actions."""

    def _patch_state_path(self, tmp_path: Path):  # type: ignore[no-untyped-def]
        """Helper to redirect state file to tmp_path."""
        return patch(
            "kimera.container.core.journal._state_path",
            return_value=tmp_path / ".kimera-state.json",
        )

    def test_load_empty_state(self, tmp_path: Path) -> None:
        """Test loading state when no file exists."""
        with self._patch_state_path(tmp_path):
            state = load_state()
        assert state == {"operations": []}

    def test_save_and_load_state(self, tmp_path: Path) -> None:
        """Test round-trip save and load."""
        with self._patch_state_path(tmp_path):
            save_state({"operations": [{"action": "test"}]})
            state = load_state()
        assert len(state["operations"]) == 1
        assert state["operations"][0]["action"] == "test"

    def test_record_operation(self, tmp_path: Path) -> None:
        """Test recording an exploit operation."""
        with self._patch_state_path(tmp_path):
            record_operation("make_vulnerable", "privileged-containers", "svc-a", "ns-1")
            ops = pending_operations()

        assert len(ops) == 1
        assert ops[0]["action"] == "make_vulnerable"
        assert ops[0]["exploit_type"] == "privileged-containers"
        assert ops[0]["service"] == "svc-a"
        assert ops[0]["namespace"] == "ns-1"
        assert "timestamp" in ops[0]

    def test_record_multiple_operations(self, tmp_path: Path) -> None:
        """Test recording multiple operations appends to the list."""
        with self._patch_state_path(tmp_path):
            record_operation("make_vulnerable", "privileged-containers", "svc-a", "ns-1")
            record_operation("make_secure", "dangerous-capabilities", "svc-b", "ns-1")
            ops = pending_operations()

        assert len(ops) == 2

    def test_clear_operation(self, tmp_path: Path) -> None:
        """Test clearing a specific operation."""
        with self._patch_state_path(tmp_path):
            record_operation("make_vulnerable", "privileged-containers", "svc-a", "ns-1")
            record_operation("make_secure", "dangerous-capabilities", "svc-b", "ns-1")
            clear_operation("privileged-containers", "svc-a", "ns-1")
            ops = pending_operations()

        assert len(ops) == 1
        assert ops[0]["exploit_type"] == "dangerous-capabilities"

    def test_clear_all(self, tmp_path: Path) -> None:
        """Test clearing all operations removes the state file."""
        with self._patch_state_path(tmp_path):
            record_operation("make_vulnerable", "privileged-containers", "svc-a", "ns-1")
            clear_all()
            state_file = tmp_path / ".kimera-state.json"
            assert not state_file.exists()

    def test_pending_operations_filters_by_namespace(self, tmp_path: Path) -> None:
        """Test filtering operations by namespace."""
        with self._patch_state_path(tmp_path):
            record_operation("make_vulnerable", "privileged-containers", "svc-a", "ns-1")
            record_operation("make_vulnerable", "dangerous-capabilities", "svc-b", "ns-2")
            ops = pending_operations(namespace="ns-1")

        assert len(ops) == 1
        assert ops[0]["namespace"] == "ns-1"

    def test_load_corrupt_state_returns_empty(self, tmp_path: Path) -> None:
        """Test that a corrupt state file returns empty state."""
        state_file = tmp_path / ".kimera-state.json"
        state_file.write_text("not valid json{{{")
        with self._patch_state_path(tmp_path):
            state = load_state()
        assert state == {"operations": []}

    def test_state_file_is_valid_json(self, tmp_path: Path) -> None:
        """Test that the saved state file is valid JSON."""
        with self._patch_state_path(tmp_path):
            record_operation("make_vulnerable", "test", "svc", "ns")
            state_file = tmp_path / ".kimera-state.json"
            data = json.loads(state_file.read_text())
        assert "operations" in data
