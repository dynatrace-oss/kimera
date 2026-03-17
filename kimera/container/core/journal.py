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

"""Operation journal for tracking exploit actions.

Records what was applied and to which services so that ``kimera revert``
can undo everything without the user needing to remember individual commands.
"""

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

STATE_FILE = ".kimera-state.json"


def _state_path() -> Path:
    """Return path to the state file in the current working directory."""
    return Path.cwd() / STATE_FILE


def load_state() -> dict[str, Any]:
    """Load the current operation journal from disk."""
    path = _state_path()
    if not path.exists():
        return {"operations": []}
    try:
        data: dict[str, Any] = json.loads(path.read_text())
        return data
    except (json.JSONDecodeError, OSError):
        return {"operations": []}


def save_state(state: dict[str, Any]) -> None:
    """Persist the operation journal to disk."""
    _state_path().write_text(json.dumps(state, indent=2) + "\n")


def record_operation(
    action: str,
    exploit_type: str,
    service: str,
    namespace: str,
) -> None:
    """Record an exploit action in the journal.

    Args:
        action: One of ``"make_vulnerable"``, ``"make_secure"``.
        exploit_type: The exploit key (e.g. ``"privileged-containers"``).
        service: Target service name.
        namespace: Kubernetes namespace.
    """
    state = load_state()
    state["operations"].append(
        {
            "action": action,
            "exploit_type": exploit_type,
            "service": service,
            "namespace": namespace,
            "timestamp": datetime.now(tz=UTC).isoformat(),
        }
    )
    save_state(state)


def clear_operation(exploit_type: str, service: str, namespace: str) -> None:
    """Remove matching operations from the journal (after revert)."""
    state = load_state()
    state["operations"] = [
        op
        for op in state["operations"]
        if not (
            op["exploit_type"] == exploit_type
            and op["service"] == service
            and op["namespace"] == namespace
        )
    ]
    save_state(state)


def clear_all() -> None:
    """Remove the state file entirely."""
    path = _state_path()
    if path.exists():
        path.unlink()


def pending_operations(namespace: str | None = None) -> list[dict[str, Any]]:
    """Return operations that have not been reverted.

    Args:
        namespace: Optionally filter to a specific namespace.
    """
    state = load_state()
    ops: list[dict[str, Any]] = state.get("operations", [])
    if namespace:
        ops = [op for op in ops if op["namespace"] == namespace]
    return ops
