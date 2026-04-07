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

import importlib
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

_REGISTRY_PATH = (
    Path(__file__).parent.parent.parent.parent / "config" / "exploits" / "registry.yaml"
)


@dataclass(frozen=True)
class ExploitEntry:
    """A registered exploit type with its class and revert strategy."""

    name: str
    cls: type[Any]
    revert_strategy: str


def _import_class(dotted_path: str) -> type[Any]:
    """Import a class from a dotted module path.

    Args:
        dotted_path: Fully qualified class path (e.g. ``kimera.container.foo.Bar``).

    Returns:
        The class object.
    """
    module_path, class_name = dotted_path.rsplit(".", 1)
    module = importlib.import_module(module_path)
    cls: type[Any] = getattr(module, class_name)
    return cls


class ExploitRegistry:
    """Loads exploit type definitions from a YAML registry file.

    Provides consistent type names across all CLI commands and maps each
    type to its implementing class and revert strategy.
    """

    def __init__(self, path: Path | None = None) -> None:
        """Load the registry from YAML.

        Args:
            path: Path to the registry YAML file. Uses the default
                ``config/exploits/registry.yaml`` if not specified.
        """
        self._entries: dict[str, ExploitEntry] = {}
        self._load(path or _REGISTRY_PATH)

    def _load(self, path: Path) -> None:
        """Parse the registry YAML and import exploit classes."""
        data = yaml.safe_load(path.read_text())
        for name, entry in data.get("exploits", {}).items():
            cls = _import_class(entry["class"])
            self._entries[name] = ExploitEntry(
                name=name,
                cls=cls,
                revert_strategy=entry.get("revert_strategy", "rollback"),
            )

    def get(self, name: str) -> ExploitEntry | None:
        """Look up an exploit entry by type name."""
        return self._entries.get(name)

    @property
    def types(self) -> list[str]:
        """Return all registered exploit type names."""
        return list(self._entries.keys())

    @property
    def classes(self) -> dict[str, type[Any]]:
        """Return a mapping of type name to exploit class."""
        return {name: entry.cls for name, entry in self._entries.items()}

    def __contains__(self, name: str) -> bool:  # noqa: D105
        return name in self._entries

    def __getitem__(self, name: str) -> ExploitEntry:  # noqa: D105
        return self._entries[name]

    def __iter__(self) -> Any:  # noqa: D105
        return iter(self._entries)

    def __len__(self) -> int:  # noqa: D105
        return len(self._entries)
