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
import inspect
import pkgutil
from typing import Any

from kimera.domain.interfaces import ExploitPlugin


class PluginRegistry:
    """Discover and manage exploit plugins.

    The registry discovers plugins in two ways:
    1. Automatic discovery from kimera.plugins package
    2. Manual registration via register() method

    Plugins must implement the ExploitPlugin protocol.
    """

    def __init__(self) -> None:
        """Initialize empty plugin registry."""
        self._plugins: dict[str, type[Any]] = {}
        self._initialized = False

    def discover(self) -> dict[str, type[Any]]:
        """Discover all available plugins.

        Searches the kimera.plugins package for classes
        that implement the ExploitPlugin protocol.

        Returns:
            Map of plugin names to plugin classes
        """
        if self._initialized:
            return self._plugins

        # Import plugins package
        try:
            import kimera.plugins as plugins_package
        except ImportError:
            # Plugins package doesn't exist yet
            return {}

        # Discover all modules in plugins package
        package_path = plugins_package.__path__
        for _, module_name, _ in pkgutil.iter_modules(package_path):
            # Import the module
            full_module_name = f"kimera.plugins.{module_name}"
            try:
                module = importlib.import_module(full_module_name)

                # Find all classes that implement ExploitPlugin
                for _name, obj in inspect.getmembers(module, inspect.isclass):
                    if self.validate(obj) and obj.__module__ == full_module_name:
                        # Get plugin name from metadata
                        instance = obj()
                        plugin_name = instance.metadata.name
                        self._plugins[plugin_name] = obj

            except Exception as e:
                import logging

                logging.getLogger(__name__).warning(
                    f"Failed to load plugin from {full_module_name}: {e}"
                )
                continue

        self._initialized = True
        return self._plugins

    def validate(self, plugin_class: type[Any]) -> bool:
        """Validate plugin implements required interface.

        Args:
            plugin_class: Plugin class to validate

        Returns:
            True if valid, False otherwise
        """
        # Check if implements ExploitPlugin protocol
        # Use isinstance check with Protocol for runtime validation
        try:
            instance = plugin_class()
            return isinstance(instance, ExploitPlugin)
        except Exception:
            return False

    def register(self, name: str, plugin_class: type[Any]) -> None:
        """Manually register a plugin.

        Args:
            name: Plugin name
            plugin_class: Plugin class

        Raises:
            ValueError: If plugin doesn't implement ExploitPlugin protocol
        """
        if not self.validate(plugin_class):
            raise ValueError(f"Plugin {name} does not implement ExploitPlugin protocol")

        self._plugins[name] = plugin_class

    def get(self, name: str) -> type[Any] | None:
        """Get plugin by name.

        Args:
            name: Plugin name

        Returns:
            Plugin class or None if not found
        """
        if not self._initialized:
            self.discover()

        return self._plugins.get(name)

    def list_plugins(self) -> dict[str, type[Any]]:
        """List all registered plugins.

        Returns:
            Map of plugin names to plugin classes
        """
        if not self._initialized:
            self.discover()

        return self._plugins.copy()

    def get_by_risk_level(self, risk_level: str) -> dict[str, type[Any]]:
        """Get plugins filtered by risk level.

        Args:
            risk_level: Risk level (CRITICAL, HIGH, MEDIUM, LOW)

        Returns:
            Filtered map of plugin names to plugin classes
        """
        if not self._initialized:
            self.discover()

        filtered = {}
        for name, plugin_class in self._plugins.items():
            instance = plugin_class()
            if instance.metadata.risk_level == risk_level:
                filtered[name] = plugin_class

        return filtered

    def get_enabled_plugins(self, config: Any) -> dict[str, type[Any]]:
        """Get plugins that are enabled in configuration.

        Args:
            config: Toolkit configuration

        Returns:
            Map of enabled plugin names to plugin classes
        """
        if not self._initialized:
            self.discover()

        enabled = {}
        for name, plugin_class in self._plugins.items():
            exploit_config = config.exploits.get(name)
            if exploit_config and exploit_config.enabled:
                enabled[name] = plugin_class

        return enabled
