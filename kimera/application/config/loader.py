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

import os
from pathlib import Path
from typing import Any

import yaml
from pydantic import ValidationError

from .schemas import ToolkitConfig


class ConfigLoader:
    """Load and merge configuration from multiple sources.

    Merge order: default.yaml → profile.yaml → environment variables → CLI flags

    The loader follows these principles:
    - Start with sensible defaults from default.yaml
    - Override with profile-specific settings (dev, prod, training)
    - Override with environment variables (K8S_EXPLOIT_*)
    - Override with CLI flags (passed at runtime)
    """

    def __init__(self, config_dir: Path | None = None) -> None:
        """Initialize configuration loader.

        Args:
            config_dir: Directory containing config files. Defaults to ./config
        """
        if config_dir is None:
            # Default to config/ in project root
            self.config_dir = Path(__file__).parent.parent.parent.parent / "config"
        else:
            self.config_dir = Path(config_dir)

        if not self.config_dir.exists():
            raise FileNotFoundError(f"Config directory not found: {self.config_dir}")

    def load(
        self,
        profile: str | None = None,
        overrides: dict[str, Any] | None = None,
    ) -> ToolkitConfig:
        """Load configuration with optional profile and overrides.

        Args:
            profile: Profile name (development, production, training, None for default)
            overrides: Runtime overrides (typically from CLI flags)

        Returns:
            Validated configuration object

        Raises:
            FileNotFoundError: If config files not found
            ValidationError: If configuration validation fails
        """
        # Step 1: Load base configuration
        config_data = self._load_yaml(self.config_dir / "default.yaml")

        # Step 2: Merge profile if specified
        if profile:
            profile_path = self.config_dir / "profiles" / f"{profile}.yaml"
            if profile_path.exists():
                profile_data = self._load_yaml(profile_path)
                config_data = self._deep_merge(config_data, profile_data)
            else:
                raise FileNotFoundError(f"Profile configuration not found: {profile_path}")

        # Step 3: Apply environment variable overrides
        env_overrides = self._load_env_vars()
        config_data = self._deep_merge(config_data, env_overrides)

        # Step 4: Apply runtime overrides
        if overrides:
            config_data = self._deep_merge(config_data, overrides)

        # Step 5: Validate and return
        try:
            return ToolkitConfig(**config_data)
        except ValidationError as e:
            raise ValueError(f"Configuration validation failed: {e}") from e

    def _load_yaml(self, path: Path) -> dict[str, Any]:
        """Load YAML configuration file.

        Args:
            path: Path to YAML file

        Returns:
            Parsed YAML data

        Raises:
            FileNotFoundError: If file doesn't exist
        """
        if not path.exists():
            raise FileNotFoundError(f"Configuration file not found: {path}")

        with open(path) as f:
            data = yaml.safe_load(f)

        return data if data else {}

    def _load_env_vars(self) -> dict[str, Any]:
        """Load configuration from environment variables.

        Environment variables follow the pattern:
        - K8S_EXPLOIT_NAMESPACE -> kubernetes.namespace
        - K8S_EXPLOIT_DRY_RUN -> dry_run
        - K8S_EXPLOIT_DEBUG -> debug
        - K8S_EXPLOIT_VERBOSE -> verbose
        - K8S_EXPLOIT_TIMEOUT_OPERATION -> timeouts.operation
        - K8S_EXPLOIT_LOG_LEVEL -> logging.level

        Returns:
            Configuration overrides from environment
        """
        env_mappings = {
            "K8S_EXPLOIT_NAMESPACE": ("kubernetes", "namespace"),
            "K8S_EXPLOIT_CONTEXT": ("kubernetes", "context"),
            "K8S_EXPLOIT_KUBECONFIG": ("kubernetes", "kubeconfig_path"),
            "K8S_EXPLOIT_DRY_RUN": ("dry_run",),
            "K8S_EXPLOIT_DEBUG": ("debug",),
            "K8S_EXPLOIT_VERBOSE": ("verbose",),
            "K8S_EXPLOIT_TIMEOUT_OPERATION": ("timeouts", "operation"),
            "K8S_EXPLOIT_TIMEOUT_ROLLOUT": ("timeouts", "rollout"),
            "K8S_EXPLOIT_TIMEOUT_STREAM": ("timeouts", "stream"),
            "K8S_EXPLOIT_TIMEOUT_COMMAND": ("timeouts", "command"),
            "K8S_EXPLOIT_LOG_LEVEL": ("logging", "level"),
            "K8S_EXPLOIT_LOG_FILE": ("logging", "file"),
        }

        config: dict[str, Any] = {}

        for env_var, path in env_mappings.items():
            raw_value = os.getenv(env_var)
            if raw_value is not None:
                # Convert string values to appropriate types
                parsed_value: Any
                if env_var.endswith(("DRY_RUN", "DEBUG", "VERBOSE")):
                    parsed_value = raw_value.lower() in ("true", "1", "yes")
                elif env_var.startswith("K8S_EXPLOIT_TIMEOUT"):
                    parsed_value = int(raw_value)
                else:
                    parsed_value = raw_value

                # Build nested structure
                current = config
                for key in path[:-1]:
                    if key not in current:
                        current[key] = {}
                    current = current[key]
                current[path[-1]] = parsed_value

        return config

    def _deep_merge(self, base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
        """Deep merge two dictionaries.

        Args:
            base: Base dictionary
            override: Override dictionary

        Returns:
            Merged dictionary
        """
        result = base.copy()

        for key, value in override.items():
            if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                result[key] = self._deep_merge(result[key], value)
            else:
                result[key] = value

        return result

    def load_exploit_configs(self) -> dict[str, dict[str, Any]]:
        """Load exploit configuration files.

        Returns:
            dictionary of exploit configurations
        """
        exploits_dir = self.config_dir / "exploits"
        if not exploits_dir.exists():
            return {}

        exploits = {}
        for exploit_file in exploits_dir.glob("*.yaml"):
            exploit_data = self._load_yaml(exploit_file)
            exploit_name = exploit_file.stem
            exploits[exploit_name] = exploit_data

        return exploits

    @staticmethod
    def from_env() -> ToolkitConfig:
        """Create configuration from environment variables only.

        Returns:
            Configuration with defaults + environment overrides
        """
        loader = ConfigLoader()
        return loader.load()

    @staticmethod
    def from_profile(profile: str) -> ToolkitConfig:
        """Create configuration from specific profile.

        Args:
            profile: Profile name (development, production, training)

        Returns:
            Configuration with profile settings
        """
        loader = ConfigLoader()
        return loader.load(profile=profile)
