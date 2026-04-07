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
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest
import yaml

from kimera.application.config.loader import ConfigLoader
from kimera.application.config.schemas import ToolkitConfig


class TestToolkitConfig:
    """Test ToolkitConfig Pydantic model."""

    def test_default_values(self):
        """Test ToolkitConfig with default values."""
        config = ToolkitConfig()

        assert config.namespace == "default"
        assert config.kubernetes.namespace == "default"
        assert config.services == []
        assert config.exploit_mappings == {}
        assert config.dry_run is False
        assert config.debug is False
        assert config.verbose is False

    def test_namespace_property(self):
        """Test namespace property delegates to kubernetes.namespace."""
        from kimera.application.config.schemas import KubernetesConfig

        config = ToolkitConfig(kubernetes=KubernetesConfig(namespace="my-ns"))
        assert config.namespace == "my-ns"

    def test_custom_values(self):
        """Test ToolkitConfig with custom values."""
        config = ToolkitConfig(
            services=["svc-a", "svc-b"],
            exploit_mappings={"privileged-containers": "svc-a"},
            dry_run=True,
            debug=True,
            verbose=True,
        )

        assert config.services == ["svc-a", "svc-b"]
        assert config.exploit_mappings["privileged-containers"] == "svc-a"
        assert config.dry_run is True
        assert config.debug is True
        assert config.verbose is True

    def test_empty_services_allowed(self):
        """Test that an empty services list is valid."""
        config = ToolkitConfig(services=[])
        assert config.services == []

    def test_secure_defaults(self):
        """Test secure defaults have expected values."""
        config = ToolkitConfig()
        assert config.secure_defaults.memory == "256Mi"
        assert config.secure_defaults.cpu == "200m"
        assert config.secure_requests.memory == "128Mi"
        assert config.secure_requests.cpu == "100m"

    def test_timeout_defaults(self):
        """Test timeout defaults are set."""
        config = ToolkitConfig()
        assert config.timeouts.operation == 300
        assert config.timeouts.rollout == 120


class TestConfigLoader:
    """Test ConfigLoader with profiles and overrides."""

    def test_load_default_config(self):
        """Test loading default.yaml produces an application-agnostic config."""
        loader = ConfigLoader()
        config = loader.load()

        assert config.namespace == "default"
        assert config.services == []
        assert config.exploit_mappings == {}

    def test_load_unguard_profile(self):
        """Test loading the unguard profile provides Unguard services."""
        loader = ConfigLoader()
        config = loader.load(profile="unguard")

        assert config.namespace == "unguard"
        assert len(config.services) == 7
        assert "unguard-payment-service" in config.services
        assert len(config.exploit_mappings) == 5
        assert config.exploit_mappings["privileged-containers"] == "unguard-payment-service"

    def test_load_with_overrides(self):
        """Test overrides take precedence."""
        loader = ConfigLoader()
        config = loader.load(overrides={"dry_run": True, "kubernetes": {"namespace": "custom"}})

        assert config.dry_run is True
        assert config.namespace == "custom"

    def test_load_nonexistent_profile_raises(self):
        """Test loading a missing profile raises FileNotFoundError."""
        loader = ConfigLoader()
        with pytest.raises(FileNotFoundError, match="Profile configuration not found"):
            loader.load(profile="nonexistent")

    def test_env_var_overrides(self):
        """Test environment variable overrides."""
        env_vars = {
            "K8S_EXPLOIT_NAMESPACE": "env-namespace",
            "K8S_EXPLOIT_DRY_RUN": "true",
            "K8S_EXPLOIT_DEBUG": "1",
        }

        with patch.dict(os.environ, env_vars, clear=False):
            loader = ConfigLoader()
            config = loader.load()

        assert config.namespace == "env-namespace"
        assert config.dry_run is True
        assert config.debug is True

    def test_deep_merge(self):
        """Test deep merge of config dictionaries."""
        loader = ConfigLoader()
        base = {"kubernetes": {"namespace": "a", "context": "ctx"}, "dry_run": False}
        override = {"kubernetes": {"namespace": "b"}, "verbose": True}

        result = loader._deep_merge(base, override)
        assert result["kubernetes"]["namespace"] == "b"
        assert result["kubernetes"]["context"] == "ctx"
        assert result["verbose"] is True


class TestConfigLoaderFromFile:
    """Test ConfigLoader with custom config files."""

    def test_from_file(self):
        """Test loading config from a custom YAML file."""
        config_data = {
            "kubernetes": {"namespace": "test-ns"},
            "services": ["svc-1", "svc-2"],
            "exploit_mappings": {"privileged-containers": "svc-1"},
        }

        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "default.yaml"
            with open(config_path, "w") as f:
                yaml.safe_dump(config_data, f)

            loader = ConfigLoader(config_dir=Path(tmpdir))
            config = loader.load()

        assert config.namespace == "test-ns"
        assert config.services == ["svc-1", "svc-2"]
        assert config.exploit_mappings == {"privileged-containers": "svc-1"}

    def test_nonexistent_config_dir_raises(self):
        """Test that a nonexistent config directory raises."""
        with pytest.raises(FileNotFoundError, match="Config directory not found"):
            ConfigLoader(config_dir=Path("/nonexistent/path"))
