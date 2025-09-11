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

from k8s_exploit_toolkit.container.core.config import Config, ExploitConfig


class TestExploitConfig:
    """Test ExploitConfig dataclass functionality."""

    def test_exploit_config_creation(self):
        """Test ExploitConfig dataclass creation."""
        config = ExploitConfig(
            name="test-exploit",
            service="test-service",
            risk_level="high",
            description="Test exploit for testing",
            vulnerability_type="privileged",
        )

        assert config.name == "test-exploit"
        assert config.service == "test-service"
        assert config.risk_level == "high"
        assert config.description == "Test exploit for testing"
        assert config.vulnerability_type == "privileged"


class TestConfig:
    """Test Config dataclass functionality."""

    def test_config_defaults(self):
        """Test Config dataclass with default values."""
        config = Config()

        assert config.namespace == "unguard"
        assert config.timeout == 300
        assert config.dry_run is False
        assert config.debug is False
        assert config.verbose is False
        assert len(config.services) == 7
        assert "unguard-payment-service" in config.services
        assert len(config.exploit_mappings) == 4
        assert config.exploit_mappings["privileged-containers"] == "unguard-payment-service"

    def test_config_custom_values(self):
        """Test Config with custom values."""
        config = Config(namespace="custom-ns", timeout=600, dry_run=True, debug=True, verbose=True)

        assert config.namespace == "custom-ns"
        assert config.timeout == 600
        assert config.dry_run is True
        assert config.debug is True
        assert config.verbose is True

    def test_config_from_env_defaults(self):
        """Test Config.from_env() with default environment."""
        with patch.dict(os.environ, {}, clear=True):
            config = Config.from_env()

        assert config.namespace == "unguard"
        assert config.timeout == 300
        assert config.dry_run is False
        assert config.debug is False
        assert config.verbose is False

    def test_config_from_env_custom(self):
        """Test Config.from_env() with custom environment variables."""
        env_vars = {
            "K8S_NAMESPACE": "test-namespace",
            "K8S_TIMEOUT": "600",
            "DRY_RUN": "true",
            "DEBUG": "TRUE",
            "VERBOSE": "True",
        }

        with patch.dict(os.environ, env_vars, clear=True):
            config = Config.from_env()

        assert config.namespace == "test-namespace"
        assert config.timeout == 600
        assert config.dry_run is True
        assert config.debug is True
        assert config.verbose is True

    def test_config_from_env_false_values(self):
        """Test Config.from_env() with false boolean values."""
        env_vars = {"DRY_RUN": "false", "DEBUG": "FALSE", "VERBOSE": "False"}

        with patch.dict(os.environ, env_vars, clear=True):
            config = Config.from_env()

        assert config.dry_run is False
        assert config.debug is False
        assert config.verbose is False

    def test_config_from_file_valid(self):
        """Test Config.from_file() with valid YAML file."""
        config_data = {
            "namespace": "test-ns",
            "timeout": 600,
            "services": ["service1", "service2"],
            "exploit_mappings": {"exploit1": "service1"},
        }

        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            yaml.safe_dump(config_data, f)
            temp_path = Path(f.name)

        try:
            config = Config.from_file(temp_path)

            assert config.namespace == "test-ns"
            assert config.timeout == 600
            assert config.services == ["service1", "service2"]
            assert config.exploit_mappings == {"exploit1": "service1"}
        finally:
            temp_path.unlink()

    def test_config_from_file_missing_keys(self):
        """Test Config.from_file() with missing required keys."""
        config_data = {
            "namespace": "test-ns",
            # Missing timeout, services, exploit_mappings
        }

        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            yaml.safe_dump(config_data, f)
            temp_path = Path(f.name)

        try:
            with pytest.raises(ValueError, match="Missing required key in config: timeout"):
                Config.from_file(temp_path)
        finally:
            temp_path.unlink()

    def test_config_from_file_nonexistent(self):
        """Test Config.from_file() with nonexistent file."""
        with pytest.raises(FileNotFoundError):
            Config.from_file(Path("/nonexistent/path.yaml"))
