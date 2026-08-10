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
from pydantic import ValidationError

from kimera.application.config.loader import ConfigLoader
from kimera.application.config.schemas import (
    ExternalEgressDestination,
    NetworkTopologyEntry,
    ToolkitConfig,
)
from kimera.cli import _load_config
from kimera.resources import config_dir


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
        assert config.timeouts.rollout == 120
        assert config.timeouts.stream == 1
        assert config.timeouts.command == 60


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


class TestNetworkTopologyEntry:
    """Ingress/egress declarations in network_topology."""

    def test_external_egress_destination_loads_with_except_alias(self):
        """The YAML key `except` populates except_, which is a reserved word in Python."""
        entry = NetworkTopologyEntry.model_validate(
            {
                "allowed_egress_to": [
                    {
                        "cidr": "0.0.0.0/0",
                        "except": ["10.0.0.0/8", "169.254.169.254/32"],
                        "ports": [443],
                        "protocol": "TCP",
                    }
                ]
            }
        )

        dest = entry.allowed_egress_to[0]
        assert str(dest.cidr) == "0.0.0.0/0"
        assert [str(n) for n in dest.except_] == ["10.0.0.0/8", "169.254.169.254/32"]
        assert dest.ports == [443]
        assert dest.protocol == "TCP"

    @pytest.mark.parametrize(
        "field,value",
        [
            ("cidr", "not-a-cidr"),
            ("except", ["not-a-cidr"]),
            ("ports", []),
            ("ports", [70000]),
            ("ports", [0]),
            ("protocol", "ICMP"),
        ],
    )
    def test_malformed_destination_rejected(self, field, value):
        """A malformed destination fails validation naming the offending field."""
        payload = {"cidr": "0.0.0.0/0", "ports": [443], "protocol": "TCP"}
        payload[field] = value

        with pytest.raises(ValidationError) as exc:
            ExternalEgressDestination.model_validate(payload)

        assert field in str(exc.value)

    def test_undeclared_ingress_is_none_not_empty_list(self):
        """None (undeclared) and [] (block all ingress) must stay distinguishable."""
        undeclared = NetworkTopologyEntry.model_validate({"allowed_egress_to": []})
        blocked = NetworkTopologyEntry.model_validate({"allowed_ingress_from": []})

        assert undeclared.allowed_ingress_from is None
        assert blocked.allowed_ingress_from == []

    def test_shipped_profiles_load_with_unchanged_ingress(self):
        """Changing the ingress default to None must not alter any shipped profile."""
        profiles = sorted((config_dir() / "profiles").glob("*.yaml"))
        assert profiles, "no profiles shipped; this guard checks nothing"
        for profile_path in profiles:
            raw = yaml.safe_load(profile_path.read_text())
            config = ConfigLoader().load(profile=profile_path.stem)

            for workload, entry in (raw.get("network_topology") or {}).items():
                expected = entry.get("allowed_ingress_from")
                actual = config.network_topology[workload].allowed_ingress_from
                assert actual == expected, f"{profile_path.name}:{workload}"


class TestProfileAutoDetection:
    """A namespace loads the profile named after it, if one is shipped."""

    def test_namespace_with_a_profile_file_loads_it(self) -> None:
        # Previously this was `namespace == "unguard"` hardcoded in the CLI, so the
        # behaviour existed for exactly one application and was invisible elsewhere.
        shipped = [p.stem for p in (config_dir() / "profiles").glob("*.yaml")]
        assert shipped, "no profiles shipped; this guard checks nothing"
        for name in shipped:
            config = _load_config(name, None, False, False, False)
            assert config.kubernetes.namespace == name

    def test_namespace_without_a_profile_file_loads_defaults(self) -> None:
        config = _load_config("no-such-namespace-here", None, False, False, False)
        assert config.kubernetes.namespace == "no-such-namespace-here"

    def test_explicit_profile_wins_over_the_namespace_name(self) -> None:
        shipped = [p.stem for p in (config_dir() / "profiles").glob("*.yaml")]
        config = _load_config("some-other-namespace", shipped[0], False, False, False)
        assert config.kubernetes.namespace == "some-other-namespace"
