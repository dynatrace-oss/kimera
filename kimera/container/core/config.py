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
from dataclasses import dataclass, field
from pathlib import Path
from typing import Self

import yaml


@dataclass
class ExploitConfig:
    """Configuration for a single exploit."""

    name: str
    service: str
    risk_level: str
    description: str
    vulnerability_type: str


@dataclass
class Config:
    """Main configuration class."""

    namespace: str = "unguard"
    timeout: int = 300
    dry_run: bool = False
    debug: bool = False
    verbose: bool = False

    # Service names
    services: list[str] = field(
        default_factory=lambda: [
            "unguard-payment-service",
            "unguard-profile-service",
            "unguard-frontend",
            "unguard-membership-service",
            "unguard-user-auth-service",
            "unguard-ad-service",
            "unguard-proxy-service",
        ]
    )

    # Exploit mappings
    exploit_mappings: dict[str, str] = field(
        default_factory=lambda: {
            "privileged-containers": "unguard-payment-service",
            "dangerous-capabilities": "unguard-profile-service",
            "host-namespace-sharing": "unguard-frontend",
            "missing-resource-limits": "unguard-membership-service",
            "missing-network-policies": "unguard-ad-service",
        }
    )

    @classmethod
    def from_env(cls) -> Self:
        """Create config from environment variables."""
        return cls(
            namespace=os.getenv("K8S_NAMESPACE", "unguard"),
            timeout=int(os.getenv("K8S_TIMEOUT", "300")),
            dry_run=os.getenv("DRY_RUN", "false").lower() == "true",
            debug=os.getenv("DEBUG", "false").lower() == "true",
            verbose=os.getenv("VERBOSE", "false").lower() == "true",
        )

    @classmethod
    def from_file(cls, path: Path) -> Self:
        """Load config from YAML file."""
        with open(path) as f:
            data = yaml.safe_load(f)

        required_keys = ["namespace", "timeout", "services", "exploit_mappings"]
        for key in required_keys:
            if key not in data:
                raise ValueError(f"Missing required key in config: {key}")

        return cls(**data)
