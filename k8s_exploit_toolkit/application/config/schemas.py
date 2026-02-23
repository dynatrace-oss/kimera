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

from pydantic import BaseModel, Field, field_validator


class ResourceLimits(BaseModel):
    """Resource limits for containers.

    Attributes:
        memory: Memory limit (e.g., "256Mi", "1Gi")
        cpu: CPU limit (e.g., "100m", "1000m")
    """

    memory: str = Field(..., description="Memory limit (e.g., 256Mi)")
    cpu: str = Field(..., description="CPU limit (e.g., 200m)")

    @field_validator("memory")
    @classmethod
    def validate_memory(cls, v: str) -> str:
        """Validate memory format."""
        if not (v.endswith("Mi") or v.endswith("Gi") or v.endswith("Ki")):
            raise ValueError("Memory must end with Mi, Gi, or Ki")
        return v

    @field_validator("cpu")
    @classmethod
    def validate_cpu(cls, v: str) -> str:
        """Validate CPU format."""
        if not (v.endswith("m") or v.isdigit()):
            raise ValueError("CPU must end with m (millicores) or be a number")
        return v


class ResourceRequests(BaseModel):
    """Resource requests for containers.

    Attributes:
        memory: Memory request
        cpu: CPU request
    """

    memory: str = Field(..., description="Memory request (e.g., 128Mi)")
    cpu: str = Field(..., description="CPU request (e.g., 100m)")


class SecurityContextConfig(BaseModel):
    """Security context configuration.

    Attributes:
        run_as_user: User ID to run container as
        run_as_non_root: Enforce non-root user
        allow_privilege_escalation: Allow privilege escalation
        privileged: Run in privileged mode
        read_only_root_filesystem: Make root filesystem read-only
        capabilities_add: Capabilities to add
        capabilities_drop: Capabilities to drop
    """

    run_as_user: int = Field(default=1000, description="User ID to run as")
    run_as_non_root: bool = Field(default=True, description="Enforce non-root execution")
    allow_privilege_escalation: bool = Field(
        default=False, description="Allow privilege escalation"
    )
    privileged: bool = Field(default=False, description="Run in privileged mode")
    read_only_root_filesystem: bool = Field(
        default=False, description="Make root filesystem read-only"
    )
    capabilities_add: list[str] = Field(default_factory=list, description="Capabilities to add")
    capabilities_drop: list[str] = Field(
        default_factory=lambda: ["ALL"], description="Capabilities to drop"
    )


class MitreAttackMapping(BaseModel):
    """MITRE ATT&CK framework mapping.

    Attributes:
        tactics: MITRE ATT&CK tactics
        techniques: MITRE ATT&CK technique IDs
        subtechniques: MITRE ATT&CK subtechnique IDs
        data_sources: Data sources for detection
    """

    tactics: list[str] = Field(default_factory=list, description="ATT&CK tactics")
    techniques: list[str] = Field(default_factory=list, description="ATT&CK technique IDs")
    subtechniques: list[str] = Field(default_factory=list, description="ATT&CK subtechnique IDs")
    data_sources: list[str] = Field(default_factory=list, description="Detection data sources")


class ExploitConfig(BaseModel):
    """Configuration for a single exploit.

    Attributes:
        name: Exploit identifier
        enabled: Whether exploit is active
        default_service: Default target service
        risk_level: Risk severity
        description: Exploit description
        mitre_attack: MITRE ATT&CK mappings
        cis_controls: CIS Kubernetes Benchmark control IDs
        cve_ids: Related CVE identifiers
        remediation_priority: Priority for remediation
    """

    name: str = Field(..., description="Unique exploit identifier")
    enabled: bool = Field(default=True, description="Enable this exploit")
    default_service: str = Field(..., description="Default target service")
    risk_level: str = Field(
        ..., pattern="^(LOW|MEDIUM|HIGH|CRITICAL)$", description="Risk severity"
    )
    description: str = Field(..., description="Exploit description")
    mitre_attack: MitreAttackMapping = Field(
        default_factory=MitreAttackMapping, description="MITRE ATT&CK mappings"
    )
    cis_controls: list[str] = Field(default_factory=list, description="CIS Benchmark control IDs")
    cve_ids: list[str] = Field(default_factory=list, description="Related CVE identifiers")
    remediation_priority: int = Field(
        default=5, ge=1, le=10, description="Remediation priority (1-10)"
    )


class TimeoutConfig(BaseModel):
    """Timeout configuration.

    Attributes:
        operation: Default operation timeout in seconds
        rollout: Deployment rollout timeout in seconds
        stream: Stream read timeout in seconds
        command: Command execution timeout in seconds
    """

    operation: int = Field(default=300, description="Operation timeout (seconds)")
    rollout: int = Field(default=120, description="Rollout wait timeout (seconds)")
    stream: int = Field(default=1, description="Stream read timeout (seconds)")
    command: int = Field(default=60, description="Command execution timeout (seconds)")


class KubernetesConfig(BaseModel):
    """Kubernetes cluster configuration.

    Attributes:
        namespace: Default Kubernetes namespace
        context: Kubeconfig context to use
        in_cluster: Whether running inside cluster
        kubeconfig_path: Path to kubeconfig file
    """

    namespace: str = Field(default="default", description="Default namespace")
    context: str | None = Field(default=None, description="Kubeconfig context")
    in_cluster: bool = Field(default=False, description="Running in-cluster")
    kubeconfig_path: str | None = Field(default=None, description="Path to kubeconfig")


class LoggingConfig(BaseModel):
    """Logging configuration.

    Attributes:
        level: Log level
        format: Log format string
        file: Log file path
        console: Enable console logging
    """

    level: str = Field(
        default="INFO",
        pattern="^(DEBUG|INFO|WARNING|ERROR|CRITICAL)$",
        description="Log level",
    )
    format: str = Field(
        default="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        description="Log format",
    )
    file: str | None = Field(default=None, description="Log file path")
    console: bool = Field(default=True, description="Enable console logging")


class ToolkitConfig(BaseModel):
    """Main toolkit configuration.

    Attributes:
        kubernetes: Kubernetes settings
        services: Service names to target
        exploit_mappings: Map of exploit types to services
        exploits: Exploit configurations
        timeouts: Timeout settings
        logging: Logging configuration
        dry_run: Preview mode without applying changes
        debug: Enable debug output
        verbose: Enable verbose output
        secure_defaults: Use secure defaults
    """

    kubernetes: KubernetesConfig = Field(
        default_factory=KubernetesConfig, description="Kubernetes configuration"
    )
    services: list[str] = Field(default_factory=list, description="Target services")
    exploit_mappings: dict[str, str] = Field(
        default_factory=dict, description="Exploit to service mappings"
    )
    exploits: dict[str, ExploitConfig] = Field(
        default_factory=dict, description="Exploit configurations"
    )
    timeouts: TimeoutConfig = Field(
        default_factory=TimeoutConfig, description="Timeout configuration"
    )
    logging: LoggingConfig = Field(
        default_factory=LoggingConfig, description="Logging configuration"
    )
    dry_run: bool = Field(default=False, description="Preview changes only")
    debug: bool = Field(default=False, description="Enable debug mode")
    verbose: bool = Field(default=False, description="Enable verbose output")
    secure_defaults: ResourceLimits = Field(
        default=ResourceLimits(memory="256Mi", cpu="200m"),
        description="Default secure resource limits",
    )
    secure_requests: ResourceRequests = Field(
        default=ResourceRequests(memory="128Mi", cpu="100m"),
        description="Default secure resource requests",
    )
    secure_context: SecurityContextConfig = Field(
        default_factory=SecurityContextConfig, description="Default secure context"
    )

    @field_validator("services")
    @classmethod
    def validate_services(cls, v: list[str]) -> list[str]:
        """Ensure services list is not empty."""
        if not v:
            raise ValueError("At least one service must be configured")
        return v

    @field_validator("exploits")
    @classmethod
    def validate_exploits(cls, v: dict[str, ExploitConfig]) -> dict[str, ExploitConfig]:
        """Ensure exploit names match their keys."""
        for key, exploit in v.items():
            if exploit.name != key:
                raise ValueError(
                    f"Exploit key '{key}' does not match exploit name '{exploit.name}'"
                )
        return v
