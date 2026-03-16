# Container Security Implementation

This directory contains the core container security functionality of the Kimera.

## 🏗️ Module Structure

```txt
container/
├── assessment/         # Security scanning and analysis
│   └── scanner.py     # Deployment security scanner
├── core/              # Core utilities and configuration
│   ├── config.py      # Configuration management
│   ├── exceptions.py  # Custom exceptions
│   ├── k8s_client.py  # Kubernetes API client wrapper
│   └── logger.py      # Logging configuration
├── infrastructure/    # Cluster infrastructure management
│   └── enforcement.py # NetworkPolicy enforcement (kube-router)
├── make_vulnerable/   # Vulnerability injection modules
│   ├── base.py                        # Base vulnerability class
│   ├── dangerous_capabilities.py      # Linux capabilities exploitation
│   ├── host_namespace_sharing.py      # Host namespace access
│   ├── missing_network_policies.py    # Network policy absence
│   ├── missing_resource_limits.py     # Resource exhaustion
│   └── privileged_containers.py       # Privileged container exploits
└── remediations/      # Security fixes and patches
    └── patcher.py     # Security remediation engine
```

## 🔍 Key Components

### Security Scanner (`assessment/scanner.py`)

Analyzes deployments for common security misconfigurations:

```python
from kimera.container.assessment.scanner import SecurityScanner

scanner = SecurityScanner(k8s_client)
results = scanner.assess_deployment("my-app")
```

### Vulnerability Modules (`make_vulnerable/`)

Each module implements specific security weaknesses:

- **Privileged Containers**: Complete isolation bypass
- **Dangerous Capabilities**: Linux capability exploitation
- **Host Namespace Sharing**: Access to host resources
- **Missing Resource Limits**: Resource exhaustion vulnerabilities
- **Missing Network Policies**: Unrestricted lateral movement across namespaces

### Policy Enforcement (`infrastructure/enforcement.py`)

Installs kube-router in firewall-only mode for NetworkPolicy enforcement on clusters
where the CNI (e.g., Flannel) does not enforce policies natively:

```python
from kimera.container.infrastructure.enforcement import PolicyEnforcementManager

manager = PolicyEnforcementManager(k8s_client)
manager.enable()   # Install kube-router
manager.disable()  # Remove kube-router
```

### Remediation Engine (`remediations/patcher.py`)

Applies security best practices to fix identified vulnerabilities:

```python
from kimera.container.remediations.patcher import SecurityPatcher

patcher = SecurityPatcher(k8s_client)
patcher.apply_security_patch("my-deployment", "privileged")
```

## 🛡️ Vulnerability Details

### Privileged Containers

- **Risk**: Complete bypass of container isolation
- **Impact**: Root access to host system
- **Demonstration**: Host filesystem access, device manipulation

### Dangerous Capabilities

- **Risk**: Container escape through Linux capabilities
- **Impact**: Kernel manipulation, host compromise
- **Demonstration**: CAP_SYS_ADMIN exploitation

### Host Namespace Sharing

- **Risk**: Access to host processes and network
- **Impact**: Information disclosure, lateral movement
- **Demonstration**: Host process visibility, network access

### Missing Resource Limits

- **Risk**: Denial of service through resource exhaustion
- **Impact**: Node instability, service degradation
- **Demonstration**: Controlled memory/CPU consumption

### Missing Network Policies

- **Risk**: Unrestricted pod-to-pod communication across namespaces
- **Impact**: Lateral movement, data store access, infrastructure reachability
- **Demonstration**: DNS enumeration, cross-namespace Redis/MariaDB access, API server connectivity

## 🔧 Configuration

The container module uses configuration from `core/config.py`:

```python
from kimera.container.core.config import ContainerConfig

config = ContainerConfig()
config.target_namespace = "production"
config.dry_run = True
```

## 🐛 Error Handling

Custom exceptions are defined in `core/exceptions.py`:

```python
from kimera.container.core.exceptions import (
    SecurityViolationError,
    DeploymentNotFoundError,
    InsufficientPermissionsError
)
```
