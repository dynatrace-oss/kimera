# Container Security Implementation

This directory contains the core container security functionality of Kimera.

## Module Structure

```txt
container/
├── assessment/         # Security scanning and analysis
│   └── scanner.py     # Deployment security scanner
├── core/              # Core utilities and configuration
│   ├── command.py     # Subprocess command execution
│   ├── config.py      # Configuration re-exports
│   ├── exceptions.py  # Custom exceptions
│   ├── journal.py     # Operation journal (.kimera-state.json)
│   ├── k8s_client.py  # Kubernetes API client wrapper
│   └── logger.py      # Logging configuration
├── infrastructure/    # Cluster infrastructure management
│   ├── dt_mcp_client.py   # Dynatrace MCP gateway client
│   ├── enforcement.py     # Cilium NetworkPolicy enforcement
│   └── resource_applier.py # YAML resource and exploit patch applier
├── make_vulnerable/   # Vulnerability injection modules
│   ├── base.py                        # Base exploit class
│   ├── dangerous_capabilities.py      # Linux capabilities exploitation
│   ├── host_namespace_sharing.py      # Host namespace access
│   ├── missing_network_policies.py    # Network policy absence
│   ├── missing_resource_limits.py     # Resource exhaustion
│   ├── privileged_containers.py       # Privileged container exploits
│   ├── probe_runner.py                # Shell probe generator for tests
│   └── test_loader.py                # YAML test definition loader
└── remediations/      # LLM-based remediation generation
    └── generator.py   # LLMRemediationGenerator (remediation + exploit)
```

## Key Components

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

### LLM Generation (`remediations/generator.py`)

Generates remediation YAML and exploit patches using Anthropic Claude:

```bash
# Remediation mode (default)
kimera -n unguard generate --type network-policies --apply

# Exploit mode (cluster-aware patches)
kimera -n unguard generate --mode exploit --type privileged-containers --apply
```

### Resource Applier (`infrastructure/resource_applier.py`)

Applies YAML resources and exploit patches with label injection and journal tracking:

```bash
kimera -n unguard apply policies.yaml
```

### Policy Enforcement (`infrastructure/enforcement.py`)

Checks for Cilium and provides installation guidance for NetworkPolicy enforcement:

```python
from kimera.container.infrastructure.enforcement import PolicyEnforcementManager

manager = PolicyEnforcementManager(k8s_client)
manager.enable()   # Check Cilium status / print guidance
```

## Vulnerability Details

### Privileged Containers
- **Risk**: Complete bypass of container isolation
- **Impact**: Root access to host system

### Dangerous Capabilities
- **Risk**: Container escape through Linux capabilities
- **Impact**: Kernel manipulation, host compromise

### Host Namespace Sharing
- **Risk**: Access to host processes and network
- **Impact**: Information disclosure, lateral movement

### Missing Resource Limits
- **Risk**: Denial of service through resource exhaustion
- **Impact**: Node instability, service degradation

### Missing Network Policies
- **Risk**: Unrestricted pod-to-pod communication across namespaces
- **Impact**: Lateral movement, data store access, infrastructure reachability
