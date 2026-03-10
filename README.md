# K8s Exploit Toolkit

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Python](https://img.shields.io/badge/python-3.13+-blue.svg)](https://www.python.org/downloads/)
[![Kubernetes](https://img.shields.io/badge/kubernetes-1.24+-blue.svg)](https://kubernetes.io/)

A comprehensive security testing framework for Kubernetes environments, designed for educational purposes and defensive security testing.

> **Note**
> This product is not officially supported by Dynatrace!

## 🎯 Purpose

The K8s Exploit Toolkit provides hands-on learning opportunities for understanding Kubernetes container security misconfigurations and their remediation. This toolkit is designed for:

- **Security researchers** studying Kubernetes attack vectors
- **DevOps engineers** learning container security best practices
- **Security professionals** testing defensive capabilities
- **Educators** teaching cloud-native security concepts

## ⚠️ Disclaimer

This toolkit is intended for **educational and defensive security testing purposes only**. It should only be used on systems you own or have explicit permission to test. The authors and contributors are not responsible for any misuse or damage caused by this tool.

## 📋 Features

### Container Security Testing

- **Privileged Container Exploits**: Demonstrate complete bypass of container isolation
- **Dangerous Capabilities**: Show impact of excessive Linux capabilities
- **Host Namespace Sharing**: Exploit shared host resources (PID/Network/IPC)
- **Resource Exhaustion**: Controlled demonstration of missing resource limits
- **Interactive Learning**: Step-by-step exploitation and remediation workflows

### Key Capabilities

- **Assessment Mode**: Analyze security posture of deployments
- **Exploitation Mode**: Safely demonstrate attack techniques
- **Remediation Mode**: Apply security best practices
- **Rollback Support**: Undo changes with built-in rollback commands
- **Verification**: Confirm security improvements
- **Debug Mode**: Detailed logging for troubleshooting

## 🚀 Quick Start

### Prerequisites

- Kubernetes cluster (1.24+ recommended)
- `kubectl` configured with cluster access
- Python 3.13+ with Poetry or pip
- Appropriate RBAC permissions for target namespace

### Installation

#### Using uv (Recommended)

```bash
git clone https://github.com/dynatrace-oss/k8s-exploit-toolkit
cd k8s-exploit-toolkit
uv sync
```

#### Using pip

```bash
git clone https://github.com/dynatrace-oss/k8s-exploit-toolkit
cd k8s-exploit-toolkit
pip install -e .
```

### Basic Usage

```bash
# Assess security posture
k8s-exploit assess

# Apply vulnerability for testing
k8s-exploit vuln-service my-deployment privileged

# Demonstrate exploit
k8s-exploit exploit privileged-containers

# Apply security fixes
k8s-exploit secure

# Verify improvements
k8s-exploit verify

# Rollback changes
k8s-exploit rollback
```

## 📚 Documentation

### Command Reference

| Command | Description | Example |
|---------|-------------|---------|
| `assess [service]` | Assess security posture | `k8s-exploit assess` |
| `vuln-service <svc> <type>` | Apply specific vulnerability | `k8s-exploit vuln-service app privileged` |
| `exploit <type>` | Run specific exploit demo | `k8s-exploit exploit privileged-containers` |
| `secure [type]` | Apply security fixes | `k8s-exploit secure` |
| `verify` | Verify security status | `k8s-exploit verify` |
| `rollback [service]` | Rollback changes | `k8s-exploit rollback` |

### Vulnerability Types

| Type | Description | Impact |
|------|-------------|---------|
| `privileged` | Privileged container mode | Complete host access |
| `capabilities` | Dangerous Linux capabilities | Container escape potential |
| `host-namespace` | Host namespace sharing | Process/network visibility |
| `no-limits` | Missing resource limits | Denial of service risk |

### Advanced Usage

#### Verbose Mode

```bash
k8s-exploit --verbose secure
```

#### Debug Mode

```bash
k8s-exploit --debug assess
```

#### Custom Namespace

```bash
k8s-exploit --namespace production assess
```

#### Dry Run

```bash
k8s-exploit --dry-run secure
```

## 🔧 Architecture

```txt
k8s-exploit-toolkit/
├── k8s_exploit_toolkit/
│   ├── application/            # Application layer
│   │   ├── config/             # Configuration loading and schemas
│   │   └── plugins/            # Plugin registry
│   ├── container/              # Container security modules
│   │   ├── assessment/         # Security scanning
│   │   ├── core/               # Core utilities (client, config, logger)
│   │   ├── make_vulnerable/    # Exploit implementations
│   │   └── remediations/       # Security fixes and patching
│   ├── domain/                 # Domain layer
│   │   └── interfaces/         # Protocols and plugin interfaces
│   ├── plugins/                # Plugin base classes
│   ├── cli.py                  # Plugin-based CLI interface
│   └── exploit_k8s.py          # Main CLI entrypoint
├── config/                     # Default configuration files
├── docs/                       # Documentation and standards
├── scripts/                    # Utility scripts
└── tests/                      # Test suite
```

## 🛡️ Safety Features

- **Namespace Isolation**: Operations target specific namespaces only
- **Confirmation Prompts**: Requires confirmation for destructive actions
- **Rollback Support**: Built-in ability to undo all changes
- **Dry Run Mode**: Preview changes without applying them
- **Resource Safety**: Controlled demonstrations that don't harm cluster stability

## 🧪 Example Workflow

Here's a typical security testing workflow:

```bash
# 1. Initial assessment
k8s-exploit assess

# 2. Make service vulnerable for testing
k8s-exploit vuln-service payment-service privileged

# 3. Demonstrate the security impact
k8s-exploit exploit privileged-containers

# 4. Apply security fixes
k8s-exploit --verbose secure-service payment-service

# 5. Verify the improvements
k8s-exploit verify

# 6. Clean up (if needed)
k8s-exploit rollback payment-service
```

## 🤝 Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for details on:

- How to report bugs
- How to suggest enhancements
- Development setup
- Code submission guidelines

## 📖 Educational Resources

- [Kubernetes Security Documentation](https://kubernetes.io/docs/concepts/security/)
- [CIS Kubernetes Benchmark](https://www.cisecurity.org/benchmark/kubernetes)
- [NIST Container Security Guide](https://csrc.nist.gov/publications/detail/sp/800-190/final)
- [OWASP Kubernetes Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Kubernetes_Security_Cheat_Sheet.html)

## 📄 License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.

## 🏢 Maintainers

This project is maintained by the [Dynatrace OSS](https://github.com/dynatrace-oss) team as part of our commitment to cloud-native security education and research.

## ⚖️ Legal Notice

This software is provided for educational and research purposes. Users must ensure they have proper authorization before testing any systems. The maintainers assume no liability for misuse of this software.
