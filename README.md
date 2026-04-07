<p align="center">
  <img src="assets/kimera_logo.png" alt="Kimera" width="400"><br>
  <em>Kubernetes security testing framework — assess, exploit, remediate, enforce.</em><br><br>
  <a href="https://opensource.org/licenses/Apache-2.0"><img src="https://img.shields.io/badge/License-Apache%202.0-blue.svg" alt="License"></a>
  <a href="https://www.python.org/downloads/"><img src="https://img.shields.io/badge/python-3.13+-blue.svg" alt="Python"></a>
  <a href="https://kubernetes.io/"><img src="https://img.shields.io/badge/kubernetes-1.24+-blue.svg" alt="Kubernetes"></a>
</p>

> **Note**
> This product is not officially supported by Dynatrace!

## What is Kimera?

Kimera is a Kubernetes security posture management (KSPM) tool that identifies container misconfigurations, demonstrates their real-world impact, and applies targeted remediations. It operates directly against live clusters, giving security teams and platform engineers a practical way to validate their defenses.

## Disclaimer

This toolkit is intended for **security testing only**. It should only be used on systems you own or have explicit permission to test. The authors and contributors are not responsible for any misuse or damage caused by this tool.

## Features

### Security Testing

| Type | Description | Impact |
|------|-------------|---------|
| `privileged` | Privileged container mode | Complete host access |
| `capabilities` | Dangerous Linux capabilities | Container escape potential |
| `host-namespace` | Host namespace sharing | Process/network visibility |
| `no-limits` | Missing resource limits | Denial of service risk |
| `no-network-policies` | Missing NetworkPolicy resources | Unrestricted lateral movement |

### Operational Modes

- **Assess** — Scan deployments for security misconfigurations
- **Exploit** — Introduce and demonstrate specific vulnerabilities
- **Secure** — Print remediation guidance (use `generate` + `apply`)
- **Generate** — LLM-based YAML generation for remediations and exploit patches
- **Apply** — Apply externally or LLM-generated YAML with label injection and journal tracking
- **Enforce** — Check Cilium for NetworkPolicy enforcement
- **Revert** — Undo all changes, restoring original deployment state
- **Verify** — Confirm security posture after remediation

## Quick Start

### Prerequisites

- Kubernetes cluster (1.24+)
- `kubectl` configured with cluster access
- Python 3.13+ with [uv](https://docs.astral.sh/uv/)
- Appropriate RBAC permissions for target namespace

### Installation

```bash
git clone https://github.com/dynatrace-oss/kimera
cd kimera
uv sync
```

### Usage

```bash
# Assess security posture (auto-discovers services)
kimera -n unguard assess

# Introduce a specific vulnerability
kimera -p unguard vuln-service unguard-payment-service privileged

# Demonstrate the exploit
kimera -p unguard exploit privileged-containers

# Apply security fixes
kimera -p unguard secure

# Verify improvements
kimera -p unguard verify

# Revert all changes (restores original state)
kimera -p unguard revert
```

## Command Reference

| Command | Description | Example |
|---------|-------------|---------|
| `assess [service]` | Scan security posture | `kimera -n unguard assess` |
| `vuln-service <svc> <type>` | Introduce a vulnerability | `kimera vuln-service app privileged` |
| `exploit <type>` | Demonstrate an exploit | `kimera exploit privileged-containers` |
| `secure [type]` | Print remediation guidance | `kimera secure` |
| `generate --type <type>` | Generate YAML via LLM | `kimera generate --type network-policies` |
| `generate --mode exploit` | Generate exploit patches via LLM | `kimera generate --mode exploit --type privileged-containers` |
| `apply <file>` | Apply YAML with label injection | `kimera apply policies.yaml` |
| `verify` | Verify security status | `kimera verify` |
| `revert [type]` | Undo all kimera changes | `kimera revert` |
| `rollback [service]` | Rollback a deployment revision | `kimera rollback` |
| `enforce enable\|disable\|status` | Manage NetworkPolicy enforcement (Cilium) | `kimera enforce enable` |

## LLM-Based Generation

Kimera uses Anthropic Claude to generate both remediations and exploit patches.
The `generate` command gathers Kubernetes context and produces YAML.

```bash
# Generate remediations (default mode)
kimera -n unguard generate --type network-policies -o policies.yaml
kimera -n unguard generate --type network-policies --apply

# Generate exploit patches (cluster-aware, targets correct containers)
kimera -n unguard generate --mode exploit --type privileged-containers
kimera -n unguard generate --mode exploit --type all --apply

# Enrich with Dynatrace MCP (requires DT_ENVIRONMENT, DT_PLATFORM_TOKEN)
kimera -n unguard generate --type missing-network-policies --use-dt-mcp
kimera -n unguard generate --type missing-network-policies --use-dt-mcp --dt-strategy llm-query
kimera -n unguard generate --type missing-network-policies --use-dt-mcp --dt-strategy davis

# Apply externally generated YAML
kimera -n unguard apply policies.yaml
```

Install extras: `uv pip install 'kimera[llm]'` for LLM, `uv pip install 'kimera[dt-mcp]'` for DT MCP, or `uv pip install 'kimera[all]'` for both.

### DT Data Strategies

When using `--use-dt-mcp`, choose a data fetching strategy with `--dt-strategy`:

| Strategy | Description | Requirements |
|---|---|---|
| `targeted` (default) | Exploit-type-specific DQL queries (CIS rule IDs, category keywords) | `kimera[dt-mcp]` |
| `llm-query` | Claude generates DQL queries from few-shot examples | `kimera[all]` |
| `davis` | Davis CoPilot natural language queries (falls back to targeted) | `kimera[dt-mcp]` |

## NetworkPolicy Enforcement

NetworkPolicies require a policy-enforcing CNI. Kimera checks for
[Cilium](https://cilium.io/) and prints installation guidance if not found.

```bash
kimera enforce enable    # Check Cilium enforcement
kimera enforce status    # Show enforcement status
kimera enforce disable   # Guidance for removing Cilium
```

## Configuration

Kimera uses a layered config system: `default.yaml` → profile → environment variables → CLI flags.

```bash
# Auto-detect profile from namespace name
kimera -n unguard assess

# Explicit profile
kimera -p unguard assess

# Any namespace (auto-discovers services)
kimera -n my-namespace assess

# Flags
kimera --verbose --debug --dry-run assess
```

Profiles live in `config/profiles/` and define target-specific services and exploit mappings.

## Safety Features

- **Namespace isolation** — Operations target specific namespaces only
- **Confirmation prompts** — Requires confirmation for destructive actions
- **Revert support** — Undo all changes via operation journal
- **Dry run mode** — Preview changes without applying them
- **Rollback** — Restore individual deployments to previous revisions

## Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for details.

## References

- [Kubernetes Security Documentation](https://kubernetes.io/docs/concepts/security/)
- [CIS Kubernetes Benchmark](https://www.cisecurity.org/benchmark/kubernetes)
- [NIST Container Security Guide](https://csrc.nist.gov/publications/detail/sp/800-190/final)
- [OWASP Kubernetes Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Kubernetes_Security_Cheat_Sheet.html)

## License

This project is licensed under the Apache License 2.0 — see the [LICENSE](LICENSE) file for details.

## Maintainers

Maintained by [Dynatrace OSS](https://github.com/dynatrace-oss).

## Legal Notice

This software is provided for research and testing purposes. Users must ensure they have proper authorization before testing any systems. The maintainers assume no liability for misuse.
