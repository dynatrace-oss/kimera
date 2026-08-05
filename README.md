<p align="center">
  <img src="assets/kimera_logo.png" alt="Kimera" width="400"><br>
  <em>AI-agent-driven Kubernetes penetration testing via MCP</em><br><br>
  <a href="https://opensource.org/licenses/Apache-2.0"><img src="https://img.shields.io/badge/License-Apache%202.0-blue.svg" alt="License"></a>
  <a href="https://www.python.org/downloads/"><img src="https://img.shields.io/badge/python-3.13+-blue.svg" alt="Python"></a>
  <a href="https://kubernetes.io/"><img src="https://img.shields.io/badge/kubernetes-1.24+-blue.svg" alt="Kubernetes"></a>
</p>

> **Note:** This product is not officially supported by Dynatrace.

## What is Kimera?

Kimera is a Kubernetes security testing toolkit that exposes attack techniques as [MCP](https://modelcontextprotocol.io/) tools. An AI agent connects to kimera's MCP server, plans multi-step attack chains using MITRE ATT&CK techniques, executes them against a cluster, and validates whether defenses caught each attack.

40 techniques across 8 phases — reconnaissance, credential access, privilege escalation, lateral movement, defense evasion, persistence, execution, and defense validation — all defined as YAML configs and executable via MCP or CLI.

## Disclaimer

This toolkit is for **authorized security testing only**. Use only on clusters you own or have explicit permission to test.

## Architecture

```
┌─────────────────┐     MCP (stdio/HTTP)      ┌──────────────┐
│   AI Agent      │◄───────────────────────►  │ kimera-mcp   │
│  (Claude, etc.) │                           │  7 tools     │
└─────────────────┘                           └──────┬───────┘
                                                     │
                                              ┌──────▼───────┐
                                              │  Svc Layer   │
                                              │  assessor    │
                                              │  technique   │
                                              │  engine      │
                                              │  enumerator  │
                                              └──────┬───────┘
                                                     │ K8s API
                                              ┌──────▼───────┐
                                              │  Target      │
                                              │  Cluster     │
                                              └──────────────┘
```

## Quick Start

### Prerequisites

- Kubernetes cluster (1.24+) with `kubectl` configured
- Python 3.13+ with [uv](https://docs.astral.sh/uv/)

### Install

```bash
git clone https://github.com/dynatrace-oss/kimera
cd kimera
uv sync --all-extras
```

### MCP Server (for AI agents)

```bash
# stdio transport (Claude Desktop, Cursor)
kimera-mcp

# HTTP transport (remote agents, CI/CD)
kimera-mcp --http
```

Claude Desktop configuration:

```json
{
  "mcpServers": {
    "kimera": {
      "command": "uv",
      "args": ["run", "kimera-mcp"],
      "cwd": "/path/to/kimera"
    }
  }
}
```

### CLI

```bash
# Assess workloads against CIS Kubernetes Benchmark
kimera -n target-namespace assess

# Assess with JSON output
kimera -n target-namespace assess --json

# Validate that security controls actually block attacks
kimera -n target-namespace validate-control --type all
```

## MCP Tools

| Tool | Description |
|------|-------------|
| `list_techniques` | Browse 22 attack techniques by phase, with MITRE ATT&CK mappings |
| `assess_target` | Scan namespace for misconfigurations (CIS checks, structured findings) |
| `enumerate_attack_surface` | Discover deployments, services, secrets, RBAC in a namespace |
| `attempt_technique` | Execute a specific technique (C1=SA token theft, L1=network probe, etc.) |
| `validate_defense` | Test admission controllers, NetworkPolicies, RBAC (production-safe) |
| `get_remediation` | Look up fix guidance for a specific finding |
| `reload_techniques` | Pick up new YAML technique definitions without restart |

## Technique Registry

40 techniques defined in `src/kimera/config/techniques/`, each a YAML file with probes, evidence markers, MITRE mappings, and remediation.

| Phase | Count | Examples |
|-------|-------|---------|
| Reconnaissance | 10 | Enumerate namespaces, services, RBAC, secrets metadata |
| Credential Access | 6 | SA token theft, secret enumeration, cloud metadata SSRF |
| Defense Validation | 6 | Admission, NetworkPolicy, RBAC validation; defense-tool version detection |
| Lateral Movement | 5 | Network probe, DNS enumeration, data store access, app-mediated request |
| Privilege Escalation | 4 | Privileged escape, SYS_ADMIN abuse, RBAC escalation |
| Defense Evasion | 4 | Delete events, disable PSA, Kyverno bypass, Cilium label mutation |
| Persistence | 3 | CronJob persistence, SA with role binding, backdoor pod |
| Execution | 2 | Exec into pod via API, ephemeral container injection |

Add a technique: drop a YAML file in `src/kimera/config/techniques/`, add to `registry.yaml`, call `reload_techniques`.

## In-Cluster Deployment

### Helm Chart (MCP server mode)

```bash
helm install kimera deploy/helm/kimera \
  --namespace kimera-system --create-namespace \
  --set targetNamespace=my-app \
  --set mode=server
```

The MCP server runs as a Deployment, accessible via ClusterIP Service on port 8000.

### Helm Chart (Job mode — CI/CD)

```bash
helm install kimera-scan deploy/helm/kimera \
  --namespace kimera-system --create-namespace \
  --set targetNamespace=my-app \
  --set mode=job \
  --set job.args="{assess,--json}"
```

One-shot scan. Results in pod logs. Job auto-deletes after 5 minutes.

### Docker

```bash
docker build -t kimera .
docker run --rm -v ~/.kube:/home/kimera/.kube:ro kimera -n my-app assess
```

## CLI Reference

| Command | Description |
|---------|-------------|
| `assess [--json]` | Scan namespace against CIS checks |
| `validate-control --type all\|admission\|network-policy\|rbac` | Test defense controls |
| `exploit <type>` | Demonstrate a specific exploit |
| `vuln-service <svc> <type>` | Introduce a vulnerability for testing |
| `generate --type <type> [--apply]` | Generate remediations via LLM |
| `generate --enrich dynatrace` | Enrich LLM context with Dynatrace data |
| `technique list [--phase <phase>]` | Browse the technique registry |
| `technique run <id> --pod <pod>` | Run one technique; `--dry-run` prints the probe |
| `query '<query>' [--json]` | Query an observability provider |
| `revert [type]` | Undo all kimera changes |
| `verify` | Confirm security posture |

## Configuration

Layered config: `src/kimera/config/default.yaml` → profile → environment variables → CLI flags.

`-n <namespace>` loads `profiles/<namespace>.yaml` automatically when that file exists; `-p` overrides it.

Assessment checks are defined in `src/kimera/config/checks/workload.yaml` — 14 checks covering privileged mode, dangerous capabilities, host namespaces, resource limits, RBAC, and network policies.

Environment variable overrides are defined in `src/kimera/config/env_mappings.yaml`.

Configuration ships inside the installed package. To supply your own profiles and checks without editing an installed package, point `KIMERA_CONFIG_DIR` at a directory laid out the same way — it replaces the packaged one wholesale, so it needs its own `default.yaml`.

### Network topology

`network_topology` in a profile drives NetworkPolicy generation. The map key names the workload an entry applies to.

```yaml
network_topology:
  unguard-mariadb:
    allowed_ingress_from:                      # omit the key to leave ingress undeclared;
      - {app.kubernetes.io/name: like-service} # an empty list means block all ingress
  unguard-user-simulator:
    allowed_egress_to:                         # destinations outside the namespace
      - cidr: 0.0.0.0/0
        except: [10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.169.254/32]
        ports: [80, 443]
        protocol: TCP
```

A workload with an external dependency needs `allowed_egress_to`, or a default-deny set severs it — the workload then fails to start while every app-to-app flow still passes, which is easy to misread as a segmentation failure. Declared destinations are added to the generated set deterministically, not left to the model, and are checked by `kimera validate-control --type network-policy`. Nothing is inferred: a destination that is not declared is not permitted.

## Observability Enrichment

Kimera supports pluggable enrichment from observability platforms via the `EnrichmentProvider` protocol. Dynatrace is the built-in provider:

```bash
# Enrich remediation context with Dynatrace KSPM + Smartscape data
kimera generate --type network-policies --enrich dynatrace
kimera generate --type network-policies --enrich dynatrace --enrich-strategy llm-query
```

Providers can also answer direct queries, which is how you measure whether a control had the effect it claims rather than feeding an LLM prompt:

```bash
# Run a query in the provider's own query language
kimera query 'fetch spans, from: -1h | filter k8s.namespace.name == "unguard" | limit 10'
kimera query '<query>' --provider dynatrace --json > evidence.json
```

The query language stays the provider's own — DQL for Dynatrace — because a common cross-platform query language would be a translation layer that could only ever expose the subset every backend shares.

Adding a new provider: implement `EnrichmentProvider` and/or `QueryProvider` in `src/kimera/container/integrations/<provider>/`. The two are separate protocols, so a provider can support either alone.

## Safety

- All destructive MCP operations default to `dry_run=True`
- Admission testing uses server-side dry-run (zero persistence)
- Probe pods have `activeDeadlineSeconds` TTLs
- Operation journal tracks all changes for reliable `revert`
- The in-cluster SA's RBAC permissions are deliberately part of the test

## References

- [MITRE ATT&CK for Containers](https://attack.mitre.org/matrices/enterprise/containers/)
- [CIS Kubernetes Benchmark](https://www.cisecurity.org/benchmark/kubernetes)
- [Microsoft Kubernetes Threat Matrix](https://microsoft.github.io/Threat-Matrix-for-Kubernetes/)
- [Model Context Protocol](https://modelcontextprotocol.io/)

<p align="center">
  Maintained by <a href="https://github.com/dynatrace-oss">Dynatrace OSS</a> · Apache 2.0
</p>
