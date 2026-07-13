# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- 5 exploit types: privileged containers, dangerous capabilities, host namespace sharing, missing resource limits, RBAC abuse
- YAML-driven exploit tests with `ProbeRunner` (7 typed probes: writable, path_exists, port_open, capability_check, count_check, file_content, socket_check)
- 25 MITRE ATT&CK-mapped attack techniques across 8 phases: reconnaissance, credential-access, privilege-escalation, lateral-movement, defense-evasion, persistence, execution, defense-validation
- S5, S6, S7 defense-tool version detection techniques (defense-validation phase)
  - S5: Cilium startup window — CVE-2023-27595 (no enforcement during eBPF reload)
  - S6: OPA Gatekeeper sync race — CVE-2021-43979 (stale state during policy evaluation)
  - S7: Kyverno SSRF and bypass — CVE-2024-48921 (PolicyException namespace bypass)
- `detect_tool_version` verb in `api_executor` for reading defense tool versions from DaemonSet/Deployment image tags
- `kimera validate-control` command with admission controller, network policy, and RBAC validation (server-side dry-run, never persists resources)
- `kimera generate` with LLM-based remediation and exploit patch generation (`--mode remediate` and `--mode exploit`)
- `kimera apply <file>` command for applying generated YAML to the cluster with `managed-by: kimera` labels
- Dynatrace MCP integration (`--use-dt-mcp`) for enriching LLM generation with live KSPM findings and Smartscape topology
- Three DT data strategies: `targeted`, `llm-query`, `davis` (via `--dt-strategy`)
- MCP server (`kimera-mcp`) exposing 7 pentest tools via the Model Context Protocol
- Operation journal (`.kimera-state.json`) and unified `kimera revert` command
- Unguard profile (`config/profiles/unguard.yaml`) with auto-detection via `-n unguard`
- Cilium-based NetworkPolicy enforcement (`kimera enforce enable/disable/status`)
- `.env` auto-loading via `python-dotenv`
- Exploit registry (`config/exploits/registry.yaml`) with centralized MITRE ATT&CK mappings
- Helm chart and Dockerfile for cluster deployment (`deploy/`)
- Interactive architecture diagram (`assets/architecture.html`)

### Changed

- Renamed project from `k8s-exploit-toolkit` to `kimera`
- Migrated from Poetry to uv for dependency management
- Replaced Black formatter with Ruff format; replaced Sphinx reST docstrings with Google style
- Split monolithic `exploit_k8s.py` into `kimera/cli/` package
- Renamed `infrastructure/` to `integrations/dynatrace/` for clarity
- Replaced `python-decouple` with `python-dotenv`
- Replaced kube-router enforcement with Cilium CNI enforcement
- Config system uses merge order: `default.yaml` → profile → env vars → CLI flags
- Removed legacy plugin architecture, build files (`setup.py`, `setup.cfg`, `requirements.txt`), and unused profiles

### Fixed

- Admission validation test isolation: `_detect_admission_controllers` now uses the passed `K8sClient`'s pre-initialized API handles
- mypy errors across `registry.py`, `assessor.py`, `api_executor.py`, `deployment_patch.py`, `mcp/server.py`, `cli/exploit.py`, `cli/generate.py`, and test files
- Stale `kimera/cli.py` stub removed (conflicted with `kimera/cli/` package causing mypy duplicate-module error)
- Helm templates excluded from `check-yaml` pre-commit hook
- Upgraded `click` to 8.3.3+ (PYSEC-2026-2132) and `pip` to 26.1.2 (PYSEC-2026-196)
