# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.0] - 2025-03-18

### Added

- NetworkPolicy enforcement via kube-router in firewall-only mode (`enforce enable/disable/status`)
- Missing network policies exploit (`missing-network-policies`) with auto-discovered policies
- Operation journal (`.kimera-state.json`) and unified `revert` command
- `run_command()` helper with `CommandResult` dataclass for structured subprocess execution
- YAML-driven security tests with `ProbeRunner` (7 typed probes: writable, path_exists, port_open, capability_check, count_check, file_content, socket_check)
- Unguard profile (`config/profiles/unguard.yaml`) with auto-detection via `-n unguard`
- K8sClient methods for NetworkPolicy, DaemonSet, ServiceAccount, ClusterRole, and ClusterRoleBinding CRUD

### Changed

- Renamed project from `k8s-exploit-toolkit` to `kimera`
- Unified config system: wired `ConfigLoader` into CLI, made `default.yaml` application-agnostic
- Moved shell scripts from Python constants to YAML config files (`config/exploits/*.yaml`)
- Standardized output to single themed Rich console — removed duplicate `Console()` and `print()` calls
- Migrated from Poetry to uv for dependency management
- Replaced Black formatter with Ruff format
- Updated all type annotations to Python 3.13+ style (`list[str]`, `str | None`)

### Fixed

- kube-router ClusterRole missing `discovery.k8s.io/endpointslices` permission
- Ruff S1066 warning for nested if statements in CLI enforce commands
- mypy errors in test files (missing return types, method-assign warnings)

## [1.0.0] - 2025-11-07

### Added

- Initial release with 4 exploit types: privileged containers, dangerous capabilities, host namespace sharing, missing resource limits
- CLI interface with `assess`, `exploit`, `secure`, `verify`, and `rollback` commands
- Security scanner for deployment assessment
- Security patcher for remediation
- Plugin architecture with protocol-based interfaces
- YAML-based configuration with profile support
- Google-style docstring standards
- Pre-commit hooks (Ruff, mypy)
- kind cluster test infrastructure

[1.1.0]: https://github.com/dynatrace-oss/kimera/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/dynatrace-oss/kimera/releases/tag/v1.0.0
