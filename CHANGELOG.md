# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.0.0] - 2025-03-23

### Added

- LLM-based remediation generation via `kimera generate` with Anthropic Claude (`--mode remediate` and `--mode exploit`)
- Dynatrace MCP integration (`--use-dt-mcp`) for enriching generation context with live KSPM findings and Smartscape topology
- Three DT data strategies (`--dt-strategy targeted|llm-query|davis`):
  - **targeted**: exploit-type-specific DQL queries using CIS rule IDs and category keywords
  - **llm-query**: Claude generates DQL from verified templates in `dql_reference.yaml`
  - **davis**: Davis CoPilot NL2DQL generation with targeted fallback
- `DynatraceMCPClient` for Streamable HTTP/SSE transport to the hosted MCP gateway
- DQL reference YAML (`kimera/prompts/dql_reference.yaml`) as single source of truth for DQL syntax, naming model, and query templates
- Jinja2 prompt templates for remediation, exploit, and DQL query generation
- `kimera apply <file>` command for applying generated YAML to the cluster with `managed-by: kimera` labels
- `ResourceApplier` with NetworkPolicy creation and exploit patch application
- `DynatraceConfig` schema with `default_strategy` field in `config/default.yaml`
- Exploit registry (`config/exploits/registry.yaml`) for centralized exploit metadata with MITRE ATT&CK mappings
- Cilium-based NetworkPolicy enforcement (`kimera enforce enable/disable/status`)
- `.env` auto-loading via `python-dotenv` — no manual `source .env` required
- `.env.example` with all required environment variables and DT platform token scopes
- Comprehensive parser tests for MCP response handling (`test_dt_mcp_client.py`)
- DT strategy tests with Davis create-dql response handling and classify_records coverage

### Changed

- Replaced `python-decouple` with `python-dotenv` for environment variable loading
- Replaced `kube-router` enforcement with Cilium CNI enforcement
- Refactored DT MCP client: extracted shared `_parse_response_records()`, removed duplicate parsing logic
- Refactored DT query strategies: extracted shared `classify_records()`, `_format_kspm()`, `_format_smartscape()` module-level utilities
- Davis strategy now sends DQL-field-hint-enriched requests for improved NL2DQL accuracy
- Moved logo from `logo/` to `assets/`
- Removed unused profiles (`development.yaml`, `production.yaml`, `training.yaml`) — only `unguard.yaml` retained
- Removed legacy plugin architecture (`kimera/plugins/`, `kimera/domain/interfaces/`, `kimera/application/plugins/`)
- Removed legacy build files (`setup.py`, `setup.cfg`, `requirements.txt`)
- Removed legacy remediation patcher (`kimera/container/remediations/patcher.py`)
- Trimmed redundant tests (`test_basic.py`, trivial CLI import tests, Python inheritance tests)
- Streamlined exploit base class and implementations (removed redundant docstrings and dead code)
- - `SmartscapeEdge` dataclass gains optional `source_workload` / `target_workload` fields
  populated from `getNodeField(entity_id, "k8s.workload.name")` in Smartscape DQL queries.
  `classify_records()` extracts these when present; `_format_smartscape()` appends
  `(k8s: <workload>)` annotations so LLM prompts can correlate Smartscape display names
  with KSPM K8s workload names. Fields default to `""` — no regression for non-K8s nodes.
- `_build_smartscape_query("full")` now fetches `source_workload` / `target_workload` via
  `getNodeField(id, "k8s.workload.name")` and includes them in the `fields` projection.
- Davis smartscape request enriched with `k8s.workload.name` hint so `create-dql` generates
  queries that include the workload mapping fields.
- `dql_reference.yaml` — `naming_model.process` and `naming_model.bridge_pattern` updated with
  DT entity approach; `smartscape_full` template includes workload fields;
  `syntax_rules.smartscape.name_resolution` documents the workload field option.
  - Updated all documentation to reflect current architecture

### Fixed

- MCP JSON parsing: response text blocks with prefixes (`"Query result records:\n[...]"`) now correctly extracted via `_extract_json()`
- Smartscape DQL syntax: corrected from `source.type` (Copilot-specific) to `getNodeField(source_id, "name")` (MCP gateway syntax)
- Davis create-dql response format: properly handles `{dql, status, metadata}` structure and permission errors

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

[2.0.0]: https://github.com/dynatrace-oss/kimera/compare/v1.1.0...v2.0.0
[1.1.0]: https://github.com/dynatrace-oss/kimera/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/dynatrace-oss/kimera/releases/tag/v1.0.0
