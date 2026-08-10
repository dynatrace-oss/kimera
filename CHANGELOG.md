# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.3.0] - 2026-08-10

### Added

- `--non-interactive` and `--yes` on the root command. `--non-interactive` never prompts and assumes the safe answer at each site; `--yes` affirms destructive ones and takes effect only alongside it, so `--yes` on its own cannot turn `vuln` into a one-liner. `exploit --mode demo` previously read stdin directly and ended the run on EOF under ssh or CI.
- `exploit --json` writes a findings document — exploit type, namespace, source workload, probed paths and evidence — to stdout, with all other output on stderr so the result is parseable.
- `generate --from-findings <file> --scope targeted|namespace`. Targeted scope constrains only the workload the exploit ran from, permitting DNS, its declared dependencies and its declared external egress. Scope defaults to targeted with findings and namespace without. Each observed path is reported as DENY, KEEP or REVIEW before the set is written, and a deterministic pass corrects any emitted policy that permits a denied path or severs a declared one.
- `exploit --service <workload>` names the workload to exploit, overriding the profile's `exploit_mappings` entry. Without a profile the mapping is empty and every exploit refused to run; the target is still resolved deterministically, never inferred.
- `dns_resolve` probe type — resolves a list of names and reports which answer, reporting an explicit unknown state when no resolver tool exists. Emits no path record: a name resolving is not a connection.
- `network_topology.<workload>.allowed_egress_to` — declares the destinations outside the namespace a workload may reach, as a CIDR with an `except` list, ports and protocol. A post-processing pass guarantees every declared destination survives generation. Undeclared destinations stay denied.

### Fixed

- Configured timeouts take effect. `timeouts.rollout`, `timeouts.stream` and `timeouts.command` were declared in the config file and the env mappings but never read, so raising `timeouts.command` for a slow API server left a rollback still killed at 60 seconds. The unused `timeouts.operation` is removed.
- NetworkPolicy matching compares protocol, not only port number. A rule permitting 443/UDP was accepted as permitting a declared 443/TCP destination, so a gap went unreported while the flow was severed. An empty `to`/`from` list now means all destinations as the spec requires, a destination covered by several peers together is recognised rather than reported as a gap, a gap is closed with a rule for the missing ports only, and a generated policy name stays unique when truncated to 63 characters.
- `kimera exploit` exits non-zero when it refuses to run. An unknown exploit type or a missing service mapping was reported and then exited 0, so a script could not tell a refusal from a completed run.
- Security tests announce their position in the run: `Test 1:`, `Test 2:`, and so on. Every test printed the same `Test:` prefix, so a run of four read as one repeated step and any numbering a test carried in its own name was whatever the author happened to type.
- The unguard profile declares `unguard-ollama` ingress from `rag-service`. The RAG service reaches the model server on 11434, and with the destination undeclared a namespace-scope set severed that call while every other flow passed. Verified against the upstream chart at `dynatrace-oss/unguard` 0.23.0.
- `missing-network-policies` reports the services it did not probe. The lateral-movement target list was capped at 10 and truncated in silence, so a namespace with more services produced a path count that understated the attack surface — on a 16-service namespace it dropped three, including the one an app-mediated exploit reached. The cap is now 25 and names what it drops.
- `generate` exits non-zero when generation fails, and when `--scope targeted` is given without `--from-findings`. It reported the error and exited 0, so a script could not tell success from failure.
- A namespace the credential cannot read stops generation instead of yielding an empty context. A 401 or 403 while listing workloads was logged and returned nothing, and the emitted set then severed every workload the listing had missed.
- `validate-control --type network-policy` reports declared external egress the policy set denies. The reachability model was pod-to-pod only, so a set that severed a workload's external dependency scored zero gaps.
- `validate-control --type network-policy` also reports flows an egress rule declares that the destination's ingress denies. Only the opposite direction was checked. Reported, never auto-corrected — inferring an ingress rule would grant access nobody declared.
- `validate-control --type network-policy` no longer reports a pass ratio for connectivity tests it did not run. A probe pod that cannot be deployed is recorded as an ERROR naming the reason; it previously printed "2/2 passed" having verified nothing.
- Techniques report operations Kimera cannot perform as `NOT_ATTEMPTED`, not `BLOCKED`. `P1`, `P2`, `P3` and `DE3` declare `verb: create` for unimplemented resources — they created nothing and summarised as blocked, which reads as a working control to anyone checking detection coverage. `TechniqueResult` gained `not_attempted`.
- **Breaking (MCP):** `attempt_technique` honours `dry_run`. It previously executed and then labelled the result a dry run. `dry_run` defaults to `True`, so a client relying on the old behaviour must now pass `dry_run=False`.
- Subprocess commands time out after 60 seconds instead of hanging. An unreachable API server left `kubectl rollout undo` waiting forever with no diagnosis.
- `query` reports a refusal by an observability provider as a denial naming the gateway and the status (401 for a missing or expired token, 403 for a scope gap), and exits non-zero. The refusal ends the transport's reader task, so the pending request was only cancelled and the status surfaced during teardown — the operator saw a page of task-group and cancel-scope tracebacks rather than a token problem. Any other connection failure is now reported as an error the CLI handles, not a bare `CancelledError`.
- Targeted egress rules name the destination pod's port, not its Service port. Service traffic is translated before a policy is evaluated, so a rule naming the Service port permitted nothing and severed the dependency it was meant to keep.
- The banner prints to stderr. It was the first thing in `exploit --json` output, so the findings document could not be parsed.
- A DNS path is reported KEEP, not DENY. Every targeted set permits DNS, so the report contradicted the policy it described.
- `enforce status` and `enforce disable` no longer treat a 403 as absence. Both report the status as unknown and name the denied resource; `status` previously raised a traceback. A 404 still means not installed.

### Changed

- The pre-commit gate runs the project's own pinned `ruff` and `mypy` instead of pre-commit's mirrors, which had drifted to ruff 0.8.4 and mypy 1.14 against the 0.16 and 2.3 the project requires. CI reported a pass while `uv run mypy .` — the documented command — reported four type errors it never saw, and `uv run ruff format .` rewrote a file CI was content with. Those four errors are fixed, and mypy skips the untracked local scaffolding directories.
- **Breaking:** environment variables use the `KIMERA_` prefix instead of `K8S_EXPLOIT_`, matching the rename of the tool. `KIMERA_NAMESPACE`, `KIMERA_CONTEXT`, `KIMERA_KUBECONFIG`, `KIMERA_DRY_RUN`, `KIMERA_DEBUG`, `KIMERA_VERBOSE`, `KIMERA_TIMEOUT_ROLLOUT`, `KIMERA_TIMEOUT_STREAM`, `KIMERA_TIMEOUT_COMMAND`, `KIMERA_LOG_LEVEL`, `KIMERA_LOG_FILE`. The old names are no longer read.
- The package moved to a `src/` layout and its YAML configuration ships inside the package. An installed wheel previously could not find its own configuration — six modules located `config/` by counting parent directories, all resolving to the repository root. Set `KIMERA_CONFIG_DIR` to supply your own; it replaces the packaged directory wholesale.
- `-n <namespace>` loads `profiles/<namespace>.yaml` when that file exists, replacing a hardcoded special case for one namespace name. `-p` still overrides.
- `missing-network-policies` builds its discovered-target probes through the shared probe runner instead of hand-written shell, and probes services discovered from the API rather than a hardcoded list. Lateral movement reports port reachability rather than HTTP status — a NetworkPolicy is an L3/L4 control.
- `R8-permission-probe` declares the permissions it probes in its own YAML rather than in Python.
- `network_topology.<workload>.allowed_ingress_from` defaults to `None` rather than an empty list, so an entry declaring only egress no longer blocks that workload's ingress. An explicit empty list still blocks all ingress.

### Security

- Upgraded `cryptography` to 50.0.0, resolving GHSA-g6cj-pr64-35w5 (high).
- Added a Dependabot config for `uv`, GitHub Actions and Docker. Routine bumps are grouped weekly; security updates stay immediate.

## [0.2.0] - 2026-08-05

### Added

- `kimera query` — runs a query against an observability provider and reports the records; `--json` for evidence capture. Adds a `QueryProvider` protocol beside `EnrichmentProvider`, so a provider can support either alone. An empty result exits zero and says so, so absence is distinguishable from failure.
- `kimera technique list` / `kimera technique run` — CLI access to the technique registry, previously reachable only through the MCP server. `run` takes `--param key=value`; `--dry-run` prints the resolved probe script.
- `app_request` probe type — issues one HTTP request to a configured URL and reports the status with a bounded body excerpt. A process Kimera starts inside a container emits no client span, so only a request the application itself makes forms a topology edge.
- `L7-app-mediated-request` technique — reaches a backend through an application that forwards caller-supplied URLs rather than directly from the attacker's pod.
- Multi-provider LLM support for `kimera generate`. A single entry point (`kimera/core/llm.py`) replaces three duplicated Anthropic SDK call sites and selects a backend in a documented order: `KIMERA_LLM_PROVIDER` override, a `provider/model` prefix routed through litellm (`openai/`, `bedrock/`, `gemini/`, `ollama/`), `ANTHROPIC_API_KEY` via the Anthropic SDK, then the `claude` CLI using an existing Claude subscription with no API key. An override that cannot be honoured is an error rather than a silent fallback to a different model, so a run is always attributable to the model that was asked for. New `litellm` extra; `all` now composes the other extras instead of re-listing them.

### Fixed

- `kimera generate` exited with a raw traceback when no LLM backend was configured or when `ANTHROPIC_API_KEY` was rejected. Both now report actionable guidance, and a rejected key names the override needed to reach a Claude subscription instead.
- The subscription backend removes `ANTHROPIC_API_KEY` from the CLI subprocess environment. The `claude` CLI treats that variable as taking precedence over the signed-in session and refuses to use the subscription while it is set, so a stale key anywhere in the environment made the backend unusable.
- The `claude-cli` backend ran from the caller's working directory, so the CLI loaded that directory's project instructions and hooks and answered with them mixed in. It now runs from an empty directory.
- `kimera generate --enrich dynatrace` raised `TypeError: TargetedQueryStrategy() takes no arguments`. The `--model` flag has a non-empty default, so `model=` was forwarded to every strategy while only `llm-query` accepts it; `create_strategy` now drops arguments the chosen strategy does not take.
- Docstrings and error messages told users to install a `kimera[dt-mcp]` extra that does not exist. The extra is `kimera[mcp-server]`.
- The default model was hardcoded in three separate files and is now defined once.

- `kimera generate` now closes egress against the ingress rules it wrote. Egress selectors assumed a label shared across a namespace that subchart-managed pods do not carry, severing 22 of 50 declared flows in a measured set. The destination selector is copied from the destination policy's own `podSelector`, so no label is inferred, and each added rule is scoped to the declared port.
- `kimera validate-control --type network-policy` probed only from an unlabeled pod, so every check passed whenever a default-deny policy existed — including against a policy set that severed the database. A `policy-reachability` check now reports, as ERROR, each flow an ingress rule permits that the source's egress denies.
- `kimera generate --type missing-network-policies` enumerated only Deployments and StatefulSets, so CronJob-managed workloads got no policy while the generated `default-deny-all` denied them all traffic. CronJobs now enter the generation context and the prompt.
- The Smartscape topology query requested `getNodeField(id, "k8s.workload.name")`, which is null on every node, and scoped edges by display name, keeping 15 of 128 in a measured window. It now filters on `source_type`/`target_type == "SERVICE"`; `SmartscapeEdge` drops its workload fields, and `dql_reference.yaml` records that neither `k8s.workload.name` nor `k8s.cluster.name` resolves on SERVICE nodes.
- Cilium install guidance printed by `kimera enforce enable` omitted the EKS case: the plain `ipam.mode=kubernetes` install does not work alongside the AWS VPC CNI. Guidance now includes the `cni.chainingMode=aws-cni` variant and the pod-restart caveat, and targets Cilium 1.20.0.
- `kimera apply` reported `[SUCCESS] Applied 0/N resources` when every resource failed; partial and total failures now report at warning and error severity.
- HTTP probe false negatives and false "secure" verdicts: `curl`/`wget` absent from a target image made reachability probes report `UNREACHABLE` and made capability probes report `Protected: Cannot list secrets` — an affirmative secure result produced by a probe that never ran. HTTP probes now fall back `curl` → `wget` and report `UNKNOWN (no probe tool)` otherwise, via the shared `kimera_http_reachable` / `kimera_http_get` / `kimera_http_post` prelude helpers. All 15 HTTP probe sites migrated.
- Evidence markers matched by substring, so the success marker `REACHABLE` fired on the failure text `UNREACHABLE` — a demonstration reported lateral movement as proven while every probe had failed. Markers now match whole tokens only.
- Probe false negatives: `nc`/`nslookup` absent from a target image made port and DNS probes report `CLOSED` / `0 services discovered`, indistinguishable from a genuinely blocked port. Probes now fall back to `bash /dev/tcp` and `getent hosts`, and report `UNKNOWN (no probe tool)` when no method exists — never `CLOSED`. `validate-control` reports `ERROR` for an untestable check instead of `PASS`. All probe shell is emitted from a single prelude in `probe_runner.py`; no module or config file constructs probe commands inline.

## [0.1.0] - 2026-07-13

Versioning restarted at 0.1.0 for the open-source release. The `v1.0.0`, `v1.1.0` and `v2.0.0`
tags predate it and are retained as history.

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
- NetworkPolicy enforcement detection (`kimera enforce enable/disable/status`) for Cilium
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
- Removed `scripts/` from version control — development scaffolding referenced by no packaged code, test or workflow

### Fixed

- Admission validation test isolation: `_detect_admission_controllers` now uses the passed `K8sClient`'s pre-initialized API handles
- mypy errors across `registry.py`, `assessor.py`, `api_executor.py`, `deployment_patch.py`, `mcp/server.py`, `cli/exploit.py`, `cli/generate.py`, and test files
- Stale `kimera/cli.py` stub removed (conflicted with `kimera/cli/` package causing mypy duplicate-module error)
- Helm templates excluded from `check-yaml` pre-commit hook
- Upgraded `click` to 8.3.3+ (PYSEC-2026-2132) and `pip` to 26.1.2 (PYSEC-2026-196)
