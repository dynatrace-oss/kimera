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

import shlex
from typing import Any

from .probe_prelude import PROBE_PRELUDE, UNKNOWN_STATE

# Supported test operators for path_exists probes
_VALID_CHECKS = {"-e", "-f", "-d", "-c", "-S", "-r", "-w", "-x"}

DEFAULT_HTTP_TIMEOUT = 5

# Prefix of a path record: parsed into an AttackPath, then stripped from the output.
# Only probes declaring a host and port emit one.
PATH_MARKER = "KIMERA_PATH|"

# Cluster DNS suffix appended after the namespace segment.
DEFAULT_DNS_SUFFIX = "svc.cluster.local"
DEFAULT_MAX_BODY_BYTES = 512


class ProbeRunner:
    """Generate shell scripts from structured probe definitions."""

    def build_script(self, probes: list[dict[str, Any]]) -> str:
        """Convert a list of probe dicts into a single shell script.

        The shared prelude is prepended so every probe, including raw ``command``
        ones, can call its helpers instead of re-implementing tool detection.

        Args:
            probes: List of probe definitions, each with a ``type`` key.

        Returns:
            Concatenated shell script string.

        Raises:
            ValueError: If a probe has an unknown type.
        """
        parts: list[str] = []
        for probe in probes:
            probe_type = probe.get("type", "")
            builder = getattr(self, f"_build_{probe_type}", None)
            if not builder:
                raise ValueError(f"Unknown probe type: {probe_type!r}")
            parts.append(builder(probe))
        if not parts:
            return ""
        return PROBE_PRELUDE + "\n" + "\n".join(parts)

    # -- Probe builders -------------------------------------------------------

    @staticmethod
    def _build_writable(probe: dict[str, Any]) -> str:
        """Check if a path is writable."""
        path = probe["path"]
        msg = probe.get("vulnerable_msg", f"Writable: {path}")
        return (
            f'if [ -w "{path}" ]; then\n'
            f'    echo "❌ VULNERABLE: {msg}"\n'
            f"else\n"
            f'    echo "✅ Protected: {path} not writable"\n'
            f"fi"
        )

    @staticmethod
    def _build_path_exists(probe: dict[str, Any]) -> str:
        """Check if a file, directory, device, or socket exists."""
        path = probe["path"]
        check = probe.get("check", "-e")
        if check not in _VALID_CHECKS:
            raise ValueError(f"Invalid check operator: {check!r}")
        msg = probe.get("vulnerable_msg", f"Path accessible: {path}")
        return (
            f'if [ {check} "{path}" ]; then\n'
            f'    echo "❌ VULNERABLE: {msg}"\n'
            f"else\n"
            f'    echo "✅ Protected: {path} not accessible"\n'
            f"fi"
        )

    @staticmethod
    def _build_capability_check(probe: dict[str, Any]) -> str:
        """Read Linux capabilities from /proc and compare."""
        field = probe.get("field", "CapEff")
        vulnerable_values = probe.get("vulnerable_values", [])
        all_nonzero = probe.get("all_nonzero", False)

        lines = [
            'echo "[*] Checking capabilities..."',
            f"cap_val=$(cat /proc/1/status | grep {field} | awk '{{print $2}}')",
            f'echo "{field}: $cap_val"',
        ]

        for val in vulnerable_values:
            lines.append(
                f'if [ "$cap_val" = "{val}" ]; then\n'
                f'    echo "❌ VULNERABLE: {field} = {val} — ALL Linux capabilities enabled!"\n'
                f"fi"
            )

        if all_nonzero:
            lines.append(
                'if [ "$cap_val" != "0000000000000000" ] && '
                '[ "$cap_val" != "" ]; then\n'
                '    echo "❌ VULNERABLE: Has dangerous capabilities!"\n'
                "fi"
            )

        return "\n".join(lines)

    @staticmethod
    def _build_port_open(probe: dict[str, Any]) -> str:
        """Check TCP port reachability using the first available probe method.

        Emits a path record from the probe definition, not the label — the label
        is free text and rewording it would silently break path capture.
        """
        host = probe["host"]
        port = probe["port"]
        timeout = probe.get("timeout", 2)
        label = probe.get("label", f"{host}:{port}")
        return (
            f'echo -n "  {label} -> "\n'
            f"_state=$(kimera_port_open {host} {port} {timeout})\n"
            f'echo "$_state"\n'
            f'echo "{PATH_MARKER}{host}|{port}|TCP|$_state"'
        )

    @staticmethod
    def _build_dns_resolve(probe: dict[str, Any]) -> str:
        """Resolve each declared name and report the ones that answer.

        Emits no path record: a name resolving proves the cluster's DNS answers,
        not that the resolver may connect to what it names.
        """
        hosts = probe.get("hosts", [])
        if not hosts:
            return ""
        suffix = probe.get("suffix", DEFAULT_DNS_SUFFIX)
        return (
            'echo "[*] Enumerating services via DNS..."\n'
            "ns=$(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace)\n"
            "found=0\n"
            "no_tool=0\n"
            f"for svc in {' '.join(str(h) for h in hosts)}; do\n"
            f'    addr=$(kimera_resolve "${{svc}}.${{ns}}.{suffix}")\n'
            "    if [ $? -eq 2 ]; then\n"
            "        no_tool=1\n"
            "        break\n"
            "    fi\n"
            '    if [ -n "$addr" ]; then\n'
            '        echo "  FOUND: ${svc} -> ${addr}"\n'
            "        found=$((found + 1))\n"
            "    fi\n"
            "done\n"
            'if [ "$no_tool" -eq 1 ]; then\n'
            f'    echo "[*] DNS enumeration: {UNKNOWN_STATE}"\n'
            "else\n"
            '    echo "[*] Total services discovered: $found"\n'
            "fi"
        )

    @staticmethod
    def _build_count_check(probe: dict[str, Any]) -> str:
        """Count entries matching a pattern and compare against threshold."""
        path = probe["path"]
        pattern = probe.get("pattern", ".*")
        threshold = probe.get("threshold", 50)
        msg = probe.get("vulnerable_msg", f"Count exceeds {threshold}")
        return (
            f"count=$(ls \"{path}\" 2>/dev/null | grep -E '{pattern}' | wc -l)\n"
            f'echo "[*] Count: $count"\n'
            f'if [ "$count" -gt {threshold} ]; then\n'
            f'    echo "❌ VULNERABLE: {msg}"\n'
            f"else\n"
            f'    echo "✅ Protected: count within limits"\n'
            f"fi"
        )

    @staticmethod
    def _build_file_content(probe: dict[str, Any]) -> str:
        """Read a file and check if content matches vulnerable values."""
        path = probe["path"]
        vulnerable_values = probe.get("vulnerable_values", [])
        msg = probe.get("vulnerable_msg", f"Vulnerable content in {path}")

        lines = [f'if [ -f "{path}" ]; then', f'    val=$(cat "{path}" 2>/dev/null)']

        conditions = " || ".join(f'[ "$val" = "{v}" ]' for v in vulnerable_values)
        if conditions:
            lines.extend(
                [
                    f"    if {conditions}; then",
                    f'        echo "❌ VULNERABLE: {msg}"',
                    "    else",
                    f'        echo "✅ Protected: {path} = $val"',
                    "    fi",
                ]
            )

        lines.extend(
            [
                "else",
                f'    echo "[!] {path} not found"',
                "fi",
            ]
        )

        return "\n".join(lines)

    @staticmethod
    def _build_socket_check(probe: dict[str, Any]) -> str:
        """Check if Unix sockets exist at specified paths."""
        paths = probe.get("paths", [])
        msg = probe.get("vulnerable_msg", "Socket accessible")
        lines = []
        for path in paths:
            lines.append(
                f'if [ -S "{path}" ] || [ -S "/proc/1/root{path}" ]; then\n'
                f'    echo "❌ VULNERABLE: {msg} — {path}"\n'
                f"fi"
            )
        return "\n".join(lines)

    @staticmethod
    def _build_app_request(probe: dict[str, Any]) -> str:
        """Request an application endpoint and report status plus a bounded response body.

        The only probe whose traffic an APM agent can attribute, since the next hop
        is the application's own. The body is reported because a status code alone
        cannot tell a forwarded request from one answered locally.
        """
        url = shlex.quote(str(probe["url"]))
        timeout = probe.get("timeout", DEFAULT_HTTP_TIMEOUT)
        max_body = probe.get("max_body", DEFAULT_MAX_BODY_BYTES)
        label = probe.get("label", str(probe["url"]))
        return (
            f'echo -n "  {label} -> "\n'
            f"_st=$(kimera_http_reachable {url} {timeout})\n"
            f'echo "$_st"\n'
            f'case "$_st" in\n'
            f"REACHABLE*)\n"
            f"    _body=$(kimera_http_get {url} {timeout})\n"
            f'    _len=$(printf %s "$_body" | wc -c)\n'
            f'    printf "    body: %s\\n" "$(printf %s "$_body" | head -c {max_body})"\n'
            f'    if [ "$_len" -gt {max_body} ]; then\n'
            f'        echo "    body truncated at {max_body} bytes"\n'
            f"    fi\n"
            f"    ;;\n"
            f"esac"
        )

    @staticmethod
    def _build_command(probe: dict[str, Any]) -> str | Any:
        """Raw shell command escape hatch for complex operations."""
        return str(probe["run"]).rstrip()
