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

from typing import Any

# Supported test operators for path_exists probes
_VALID_CHECKS = {"-e", "-f", "-d", "-c", "-S", "-r", "-w", "-x"}

UNKNOWN_STATE = "UNKNOWN (no probe tool)"

# Emitted once per script and called by every probe that touches the network, so that
# "we proved this is closed" is never confused with "we had no tool to test it".
# POSIX sh only — exec_in_pod runs scripts under /bin/sh.
PROBE_PRELUDE = f"""\
kimera_port_open() {{
    if command -v nc >/dev/null 2>&1; then
        if nc -z -w "$3" "$1" "$2" >/dev/null 2>&1; then echo OPEN; else echo CLOSED; fi
    elif command -v bash >/dev/null 2>&1 && command -v timeout >/dev/null 2>&1; then
        if timeout "$3" bash -c "exec 3<>/dev/tcp/$1/$2" >/dev/null 2>&1; then
            echo OPEN
        else
            echo CLOSED
        fi
    else
        echo "{UNKNOWN_STATE}"
    fi
}}

kimera_resolve() {{
    if command -v nslookup >/dev/null 2>&1; then
        nslookup "$1" 2>/dev/null | awk '/^Address: /{{print $2}}' | tail -1
    elif command -v getent >/dev/null 2>&1; then
        getent hosts "$1" 2>/dev/null | awk '{{print $1}}' | head -1
    else
        return 2
    fi
}}

kimera_tcp_send() {{
    if command -v nc >/dev/null 2>&1; then
        nc -w "$3" "$1" "$2" 2>/dev/null
    elif command -v bash >/dev/null 2>&1 && command -v timeout >/dev/null 2>&1; then
        timeout "$3" bash -c '
            exec 3<>/dev/tcp/"$0"/"$1" || exit 1
            cat >&3
            cat <&3
        ' "$1" "$2" 2>/dev/null
    else
        return 2
    fi
}}

kimera_http_reachable() {{
    if command -v curl >/dev/null 2>&1; then
        _code=$(curl -sk -o /dev/null -w "%{{http_code}}" -m "$2" "$1" 2>/dev/null)
    elif command -v wget >/dev/null 2>&1; then
        _code=$(wget -q -O /dev/null -T "$2" -S "$1" 2>&1 \\
                | awk '/^  HTTP\\//{{print $2}}' | tail -1)
    else
        echo "{UNKNOWN_STATE}"
        return 2
    fi
    if [ -n "$_code" ] && [ "$_code" != "000" ] && [ "$_code" != "0" ]; then
        echo "REACHABLE (HTTP $_code)"
    else
        echo UNREACHABLE
    fi
}}

kimera_http_get() {{
    _url=$1
    _tmo=$2
    shift 2
    if command -v curl >/dev/null 2>&1; then
        for _h in "$@"; do set -- "$@" -H "$_h"; shift; done
        curl -sk -m "$_tmo" "$@" "$_url" 2>/dev/null
    elif command -v wget >/dev/null 2>&1; then
        for _h in "$@"; do set -- "$@" --header="$_h"; shift; done
        wget -q -O- --timeout="$_tmo" --no-check-certificate "$@" "$_url" 2>/dev/null
    else
        return 2
    fi
}}

kimera_http_post() {{
    _url=$1
    _tmo=$2
    _body=$3
    shift 3
    if command -v curl >/dev/null 2>&1; then
        for _h in "$@"; do set -- "$@" -H "$_h"; shift; done
        curl -sk -m "$_tmo" -X POST -d "$_body" "$@" "$_url" 2>/dev/null
    elif command -v wget >/dev/null 2>&1; then
        for _h in "$@"; do set -- "$@" --header="$_h"; shift; done
        wget -q -O- --timeout="$_tmo" --no-check-certificate \\
            --post-data="$_body" "$@" "$_url" 2>/dev/null
    else
        return 2
    fi
}}
"""


class ProbeRunner:
    """Generate shell scripts from structured probe definitions."""

    def build_script(self, probes: list[dict[str, Any]]) -> str:
        """Convert a list of probe dicts into a single shell script.

        The shared probe prelude is prepended so every probe — including raw
        ``command`` probes defined in YAML — can call ``kimera_port_open`` and
        ``kimera_resolve`` instead of re-implementing tool detection.

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
        """Check TCP port reachability using the first available probe method."""
        host = probe["host"]
        port = probe["port"]
        timeout = probe.get("timeout", 2)
        label = probe.get("label", f"{host}:{port}")
        return f'echo -n "  {label} -> "\nkimera_port_open {host} {port} {timeout}'

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
    def _build_command(probe: dict[str, Any]) -> str | Any:
        """Raw shell command escape hatch for complex operations."""
        return str(probe["run"]).rstrip()
