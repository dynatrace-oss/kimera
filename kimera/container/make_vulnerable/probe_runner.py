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


class ProbeRunner:
    """Generate shell scripts from structured probe definitions."""

    def build_script(self, probes: list[dict[str, Any]]) -> str:
        """Convert a list of probe dicts into a single shell script.

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
        return "\n".join(parts)

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
        """Check TCP port reachability via nc."""
        host = probe["host"]
        port = probe["port"]
        timeout = probe.get("timeout", 2)
        label = probe.get("label", f"{host}:{port}")
        return (
            f'echo -n "  {label} -> "\n'
            f"if nc -z -w {timeout} {host} {port} 2>/dev/null; then\n"
            f'    echo "OPEN"\n'
            f"else\n"
            f'    echo "CLOSED"\n'
            f"fi"
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
    def _build_command(probe: dict[str, Any]) -> str | Any:
        """Raw shell command escape hatch for complex operations."""
        return str(probe["run"]).rstrip()
