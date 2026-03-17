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

"""Tests for ProbeRunner — structured probe to shell script generation."""

import pytest

from kimera.container.make_vulnerable.probe_runner import ProbeRunner


@pytest.fixture
def runner() -> ProbeRunner:
    """Create a ProbeRunner instance."""
    return ProbeRunner()


class TestWritableProbe:
    """Tests for the writable probe type."""

    def test_generates_writable_check(self, runner: ProbeRunner) -> None:
        """Test writable probe generates correct shell."""
        script = runner.build_script([{"type": "writable", "path": "/sys"}])
        assert '[ -w "/sys" ]' in script
        assert "VULNERABLE" in script
        assert "Protected" in script

    def test_custom_message(self, runner: ProbeRunner) -> None:
        """Test writable probe with custom vulnerable message."""
        script = runner.build_script(
            [{"type": "writable", "path": "/sys", "vulnerable_msg": "Full access!"}]
        )
        assert "Full access!" in script


class TestPathExistsProbe:
    """Tests for the path_exists probe type."""

    def test_default_check(self, runner: ProbeRunner) -> None:
        """Test path_exists with default -e check."""
        script = runner.build_script([{"type": "path_exists", "path": "/dev/mem"}])
        assert '[ -e "/dev/mem" ]' in script

    def test_directory_check(self, runner: ProbeRunner) -> None:
        """Test path_exists with -d check."""
        script = runner.build_script(
            [{"type": "path_exists", "path": "/proc/1/root", "check": "-d"}]
        )
        assert '[ -d "/proc/1/root" ]' in script

    def test_socket_check_operator(self, runner: ProbeRunner) -> None:
        """Test path_exists with -S (socket) check."""
        script = runner.build_script(
            [{"type": "path_exists", "path": "/var/run/docker.sock", "check": "-S"}]
        )
        assert '[ -S "/var/run/docker.sock" ]' in script

    def test_invalid_check_raises(self, runner: ProbeRunner) -> None:
        """Test that invalid check operator raises ValueError."""
        with pytest.raises(ValueError, match="Invalid check operator"):
            runner.build_script([{"type": "path_exists", "path": "/x", "check": "-z"}])


class TestCapabilityCheckProbe:
    """Tests for the capability_check probe type."""

    def test_checks_specific_values(self, runner: ProbeRunner) -> None:
        """Test capability probe checks specified values."""
        script = runner.build_script(
            [
                {
                    "type": "capability_check",
                    "field": "CapEff",
                    "vulnerable_values": ["000001ffffffffff"],
                }
            ]
        )
        assert "CapEff" in script
        assert "000001ffffffffff" in script
        assert "ALL Linux capabilities" in script

    def test_all_nonzero_flag(self, runner: ProbeRunner) -> None:
        """Test capability probe with all_nonzero flag."""
        script = runner.build_script([{"type": "capability_check", "all_nonzero": True}])
        assert "0000000000000000" in script
        assert "Has dangerous capabilities" in script


class TestPortOpenProbe:
    """Tests for the port_open probe type."""

    def test_generates_nc_command(self, runner: ProbeRunner) -> None:
        """Test port probe generates nc command."""
        script = runner.build_script([{"type": "port_open", "host": "k8s.default", "port": 443}])
        assert "nc -z -w 2 k8s.default 443" in script
        assert "OPEN" in script
        assert "CLOSED" in script

    def test_custom_timeout(self, runner: ProbeRunner) -> None:
        """Test port probe with custom timeout."""
        script = runner.build_script(
            [{"type": "port_open", "host": "db", "port": 3306, "timeout": 5}]
        )
        assert "nc -z -w 5 db 3306" in script

    def test_custom_label(self, runner: ProbeRunner) -> None:
        """Test port probe with custom label."""
        script = runner.build_script(
            [
                {
                    "type": "port_open",
                    "host": "api",
                    "port": 443,
                    "label": "K8s API :443",
                }
            ]
        )
        assert "K8s API :443" in script


class TestCountCheckProbe:
    """Tests for the count_check probe type."""

    def test_generates_count_check(self, runner: ProbeRunner) -> None:
        """Test count probe generates correct shell."""
        script = runner.build_script([{"type": "count_check", "path": "/proc", "threshold": 50}])
        assert '"/proc"' in script
        assert "-gt 50" in script


class TestFileContentProbe:
    """Tests for the file_content probe type."""

    def test_checks_file_values(self, runner: ProbeRunner) -> None:
        """Test file content probe checks specified values."""
        script = runner.build_script(
            [
                {
                    "type": "file_content",
                    "path": "/sys/fs/cgroup/memory.max",
                    "vulnerable_values": ["max"],
                    "vulnerable_msg": "No memory limit",
                }
            ]
        )
        assert "/sys/fs/cgroup/memory.max" in script
        assert '"max"' in script
        assert "No memory limit" in script


class TestSocketCheckProbe:
    """Tests for the socket_check probe type."""

    def test_checks_multiple_paths(self, runner: ProbeRunner) -> None:
        """Test socket probe checks multiple paths."""
        script = runner.build_script(
            [
                {
                    "type": "socket_check",
                    "paths": ["/var/run/docker.sock", "/run/containerd/containerd.sock"],
                    "vulnerable_msg": "Runtime socket found",
                }
            ]
        )
        assert "/var/run/docker.sock" in script
        assert "/run/containerd/containerd.sock" in script
        assert "Runtime socket found" in script


class TestCommandProbe:
    """Tests for the command (escape hatch) probe type."""

    def test_passes_through_raw_script(self, runner: ProbeRunner) -> None:
        """Test command probe returns raw script verbatim."""
        raw = 'echo "hello world"\nls -la'
        script = runner.build_script([{"type": "command", "run": raw}])
        assert script == raw

    def test_strips_trailing_newline(self, runner: ProbeRunner) -> None:
        """Test that trailing newlines are stripped."""
        script = runner.build_script([{"type": "command", "run": "echo hi\n\n"}])
        assert script == "echo hi"


class TestBuildScript:
    """Tests for the build_script composition."""

    def test_unknown_type_raises(self, runner: ProbeRunner) -> None:
        """Test that unknown probe type raises ValueError."""
        with pytest.raises(ValueError, match="Unknown probe type"):
            runner.build_script([{"type": "nonexistent"}])

    def test_composes_multiple_probes(self, runner: ProbeRunner) -> None:
        """Test that multiple probes are concatenated."""
        script = runner.build_script(
            [
                {"type": "writable", "path": "/sys"},
                {"type": "path_exists", "path": "/dev/mem"},
            ]
        )
        assert "/sys" in script
        assert "/dev/mem" in script
        # Should be two separate blocks joined by newline
        assert script.count("VULNERABLE") >= 2
