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

import http.server
import os
import re
import shutil
import socket
import subprocess
import tempfile
import threading
from pathlib import Path
from typing import ClassVar

import pytest

from kimera.container.make_vulnerable.base import _marker_matches
from kimera.container.make_vulnerable.probe_prelude import PROBE_PRELUDE, UNKNOWN_STATE
from kimera.container.make_vulnerable.probe_runner import ProbeRunner


class _SilentHandler(http.server.BaseHTTPRequestHandler):
    """Echoes request headers and body so header/body propagation is observable."""

    def _respond(self, payload: bytes, status: int = 200) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        # Routes used by the app_request probe tests; any other path keeps the
        # header-echo behaviour the prelude tests rely on.
        if self.path.startswith("/status/"):
            self._respond(b"error-page-body", int(self.path.rsplit("/", 1)[1]))
        elif self.path == "/big":
            self._respond(b"A" * 4096)
        elif self.path == "/empty":
            self._respond(b"")
        else:
            self._respond(self.headers.get("X-Kimera", "ok").encode())

    def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        length = int(self.headers.get("Content-Length", 0))
        self._respond(self.rfile.read(length) or b"ok")

    def log_message(self, *args: object) -> None:
        return


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

    def test_delegates_to_shared_helper_with_default_timeout(self, runner: ProbeRunner) -> None:
        """Port probe calls the shared helper rather than emitting a tool inline."""
        script = runner.build_script([{"type": "port_open", "host": "k8s.default", "port": 443}])
        assert "kimera_port_open k8s.default 443 2" in script

    def test_custom_timeout(self, runner: ProbeRunner) -> None:
        """Test port probe with custom timeout."""
        script = runner.build_script(
            [{"type": "port_open", "host": "db", "port": 3306, "timeout": 5}]
        )
        assert "kimera_port_open db 3306 5" in script

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
        assert script.endswith(raw)
        assert script.startswith(PROBE_PRELUDE)

    def test_strips_trailing_newline(self, runner: ProbeRunner) -> None:
        """Test that trailing newlines are stripped."""
        script = runner.build_script([{"type": "command", "run": "echo hi\n\n"}])
        assert script.endswith("echo hi")


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


class _PreludeSandbox:
    """PATH sandbox shared by the prelude behaviour tests. Not collected."""

    _sandbox_cache: ClassVar[dict[tuple[str, ...], str]] = {}

    @classmethod
    def _sandbox(cls, tools: tuple[str, ...]) -> dict[str, str]:
        # Built once per tool-set: on macOS each freshly created symlink to a
        # Homebrew binary costs a multi-second Gatekeeper scan on first exec.
        if tools in cls._sandbox_cache:
            return {**os.environ, "PATH": cls._sandbox_cache[tools]}
        bin_dir = Path(tempfile.mkdtemp()) / "bin"
        bin_dir.mkdir(parents=True, exist_ok=True)
        for tool in tools:
            target = bin_dir / tool
            if tool == "timeout" and shutil.which("timeout") is None:
                target.write_text('#!/bin/sh\nshift\nexec "$@"\n')
                target.chmod(0o755)
            else:
                # Prefer the system bash: a Homebrew binary reached through a new
                # symlink costs a multi-second Gatekeeper scan on every exec.
                source = "/bin/bash" if tool == "bash" and Path("/bin/bash").exists() else None
                source = source or shutil.which(tool)
                if source:
                    target.symlink_to(source)
        for helper in ("awk", "tail", "head", "wc"):
            path = shutil.which(helper)
            if path and not (bin_dir / helper).exists():
                (bin_dir / helper).symlink_to(path)
        cls._sandbox_cache[tools] = str(bin_dir)
        return {**os.environ, "PATH": str(bin_dir)}

    @pytest.fixture
    def closed_port(self):
        sock = socket.socket()
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
        sock.close()
        return port


class TestProbePreludeBehaviour(_PreludeSandbox):
    """Execute the emitted prelude under /bin/sh with tool availability controlled via PATH.

    These assert behaviour, not text: a wrong fallback chain still looks plausible
    in the emitted string but reports the wrong state when it runs.
    """

    def _probe(self, tools: tuple[str, ...], host: str, port: int) -> str:
        result: subprocess.CompletedProcess[str] = subprocess.run(  # noqa: S603 - fixed argv, test-controlled host/port
            ["/bin/sh", "-c", f"{PROBE_PRELUDE}\nkimera_port_open {host} {port} 2"],
            capture_output=True,
            text=True,
            env=self._sandbox(tools),
        )
        return result.stdout.strip()

    @pytest.fixture
    def open_port(self):
        sock = socket.socket()
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("127.0.0.1", 0))
        sock.listen(5)
        yield sock.getsockname()[1]
        sock.close()

    @pytest.mark.parametrize(
        "tools,expected",
        [
            (("nc", "bash", "timeout"), "OPEN"),
            (("bash", "timeout"), "OPEN"),
            (("nc",), "OPEN"),
            (("bash",), UNKNOWN_STATE),
            ((), UNKNOWN_STATE),
        ],
    )
    def test_reachable_port_by_available_tooling(self, tools, expected, open_port):
        assert self._probe(tools, "127.0.0.1", open_port) == expected

    @pytest.mark.parametrize(
        "tools,expected",
        [
            (("nc", "bash", "timeout"), "CLOSED"),
            (("bash", "timeout"), "CLOSED"),
            (("bash",), UNKNOWN_STATE),
            ((), UNKNOWN_STATE),
        ],
    )
    def test_unreachable_port_never_reports_closed_without_a_tool(
        self, tools, expected, closed_port
    ):
        assert self._probe(tools, "127.0.0.1", closed_port) == expected


class TestHttpPreludeBehaviour(_PreludeSandbox):
    """A missing HTTP client must never be reported as an unreachable endpoint.

    Inherits the PATH sandbox: `unguard-ad-service` ships wget but no curl, and
    `unguard-like-service` the reverse, so both single-client rows are real images.
    """

    @pytest.fixture
    def http_server(self):
        server = http.server.HTTPServer(("127.0.0.1", 0), _SilentHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        yield server.server_address[1]
        server.shutdown()
        server.server_close()

    def _http(self, tools: tuple[str, ...], url: str) -> str:
        result: subprocess.CompletedProcess[str] = subprocess.run(  # noqa: S603 - fixed argv, test-controlled url
            ["/bin/sh", "-c", f"{PROBE_PRELUDE}\nkimera_http_reachable {url} 2"],
            capture_output=True,
            text=True,
            env=self._sandbox(tools),
        )
        return result.stdout.strip()

    @pytest.mark.parametrize(
        "tools,expected",
        [
            (("curl", "wget"), "REACHABLE (HTTP 200)"),
            (("curl",), "REACHABLE (HTTP 200)"),
            (("wget",), "REACHABLE (HTTP 200)"),
            ((), UNKNOWN_STATE),
        ],
    )
    def test_reachable_endpoint_by_available_client(self, tools, expected, http_server):
        assert self._http(tools, f"http://127.0.0.1:{http_server}/") == expected

    @pytest.mark.parametrize(
        "tools,expected",
        [
            (("curl", "wget"), "UNREACHABLE"),
            (("curl",), "UNREACHABLE"),
            (("wget",), "UNREACHABLE"),
            ((), UNKNOWN_STATE),
        ],
    )
    def test_blocked_endpoint_never_unreachable_without_a_client(
        self, tools, expected, closed_port
    ):
        assert self._http(tools, f"http://127.0.0.1:{closed_port}/") == expected

    def test_get_signals_missing_client_by_exit_status(self, http_server):
        script = (
            f"{PROBE_PRELUDE}\n"
            f'body=$(kimera_http_get http://127.0.0.1:{http_server}/ 2); echo "exit=$?"'
        )
        for tools, expected in ((("curl",), "exit=0"), ((), "exit=2")):
            result = subprocess.run(  # noqa: S603 - fixed argv, test-controlled url
                ["/bin/sh", "-c", script],
                capture_output=True,
                text=True,
                env=self._sandbox(tools),
            )
            assert expected in result.stdout

    @pytest.mark.parametrize("tools", [("curl",), ("wget",)])
    def test_get_sends_request_headers(self, tools, http_server):
        script = (
            f"{PROBE_PRELUDE}\n"
            f'kimera_http_get http://127.0.0.1:{http_server}/hdr 2 "X-Kimera: probe"'
        )
        result = subprocess.run(  # noqa: S603 - fixed argv, test-controlled url
            ["/bin/sh", "-c", script],
            capture_output=True,
            text=True,
            env=self._sandbox(tools),
        )
        assert "probe" in result.stdout

    @pytest.mark.parametrize("tools", [("curl",), ("wget",)])
    def test_post_sends_request_body(self, tools, http_server):
        script = (
            f"{PROBE_PRELUDE}\n"
            f"kimera_http_post http://127.0.0.1:{http_server}/echo 2 '{{\"allowed\":true}}'"
        )
        result = subprocess.run(  # noqa: S603 - fixed argv, test-controlled url
            ["/bin/sh", "-c", script],
            capture_output=True,
            text=True,
            env=self._sandbox(tools),
        )
        assert '"allowed":true' in result.stdout


class TestAppRequestProbe(_PreludeSandbox):
    """Drive the emitted script for real: the probe's value is what it reports, not its text.

    The probe exists to make one distinction — an application that forwarded the request
    versus one that answered without forwarding — and only the response body carries it.
    """

    @pytest.fixture
    def http_server(self):
        server = http.server.HTTPServer(("127.0.0.1", 0), _SilentHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        yield server.server_address[1]
        server.shutdown()
        server.server_close()

    def _run(
        self,
        runner: ProbeRunner,
        url: str,
        tools: tuple[str, ...] = ("curl",),
        **probe: object,
    ) -> str:
        script = runner.build_script([{"type": "app_request", "url": url, **probe}])
        result: subprocess.CompletedProcess[str] = subprocess.run(  # noqa: S603 - fixed argv, test-controlled url
            ["/bin/sh", "-c", script],
            capture_output=True,
            text=True,
            env=self._sandbox(tools),
        )
        return result.stdout

    def test_emits_the_configured_url_and_no_other(self, runner, http_server):
        url = f"http://127.0.0.1:{http_server}/only-this"
        script = runner.build_script([{"type": "app_request", "url": url}])
        assert url in script
        # The probe must request nothing the operator did not configure.
        assert set(re.findall(r"https?://[^\s'\"]+", script)) == {url}

    def test_percent_encoded_target_survives_verbatim(self, runner):
        # An SSRF endpoint carries its target as an encoded parameter; re-encoding
        # or unescaping it silently changes which host the application contacts.
        url = "http://svc/image?url=http%3A%2F%2Fbackend%2Fpath%3Fa%3D1"
        script = runner.build_script([{"type": "app_request", "url": url}])
        assert "http%3A%2F%2Fbackend%2Fpath%3Fa%3D1" in script

    @pytest.mark.parametrize("tools", [("curl",), ("wget",)])
    def test_reports_status_and_body(self, runner, tools, http_server):
        out = self._run(runner, f"http://127.0.0.1:{http_server}/hello", tools)
        assert "200" in out
        assert "ok" in out

    @pytest.mark.parametrize("tools", [("curl",), ("wget",)])
    def test_body_is_reported_for_a_non_success_status(self, runner, tools, http_server):
        # The case the probe exists for: a 404 body is how a refusal to forward
        # is told apart from the downstream target's own response.
        out = self._run(runner, f"http://127.0.0.1:{http_server}/status/404", tools)
        assert "404" in out
        assert "error-page-body" in out
        assert "UNREACHABLE" not in out

    def test_oversized_body_is_truncated_and_marked(self, runner, http_server):
        out = self._run(runner, f"http://127.0.0.1:{http_server}/big", max_body=64)
        assert "A" * 64 in out
        assert "A" * 65 not in out
        assert "truncated" in out

    def test_body_within_limit_is_not_marked_truncated(self, runner, http_server):
        out = self._run(runner, f"http://127.0.0.1:{http_server}/hello", max_body=512)
        assert "truncated" not in out

    def test_empty_body_is_not_reported_as_unreachable(self, runner, http_server):
        out = self._run(runner, f"http://127.0.0.1:{http_server}/empty")
        assert "200" in out
        assert "UNREACHABLE" not in out

    def test_connection_failure_reports_no_status_code(self, runner, closed_port):
        out = self._run(runner, f"http://127.0.0.1:{closed_port}/")
        assert "UNREACHABLE" in out
        assert "HTTP" not in out

    def test_absent_http_client_reports_unknown_not_a_negative(self, runner, http_server):
        out = self._run(runner, f"http://127.0.0.1:{http_server}/hello", tools=())
        assert UNKNOWN_STATE in out
        assert "UNREACHABLE" not in out
        assert "200" not in out

    def test_unknown_state_does_not_fire_a_success_marker(self, runner, http_server):
        out = self._run(runner, f"http://127.0.0.1:{http_server}/hello", tools=())
        assert _marker_matches("REACHABLE", out) is False

    def test_output_claims_nothing_about_observability(self, runner, http_server):
        out = self._run(runner, f"http://127.0.0.1:{http_server}/hello").lower()
        for claim in ("span", "topology", "edge", "service call"):
            assert claim not in out

    def test_shell_metacharacters_in_url_are_not_executed(self, runner, tmp_path):
        canary = tmp_path / "canary"
        out = self._run(runner, f"http://127.0.0.1:1/';touch {canary};'")
        assert not canary.exists(), "URL content reached the shell as code"
        assert "UNREACHABLE" in out


class TestEvidenceMarkerMatching:
    """A success marker must not fire on its own negation."""

    @pytest.mark.parametrize(
        "marker,output,matches",
        [
            ("REACHABLE", "  svc -> UNREACHABLE", False),
            ("REACHABLE", "  svc -> REACHABLE (HTTP 200)", True),
            ("OPEN", f"  redis -> {UNKNOWN_STATE}", False),
            ("OPEN", "  redis -> OPEN", True),
            ("OPEN", "  redis -> CLOSED", False),
            ("Can list secrets", "❌ VULNERABLE: Can list secrets — found 4", True),
        ],
    )
    def test_marker_matches_whole_tokens_only(self, marker, output, matches):
        assert _marker_matches(marker, output) is matches


class TestNoInlineProbeCommands:
    """The prelude is the only place a probe tool may be named."""

    def test_no_raw_probe_shell_outside_prelude(self):
        root = Path(__file__).resolve().parent.parent
        sources = root / "src" / "kimera"
        configs = sources / "config"
        # rglob on a missing directory yields nothing, which would make this
        # guard pass while inspecting zero files.
        assert (
            sources.is_dir() and configs.is_dir()
        ), "source roots moved; guard is checking nothing"
        offenders = []
        for path in list(sources.rglob("*.py")) + list(configs.rglob("*.yaml")):
            if path.name in ("probe_runner.py", "probe_prelude.py"):
                continue
            text = path.read_text(encoding="utf-8")
            raw = [
                tool
                for tool in ("nc -z", "nslookup", "curl ", "wget ")
                if tool in text and f"kimera_http_{tool.strip()}" not in text
            ]
            if raw:
                offenders.append(f"{path.relative_to(root)}: {raw}")
        assert offenders == [], f"inline probe commands found in: {offenders}"
