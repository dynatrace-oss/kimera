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

"""Tests for the run_command() helper and CommandResult model."""

import subprocess
from unittest.mock import MagicMock, patch

from kimera.container.core.command import (
    DEFAULT_COMMAND_TIMEOUT,
    TIMEOUT_RETURNCODE,
    run_command,
)
from kimera.container.core.logger import SecurityLogger
from kimera.domain.models import CommandResult


class TestCommandResult:
    """Tests for the CommandResult dataclass."""

    def test_success_when_returncode_zero(self):
        """Test that success is True when returncode is 0."""
        result = CommandResult(command=["echo"], returncode=0, stdout="hi", stderr="")
        assert result.success is True

    def test_failure_when_returncode_nonzero(self):
        """Test that success is False when returncode is non-zero."""
        result = CommandResult(command=["false"], returncode=1, stdout="", stderr="err")
        assert result.success is False

    def test_stores_command_and_output(self):
        """Test that all fields are stored correctly."""
        result = CommandResult(command=["ls", "-la"], returncode=0, stdout="file.txt", stderr="")
        assert result.command == ["ls", "-la"]
        assert result.stdout == "file.txt"
        assert result.stderr == ""


class TestRunCommand:
    """Tests for the run_command() function."""

    @patch("kimera.container.core.command.subprocess.run")
    def test_executes_command(self, mock_run: MagicMock) -> None:
        """Test that run_command calls subprocess.run with correct args."""
        mock_run.return_value = MagicMock(returncode=0, stdout="ok", stderr="")
        result = run_command(["echo", "hello"])

        mock_run.assert_called_once_with(
            ["echo", "hello"], capture_output=True, text=True, timeout=DEFAULT_COMMAND_TIMEOUT
        )
        assert result.success is True
        assert result.stdout == "ok"

    @patch("kimera.container.core.command.subprocess.run")
    def test_timeout_reported_as_failure_not_raised(self, mock_run: MagicMock) -> None:
        """A command exceeding its timeout is killed and reported, never left hanging."""
        mock_run.side_effect = subprocess.TimeoutExpired(
            cmd=["kubectl", "rollout", "undo"], timeout=5, output="partial"
        )
        logger = MagicMock(spec=SecurityLogger)
        result = run_command(["kubectl", "rollout", "undo"], logger=logger, timeout=5)

        assert result.success is False
        assert result.returncode == TIMEOUT_RETURNCODE
        assert result.stdout == "partial"
        assert "timed out after 5s" in result.stderr
        logger.error.assert_called_once()

    @patch("kimera.container.core.command.subprocess.run")
    def test_timeout_is_passed_through(self, mock_run: MagicMock) -> None:
        """An explicit timeout reaches subprocess.run rather than being ignored."""
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
        run_command(["sleep", "1"], timeout=7)

        assert mock_run.call_args.kwargs["timeout"] == 7

    @patch("kimera.container.core.command.subprocess.run")
    def test_captures_failure(self, mock_run: MagicMock) -> None:
        """Test that run_command captures non-zero exit codes."""
        mock_run.return_value = MagicMock(returncode=1, stdout="", stderr="not found")
        result = run_command(["kubectl", "get", "pods"])

        assert result.success is False
        assert result.stderr == "not found"
        assert result.returncode == 1

    def test_dry_run_does_not_execute(self):
        """Test that dry_run returns success without executing."""
        result = run_command(["rm", "-rf", "/"], dry_run=True)

        assert result.success is True
        assert result.stdout == ""
        assert result.command == ["rm", "-rf", "/"]

    def test_dry_run_logs_message(self):
        """Test that dry_run logs the command when logger provided."""
        logger = MagicMock(spec=SecurityLogger)
        run_command(["kubectl", "apply"], dry_run=True, logger=logger)

        logger.info.assert_called_once()
        call_arg = logger.info.call_args[0][0]
        assert "DRY RUN" in call_arg
        assert "kubectl apply" in call_arg

    @patch("kimera.container.core.command.subprocess.run")
    def test_returns_command_in_result(self, mock_run: MagicMock) -> None:
        """Test that the command list is included in the result."""
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
        result = run_command(["git", "status"])

        assert result.command == ["git", "status"]
