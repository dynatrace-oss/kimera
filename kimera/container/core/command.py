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

"""Subprocess command execution with structured results."""

import subprocess

from kimera.container.core.logger import SecurityLogger
from kimera.domain.models import CommandResult

# Matches timeouts.command in config/default.yaml and TimeoutConfig.command.
DEFAULT_COMMAND_TIMEOUT = 60

# Exit code GNU coreutils' `timeout` uses when it kills the command.
TIMEOUT_RETURNCODE = 124


def run_command(
    cmd: list[str],
    *,
    dry_run: bool = False,
    logger: SecurityLogger | None = None,
    timeout: int = DEFAULT_COMMAND_TIMEOUT,
) -> CommandResult:
    """Execute a subprocess command and return a structured result.

    Uses list-based arguments (no shell=True) to prevent injection.
    Captures stdout and stderr as strings.

    Args:
        cmd: Command and arguments as a list of strings.
        dry_run: If True, log the command without executing it.
        logger: Optional logger for dry-run and error messages.
        timeout: Seconds to wait before killing the command.

    Returns:
        CommandResult with returncode, stdout, and stderr. A command that
        exceeds ``timeout`` is killed and reported as a failure rather than
        raising, so callers handle it through the path they already have.
    """
    if dry_run:
        if logger:
            logger.info(f"DRY RUN: Would execute: {' '.join(cmd)}")
        return CommandResult(command=cmd, returncode=0, stdout="", stderr="")

    try:
        result = subprocess.run(  # noqa: S603
            cmd, capture_output=True, text=True, timeout=timeout
        )
    except subprocess.TimeoutExpired as e:
        message = f"Command timed out after {timeout}s: {' '.join(cmd)}"
        if logger:
            logger.error(message)
        # text=True yields str, but the exception is typed to allow bytes.
        partial = e.stdout.decode(errors="replace") if isinstance(e.stdout, bytes) else e.stdout
        return CommandResult(
            command=cmd,
            returncode=TIMEOUT_RETURNCODE,
            stdout=partial or "",
            stderr=message,
        )

    return CommandResult(
        command=cmd,
        returncode=result.returncode,
        stdout=result.stdout,
        stderr=result.stderr,
    )
