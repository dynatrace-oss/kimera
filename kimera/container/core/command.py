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


def run_command(
    cmd: list[str],
    *,
    dry_run: bool = False,
    logger: SecurityLogger | None = None,
) -> CommandResult:
    """Execute a subprocess command and return a structured result.

    Uses list-based arguments (no shell=True) to prevent injection.
    Captures stdout and stderr as strings.

    Args:
        cmd: Command and arguments as a list of strings.
        dry_run: If True, log the command without executing it.
        logger: Optional logger for dry-run and error messages.

    Returns:
        CommandResult with returncode, stdout, and stderr.
    """
    if dry_run:
        if logger:
            logger.info(f"DRY RUN: Would execute: {' '.join(cmd)}")
        return CommandResult(command=cmd, returncode=0, stdout="", stderr="")

    result = subprocess.run(cmd, capture_output=True, text=True)  # noqa: S603
    return CommandResult(
        command=cmd,
        returncode=result.returncode,
        stdout=result.stdout,
        stderr=result.stderr,
    )
