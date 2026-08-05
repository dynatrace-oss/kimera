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

import logging

from rich.console import Console
from rich.logging import RichHandler
from rich.theme import Theme

# Custom theme for security-related messages
SECURITY_THEME = Theme(
    {
        "info": "blue",
        "success": "green",
        "warning": "yellow",
        "error": "red",
        "exploit": "purple",
        "secure": "cyan",
        "debug": "dim white",
    }
)

console = Console(theme=SECURITY_THEME)


def setup_logger(name: str, level: str = "INFO", debug: bool = False) -> logging.Logger:
    """Set up a logger with rich formatting."""
    logger = logging.getLogger(name)

    # Validate logging level
    valid_levels = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
    if level.upper() not in valid_levels:
        raise ValueError(f"Invalid log level: {level}. Choose from {valid_levels}")

    # Clear existing handlers
    logger.handlers.clear()

    # Set level
    log_level = logging.DEBUG if debug else getattr(logging, level.upper())
    logger.setLevel(log_level)

    # Create rich handler
    handler = RichHandler(
        console=console,
        show_time=False,
        show_path=False,
        rich_tracebacks=True,
    )
    handler.setFormatter(logging.Formatter("%(message)s"))
    logger.addHandler(handler)

    return logger


class SecurityLogger:
    """Custom logger with security-specific methods."""

    def __init__(self, logger: logging.Logger):
        """Initialize SecurityLogger with a standard logger instance."""
        self.logger = logger
        self.console = console

    def info(self, message: str) -> None:
        """Log an informational message."""
        self.console.print(f"[info][INFO][/info] {message}")

    def success(self, message: str) -> None:
        """Log a success message."""
        self.console.print(f"[success][SUCCESS][/success] {message}")

    def warning(self, message: str) -> None:
        """Log a warning message."""
        self.console.print(f"[warning][WARNING][/warning] {message}")

    def error(self, message: str) -> None:
        """Log an error message."""
        self.console.print(f"[error][ERROR][/error] {message}")

    def exploit(self, message: str) -> None:
        """Log an exploit-related message."""
        self.console.print(f"[exploit][EXPLOIT][/exploit] {message}")

    def secure(self, message: str) -> None:
        """Log a security-related message."""
        self.console.print(f"[secure][SECURE][/secure] {message}")

    def debug(self, message: str) -> None:
        """Log a debug message if debug level is enabled."""
        if self.logger.level <= logging.DEBUG:
            self.console.print(f"[debug][DEBUG][/debug] {message}")
