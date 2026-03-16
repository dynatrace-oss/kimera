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
from unittest.mock import MagicMock, patch

import pytest
from rich.console import Console

from kimera.container.core.logger import (
    SECURITY_THEME,
    SecurityLogger,
    console,
    setup_logger,
)


class TestSetupLogger:
    """Test the setup_logger function."""

    def test_setup_logger_default(self):
        """Test setup_logger with default parameters."""
        logger = setup_logger("test_logger")

        assert logger.name == "test_logger"
        assert logger.level == logging.INFO
        assert len(logger.handlers) == 1
        assert isinstance(logger.handlers[0], logging.Handler)

    def test_setup_logger_debug_mode(self):
        """Test setup_logger with debug mode enabled."""
        logger = setup_logger("test_debug", debug=True)

        assert logger.name == "test_debug"
        assert logger.level == logging.DEBUG

    def test_setup_logger_custom_level(self):
        """Test setup_logger with custom log level."""
        logger = setup_logger("test_warning", level="WARNING")

        assert logger.name == "test_warning"
        assert logger.level == logging.WARNING

    def test_setup_logger_invalid_level(self):
        """Test setup_logger with invalid log level."""
        with pytest.raises(ValueError, match="Invalid log level: INVALID"):
            setup_logger("test_invalid", level="INVALID")

    def test_setup_logger_case_insensitive_level(self):
        """Test setup_logger with case insensitive log level."""
        logger = setup_logger("test_case", level="error")
        assert logger.level == logging.ERROR

        logger = setup_logger("test_case2", level="Error")
        assert logger.level == logging.ERROR

    def test_setup_logger_clears_existing_handlers(self):
        """Test that setup_logger clears existing handlers."""
        logger_name = "test_clear_handlers"

        # First setup
        logger1 = setup_logger(logger_name)
        initial_handlers = len(logger1.handlers)

        # Second setup should clear and recreate handlers
        logger2 = setup_logger(logger_name)

        assert logger1 is logger2  # Same logger instance
        assert len(logger2.handlers) == initial_handlers  # Same number of handlers


class TestSecurityLogger:
    """Test the SecurityLogger class."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_logger = MagicMock(spec=logging.Logger)
        self.mock_logger.level = logging.INFO

    @patch("kimera.container.core.logger.console")
    def test_security_logger_init(self, mock_console):
        """Test SecurityLogger initialization."""
        sec_logger = SecurityLogger(self.mock_logger)

        assert sec_logger.logger is self.mock_logger
        assert sec_logger.console is mock_console

    @patch("kimera.container.core.logger.console")
    def test_info_message(self, mock_console):
        """Test info message logging."""
        sec_logger = SecurityLogger(self.mock_logger)
        sec_logger.info("Test info message")

        mock_console.print.assert_called_once_with("[info][INFO][/info] Test info message")

    @patch("kimera.container.core.logger.console")
    def test_success_message(self, mock_console):
        """Test success message logging."""
        sec_logger = SecurityLogger(self.mock_logger)
        sec_logger.success("Test success message")

        mock_console.print.assert_called_once_with(
            "[success][SUCCESS][/success] Test success message"
        )

    @patch("kimera.container.core.logger.console")
    def test_warning_message(self, mock_console):
        """Test warning message logging."""
        sec_logger = SecurityLogger(self.mock_logger)
        sec_logger.warning("Test warning message")

        mock_console.print.assert_called_once_with(
            "[warning][WARNING][/warning] Test warning message"
        )

    @patch("kimera.container.core.logger.console")
    def test_error_message(self, mock_console):
        """Test error message logging."""
        sec_logger = SecurityLogger(self.mock_logger)
        sec_logger.error("Test error message")

        mock_console.print.assert_called_once_with("[error][ERROR][/error] Test error message")

    @patch("kimera.container.core.logger.console")
    def test_exploit_message(self, mock_console):
        """Test exploit message logging."""
        sec_logger = SecurityLogger(self.mock_logger)
        sec_logger.exploit("Test exploit message")

        mock_console.print.assert_called_once_with(
            "[exploit][EXPLOIT][/exploit] Test exploit message"
        )

    @patch("kimera.container.core.logger.console")
    def test_secure_message(self, mock_console):
        """Test secure message logging."""
        sec_logger = SecurityLogger(self.mock_logger)
        sec_logger.secure("Test secure message")

        mock_console.print.assert_called_once_with("[secure][SECURE][/secure] Test secure message")

    @patch("kimera.container.core.logger.console")
    def test_debug_message_enabled(self, mock_console):
        """Test debug message logging when debug is enabled."""
        self.mock_logger.level = logging.DEBUG
        sec_logger = SecurityLogger(self.mock_logger)
        sec_logger.debug("Test debug message")

        mock_console.print.assert_called_once_with("[debug][DEBUG][/debug] Test debug message")

    @patch("kimera.container.core.logger.console")
    def test_debug_message_disabled(self, mock_console):
        """Test debug message logging when debug is disabled."""
        self.mock_logger.level = logging.INFO
        sec_logger = SecurityLogger(self.mock_logger)
        sec_logger.debug("Test debug message")

        mock_console.print.assert_not_called()


class TestSecurityTheme:
    """Test the security theme configuration."""

    def test_security_theme_exists(self):
        """Test that SECURITY_THEME is properly defined."""
        assert SECURITY_THEME is not None

        # Check that expected theme keys exist
        expected_keys = ["info", "success", "warning", "error", "exploit", "secure", "debug"]
        for key in expected_keys:
            assert key in SECURITY_THEME.styles

    def test_console_uses_theme(self):
        """Test that console uses the security theme."""
        # Test that console was created with the theme
        assert isinstance(console, Console)
        # The theme should be accessible through the options
        assert SECURITY_THEME is not None


class TestLoggerIntegration:
    """Integration tests for logger components."""

    def test_setup_logger_with_security_logger(self):
        """Test integration between setup_logger and SecurityLogger."""
        logger = setup_logger("test_integration")
        sec_logger = SecurityLogger(logger)

        assert sec_logger.logger is logger
        assert isinstance(sec_logger, SecurityLogger)

    @patch("kimera.container.core.logger.console")
    def test_different_log_levels_integration(self, mock_console):
        """Test SecurityLogger with different underlying logger levels."""
        # Test with INFO level
        info_logger = setup_logger("test_info", level="INFO")
        sec_logger_info = SecurityLogger(info_logger)
        sec_logger_info.debug("Debug message")
        mock_console.print.assert_not_called()

        # Test with DEBUG level
        debug_logger = setup_logger("test_debug", level="DEBUG")
        sec_logger_debug = SecurityLogger(debug_logger)
        sec_logger_debug.debug("Debug message")
        mock_console.print.assert_called_once()
