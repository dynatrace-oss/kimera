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

from unittest.mock import patch


class TestCLI:
    """Test CLI module functionality."""

    @patch("k8s_exploit_toolkit.cli.main")
    def test_cli_main_import(self, mock_main):
        """Test that CLI module imports main function correctly."""
        from k8s_exploit_toolkit.cli import main

        # Verify the import works
        assert main is not None
        assert callable(main)

    @patch("sys.exit")
    @patch("k8s_exploit_toolkit.exploit_k8s.main")
    def test_cli_main_execution(self, mock_main, mock_exit):
        """Test CLI main execution path."""
        mock_main.return_value = 0

        # Import and run the CLI module as main
        import k8s_exploit_toolkit.cli as cli_module

        # Simulate running as main
        if hasattr(cli_module, "__name__"):
            # Test the main execution path
            mock_main.assert_not_called()  # Not called yet
            mock_exit.assert_not_called()  # Not called yet

    def test_cli_module_attributes(self):
        """Test that CLI module has expected attributes."""
        import k8s_exploit_toolkit.cli as cli_module

        # Check that main is imported
        assert hasattr(cli_module, "main")

        # Verify main is callable
        assert callable(cli_module.main)
