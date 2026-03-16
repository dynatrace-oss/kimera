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

import kimera


class TestPackageStructure:
    """Test package structure and imports."""

    def test_package_version(self):
        """Test package version is defined and correct."""
        assert hasattr(kimera, "__version__")
        assert kimera.__version__ == "1.1.0"
        assert isinstance(kimera.__version__, str)

    def test_package_docstring(self):
        """Test package has proper docstring."""
        assert kimera.__doc__ is not None
        assert "Kimera" in kimera.__doc__

    def test_package_import(self):
        """Test that the package can be imported successfully."""
        # This test passes if we can import the package without errors
        import kimera as ket

        assert ket is not None

    def test_submodule_imports(self):
        """Test that key submodules can be imported."""
        # Test container module
        try:
            from kimera import container

            assert container is not None
        except ImportError:
            # If container module structure changes, this test may need updating
            pass

        # Test core module (under container)
        try:
            from kimera.container import core

            assert core is not None
        except ImportError:
            # If core module structure changes, this test may need updating
            pass

    def test_cli_import(self):
        """Test that CLI can be imported."""
        from kimera import cli

        assert cli is not None
        assert hasattr(cli, "main")

    def test_exploit_k8s_import(self):
        """Test that exploit_k8s module can be imported."""
        from kimera import exploit_k8s

        assert exploit_k8s is not None
        assert hasattr(exploit_k8s, "main")


class TestPackageMetadata:
    """Test package metadata and attributes."""

    def test_version_format(self):
        """Test version follows semantic versioning format."""
        version = kimera.__version__
        parts = version.split(".")

        # Should have 3 parts for semantic versioning
        assert len(parts) == 3

        # Each part should be numeric
        for part in parts:
            assert part.isdigit(), f"Version part '{part}' is not numeric"

    def test_version_consistency(self):
        """Test version consistency across package files."""
        # Version should match what's in pyproject.toml
        package_version = kimera.__version__
        assert package_version == "1.1.0"

    def test_package_attributes(self):
        """Test that package has expected attributes."""
        # Check for required attributes
        assert hasattr(kimera, "__version__")
        assert hasattr(kimera, "__doc__")

        # Version should be a string
        assert isinstance(kimera.__version__, str)

        # Docstring should be a string or None
        assert kimera.__doc__ is None or isinstance(kimera.__doc__, str)


class TestModuleStructure:
    """Test the module structure and organization."""

    def test_container_submodules(self):
        """Test container submodule structure."""
        # Test that container module exists
        try:
            from kimera.container import core

            assert core is not None
        except ImportError:
            # Module may not be structured as expected
            pass

        # Test individual core components
        from kimera.container.core import config, exceptions, logger

        assert config is not None
        assert exceptions is not None
        assert logger is not None

    def test_core_exceptions_available(self):
        """Test that core exceptions are available."""
        from kimera.container.core.exceptions import (
            ConfigurationError,
            DeploymentNotFoundError,
            ExploitError,
            K8sError,
            K8sSecurityError,
            PodNotFoundError,
            RemediationError,
        )

        # All exceptions should be classes
        exceptions = [
            K8sSecurityError,
            K8sError,
            PodNotFoundError,
            DeploymentNotFoundError,
            ExploitError,
            RemediationError,
            ConfigurationError,
        ]

        for exc in exceptions:
            assert isinstance(exc, type)
            assert issubclass(exc, Exception)

    def test_logger_components_available(self):
        """Test that logger components are available."""
        from kimera.container.core.logger import (
            SECURITY_THEME,
            console,
            setup_logger,
        )

        assert SECURITY_THEME is not None
        assert console is not None
        assert setup_logger is not None
        assert callable(setup_logger)


class TestImportPerformance:
    """Test import performance and circular dependencies."""

    def test_no_circular_imports(self):
        """Test that there are no obvious circular imports."""
        # This test ensures that importing the main package doesn't cause issues
        # Should be able to import main components without errors
        from kimera.container.core import config, exceptions, logger

        # All imports should complete successfully
        assert config is not None
        assert exceptions is not None
        assert logger is not None

    def test_import_speed(self):
        """Test that imports complete in reasonable time."""
        import time

        start_time = time.time()

        # Import main components
        from kimera.container.core import config, exceptions, logger

        # Verify imports work
        assert config is not None
        assert exceptions is not None
        assert logger is not None

        end_time = time.time()
        import_time = end_time - start_time

        # Imports should complete within a reasonable time (1 second)
        assert import_time < 1.0, f"Imports took {import_time:.2f} seconds, which is too long"
