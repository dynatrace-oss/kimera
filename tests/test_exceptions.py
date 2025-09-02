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

import pytest

from k8s_exploit_toolkit.container.core.exceptions import (
    ConfigurationError,
    DeploymentNotFoundError,
    ExploitError,
    K8sError,
    K8sSecurityError,
    PodNotFoundError,
    RemediationError,
)


class TestExceptions:
    """Test exception hierarchy and functionality."""

    def test_k8s_security_error_base(self):
        """Test K8sSecurityError as base exception."""
        error = K8sSecurityError("Test error")
        assert str(error) == "Test error"
        assert isinstance(error, Exception)

    def test_k8s_error_inheritance(self):
        """Test K8sError inherits from K8sSecurityError."""
        error = K8sError("K8s API error")
        assert str(error) == "K8s API error"
        assert isinstance(error, K8sSecurityError)
        assert isinstance(error, Exception)

    def test_pod_not_found_error_inheritance(self):
        """Test PodNotFoundError inherits from K8sError."""
        error = PodNotFoundError("Pod not found")
        assert str(error) == "Pod not found"
        assert isinstance(error, K8sError)
        assert isinstance(error, K8sSecurityError)
        assert isinstance(error, Exception)

    def test_deployment_not_found_error_inheritance(self):
        """Test DeploymentNotFoundError inherits from K8sError."""
        error = DeploymentNotFoundError("Deployment not found")
        assert str(error) == "Deployment not found"
        assert isinstance(error, K8sError)
        assert isinstance(error, K8sSecurityError)
        assert isinstance(error, Exception)

    def test_exploit_error_inheritance(self):
        """Test ExploitError inherits from K8sSecurityError."""
        error = ExploitError("Exploit failed")
        assert str(error) == "Exploit failed"
        assert isinstance(error, K8sSecurityError)
        assert isinstance(error, Exception)

    def test_remediation_error_inheritance(self):
        """Test RemediationError inherits from K8sSecurityError."""
        error = RemediationError("Remediation failed")
        assert str(error) == "Remediation failed"
        assert isinstance(error, K8sSecurityError)
        assert isinstance(error, Exception)

    def test_configuration_error_inheritance(self):
        """Test ConfigurationError inherits from K8sSecurityError."""
        error = ConfigurationError("Configuration invalid")
        assert str(error) == "Configuration invalid"
        assert isinstance(error, K8sSecurityError)
        assert isinstance(error, Exception)

    def test_exception_raising(self):
        """Test that exceptions can be raised and caught properly."""
        with pytest.raises(K8sSecurityError):
            raise K8sSecurityError("Base error")

        with pytest.raises(K8sError):
            raise K8sError("K8s error")

        with pytest.raises(PodNotFoundError):
            raise PodNotFoundError("Pod error")

        with pytest.raises(DeploymentNotFoundError):
            raise DeploymentNotFoundError("Deployment error")

        with pytest.raises(ExploitError):
            raise ExploitError("Exploit error")

        with pytest.raises(RemediationError):
            raise RemediationError("Remediation error")

        with pytest.raises(ConfigurationError):
            raise ConfigurationError("Config error")

    def test_exception_hierarchy_catching(self):
        """Test that exceptions can be caught by their parent classes."""
        # Test that K8sError can be caught as K8sSecurityError
        with pytest.raises(K8sSecurityError):
            raise K8sError("K8s error")

        # Test that PodNotFoundError can be caught as K8sError
        with pytest.raises(K8sError):
            raise PodNotFoundError("Pod error")

        # Test that DeploymentNotFoundError can be caught as K8sError
        with pytest.raises(K8sError):
            raise DeploymentNotFoundError("Deployment error")

        # Test that all specific errors can be caught as K8sSecurityError
        with pytest.raises(K8sSecurityError):
            raise ExploitError("Exploit error")

        with pytest.raises(K8sSecurityError):
            raise RemediationError("Remediation error")

        with pytest.raises(K8sSecurityError):
            raise ConfigurationError("Config error")

    def test_empty_error_messages(self):
        """Test exceptions with empty messages."""
        error = K8sSecurityError("")
        assert str(error) == ""

        error = K8sError("")
        assert str(error) == ""

    def test_none_error_messages(self):
        """Test exceptions with None messages."""
        error = K8sSecurityError(None)
        assert str(error) == "None"
