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

from kimera.container.core.exceptions import (
    ConfigurationError,
    DeploymentNotFoundError,
    ExploitError,
    K8sError,
    K8sSecurityError,
    PodNotFoundError,
    RemediationError,
)


class TestExceptions:
    """Test exception hierarchy."""

    def test_all_exceptions_have_correct_message(self) -> None:
        for cls in (
            K8sSecurityError,
            K8sError,
            PodNotFoundError,
            DeploymentNotFoundError,
            ExploitError,
            RemediationError,
            ConfigurationError,
        ):
            error = cls("test message")
            assert str(error) == "test message"

    def test_hierarchy_root_catches_all(self) -> None:
        """All custom exceptions are catchable as K8sSecurityError."""
        for cls in (
            K8sError,
            PodNotFoundError,
            DeploymentNotFoundError,
            ExploitError,
            RemediationError,
            ConfigurationError,
        ):
            with pytest.raises(K8sSecurityError):
                raise cls("test")

    def test_k8s_error_catches_resource_errors(self) -> None:
        """Resource-specific errors are catchable as K8sError."""
        for cls in (PodNotFoundError, DeploymentNotFoundError):
            with pytest.raises(K8sError):
                raise cls("test")
