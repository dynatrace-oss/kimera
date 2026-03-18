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


class K8sSecurityError(Exception):
    """Base exception for all security toolkit errors."""

    pass


class K8sError(K8sSecurityError):
    """Kubernetes API related errors."""

    pass


class PodNotFoundError(K8sError):
    """Raised when a pod cannot be found."""

    pass


class DeploymentNotFoundError(K8sError):
    """Raised when a deployment cannot be found."""

    pass


class ExploitError(K8sSecurityError):
    """Exploit execution errors."""

    pass


class RemediationError(K8sSecurityError):
    """Remediation application errors."""

    pass


class ConfigurationError(K8sSecurityError):
    """Configuration related errors."""

    pass


class InfrastructureError(K8sSecurityError):
    """Infrastructure setup and teardown errors."""

    pass
