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

"""Unit tests for admission controller validation."""

from unittest.mock import MagicMock

import pytest
from kubernetes.client import ApiException

from kimera.container.core.logger import SecurityLogger, setup_logger
from kimera.container.validation.admission import (
    ADMISSION_TEST_CASES,
    _build_test_pod,
    _detect_admission_controllers,
    validate_admission,
)
from kimera.container.validation.models import ValidationVerdict  # noqa: F401


@pytest.fixture
def mock_k8s():
    k8s = MagicMock()
    k8s.namespace = "demo"
    return k8s


@pytest.fixture
def sec_logger():
    return SecurityLogger(setup_logger("test", debug=False))


class TestBuildTestPod:
    def test_basic_structure(self):
        test_case = {
            "id": "test-case",
            "description": "Test",
        }
        pod = _build_test_pod("demo", test_case)

        assert pod["apiVersion"] == "v1"
        assert pod["kind"] == "Pod"
        assert pod["metadata"]["name"] == "kimera-admission-test-test-case"
        assert pod["metadata"]["namespace"] == "demo"
        assert pod["spec"]["restartPolicy"] == "Never"

    def test_privileged_override(self):
        test_case = {
            "id": "priv",
            "description": "Test priv",
            "pod_overrides": {
                "securityContext": {"privileged": True},
            },
        }
        pod = _build_test_pod("demo", test_case)
        container = pod["spec"]["containers"][0]
        assert container["securityContext"]["privileged"] is True

    def test_host_pid_override(self):
        test_case = {
            "id": "host-pid",
            "description": "Test hostPID",
            "pod_spec_overrides": {"hostPID": True},
        }
        pod = _build_test_pod("demo", test_case)
        assert pod["spec"]["hostPID"] is True

    def test_strip_resources(self):
        test_case = {
            "id": "no-limits",
            "description": "No limits",
            "strip_resources": True,
        }
        pod = _build_test_pod("demo", test_case)
        container = pod["spec"]["containers"][0]
        assert "resources" not in container

    def test_has_resources_by_default(self):
        test_case = {"id": "normal", "description": "Normal"}
        pod = _build_test_pod("demo", test_case)
        container = pod["spec"]["containers"][0]
        assert "resources" in container
        assert "limits" in container["resources"]

    def test_kimera_label_present(self):
        test_case = {"id": "labels", "description": "Labels"}
        pod = _build_test_pod("demo", test_case)
        assert pod["metadata"]["labels"]["app.kubernetes.io/managed-by"] == "kimera"


class TestDetectAdmissionControllers:
    def test_detects_psa_labels(self, mock_k8s):
        ns_obj = MagicMock()
        ns_obj.metadata.labels = {
            "pod-security.kubernetes.io/enforce": "restricted",
        }
        mock_k8s.v1.read_namespace.return_value = ns_obj

        controllers = _detect_admission_controllers(mock_k8s)
        psa = [c for c in controllers if c["type"] == "PSA"]
        assert len(psa) == 1
        assert psa[0]["level"] == "restricted"

    def test_no_psa_labels(self, mock_k8s):
        ns_obj = MagicMock()
        ns_obj.metadata.labels = {}
        mock_k8s.v1.read_namespace.return_value = ns_obj

        controllers = _detect_admission_controllers(mock_k8s)
        psa = [c for c in controllers if c["type"] == "PSA"]
        assert len(psa) == 0

    def test_api_error_handled(self, mock_k8s):
        mock_k8s.v1.read_namespace.side_effect = ApiException(status=403)
        controllers = _detect_admission_controllers(mock_k8s)
        # Should not raise, just return empty/partial results
        assert isinstance(controllers, list)


class TestValidateAdmission:
    def test_all_rejected(self, mock_k8s, sec_logger):
        """All test pods rejected by admission → all pass."""
        ns_obj = MagicMock()
        ns_obj.metadata.labels = {"pod-security.kubernetes.io/enforce": "restricted"}
        mock_k8s.v1.read_namespace.return_value = ns_obj

        mock_k8s.v1.create_namespaced_pod.side_effect = ApiException(status=422, reason="Forbidden")

        report = validate_admission(mock_k8s, sec_logger)
        assert report.total == len(ADMISSION_TEST_CASES)
        assert report.failed == 0
        assert report.all_passed

    def test_all_admitted(self, mock_k8s, sec_logger):
        """All test pods admitted → all fail."""
        ns_obj = MagicMock()
        ns_obj.metadata.labels = {}
        mock_k8s.v1.read_namespace.return_value = ns_obj

        # create_namespaced_pod succeeds → pod was admitted
        mock_k8s.v1.create_namespaced_pod.return_value = MagicMock()

        report = validate_admission(mock_k8s, sec_logger)
        assert report.total == len(ADMISSION_TEST_CASES)
        assert report.passed == 0
        assert report.failed == len(ADMISSION_TEST_CASES)

    def test_mixed_results(self, mock_k8s, sec_logger):
        """Some rejected, some admitted."""
        ns_obj = MagicMock()
        ns_obj.metadata.labels = {}
        mock_k8s.v1.read_namespace.return_value = ns_obj

        call_count = 0

        def side_effect(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count <= 3:
                raise ApiException(status=422, reason="Forbidden")
            return MagicMock()

        mock_k8s.v1.create_namespaced_pod.side_effect = side_effect

        report = validate_admission(mock_k8s, sec_logger)
        assert report.passed == 3
        assert report.failed == len(ADMISSION_TEST_CASES) - 3

    def test_api_error_recorded(self, mock_k8s, sec_logger):
        """Non-admission API errors recorded as ERROR verdict."""
        ns_obj = MagicMock()
        ns_obj.metadata.labels = {}
        mock_k8s.v1.read_namespace.return_value = ns_obj

        mock_k8s.v1.create_namespaced_pod.side_effect = ApiException(
            status=500, reason="Internal Server Error"
        )

        report = validate_admission(mock_k8s, sec_logger)
        assert report.errors == len(ADMISSION_TEST_CASES)

    def test_test_cases_coverage(self):
        """Verify all test cases have required fields."""
        for tc in ADMISSION_TEST_CASES:
            assert "id" in tc
            assert "description" in tc
            assert "expected_rejection" in tc
            assert "remediation" in tc
