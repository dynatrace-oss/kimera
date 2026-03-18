#!/usr/bin/env python3
#
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
#

"""Basic usage example for Kimera.

This example demonstrates how to use the toolkit programmatically
to assess container security issues in a Kubernetes namespace.
"""

from kimera.application.config.loader import ConfigLoader
from kimera.container.assessment.scanner import SecurityScanner
from kimera.container.core.k8s_client import K8sClient
from kimera.container.core.logger import SecurityLogger, setup_logger


def main() -> int:
    """Demonstrate basic toolkit usage."""
    # Load configuration with namespace override
    loader = ConfigLoader()
    config = loader.load(overrides={"kubernetes": {"namespace": "default"}, "debug": True})

    # Setup logging
    logger = SecurityLogger(setup_logger("example", debug=config.debug))

    try:
        # Initialize Kubernetes client
        k8s_client = K8sClient(namespace=config.namespace, logger=logger)

        # Create security scanner
        scanner = SecurityScanner(k8s_client, logger)

        # Assess security posture
        logger.info("Starting security assessment...")
        scanner.assess_all_services(["your-deployment-name"])

        logger.info("Assessment complete!")

    except Exception as e:
        logger.error(f"Error during assessment: {e}")
        return 1

    return 0


if __name__ == "__main__":
    exit(main())
