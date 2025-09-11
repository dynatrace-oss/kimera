"""Setup script for K8s Exploit Toolkit."""

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

from setuptools import find_packages, setup

setup(
    name="k8s-exploit-toolkit",
    version="1.0.0",
    py_modules=["k8s_exploit_toolkit"],
    packages=find_packages(include=["k8s_exploit_toolkit", "k8s_exploit_toolkit.*"]),
    install_requires=[
        "click>=8.1.0",
        "kubernetes>=28.1.0",
        "pyyaml>=6.0",
        "rich>=13.7.0",
        "tabulate>=0.9.0",
        "jsonpatch>=1.33",
        "python-decouple>=3.4",
        "setuptools>=45",
    ],
    entry_points={
        "console_scripts": [
            "k8s-exploit=k8s_exploit_toolkit.cli:main",
            "k8s-exploit-toolkit=k8s_exploit_toolkit.exploit_k8s:main",
        ],
    },
)
