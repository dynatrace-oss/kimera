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

from typing import Any

import yaml


def _parse_documents(yaml_text: str) -> list[tuple[int, dict[str, Any]]]:
    """Parse multi-document YAML into mappings, rejecting anything else.

    Empty documents are dropped; each mapping keeps its original position so
    errors point at the document the model emitted, not a renumbered one.
    """
    try:
        docs = list(yaml.safe_load_all(yaml_text))
    except yaml.YAMLError as e:
        raise ValueError(f"LLM returned invalid YAML: {e}") from e

    parsed: list[tuple[int, dict[str, Any]]] = []
    for i, doc in enumerate(docs):
        if doc is None:
            continue
        if not isinstance(doc, dict):
            raise ValueError(f"Document {i} is not a mapping")
        parsed.append((i, doc))
    return parsed


def validate_resource_yaml(yaml_text: str) -> None:
    """Check generated Kubernetes resources carry the fields the applier needs.

    Raises:
        ValueError: naming the document and the missing field.
    """
    for i, doc in _parse_documents(yaml_text):
        if "apiVersion" not in doc:
            raise ValueError(f"Document {i} missing apiVersion")
        if "kind" not in doc:
            raise ValueError(f"Document {i} missing kind")
        if not doc.get("metadata", {}).get("name"):
            raise ValueError(f"Document {i} missing metadata.name")


def validate_exploit_yaml(yaml_text: str) -> None:
    """Check generated exploit patches name a target and carry patches.

    Raises:
        ValueError: naming the document and the missing field.
    """
    for i, doc in _parse_documents(yaml_text):
        if "target" not in doc:
            raise ValueError(f"Document {i} missing 'target' field")
        target = doc["target"]
        if not isinstance(target, dict) or "deployment" not in target:
            raise ValueError(f"Document {i} missing 'target.deployment'")
        if "patches" not in doc:
            raise ValueError(f"Document {i} missing 'patches' field")
        patches = doc["patches"]
        if not isinstance(patches, list) or not patches:
            raise ValueError(f"Document {i} has empty or invalid 'patches'")
