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

import os
from pathlib import Path

CONFIG_DIR_ENV_VAR = "KIMERA_CONFIG_DIR"

# Resolved once, from this module only. Every other module asks here rather than
# counting parent directories of its own __file__, which is what previously gave
# six call sites four different depth expressions for the same directory.
_PACKAGE_ROOT = Path(__file__).resolve().parent


def config_dir() -> Path:
    """Directory holding Kimera's YAML configuration.

    Ships inside the package. Setting ``KIMERA_CONFIG_DIR`` replaces it
    wholesale, which is how an operator supplies their own profiles and checks
    without editing an installed package.
    """
    override = os.environ.get(CONFIG_DIR_ENV_VAR)
    return Path(override) if override else _PACKAGE_ROOT / "config"


def prompts_dir() -> Path:
    """Directory holding the Jinja prompt templates shipped with the package."""
    return _PACKAGE_ROOT / "prompts"
