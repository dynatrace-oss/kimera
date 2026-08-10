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

"""Configuration re-exports for backward compatibility.

The canonical config classes live in ``kimera.application.config.schemas``
and ``kimera.application.config.loader``. This module re-exports them so
that existing imports from ``kimera.container.core.config`` continue to work.
"""

from kimera.application.config.loader import ConfigLoader
from kimera.application.config.schemas import ToolkitConfig

__all__ = ["ConfigLoader", "ToolkitConfig"]
