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

from pathlib import Path

import pytest

import kimera
from kimera.resources import CONFIG_DIR_ENV_VAR, config_dir, prompts_dir


class TestPackagedResources:
    """Config and prompts must resolve relative to the package, not the repo root."""

    def test_config_and_prompts_live_inside_the_installed_package(self) -> None:
        # The failure this guards against: locating config/ by counting parent
        # directories of a module's __file__, which resolved to the repo root and
        # left an installed wheel unable to find its own configuration.
        package_root = Path(kimera.__file__).resolve().parent
        assert config_dir() == package_root / "config"
        assert prompts_dir() == package_root / "prompts"

    @pytest.mark.parametrize(
        "relative",
        ["default.yaml", "env_mappings.yaml", "checks/workload.yaml", "exploits/registry.yaml"],
    )
    def test_shipped_config_files_are_present(self, relative: str) -> None:
        assert (config_dir() / relative).is_file()

    def test_env_var_replaces_the_packaged_directory(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(CONFIG_DIR_ENV_VAR, str(tmp_path))
        assert config_dir() == tmp_path

    def test_prompts_ignore_the_config_override(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Prompts are code, not operator configuration; an operator pointing
        # KIMERA_CONFIG_DIR at their own profiles must not lose the templates.
        monkeypatch.setenv(CONFIG_DIR_ENV_VAR, str(tmp_path))
        assert prompts_dir() != tmp_path
        assert (prompts_dir() / "generate_system.j2").is_file()
