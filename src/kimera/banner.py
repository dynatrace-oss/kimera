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

"""ASCII art banner and display utilities for Kimera CLI."""

from .container.core.logger import console

KIMERA_LOGO = """\
██   ██ ██ ███    ███ ███████ ██████   █████
██  ██  ██ ████  ████ ██      ██   ██ ██   ██
█████   ██ ██ ████ ██ █████   ██████  ███████
██  ██  ██ ██  ██  ██ ██      ██   ██ ██   ██
██   ██ ██ ██      ██ ███████ ██   ██ ██   ██"""

TAGLINE = "Kubernetes Security Testing Framework"


def show_banner(namespace: str | None = None) -> None:
    """Display the Kimera banner with optional namespace info."""
    console.print()
    console.print(f"[bold cyan]{KIMERA_LOGO}[/bold cyan]")
    console.print(f"  [dim]{TAGLINE}[/dim]")
    if namespace:
        console.print(f"  Namespace: [bold]{namespace}[/bold]")
    console.print()
