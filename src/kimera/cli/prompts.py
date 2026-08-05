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

import click


def confirm(ctx: click.Context, message: str, *, default: bool) -> bool:
    """Ask the operator to confirm, honouring the run's interaction flags.

    The two flags are orthogonal on purpose. ``--non-interactive`` says never
    prompt, and each site supplies the answer to assume via ``default`` — the
    safe one, which for a destructive site is no. ``--yes`` is what affirms a
    destructive site, and it only takes effect together with
    ``--non-interactive``; on its own it would turn a single flag into a
    one-liner that makes every mapped service extremely vulnerable.
    """
    obj = ctx.obj or {}
    if obj.get("non_interactive"):
        return True if obj.get("assume_yes") else default
    return bool(click.confirm(message, default=default))
