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

from unittest.mock import MagicMock, patch

import click
import pytest

from kimera.cli.prompts import confirm


def _ctx(**obj: bool) -> click.Context:
    ctx = click.Context(click.Command("t"))
    ctx.obj = dict(obj)
    return ctx


class TestConfirm:
    """--non-interactive supplies the answer; --yes affirms destructive sites."""

    @pytest.mark.parametrize("default", [True, False])
    def test_non_interactive_assumes_the_site_default(self, default: bool) -> None:
        with patch("kimera.cli.prompts.click.confirm") as prompt:
            assert confirm(_ctx(non_interactive=True), "go?", default=default) is default
            prompt.assert_not_called()

    @pytest.mark.parametrize("default", [True, False])
    def test_yes_affirms_when_non_interactive(self, default: bool) -> None:
        with patch("kimera.cli.prompts.click.confirm") as prompt:
            assert (
                confirm(_ctx(non_interactive=True, assume_yes=True), "go?", default=default) is True
            )
            prompt.assert_not_called()

    def test_yes_alone_does_not_suppress_prompting(self) -> None:
        # Otherwise `kimera vuln --yes` becomes a one-liner that makes every
        # mapped service extremely vulnerable.
        with patch("kimera.cli.prompts.click.confirm", return_value=False) as prompt:
            assert confirm(_ctx(assume_yes=True), "go?", default=False) is False
            prompt.assert_called_once()

    def test_interactive_run_prompts(self) -> None:
        with patch("kimera.cli.prompts.click.confirm", return_value=True) as prompt:
            assert confirm(_ctx(), "go?", default=False) is True
            prompt.assert_called_once()

    def test_missing_context_object_still_prompts(self) -> None:
        ctx = click.Context(click.Command("t"))
        with patch("kimera.cli.prompts.click.confirm", return_value=True):
            assert confirm(ctx, "go?", default=False) is True


class TestRunInteractiveDecision:
    """The vulnerable-or-not decision is injected, never read from stdin."""

    def test_defaults_to_not_mutating(self) -> None:
        exploit = MagicMock()
        from kimera.container.make_vulnerable.base import BaseExploit

        exploit.check_vulnerability.return_value = False
        BaseExploit.run_interactive(exploit)

        exploit.make_vulnerable.assert_not_called()
        exploit.demonstrate.assert_called_once()

    def test_affirmative_decision_makes_vulnerable_then_demonstrates(self) -> None:
        from kimera.container.make_vulnerable.base import BaseExploit

        exploit = MagicMock()
        exploit.check_vulnerability.return_value = False
        with patch("kimera.container.make_vulnerable.base.time.sleep"):
            BaseExploit.run_interactive(exploit, lambda: True)

        exploit.make_vulnerable.assert_called_once()
        exploit.demonstrate.assert_called_once()

    def test_already_vulnerable_never_asks(self) -> None:
        from kimera.container.make_vulnerable.base import BaseExploit

        exploit = MagicMock()
        exploit.check_vulnerability.return_value = True
        decide = MagicMock(return_value=True)
        BaseExploit.run_interactive(exploit, decide)

        decide.assert_not_called()
        exploit.make_vulnerable.assert_not_called()
