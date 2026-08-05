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

import json
import subprocess
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from kimera.container.core.exceptions import ProviderError, ProviderNotConfiguredError
from kimera.core import llm


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Neutralise ambient credentials so resolution is decided by the test, not the machine."""
    monkeypatch.delenv("KIMERA_LLM_PROVIDER", raising=False)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.setattr(llm.shutil, "which", lambda _name: None)


def _with_cli(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        llm.shutil, "which", lambda name: "/usr/bin/claude" if name == "claude" else None
    )


class TestBackendResolution:
    """Selection must be deterministic and ordered — same inputs, same backend, every time."""

    def test_prefixed_model_selects_litellm(self) -> None:
        assert llm._resolve("openai/gpt-4o") == llm.Backend.LITELLM

    def test_api_key_selects_anthropic(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
        assert llm._resolve("claude-sonnet-4-6") == llm.Backend.ANTHROPIC

    def test_prefix_outranks_api_key(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # A user asking for openai/gpt-4o while holding an Anthropic key must get OpenAI.
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
        assert llm._resolve("openai/gpt-4o") == llm.Backend.LITELLM

    def test_cli_selected_only_without_key(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _with_cli(monkeypatch)
        assert llm._resolve("claude-sonnet-4-6") == llm.Backend.CLAUDE_CLI

    def test_api_key_outranks_cli(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _with_cli(monkeypatch)
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
        assert llm._resolve("claude-sonnet-4-6") == llm.Backend.ANTHROPIC

    def test_override_outranks_everything(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
        monkeypatch.setenv("KIMERA_LLM_PROVIDER", "litellm")
        assert llm._resolve("claude-sonnet-4-6") == llm.Backend.LITELLM

    def test_no_backend_available_raises(self) -> None:
        with pytest.raises(ProviderNotConfiguredError) as exc:
            llm._resolve("claude-sonnet-4-6")
        # The message has to tell the user what to do, or it is just a different traceback.
        assert "ANTHROPIC_API_KEY" in str(exc.value)


class TestUnusableOverride:
    """An override that cannot be honoured must fail, never silently answer from another model."""

    def test_unknown_override_names_valid_backends(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("KIMERA_LLM_PROVIDER", "not-a-backend")
        with pytest.raises(ProviderNotConfiguredError) as exc:
            llm._resolve("claude-sonnet-4-6")
        message = str(exc.value)
        assert "not-a-backend" in message
        assert llm.Backend.ANTHROPIC.value in message

    def test_override_does_not_fall_back_to_available_backend(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
        monkeypatch.setenv("KIMERA_LLM_PROVIDER", "claude-cli")  # CLI absent per fixture
        with pytest.raises(ProviderNotConfiguredError):
            llm._resolve("claude-sonnet-4-6")


class TestAnthropicBackend:
    """The pre-existing key-based path must behave exactly as it did before the refactor."""

    def test_request_carries_all_four_inputs(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
        block = MagicMock()
        block.text = "generated"
        client = MagicMock()
        client.messages.create.return_value = MagicMock(content=[block])
        fake_sdk = MagicMock(Anthropic=MagicMock(return_value=client))

        with patch.dict("sys.modules", {"anthropic": fake_sdk}):
            result = llm.complete(
                system="sys-prompt", user="user-prompt", model="claude-sonnet-4-6", max_tokens=8192
            )

        assert result == "generated"
        kwargs = client.messages.create.call_args.kwargs
        assert kwargs["model"] == "claude-sonnet-4-6"
        assert kwargs["system"] == "sys-prompt"
        assert kwargs["max_tokens"] == 8192
        assert kwargs["messages"] == [{"role": "user", "content": "user-prompt"}]

    def test_rejected_key_names_the_override(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # A stale key in .env outranks the subscription backend, so the error has to say how
        # to get past it — otherwise the user is stuck with no actionable message.
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-stale")

        class _AuthError(Exception):
            pass

        client = MagicMock()
        client.messages.create.side_effect = _AuthError("401")
        fake_sdk = MagicMock(
            Anthropic=MagicMock(return_value=client),
            AuthenticationError=_AuthError,
            APIError=Exception,
        )

        with (
            patch.dict("sys.modules", {"anthropic": fake_sdk}),
            pytest.raises(ProviderNotConfiguredError) as exc,
        ):
            llm.complete(system="s", user="u", model="m", max_tokens=10)

        message = str(exc.value)
        assert llm.PROVIDER_ENV_VAR in message
        assert llm.Backend.CLAUDE_CLI.value in message

    def test_empty_content_returns_empty_string(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # An empty completion is a valid model response, not a crash.
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
        client = MagicMock()
        client.messages.create.return_value = MagicMock(content=[])
        fake_sdk = MagicMock(Anthropic=MagicMock(return_value=client))

        with patch.dict("sys.modules", {"anthropic": fake_sdk}):
            assert llm.complete(system="s", user="u", model="m", max_tokens=10) == ""


class TestClaudeCliBackend:
    """Subscription path: no API key, structured output, and every failure mode reported."""

    @staticmethod
    def _run(stdout: str = "", returncode: int = 0) -> Any:
        return subprocess.CompletedProcess(args=[], returncode=returncode, stdout=stdout, stderr="")

    def test_returns_only_generated_text(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _with_cli(monkeypatch)
        payload = json.dumps({"result": "policy-yaml", "total_cost_usd": 0.04, "duration_ms": 12})
        with patch.object(llm.subprocess, "run", return_value=self._run(payload)) as run:
            assert llm.complete(system="s", user="u", model="m", max_tokens=10) == "policy-yaml"

        argv = run.call_args.args[0]
        assert argv[0] == "claude"
        assert "u" in argv and "s" in argv
        # Prompts must travel via argv, never through a shell.
        assert run.call_args.kwargs.get("shell") is not True

    def test_api_key_is_scrubbed_from_subprocess_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # The CLI refuses the subscription while ANTHROPIC_API_KEY is set, so a stale key
        # would make the override unusable on exactly the machines that need it.
        _with_cli(monkeypatch)
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-stale")
        monkeypatch.setenv("KIMERA_LLM_PROVIDER", "claude-cli")
        with patch.object(llm.subprocess, "run", return_value=self._run('{"result":"x"}')) as run:
            llm.complete(system="s", user="u", model="m", max_tokens=10)
        env = run.call_args.kwargs["env"]
        assert "ANTHROPIC_API_KEY" not in env
        assert "PATH" in env

    def test_runs_outside_the_callers_working_directory(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # The CLI loads the working directory's project instructions and hooks. Run from the
        # caller's repository it answered about that repository instead of the prompt, and the
        # generated YAML was unparseable.
        _with_cli(monkeypatch)
        with patch.object(llm.subprocess, "run", return_value=self._run('{"result":"x"}')) as run:
            llm.complete(system="s", user="u", model="m", max_tokens=10)
        cwd = Path(run.call_args.kwargs["cwd"]).resolve()
        assert cwd != Path.cwd().resolve()
        assert Path.cwd().resolve() not in cwd.parents
        # A temporary directory, so it is gone once the call returns and can carry no project
        # state between calls.
        assert not cwd.exists()

    def test_timeout_is_bounded(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _with_cli(monkeypatch)
        with patch.object(llm.subprocess, "run", return_value=self._run('{"result":"x"}')) as run:
            llm.complete(system="s", user="u", model="m", max_tokens=10)
        assert run.call_args.kwargs["timeout"] == llm.REQUEST_TIMEOUT_SECONDS

    def test_nonzero_exit_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _with_cli(monkeypatch)
        with (
            patch.object(llm.subprocess, "run", return_value=self._run("", returncode=1)),
            pytest.raises(ProviderError) as exc,
        ):
            llm.complete(system="s", user="u", model="m", max_tokens=10)
        assert llm.Backend.CLAUDE_CLI.value in str(exc.value)

    def test_unparseable_output_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # Exit 0 with garbage must not be returned to the caller as if it were a completion.
        _with_cli(monkeypatch)
        with (
            patch.object(llm.subprocess, "run", return_value=self._run("not json")),
            pytest.raises(ProviderError),
        ):
            llm.complete(system="s", user="u", model="m", max_tokens=10)

    def test_expired_process_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _with_cli(monkeypatch)
        timeout = subprocess.TimeoutExpired(cmd="claude", timeout=1)
        with (
            patch.object(llm.subprocess, "run", side_effect=timeout),
            pytest.raises(ProviderError),
        ):
            llm.complete(system="s", user="u", model="m", max_tokens=10)


class TestLitellmBackend:
    def test_missing_dependency_names_the_extra(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(llm, "_import_litellm", MagicMock(side_effect=ImportError))
        with pytest.raises(ProviderNotConfiguredError) as exc:
            llm.complete(system="s", user="u", model="openai/gpt-4o", max_tokens=10)
        assert "litellm" in str(exc.value)


class TestCodeFenceStripping:
    """One helper replaces two divergent copies; it must handle what LLMs actually emit."""

    @pytest.mark.parametrize(
        "raw,expected",
        [
            ("apiVersion: v1", "apiVersion: v1"),
            ("```yaml\napiVersion: v1\n```", "apiVersion: v1"),
            ("```\napiVersion: v1\n```", "apiVersion: v1"),
            ("```json\n[1, 2]\n```", "[1, 2]"),
            ("  ```yaml\napiVersion: v1\n```  ", "apiVersion: v1"),
            # A fenced block whose first line is not a bare language tag must be preserved.
            ("```\nkey: a b\n```", "key: a b"),
        ],
    )
    def test_strip(self, raw: str, expected: str) -> None:
        assert llm.strip_code_fence(raw) == expected


class TestDefaultModel:
    def test_single_definition_is_exported(self) -> None:
        assert llm.DEFAULT_MODEL
        assert "/" not in llm.DEFAULT_MODEL
