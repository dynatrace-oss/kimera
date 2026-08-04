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
import logging
import os
import shutil
import subprocess
from enum import StrEnum
from typing import Any

from kimera.container.core.exceptions import ProviderError, ProviderNotConfiguredError

logger = logging.getLogger(__name__)

DEFAULT_MODEL = "claude-sonnet-4-6"
REQUEST_TIMEOUT_SECONDS = 300

PROVIDER_ENV_VAR = "KIMERA_LLM_PROVIDER"
ANTHROPIC_KEY_ENV_VAR = "ANTHROPIC_API_KEY"
CLAUDE_CLI_BINARY = "claude"


class Backend(StrEnum):
    ANTHROPIC = "anthropic"
    LITELLM = "litellm"
    CLAUDE_CLI = "claude-cli"


def complete(*, system: str, user: str, model: str, max_tokens: int) -> str:
    """Generate a completion using the first available backend.

    Args:
        system: System prompt.
        user: User prompt.
        model: Model identifier. A ``provider/model`` prefix routes through LiteLLM.
        max_tokens: Output token limit.

    Returns:
        The generated text, or an empty string if the model returned no content.

    Raises:
        ProviderNotConfiguredError: No usable backend, or an override that cannot be honoured.
        ProviderError: The selected backend failed to produce a usable response.
    """
    backend = _resolve(model)
    logger.debug("Using %s backend for model %s", backend.value, model)
    if backend is Backend.LITELLM:
        return _complete_litellm(system=system, user=user, model=model, max_tokens=max_tokens)
    if backend is Backend.ANTHROPIC:
        return _complete_anthropic(system=system, user=user, model=model, max_tokens=max_tokens)
    return _complete_claude_cli(system=system, user=user, model=model)


def strip_code_fence(raw: str) -> str:
    """Remove a wrapping markdown code fence, with its language tag, if present."""
    text = raw.strip()
    if not text.startswith("```"):
        return text
    text = text.split("```", 2)[1]
    first_line_end = text.find("\n")
    if first_line_end != -1:
        lang = text[:first_line_end].strip()
        if lang.isalpha():
            text = text[first_line_end:]
    return text.rsplit("```", 1)[0].strip()


def _resolve(model: str) -> Backend:
    """Select a backend from configuration, the model identifier and the environment."""
    override = os.environ.get(PROVIDER_ENV_VAR)
    if override:
        return _resolve_override(override)
    # LiteLLM's own model syntax is provider/model, and no Anthropic identifier contains a
    # slash, so the prefix alone decides without maintaining a list of provider names.
    if "/" in model:
        return Backend.LITELLM
    if os.environ.get(ANTHROPIC_KEY_ENV_VAR):
        return Backend.ANTHROPIC
    if shutil.which(CLAUDE_CLI_BINARY):
        return Backend.CLAUDE_CLI
    raise ProviderNotConfiguredError(
        "No LLM backend available. Set "
        f"{ANTHROPIC_KEY_ENV_VAR} for the Anthropic API, install the '{CLAUDE_CLI_BINARY}' CLI "
        "and sign in to use a Claude subscription, or pass a prefixed model such as "
        f"'openai/gpt-4o' with the litellm extra installed. Override with {PROVIDER_ENV_VAR}."
    )


def _resolve_override(override: str) -> Backend:
    """Honour an explicit override, or fail — never silently answer from a different model."""
    try:
        backend = Backend(override)
    except ValueError:
        valid = ", ".join(b.value for b in Backend)
        raise ProviderNotConfiguredError(
            f"{PROVIDER_ENV_VAR}={override!r} is not a known backend. Valid backends: {valid}."
        ) from None
    if backend is Backend.ANTHROPIC and not os.environ.get(ANTHROPIC_KEY_ENV_VAR):
        raise ProviderNotConfiguredError(
            f"{PROVIDER_ENV_VAR}={override!r} requires {ANTHROPIC_KEY_ENV_VAR} to be set."
        )
    if backend is Backend.CLAUDE_CLI and not shutil.which(CLAUDE_CLI_BINARY):
        raise ProviderNotConfiguredError(
            f"{PROVIDER_ENV_VAR}={override!r} requires the '{CLAUDE_CLI_BINARY}' CLI on PATH."
        )
    return backend


def _import_litellm() -> Any:
    import litellm  # noqa: PLC0415

    return litellm


def _complete_litellm(*, system: str, user: str, model: str, max_tokens: int) -> str:
    try:
        litellm = _import_litellm()
    except ImportError as exc:
        raise ProviderNotConfiguredError(
            f"Model {model!r} needs litellm. Install with: uv pip install 'kimera[litellm]'"
        ) from exc

    response = litellm.completion(
        model=model,
        max_tokens=max_tokens,
        messages=[
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
        timeout=REQUEST_TIMEOUT_SECONDS,
    )
    try:
        return str(response.choices[0].message.content or "")
    except (AttributeError, IndexError) as exc:
        raise ProviderError(f"{Backend.LITELLM.value}: unexpected response shape") from exc


def _complete_anthropic(*, system: str, user: str, model: str, max_tokens: int) -> str:
    try:
        import anthropic  # noqa: PLC0415
    except ImportError as exc:
        raise ProviderNotConfiguredError(
            "Anthropic SDK is required. Install with: uv pip install 'kimera[llm]'"
        ) from exc

    client = anthropic.Anthropic(timeout=REQUEST_TIMEOUT_SECONDS)
    try:
        message = client.messages.create(
            model=model,
            max_tokens=max_tokens,
            system=system,
            messages=[{"role": "user", "content": user}],
        )
    except anthropic.AuthenticationError as exc:
        # A stale key in the environment or .env outranks the subscription backend by design,
        # so name the override rather than silently answering from a different model.
        raise ProviderNotConfiguredError(
            f"{ANTHROPIC_KEY_ENV_VAR} was rejected by the Anthropic API. Correct or unset it, "
            f"or set {PROVIDER_ENV_VAR}={Backend.CLAUDE_CLI.value} to use a Claude subscription."
        ) from exc
    except anthropic.APIError as exc:
        raise ProviderError(f"{Backend.ANTHROPIC.value}: {exc}") from exc
    return str(getattr(message.content[0], "text", "")) if message.content else ""


def _complete_claude_cli(*, system: str, user: str, model: str) -> str:
    """Complete via the Claude CLI's existing authenticated session.

    The CLI exposes no output-token limit, so ``max_tokens`` has no equivalent here and is
    deliberately not forwarded. Prompts travel through argv, never a shell.

    ``ANTHROPIC_API_KEY`` is removed from the subprocess environment: the CLI treats it as
    taking precedence over the signed-in session and refuses to use the subscription while it
    is set, so a stale key elsewhere in the environment would otherwise make this backend
    unusable on the machines that need it most.
    """
    argv = [
        CLAUDE_CLI_BINARY,
        "-p",
        user,
        "--append-system-prompt",
        system,
        "--model",
        model,
        "--output-format",
        "json",
    ]
    env = {k: v for k, v in os.environ.items() if k != ANTHROPIC_KEY_ENV_VAR}
    try:
        result = subprocess.run(  # noqa: S603 - fixed argv, no shell
            argv,
            capture_output=True,
            text=True,
            timeout=REQUEST_TIMEOUT_SECONDS,
            env=env,
        )
    except subprocess.TimeoutExpired as exc:
        raise ProviderError(
            f"{Backend.CLAUDE_CLI.value}: no response within {REQUEST_TIMEOUT_SECONDS}s"
        ) from exc

    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "").strip()[:400]
        raise ProviderError(
            f"{Backend.CLAUDE_CLI.value}: exited {result.returncode}. {detail}".rstrip()
        )

    try:
        payload = json.loads(result.stdout)
        return str(payload["result"])
    except (json.JSONDecodeError, KeyError, TypeError) as exc:
        raise ProviderError(
            f"{Backend.CLAUDE_CLI.value}: could not read a result from the CLI response"
        ) from exc
