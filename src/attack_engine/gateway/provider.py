"""Model providers behind the BYOM gateway.

Providers are the swappable backends the gateway routes to (rule #4). Two ship
in Sprint 0:

* :class:`LiteLLMProvider` — one interface across frontier/open/local via
  LiteLLM. Configured for Fireworks AI open-source models
  (``fireworks_ai/...``); a different model or provider is a config change, not
  a code change.
* :class:`MockProvider` — deterministic, offline responder so agents and the
  whole loop are testable with no API key or GPU. This is the default whenever
  no Fireworks key is present.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Callable, Sequence

from ..errors import ModelGatewayError
from .types import ChatMessage, ModelResponse, Usage


class ModelProvider(ABC):
    name: str = "abstract"

    @abstractmethod
    def complete(
        self,
        model: str,
        messages: Sequence[ChatMessage],
        *,
        temperature: float = 0.0,
        max_tokens: int | None = None,
        timeout_sec: int = 120,
    ) -> ModelResponse: ...


#: A scripted responder: receives the message list, returns the reply text.
MockResponder = Callable[[Sequence[ChatMessage]], str]


def _echo_responder(messages: Sequence[ChatMessage]) -> str:
    last_user = next(
        (m.content for m in reversed(messages) if m.role == "user"), ""
    )
    return f"[mock] {last_user}".strip()


class MockProvider(ModelProvider):
    """Deterministic, offline provider for tests and no-key environments.

    Pass a ``responder`` to script behaviour (e.g. return valid JSON a parser
    expects), or rely on the default echo. Token usage is estimated by word
    count so downstream accounting has non-zero, stable numbers.
    """

    name = "mock"

    def __init__(self, responder: MockResponder | None = None) -> None:
        self._responder = responder or _echo_responder

    def complete(
        self,
        model: str,
        messages: Sequence[ChatMessage],
        *,
        temperature: float = 0.0,
        max_tokens: int | None = None,
        timeout_sec: int = 120,
    ) -> ModelResponse:
        text = self._responder(messages)
        prompt_tokens = sum(len(m.content.split()) for m in messages)
        return ModelResponse(
            text=text,
            model=model,
            tier="mock",
            usage=Usage(prompt_tokens=prompt_tokens, completion_tokens=len(text.split())),
            finish_reason="stop",
            provider=self.name,
        )


class LiteLLMProvider(ModelProvider):
    """Routes completions through LiteLLM across providers (BYOM, rule #4).

    Keys are held per provider and selected by the model's provider prefix
    (``fireworks_ai/…`` → Fireworks key, ``anthropic/…`` → Anthropic key), so a
    frontier tier on Claude and a local tier on Fireworks GLM coexist. A model
    whose provider has no key falls back to LiteLLM's own env lookup.
    """

    name = "litellm"

    def __init__(
        self, keys: dict[str, str] | None = None, *, api_key: str | None = None
    ) -> None:
        self._keys = dict(keys or {})
        # Back-compat: a bare api_key is treated as the Fireworks key.
        if api_key and "fireworks_ai" not in self._keys:
            self._keys["fireworks_ai"] = api_key

    def _key_for(self, model: str) -> str | None:
        provider = model.split("/", 1)[0] if "/" in model else ""
        return self._keys.get(provider)

    def complete(
        self,
        model: str,
        messages: Sequence[ChatMessage],
        *,
        temperature: float = 0.0,
        max_tokens: int | None = None,
        timeout_sec: int = 120,
    ) -> ModelResponse:
        try:
            import litellm
        except ImportError as exc:  # pragma: no cover
            raise ModelGatewayError("litellm is not installed") from exc

        try:
            resp = litellm.completion(
                model=model,
                messages=[m.to_dict() for m in messages],
                temperature=temperature,
                max_tokens=max_tokens,
                timeout=timeout_sec,
                api_key=self._key_for(model),
                # Providers differ on which params they accept (e.g. Claude
                # Sonnet 5 requires temperature=1); drop unsupported ones rather
                # than fail. Keeps the gateway truly model-agnostic (rule #4).
                drop_params=True,
            )
        except Exception as exc:
            raise ModelGatewayError(f"completion failed for {model!r}: {exc}") from exc

        choice = resp.choices[0]
        usage = getattr(resp, "usage", None)
        return ModelResponse(
            text=choice.message.content or "",
            model=model,
            tier="unknown",
            usage=Usage(
                prompt_tokens=getattr(usage, "prompt_tokens", 0) or 0,
                completion_tokens=getattr(usage, "completion_tokens", 0) or 0,
            ),
            finish_reason=getattr(choice, "finish_reason", None),
            provider=self.name,
        )
