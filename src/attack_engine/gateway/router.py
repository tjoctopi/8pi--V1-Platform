"""BYOM Model Gateway — model-agnostic routing per task tier (spec §2, rule #4).

No agent names a model. Each agent declares a *tier* (frontier / local); the
gateway resolves that tier to a concrete model id from configuration and routes
the completion through the active provider. Swapping in the specialized model
the day it wins the eval is a one-line config change — no agent code moves.

Every model decision is recorded in the audit log: the tier, the resolved
model, token usage, and content hashes (not the raw prompt), so the governance
record is complete without leaking sensitive prompt text.
"""

from __future__ import annotations

import hashlib
from collections.abc import Sequence

from ..config import Settings, get_settings
from ..errors import ModelGatewayError
from ..governance.audit import AuditLog
from ..logging import get_logger
from ..schemas.agentspec import ModelTier
from .provider import LiteLLMProvider, MockProvider, ModelProvider
from .types import ChatMessage, ModelResponse

_log = get_logger("gateway")


def _sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


class ModelGateway:
    """Routes completions by tier and audits every model decision."""

    def __init__(
        self,
        *,
        settings: Settings | None = None,
        provider: ModelProvider | None = None,
        audit: AuditLog | None = None,
    ) -> None:
        self._settings = settings or get_settings()
        self._audit = audit
        self._provider = provider or self._build_provider(self._settings)
        self._tier_map = {
            ModelTier.FRONTIER: self._settings.model_frontier,
            ModelTier.LOCAL: self._settings.model_local,
        }

    @staticmethod
    def _build_provider(settings: Settings) -> ModelProvider:
        """Pick a provider from config: mock unless a real key is configured.

        Assembles a per-provider key map (Fireworks + Anthropic) so tiers can
        route to different providers; mock if none configured.
        """

        if settings.model_mock:
            return MockProvider()
        keys: dict[str, str] = {}
        if settings.fireworks_api_key:
            keys["fireworks_ai"] = settings.fireworks_api_key.get_secret_value()
        if settings.anthropic_api_key:
            keys["anthropic"] = settings.anthropic_api_key.get_secret_value()
        if not keys:
            _log.warning("no model provider keys set; falling back to MockProvider")
            return MockProvider()
        return LiteLLMProvider(keys=keys)

    @property
    def provider_name(self) -> str:
        return self._provider.name

    def resolve(self, tier: ModelTier) -> str:
        try:
            return self._tier_map[tier]
        except KeyError:
            raise ModelGatewayError(f"unknown model tier {tier!r}") from None

    def complete(
        self,
        messages: Sequence[ChatMessage],
        *,
        tier: ModelTier = ModelTier.LOCAL,
        temperature: float = 0.0,
        max_tokens: int | None = None,
        engagement_id: str | None = None,
        actor: str = "gateway",
    ) -> ModelResponse:
        """Route a completion through the tier's model, with retries + audit."""

        model = self.resolve(tier)
        last_exc: Exception | None = None
        attempts = max(1, self._settings.model_max_retries + 1)
        for attempt in range(attempts):
            try:
                resp = self._provider.complete(
                    model,
                    messages,
                    temperature=temperature,
                    max_tokens=max_tokens,
                    timeout_sec=self._settings.model_timeout_sec,
                )
                resp = resp.model_copy(update={"tier": tier.value})
                self._audit_decision(resp, messages, engagement_id, actor)
                return resp
            except ModelGatewayError as exc:
                last_exc = exc
                _log.warning(
                    "model completion failed", attempt=attempt, model=model, error=str(exc)
                )
        raise ModelGatewayError(
            f"model tier {tier.value!r} ({model}) failed after {attempts} attempts"
        ) from last_exc

    def _audit_decision(
        self,
        resp: ModelResponse,
        messages: Sequence[ChatMessage],
        engagement_id: str | None,
        actor: str,
    ) -> None:
        if self._audit is None or engagement_id is None:
            return
        prompt_concat = "\n".join(m.content for m in messages)
        self._audit.append(
            engagement_id=engagement_id,
            actor=actor,
            action="model.decision",
            payload={
                "tier": resp.tier,
                "model": resp.model,
                "provider": resp.provider,
                "prompt_sha256": _sha256_text(prompt_concat),
                "response_sha256": _sha256_text(resp.text),
                "prompt_tokens": resp.usage.prompt_tokens,
                "completion_tokens": resp.usage.completion_tokens,
                "finish_reason": resp.finish_reason,
            },
        )
