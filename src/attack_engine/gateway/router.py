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
import json
from collections.abc import Sequence
from typing import TypeVar

from pydantic import BaseModel, ValidationError

from ..config import Settings, get_settings
from ..errors import ModelGatewayError, StructuredOutputError
from ..governance.audit import AuditLog
from ..logging import get_logger
from ..schemas.agentspec import ModelTier
from .budget import TokenBudget
from .provider import LiteLLMProvider, MockProvider, ModelProvider
from .types import ChatMessage, ModelResponse

_log = get_logger("gateway")

T = TypeVar("T", bound=BaseModel)


def _sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def extract_json(text: str) -> object:
    """Pull a JSON value out of a model reply, tolerating prose and code fences.

    Models wrap JSON in ```json fences or add a sentence of preamble even when
    told not to. We try, in order: the whole string, a fenced block, then the
    span from the first ``{``/``[`` to its matching last ``}``/``]``. Raises
    :class:`ValueError` if nothing parses, so the caller can retry with feedback.
    """

    candidates: list[str] = [text.strip()]

    fence = "```"
    if fence in text:
        after = text.split(fence, 1)[1]
        block = after.split(fence, 1)[0]
        # Drop an optional language tag on the opening fence line (```json).
        if "\n" in block:
            first_line, rest = block.split("\n", 1)
            block = rest if first_line.strip().isalpha() else block
        candidates.append(block.strip())

    for opener, closer in (("{", "}"), ("[", "]")):
        start = text.find(opener)
        end = text.rfind(closer)
        if start != -1 and end > start:
            candidates.append(text[start : end + 1])

    for candidate in candidates:
        if not candidate:
            continue
        try:
            return json.loads(candidate)
        except json.JSONDecodeError:
            continue
    raise ValueError("no parseable JSON found in model response")


def _schema_instruction(schema: type[BaseModel]) -> ChatMessage:
    """A user turn telling the model the exact JSON shape to return."""

    compact = json.dumps(schema.model_json_schema(), separators=(",", ":"))
    return ChatMessage.user(
        "Respond with ONLY a JSON object conforming to this JSON Schema "
        "(no prose, no code fences):\n" + compact
    )


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
        # Bedrock needs no API key — LiteLLM authenticates via the AWS credential
        # chain (env / EC2 instance role), so a `bedrock/…` tier is a keyless path.
        uses_bedrock = (settings.model_frontier or "").startswith("bedrock/") or (
            settings.model_local or ""
        ).startswith("bedrock/")
        if not keys and not uses_bedrock:
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
        budget: TokenBudget | None = None,
    ) -> ModelResponse:
        """Route a completion through the tier's model, with retries + audit.

        If a :class:`TokenBudget` is supplied it is checked before the call
        (raising :class:`BudgetExceededError` once exhausted) and charged after
        a successful one.
        """

        if budget is not None:
            budget.ensure_available()
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
                if budget is not None:
                    budget.charge(resp.usage)
                return resp
            except ModelGatewayError as exc:
                last_exc = exc
                _log.warning(
                    "model completion failed", attempt=attempt, model=model, error=str(exc)
                )
        raise ModelGatewayError(
            f"model tier {tier.value!r} ({model}) failed after {attempts} attempts"
        ) from last_exc

    def respond_json(
        self,
        messages: Sequence[ChatMessage],
        schema: type[T],
        *,
        tier: ModelTier = ModelTier.LOCAL,
        temperature: float = 0.0,
        max_tokens: int | None = None,
        engagement_id: str | None = None,
        actor: str = "gateway",
        budget: TokenBudget | None = None,
    ) -> T:
        """Complete and parse the reply into a validated ``schema`` instance.

        The provider-agnostic way to make a model emit a *structured action*
        (rule #4): we append the JSON Schema to the prompt, parse the reply, and
        validate it against ``schema``. On a parse/validation failure we replay
        the model's own bad reply plus the error and ask again, up to
        ``model_json_max_retries`` times, then raise :class:`StructuredOutputError`.

        Built on :meth:`complete`, so budget accounting and per-call audit apply
        to every attempt — including the failed ones (they cost tokens too).
        """

        convo: list[ChatMessage] = [*messages, _schema_instruction(schema)]
        attempts = max(1, self._settings.model_json_max_retries + 1)
        last_err: Exception | None = None
        for _ in range(attempts):
            resp = self.complete(
                convo,
                tier=tier,
                temperature=temperature,
                max_tokens=max_tokens,
                engagement_id=engagement_id,
                actor=actor,
                budget=budget,
            )
            try:
                payload = extract_json(resp.text)
                return schema.model_validate(payload)
            except (ValueError, ValidationError) as exc:
                last_err = exc
                _log.warning("structured output invalid; retrying", error=str(exc))
                convo = [
                    *convo,
                    ChatMessage.assistant(resp.text),
                    ChatMessage.user(
                        "That response was not valid. Error:\n"
                        f"{exc}\n"
                        "Return ONLY a JSON object matching the schema, no prose."
                    ),
                ]
        raise StructuredOutputError(
            f"model did not produce valid {schema.__name__} JSON "
            f"after {attempts} attempts"
        ) from last_err

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
