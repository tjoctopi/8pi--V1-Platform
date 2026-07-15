"""BYOM gateway tests — tier routing, mock provider, retries, audit."""

from __future__ import annotations

import pytest

from attack_engine.config import Settings
from attack_engine.errors import ModelGatewayError
from attack_engine.gateway.provider import MockProvider, ModelProvider
from attack_engine.gateway.router import ModelGateway
from attack_engine.gateway.types import ChatMessage, ModelResponse, Usage
from attack_engine.governance.audit import AuditLog
from attack_engine.schemas.agentspec import ModelTier


@pytest.fixture
def settings() -> Settings:
    return Settings(
        model_mock=True,
        model_frontier="fireworks_ai/frontier-model",
        model_local="fireworks_ai/local-model",
        model_max_retries=2,
    )


def test_tier_resolves_to_configured_model(settings: Settings) -> None:
    gw = ModelGateway(settings=settings, provider=MockProvider())
    assert gw.resolve(ModelTier.FRONTIER) == "fireworks_ai/frontier-model"
    assert gw.resolve(ModelTier.LOCAL) == "fireworks_ai/local-model"


def test_mock_completion_roundtrip(settings: Settings) -> None:
    gw = ModelGateway(settings=settings, provider=MockProvider())
    resp = gw.complete([ChatMessage.user("enumerate services")], tier=ModelTier.LOCAL)
    assert "enumerate services" in resp.text
    assert resp.tier == "local"
    assert resp.model == "fireworks_ai/local-model"
    assert resp.usage.total_tokens > 0


def test_scripted_responder(settings: Settings) -> None:
    provider = MockProvider(responder=lambda _m: '{"decision": "scan"}')
    gw = ModelGateway(settings=settings, provider=provider)
    resp = gw.complete([ChatMessage.user("plan")], tier=ModelTier.FRONTIER)
    assert resp.text == '{"decision": "scan"}'


def test_model_decision_is_audited_without_leaking_prompt(settings: Settings) -> None:
    audit = AuditLog()
    gw = ModelGateway(settings=settings, provider=MockProvider(), audit=audit)
    gw.complete(
        [ChatMessage.user("secret prompt text")],
        tier=ModelTier.LOCAL,
        engagement_id="eng-1",
    )
    entry = next(e for e in audit.entries("eng-1") if e.action == "model.decision")
    assert entry.payload["model"] == "fireworks_ai/local-model"
    assert "prompt_sha256" in entry.payload
    # Raw prompt text must NOT appear in the audit payload.
    assert "secret prompt text" not in str(entry.payload)
    assert audit.verify() is True


def test_no_audit_without_engagement(settings: Settings) -> None:
    audit = AuditLog()
    gw = ModelGateway(settings=settings, provider=MockProvider(), audit=audit)
    gw.complete([ChatMessage.user("x")], tier=ModelTier.LOCAL)  # no engagement_id
    assert len(audit) == 0


class _FlakyProvider(ModelProvider):
    name = "flaky"

    def __init__(self, fail_times: int) -> None:
        self.fail_times = fail_times
        self.calls = 0

    def complete(self, model, messages, **kwargs):
        self.calls += 1
        if self.calls <= self.fail_times:
            raise ModelGatewayError("transient")
        return ModelResponse(text="ok", model=model, tier="?", usage=Usage())


def test_retries_then_succeeds(settings: Settings) -> None:
    provider = _FlakyProvider(fail_times=2)  # retries=2 → 3 attempts total
    gw = ModelGateway(settings=settings, provider=provider)
    resp = gw.complete([ChatMessage.user("x")], tier=ModelTier.LOCAL)
    assert resp.text == "ok"
    assert provider.calls == 3


def test_exhausts_retries_and_raises(settings: Settings) -> None:
    provider = _FlakyProvider(fail_times=99)
    gw = ModelGateway(settings=settings, provider=provider)
    with pytest.raises(ModelGatewayError, match="failed after"):
        gw.complete([ChatMessage.user("x")], tier=ModelTier.LOCAL)


def test_falls_back_to_mock_without_api_key() -> None:
    # model_mock False, but no key → provider must be the mock, not litellm.
    # _env_file=None keeps this hermetic even when a real .env with a key exists.
    s = Settings(model_mock=False, fireworks_api_key=None, _env_file=None)
    gw = ModelGateway(settings=s)
    assert gw.provider_name == "mock"


def test_litellm_provider_routes_key_by_model_provider() -> None:
    from attack_engine.gateway.provider import LiteLLMProvider

    p = LiteLLMProvider(keys={"fireworks_ai": "fw-secret", "anthropic": "an-secret"})
    assert p._key_for("fireworks_ai/accounts/fireworks/models/glm-5p2") == "fw-secret"
    assert p._key_for("anthropic/claude-sonnet-5") == "an-secret"
    assert p._key_for("openai/gpt-4o") is None  # no key → litellm env fallback


def test_gateway_builds_multiprovider_from_both_keys() -> None:
    from pydantic import SecretStr

    from attack_engine.gateway.provider import LiteLLMProvider

    s = Settings(model_mock=False, fireworks_api_key=SecretStr("fw"),
                 anthropic_api_key=SecretStr("an"), _env_file=None)
    gw = ModelGateway(settings=s)
    assert gw.provider_name == "litellm"
    assert isinstance(gw._provider, LiteLLMProvider)
    assert gw._provider._keys == {"fireworks_ai": "fw", "anthropic": "an"}


class TestProviderSelection:
    """`_build_provider` picks mock vs LiteLLM from config. `_env_file=None`
    isolates these from any real `.env` on the box."""

    def test_bedrock_tier_builds_litellm_without_a_key(self) -> None:
        # Bedrock authenticates via the AWS credential chain — no api key needed,
        # so a bedrock/ tier must NOT fall back to the mock provider.
        s = Settings(_env_file=None, model_mock=False, fireworks_api_key=None,
                     anthropic_api_key=None,
                     model_frontier="bedrock/anthropic.claude-opus-4-8",
                     model_local="bedrock/anthropic.claude-haiku")
        provider = ModelGateway._build_provider(s)
        assert provider.name == "litellm"

    def test_no_keys_and_no_bedrock_falls_back_to_mock(self) -> None:
        s = Settings(_env_file=None, model_mock=False, fireworks_api_key=None,
                     anthropic_api_key=None, model_frontier="fireworks_ai/frontier",
                     model_local="fireworks_ai/local")
        provider = ModelGateway._build_provider(s)
        assert provider.name == "mock"

    def test_fireworks_key_builds_litellm(self) -> None:
        s = Settings(_env_file=None, model_mock=False, fireworks_api_key="fw-test-key",
                     anthropic_api_key=None, model_frontier="fireworks_ai/frontier",
                     model_local="fireworks_ai/local")
        provider = ModelGateway._build_provider(s)
        assert provider.name == "litellm"
