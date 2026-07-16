"""Gateway v2: structured (JSON-schema) output + token budget.

These prove the primitive the reasoning loop stands on — a model emitting a
*validated action object* — plus the cost ceiling the agent fleet spends under.
All offline against MockProvider (no key, no network).
"""

from __future__ import annotations

from collections.abc import Sequence

import pytest
from pydantic import BaseModel

from attack_engine.config import Settings
from attack_engine.errors import BudgetExceededError, StructuredOutputError
from attack_engine.gateway.budget import TokenBudget
from attack_engine.gateway.provider import MockProvider
from attack_engine.gateway.router import ModelGateway, extract_json
from attack_engine.gateway.types import ChatMessage, Usage
from attack_engine.schemas.agentspec import ModelTier


class Action(BaseModel):
    tool: str
    rationale: str
    priority: int


@pytest.fixture
def settings() -> Settings:
    return Settings(
        model_mock=True,
        model_frontier="fireworks_ai/frontier-model",
        model_local="fireworks_ai/local-model",
        model_max_retries=2,
        model_json_max_retries=2,
    )


def _gw(settings: Settings, responder) -> ModelGateway:
    return ModelGateway(settings=settings, provider=MockProvider(responder=responder))


# --- extract_json ---------------------------------------------------------------


def test_extract_json_plain() -> None:
    assert extract_json('{"a": 1}') == {"a": 1}


def test_extract_json_from_code_fence() -> None:
    text = 'Here you go:\n```json\n{"a": 1, "b": [2, 3]}\n```\nDone.'
    assert extract_json(text) == {"a": 1, "b": [2, 3]}


def test_extract_json_embedded_in_prose() -> None:
    assert extract_json('Sure! {"a": 1} hope that helps') == {"a": 1}


def test_extract_json_raises_when_absent() -> None:
    with pytest.raises(ValueError, match="no parseable JSON"):
        extract_json("there is no json here")


# --- respond_json ---------------------------------------------------------------


def test_respond_json_valid(settings: Settings) -> None:
    gw = _gw(settings, lambda _m: '{"tool": "nmap", "rationale": "map", "priority": 1}')
    action = gw.respond_json([ChatMessage.user("plan")], Action, tier=ModelTier.FRONTIER)
    assert isinstance(action, Action)
    assert action.tool == "nmap"
    assert action.priority == 1


def test_respond_json_tolerates_fences(settings: Settings) -> None:
    gw = _gw(
        settings,
        lambda _m: '```json\n{"tool": "httpx", "rationale": "probe", "priority": 2}\n```',
    )
    action = gw.respond_json([ChatMessage.user("plan")], Action)
    assert action.tool == "httpx"


def test_respond_json_retries_then_succeeds(settings: Settings) -> None:
    calls = {"n": 0}

    def responder(_messages: Sequence[ChatMessage]) -> str:
        calls["n"] += 1
        if calls["n"] == 1:
            return "not json at all"
        return '{"tool": "ffuf", "rationale": "fuzz", "priority": 3}'

    gw = _gw(settings, responder)
    action = gw.respond_json([ChatMessage.user("plan")], Action)
    assert action.tool == "ffuf"
    assert calls["n"] == 2  # first attempt failed, second recovered


def test_respond_json_schema_violation_retries(settings: Settings) -> None:
    calls = {"n": 0}

    def responder(_messages: Sequence[ChatMessage]) -> str:
        calls["n"] += 1
        if calls["n"] == 1:
            return '{"tool": "nmap"}'  # missing required fields
        return '{"tool": "nmap", "rationale": "map", "priority": 1}'

    gw = _gw(settings, responder)
    action = gw.respond_json([ChatMessage.user("plan")], Action)
    assert action.rationale == "map"
    assert calls["n"] == 2


def test_respond_json_exhausts_and_raises(settings: Settings) -> None:
    gw = _gw(settings, lambda _m: "never valid")
    with pytest.raises(StructuredOutputError, match="Action"):
        gw.respond_json([ChatMessage.user("plan")], Action)


# --- TokenBudget ----------------------------------------------------------------


def test_budget_unlimited_by_default() -> None:
    b = TokenBudget()
    b.charge(Usage(prompt_tokens=1000, completion_tokens=1000))
    b.ensure_available()  # never raises
    assert b.remaining() is None
    assert b.spent == 2000


def test_budget_charge_and_remaining() -> None:
    b = TokenBudget(max_total_tokens=100)
    b.charge(Usage(prompt_tokens=30, completion_tokens=10))
    assert b.spent == 40
    assert b.remaining() == 60


def test_budget_rejects_negative_ceiling() -> None:
    with pytest.raises(ValueError, match="non-negative"):
        TokenBudget(max_total_tokens=-1)


def test_budget_blocks_when_exhausted() -> None:
    b = TokenBudget(max_total_tokens=10)
    b.charge(Usage(prompt_tokens=8, completion_tokens=5))  # 13 >= 10
    with pytest.raises(BudgetExceededError) as exc:
        b.ensure_available()
    assert exc.value.spent == 13
    assert exc.value.limit == 10


def test_gateway_charges_budget(settings: Settings) -> None:
    gw = _gw(settings, lambda _m: "ok")
    b = TokenBudget(max_total_tokens=1000)
    gw.complete([ChatMessage.user("one two three")], tier=ModelTier.LOCAL, budget=b)
    assert b.spent > 0


def test_gateway_refuses_once_budget_exhausted(settings: Settings) -> None:
    gw = _gw(settings, lambda _m: "some words here to spend")
    b = TokenBudget(max_total_tokens=3)
    # First call is allowed (spent starts at 0) but pushes spent over the ceiling.
    gw.complete([ChatMessage.user("a b c d e")], tier=ModelTier.LOCAL, budget=b)
    with pytest.raises(BudgetExceededError):
        gw.complete([ChatMessage.user("more")], tier=ModelTier.LOCAL, budget=b)
