"""OOB interaction server — token minting, callback correlation, blind-vuln proof."""

from __future__ import annotations

from attack_engine.verify.oob import InMemoryOobServer, OobToken


def _server() -> InMemoryOobServer:
    return InMemoryOobServer(base_domain="oob.8pi-range.test")


def test_mint_embeds_token_in_endpoints() -> None:
    server = _server()
    tok = server.mint("ssrf f-1")
    assert isinstance(tok, OobToken)
    assert tok.dns_hostname == f"{tok.token}.oob.8pi-range.test"
    assert tok.http_url == f"http://{tok.token}.oob.8pi-range.test/"
    assert server.purpose(tok.token) == "ssrf f-1"


def test_tokens_are_unique() -> None:
    server = _server()
    tokens = {server.mint().token for _ in range(50)}
    assert len(tokens) == 50


def test_no_interaction_means_not_proven() -> None:
    server = _server()
    tok = server.mint()
    assert not server.saw(tok.token)
    assert server.interactions(tok.token) == []


def test_recorded_callback_proves_interaction() -> None:
    server = _server()
    tok = server.mint("blind sqli")
    assert server.record(tok.token, "http", source_ip="10.5.0.11", detail="GET /")
    assert server.saw(tok.token)
    hits = server.interactions(tok.token)
    assert len(hits) == 1
    assert hits[0].kind == "http"
    assert hits[0].source_ip == "10.5.0.11"


def test_unminted_token_is_rejected() -> None:
    server = _server()
    # A stray callback for a token we never issued cannot forge a proof.
    assert server.record("never-minted", "dns") is False
    assert not server.saw("never-minted")


def test_record_hostname_attributes_to_token() -> None:
    server = _server()
    tok = server.mint()
    # A DNS lookup of "<token>.oob.8pi-range.test" from the target.
    assert server.record_hostname(f"{tok.token}.oob.8pi-range.test.", source_ip="10.5.0.12")
    assert server.saw(tok.token)
    assert server.interactions(tok.token)[0].kind == "dns"


def test_record_hostname_with_prepended_labels() -> None:
    server = _server()
    tok = server.mint()
    # Payloads sometimes prepend sub-labels; the left-most label is the token.
    assert server.record_hostname(f"data.exfil.{tok.token}.oob.8pi-range.test")
    assert server.saw(tok.token)


def test_hostname_outside_base_domain_ignored() -> None:
    server = _server()
    server.mint()
    assert server.token_from_host("evil.example.com") is None
    assert server.record_hostname("evil.example.com") is False


def test_deterministic_factory_and_collision_guard() -> None:
    import pytest

    server = InMemoryOobServer(token_factory=lambda: "fixed")
    server.mint()
    with pytest.raises(ValueError, match="collision"):
        server.mint()
