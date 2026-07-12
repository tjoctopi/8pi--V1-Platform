"""Edge (CDN/WAF) fingerprinting tests."""

from __future__ import annotations

from attack_engine.intel.edge import detect_edge


def test_detects_cloudflare_cdn_and_waf() -> None:
    headers = (
        "HTTP/2 200\r\n"
        "server: cloudflare\r\n"
        "cf-ray: 8a1b2c3d4e5f6789-SJC\r\n"
        "cf-cache-status: DYNAMIC\r\n"
    )
    edge = detect_edge(headers)
    assert edge.is_cdn is True
    assert edge.is_waf is True
    assert edge.vendor == "Cloudflare"
    assert edge.present is True
    assert "cf-ray" in edge.signals


def test_detects_fastly_cdn_without_waf() -> None:
    edge = detect_edge("HTTP/1.1 200 OK\nx-served-by: cache-sjc\nx-cache: HIT\n")
    assert edge.is_cdn is True
    assert edge.vendor == "Fastly"


def test_plain_origin_has_no_edge() -> None:
    edge = detect_edge("HTTP/1.1 200 OK\r\nserver: nginx\r\ncontent-type: text/html\r\n")
    assert edge.present is False
    assert edge.vendor is None
    assert edge.describe() == "origin (no CDN/WAF detected)"


def test_waf_only_signature_flips_waf_flag() -> None:
    edge = detect_edge("HTTP/1.1 403 Forbidden\r\nserver: nginx\r\nx-mod-security: 1\r\n")
    assert edge.is_waf is True
    assert edge.is_cdn is False
    assert "WAF" in edge.describe()
