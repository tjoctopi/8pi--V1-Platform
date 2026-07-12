"""Observation corroboration — the false-positive gate.

A templated scanner (Nuclei) will happily promote a *single-source* pattern
match to "critical". On a live run against an nginx/Cloudflare edge we saw a
critical **"VMware ESXi SLP – Heap Overflow DoS"** fired off a port mis-fingerprint
— there was no ESXi anywhere. Surfacing that as a confirmed critical destroys
operator trust in the whole report.

This module is the gate: a high/critical observation is only allowed to *keep*
its severity if a second, independent signal corroborates it — namely the
asset's own service/technology fingerprint mentions what the template claims to
have found. Otherwise it is tagged ``unconfirmed`` and clearly separated from
corroborated findings in the dossier. Informational signals pass through as
``reported`` (no corroboration needed — they claim nothing alarming).

Deliberately conservative: corroboration *downgrades confidence*, never the
finding away. The observation is still recorded — an operator can promote it —
it just does not masquerade as a confirmed critical.
"""

from __future__ import annotations

import re

#: Confidence a corroboration check assigns to an observation.
CONFIRMED = "corroborated"     # a second signal backs the template match
UNCONFIRMED = "unconfirmed"    # high/critical with no corroborating signal
REPORTED = "reported"          # informational — nothing to corroborate

_HIGH_SEVERITIES = frozenset({"critical", "high"})

#: Generic tokens that carry no product identity — they must never be the thing
#: that "corroborates" a match (e.g. a template named "default-login-panel"
#: should not self-corroborate off the word "login").
_STOPWORDS = frozenset({
    "detection", "detect", "panel", "login", "default", "exposure", "exposed",
    "disclosure", "misconfiguration", "misconfig", "cve", "vulnerability", "vuln",
    "generic", "unauth", "unauthenticated", "auth", "remote", "heap", "overflow",
    "dos", "rce", "lfi", "xss", "sqli", "ssrf", "injection", "bypass", "takeover",
    "service", "server", "http", "https", "tcp", "udp", "web", "api", "test",
    "check", "scan", "version", "config", "file", "path", "page", "error", "info",
    "the", "and", "for", "with", "via", "log4j",
})

_TOKEN_RE = re.compile(r"[a-z0-9]{3,}")


def _tokens(text: str) -> set[str]:
    """Significant lower-case identity tokens from a template id/title."""

    return {t for t in _TOKEN_RE.findall(text.lower()) if t not in _STOPWORDS}


def corroborate(
    *, name: str, template_id: str, severity: str, tech_tokens: set[str]
) -> tuple[str, str]:
    """Return ``(confidence, reason)`` for one observation.

    ``tech_tokens`` is the identity vocabulary of the asset — tokens drawn from
    its detected services (product/name/banner) and technologies. A high/critical
    match is corroborated iff one of the template's identity tokens appears in
    that vocabulary.
    """

    sev = (severity or "info").lower()
    if sev not in _HIGH_SEVERITIES:
        return REPORTED, "informational — no corroboration required"

    claim = _tokens(f"{template_id} {name}")
    overlap = claim & tech_tokens
    if overlap:
        return CONFIRMED, f"fingerprint corroborates: {', '.join(sorted(overlap))}"
    return (
        UNCONFIRMED,
        "no service/tech fingerprint corroborates this template — treat as "
        "unverified scanner signal, not a confirmed finding",
    )


def tech_vocabulary(tokens_source: str) -> set[str]:
    """Build the asset identity vocabulary from a blob of its fingerprint text."""

    return _tokens(tokens_source)
