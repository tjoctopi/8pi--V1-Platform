"""Impact + remediation knowledge for confirmed findings.

A confirmed vulnerability is only actionable if it carries *impact* (how severe,
CVSS) and *remediation* (how to fix) — the fields a report and a defender need.
CVE findings get CVSS from the feed; oracle-proven web/service vulnerabilities
have no CVE, so this module supplies a deterministic, industry-standard baseline
keyed by vulnerability class (CVSS v3.1 base scores for the canonical instance of
each class) plus concise, class-specific remediation guidance.

Deterministic on purpose: severity and fix advice must not depend on a model
being reachable (the pilot box is network-restricted). A model gateway, when
present, may layer a human-readable rationale on top (see the Converter), but the
substance lives here.
"""

from __future__ import annotations

from ..schemas.findings import Finding, Priority

#: Vulnerability class → (CVSS v3.1 base score, one-line remediation). Keyed by
#: the finding-type prefix the oracles/exploit modules emit. Scores are the
#: standard base for the canonical instance of the class.
_IMPACT: tuple[tuple[tuple[str, ...], float, str], ...] = (
    (("command-injection", "cmdi", "os-command", "rce"), 9.8,
     "Never pass user input to a shell. Use exec APIs that take an argument vector "
     "(no shell), allow-list permitted values, and drop the affected code path's "
     "privileges. Add a WAF rule for the endpoint as an interim control."),
    (("sqli", "sql-injection"), 9.8,
     "Replace string-built SQL with parameterised/prepared statements everywhere the "
     "parameter flows. Add server-side input validation and least-privilege DB "
     "credentials. Deploy a WAF rule for the endpoint until the code fix ships."),
    (("ssti", "template-injection"), 9.0,
     "Do not render user input as a template. Use a sandboxed/logic-less template "
     "engine, pass user data only as bound variables, and validate input server-side."),
    (("ssrf",), 8.6,
     "Validate and allow-list outbound destinations, resolve and pin hostnames, block "
     "link-local/metadata ranges (169.254.0.0/16), and require authentication on "
     "internal services. Disable unused URL schemes."),
    (("xxe",), 7.5,
     "Disable external entity and DTD processing in the XML parser (set "
     "FEATURE_SECURE_PROCESSING / disallow-doctype-decl). Prefer a hardened parser."),
    (("lfi", "path-traversal"), 7.5,
     "Resolve the requested path and confirm it stays within an allow-listed base "
     "directory (canonicalise, reject '..'). Serve files by opaque id, not by path, "
     "and run the service with least privilege."),
    (("open-redirect",), 6.1,
     "Do not redirect to a user-supplied URL. Redirect only to a server-side "
     "allow-list of paths, or map an opaque token to a known destination."),
    (("xss",), 6.1,
     "Context-encode all user data on output, set a strict Content-Security-Policy, "
     "and validate input server-side. Prefer a framework that auto-escapes."),
    (("default-cred", "weak-cred"), 9.8,
     "Rotate the credential immediately to a strong, unique secret, disable the "
     "default account, and enforce MFA. Store secrets in a managed vault."),
)

#: CVSS base → engine priority bucket (CVSS v3.1 qualitative severity ratings).
def priority_for_cvss(cvss: float) -> Priority:
    """Map a CVSS base score to the engine's priority bucket."""

    if cvss >= 9.0:
        return Priority.PATCH_IMMEDIATELY
    if cvss >= 7.0:
        return Priority.HIGH
    if cvss >= 4.0:
        return Priority.MEDIUM
    if cvss > 0.0:
        return Priority.LOW
    return Priority.INFORMATIONAL


def _impact_for_type(finding_type: str) -> tuple[float, str] | None:
    ft = (finding_type or "").lower()
    for prefixes, cvss, remediation in _IMPACT:
        if ft.startswith(prefixes):
            return cvss, remediation
    return None


def reachability_reason(finding: Finding, *, reachable: bool) -> str:
    """A human-readable justification of the finding's reachability.

    A finding an oracle *proved* was reached by a live probe is reachable in
    practice regardless of the graph; otherwise we defer to the attack-graph
    route from the engagement entry node.
    """

    proven = finding.verified_by is not None
    if proven:
        return (
            "Proven reachable: a live probe from the scanner vantage reached this "
            "endpoint and the oracle confirmed exploitation."
        )
    if reachable:
        return (
            "Reachable from the engagement entry: a route exists in the attack graph "
            "from an external entry node to this asset."
        )
    return (
        "Reachability from the engagement entry node is not yet established; the "
        "finding was observed but no external route has been confirmed."
    )


def enrich_impact(finding: Finding, *, reachable: bool) -> dict[str, object]:
    """Impact/remediation metadata to merge onto a confirmed finding.

    Returns ``{cvss, severity, remediation, reachability_reason}`` for a known
    vulnerability class, or just ``{reachability_reason}`` for an unclassified
    type (still useful, never fabricating a CVSS). Existing keys are never
    overwritten by the caller when the finding already carries richer data
    (e.g. a CVE's feed-provided CVSS).
    """

    out: dict[str, object] = {
        "reachability_reason": reachability_reason(finding, reachable=reachable)
    }
    impact = _impact_for_type(finding.type)
    if impact is not None:
        cvss, remediation = impact
        out["cvss"] = cvss
        out["severity"] = priority_for_cvss(cvss).value
        out["remediation"] = remediation
    return out
