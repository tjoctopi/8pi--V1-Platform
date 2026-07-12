"""Edge fingerprinting — is this asset fronted by a CDN / WAF?

A large fraction of real targets sit behind a CDN or WAF (Cloudflare, Akamai,
Fastly, CloudFront, Sucuri, Imperva…). That single fact should *steer the
strategy*, not merely be noted: blasting an XSS fuzzer or the full templated
corpus at a CDN edge that exposes one static route burns wall-clock for zero
yield, and the WAF rate-limits us into slow timeouts anyway. So we detect the
edge cheaply from response headers up front and let the web phase adapt
(lead-gated escalation, focused templates, tighter timeouts).

This is *not* an infra-type restriction — the signed scope alone governs whether
we may touch a target. It is tool-selection policy: run the tools that can
actually find something on *this* surface, and skip the ones that can't.
"""

from __future__ import annotations

from ..schemas.common import StrictModel

#: header-substring (lower-cased) → (vendor, is_cdn, is_waf). Matched against the
#: raw response header block. Ordered most-specific first.
_EDGE_SIGNATURES: tuple[tuple[str, str, bool, bool], ...] = (
    ("cf-ray", "Cloudflare", True, True),
    ("cf-cache-status", "Cloudflare", True, False),
    ("server: cloudflare", "Cloudflare", True, True),
    ("__cfduid", "Cloudflare", True, True),
    ("x-amz-cf-id", "AWS CloudFront", True, False),
    ("via: 1.1 varnish", "Fastly/Varnish", True, False),
    ("x-served-by", "Fastly", True, False),
    ("x-fastly", "Fastly", True, False),
    ("server: akamaighost", "Akamai", True, True),
    ("x-akamai", "Akamai", True, True),
    ("x-sucuri-id", "Sucuri", True, True),
    ("x-sucuri-cache", "Sucuri", True, True),
    ("x-iinfo", "Imperva Incapsula", True, True),
    ("incap_ses", "Imperva Incapsula", True, True),
    ("x-cdn", "Generic CDN", True, False),
    ("x-azure-ref", "Azure Front Door", True, True),
    ("server: awselb", "AWS ELB", False, False),
    # WAF-only signatures (no CDN implied).
    ("x-waf", "Generic WAF", False, True),
    ("mod_security", "ModSecurity", False, True),
    ("x-mod-security", "ModSecurity", False, True),
    ("bigip", "F5 BIG-IP", False, True),
    ("barracuda", "Barracuda WAF", False, True),
)


class EdgeProfile(StrictModel):
    """What fronts an asset — a CDN, a WAF, both, or neither."""

    is_cdn: bool = False
    is_waf: bool = False
    vendor: str | None = None
    #: The header signals that fired (for the audit trail / dossier).
    signals: list[str] = []

    @property
    def present(self) -> bool:
        return self.is_cdn or self.is_waf

    def describe(self) -> str:
        if not self.present:
            return "origin (no CDN/WAF detected)"
        kinds = "/".join(k for k, on in (("CDN", self.is_cdn), ("WAF", self.is_waf)) if on)
        return f"{self.vendor or 'unknown'} {kinds}"


def detect_edge(header_block: str) -> EdgeProfile:
    """Fingerprint the CDN/WAF from a raw HTTP response header block.

    Scans the (case-insensitive) header text for known vendor signals. The first
    matching signature sets the vendor; every match contributes to the flags and
    the recorded signal list, so a WAF-only header still flips ``is_waf`` even
    when a different vendor named the profile.
    """

    text = header_block.lower()
    profile = EdgeProfile()
    for sig, vendor, is_cdn, is_waf in _EDGE_SIGNATURES:
        if sig in text:
            if profile.vendor is None:
                profile.vendor = vendor
            profile.is_cdn = profile.is_cdn or is_cdn
            profile.is_waf = profile.is_waf or is_waf
            profile.signals.append(sig)
    return profile
