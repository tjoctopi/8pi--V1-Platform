"""Out-of-band (OOB) interaction server — proof infrastructure for blind vulns.

Many of the highest-impact bugs are *blind*: a server-side request forgery,
blind SQL injection, XXE, or a reverse callback proves itself not in the HTTP
response but by making the target reach out to an attacker-controlled endpoint.
This is the Burp-Collaborator-style capability that makes that proof possible.

The flow an impact oracle follows:

    token = server.mint("ssrf f-123")          # unique, unguessable token
    ... embed token.http_url / token.dns_hostname in the payload, run the tool ...
    if server.saw(token.token):                 # the target called home → proven
        promote to CONFIRMED with the interaction as evidence

This module is transport-agnostic. :class:`InMemoryOobServer` records
interactions pushed into it — the unit-testable core and the dev default. A real
deployment runs DNS/HTTP listeners that call :meth:`record` on every inbound hit
(wired in the production deploy phase); oracles depend only on the
:class:`OobServer` interface, so nothing above changes.
"""

from __future__ import annotations

import threading
import uuid
from abc import ABC, abstractmethod
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Literal

from ..schemas.common import iso_now

OobKind = Literal["dns", "http"]


@dataclass(frozen=True)
class OobInteraction:
    """One inbound callback attributed to a minted token."""

    token: str
    kind: OobKind
    source_ip: str | None = None
    detail: str = ""
    at: str = field(default_factory=iso_now)


@dataclass(frozen=True)
class OobToken:
    """A minted correlation token plus the endpoints that embed it.

    A payload uses :attr:`http_url` or :attr:`dns_hostname`; when the target
    resolves/requests it, the listener attributes the hit back to :attr:`token`.
    """

    token: str
    base_domain: str

    @property
    def dns_hostname(self) -> str:
        return f"{self.token}.{self.base_domain}"

    @property
    def http_url(self) -> str:
        return f"http://{self.token}.{self.base_domain}/"


class OobServer(ABC):
    """Mint correlation tokens and report interactions seen against them."""

    @abstractmethod
    def mint(self, purpose: str = "") -> OobToken:
        """Issue a fresh, unique token for one oracle probe."""

    @abstractmethod
    def interactions(self, token: str) -> list[OobInteraction]:
        """All interactions recorded for ``token`` (empty if none / unknown)."""

    def saw(self, token: str) -> bool:
        """Whether the target ever called back on ``token`` — the proof check."""

        return bool(self.interactions(token))


class InMemoryOobServer(OobServer):
    """In-process OOB server: the test/dev core behind the real listeners.

    Tokens are UUID4 by default (unguessable, so an unrelated request can't
    forge a proof); inject ``token_factory`` for deterministic tests.
    """

    def __init__(
        self,
        base_domain: str = "oob.8pi-range.test",
        *,
        token_factory: Callable[[], str] | None = None,
    ) -> None:
        self.base_domain = base_domain
        self._factory = token_factory or (lambda: uuid.uuid4().hex[:16])
        self._interactions: dict[str, list[OobInteraction]] = {}
        self._purposes: dict[str, str] = {}
        self._lock = threading.RLock()

    def mint(self, purpose: str = "") -> OobToken:
        with self._lock:
            token = self._factory()
            # Guard against a factory collision (matters for injected factories).
            if token in self._interactions:
                raise ValueError(f"OOB token collision: {token!r}")
            self._interactions[token] = []
            self._purposes[token] = purpose
        return OobToken(token=token, base_domain=self.base_domain)

    def record(
        self,
        token: str,
        kind: OobKind,
        *,
        source_ip: str | None = None,
        detail: str = "",
    ) -> bool:
        """Log an inbound callback. Returns False for an unminted token.

        Only minted tokens are accepted, so a stray request to the listener can
        never manufacture a false proof for a probe that was never issued.
        """

        with self._lock:
            if token not in self._interactions:
                return False
            self._interactions[token].append(
                OobInteraction(token=token, kind=kind, source_ip=source_ip, detail=detail)
            )
            return True

    def record_hostname(
        self, hostname: str, kind: OobKind = "dns", *, source_ip: str | None = None
    ) -> bool:
        """Attribute a raw inbound hostname (e.g. ``<token>.oob…``) to its token."""

        token = self.token_from_host(hostname)
        if token is None:
            return False
        return self.record(token, kind, source_ip=source_ip, detail=hostname)

    def interactions(self, token: str) -> list[OobInteraction]:
        with self._lock:
            return list(self._interactions.get(token, []))

    def purpose(self, token: str) -> str | None:
        with self._lock:
            return self._purposes.get(token)

    def token_from_host(self, host: str) -> str | None:
        """Extract the token label from an inbound host under our base domain."""

        host = host.strip().rstrip(".").lower()
        suffix = "." + self.base_domain.lower()
        if not host.endswith(suffix):
            return None
        label = host[: -len(suffix)]
        # The token is the left-most label (payloads may prepend sub-labels).
        return label.rsplit(".", 1)[-1] or None
