"""Scope enforcement at the boundary — radix-trie CIDR matching (rule #2).

An out-of-scope target must be refused *before* any tool executes, and the
check must be fast enough to run on every single invocation. We use a binary
radix (patricia-style) trie over the network-address bits: lookup is
O(prefix-length) — at most 32 steps for IPv4, 128 for IPv6 — independent of how
many CIDRs are in the allowlist.

Hostname targets are matched against the explicit host allowlist (exact match,
or a resolved IP if a resolver is supplied). Everything not explicitly allowed
is denied — the allowlist is the whole contract.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Callable

from ..errors import ScopeViolationError
from ..schemas.scope import Scope

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address
IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network
Resolver = Callable[[str], list[str]]


class _RadixNode:
    """One node in the binary trie. ``terminal`` marks the end of a network."""

    __slots__ = ("children", "prefix", "terminal")

    def __init__(self) -> None:
        # children[0] / children[1] for bit 0 / bit 1
        self.children: list[_RadixNode | None] = [None, None]
        self.terminal: bool = False
        self.prefix: str | None = None  # the CIDR string, for diagnostics


class _RadixTrie:
    """Binary radix trie of CIDR networks for one address family."""

    def __init__(self, bit_width: int) -> None:
        self._root = _RadixNode()
        self._bit_width = bit_width
        self._size = 0

    def insert(self, network: IPNetwork) -> None:
        node = self._root
        prefixlen = network.prefixlen
        addr_int = int(network.network_address)
        for i in range(prefixlen):
            # Walk from most-significant bit downward.
            bit = (addr_int >> (self._bit_width - 1 - i)) & 1
            child = node.children[bit]
            if child is None:
                child = _RadixNode()
                node.children[bit] = child
            node = child
        if not node.terminal:
            self._size += 1
        node.terminal = True
        node.prefix = str(network)

    def contains(self, address: IPAddress) -> bool:
        """True if ``address`` falls inside any inserted network.

        We descend the trie following the address bits; if we pass through any
        terminal node, the address is covered by that (shorter-or-equal) prefix.
        """

        if self._root.terminal:  # a 0.0.0.0/0-style catch-all
            return True
        node = self._root
        addr_int = int(address)
        for i in range(self._bit_width):
            bit = (addr_int >> (self._bit_width - 1 - i)) & 1
            child = node.children[bit]
            if child is None:
                return False
            if child.terminal:
                return True
            node = child
        return False

    def __len__(self) -> int:
        return self._size


class ScopeEnforcer:
    """Fast, deterministic in/out-of-scope decisions for a single engagement.

    Construct once per engagement from its :class:`Scope`; reuse across every
    tool invocation. Thread-safe for reads (the tries are immutable after
    construction).
    """

    def __init__(self, scope: Scope, *, resolver: Resolver | None = None) -> None:
        self._scope = scope
        self._resolver = resolver
        self._v4 = _RadixTrie(bit_width=32)
        self._v6 = _RadixTrie(bit_width=128)
        self._hosts: frozenset[str] = frozenset(scope.allowed_hosts)

        for cidr in scope.allowed_cidrs:
            net = ipaddress.ip_network(cidr, strict=False)
            if isinstance(net, ipaddress.IPv4Network):
                self._v4.insert(net)
            else:
                self._v6.insert(net)

    @property
    def scope(self) -> Scope:
        return self._scope

    def _ip_allowed(self, ip: IPAddress) -> bool:
        trie = self._v4 if isinstance(ip, ipaddress.IPv4Address) else self._v6
        return trie.contains(ip)

    def _host_allowed(self, host: str) -> bool:
        host = host.lower().rstrip(".")
        if host in self._hosts:
            return True
        # If a resolver is configured, a hostname is in scope when *all* of its
        # resolved addresses fall inside the allowlist (fail-closed on any miss).
        if self._resolver is not None:
            resolved = self._resolver(host)
            if not resolved:
                return False
            return all(self._ip_allowed(ipaddress.ip_address(a)) for a in resolved)
        return False

    def allows(self, target: str) -> bool:
        """Return whether ``target`` (IP or hostname) is in scope."""

        target = target.strip()
        if not target:
            return False
        try:
            ip = ipaddress.ip_address(target)
        except ValueError:
            return self._host_allowed(target)
        return self._ip_allowed(ip)

    def check(self, target: str) -> None:
        """Raise :class:`ScopeViolationError` if ``target`` is out of scope.

        This is the call the Tool Runner makes *first*, before anything else.
        """

        if self._scope.is_expired():
            raise ScopeViolationError(target, reason="engagement scope expired")
        if not self.allows(target):
            raise ScopeViolationError(target, reason="target not in allowlist")

    def stats(self) -> dict[str, int]:
        return {
            "cidrs_v4": len(self._v4),
            "cidrs_v6": len(self._v6),
            "hosts": len(self._hosts),
        }
