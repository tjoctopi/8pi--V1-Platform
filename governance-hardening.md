# 8π — Governance Hardening & Missing Guardrails (future work)

> **Purpose.** This is the honest, code-grounded backlog of the safety controls that
> must be closed before pointing the platform at a **real third-party authorized
> target**. Landing real shells raises the stakes — the envelope must get *stronger*,
> not looser. Everything here is drawn from an actual code audit (file:line cited),
> not aspiration. It expands §8 of [offensive-depth-plan.md](offensive-depth-plan.md)
> and the safety rules in [rules.md](rules.md) (§4/§5/§8).
>
> **These are prerequisites, not nice-to-haves.** On the local range they don't bite;
> against someone else's network, each of them is the difference between an authorized
> test and an incident.

_Last audited: 2026-07-17._

## Status legend
- ✅ **Done** — real and enforced.
- 🟡 **Partial** — a real mechanism exists but a key piece is missing.
- ❌ **Not started** — interface/placeholder only, or absent.

## Summary

| # | Guardrail | Status | The gap in one line |
|---|-----------|--------|---------------------|
| 1 | Signed scope + authorization | 🟡 | Enforced, but signature is a *presence check*, not cryptographically verified. |
| 2 | Egress-controlled sandbox / C2 | ❌ | Container is *placed* on a network + hardened, but nothing restricts *outbound* to the authorized target + C2. |
| 3 | Evidence capture | 🟡 | Command output + hashes are durably captured; no pcap / screenshot / full request-response artifacts. |
| 4 | Credential-vault encryption-at-rest | ❌ | Secret material is held in-memory as plaintext; the encrypted store is a docstring promise. |
| 5 | Kill-switch tears down live beacons | 🟡 | `teardown()` exists and refusal-on-trip works; nothing auto-invokes teardown *when the switch trips*. |

Plus a related item shipped as a **testing convenience** with its own guardrail:
- ✳️ **One-click test authorization** — `Scope.for_testing()` / `Engine.testing_engagement()`. Signed with a sentinel that the engine **refuses in production** (fail-safe). Dev/test only; documented below so it is never mistaken for real authorization.

---

## 1. Signed scope + authorization — 🟡 crypto-verification missing

**What exists.** `Scope.authorized_by` + `Scope.signature`
([schemas/scope.py](src/attack_engine/schemas/scope.py)) with `is_signed()`; the
engine refuses an unsigned scope in prod
([engine.py `engagement()`](src/attack_engine/engine.py)). Every action is bound to
the signed scope and hash-chained into the audit log.

**The gap.** `is_signed()` is `bool(signature) and bool(authorized_by)` — a
**presence** check. Any non-empty string passes. There is no cryptographic
verification that the signature was produced by an authorized key over the scope's
contents, and no detection of a tampered scope (targets widened after signing).

**Risk.** A forged or altered scope authorizes action against targets no human
actually signed off on — the single worst failure mode for offensive tooling.

**Recommendation.**
- Sign the canonical serialization of the scope (targets + RoE + expiry) with an
  operator/asymmetric key (Ed25519); store the detached signature in `signature`.
- `verify_signature(scope, pubkey)` in the Tool Runner boundary; `is_signed()`
  becomes "signature verifies over the current bytes," so any post-sign edit fails.
- Key management: authorizer keys in a KMS/secrets manager, never in the repo.

---

## 2. Egress-controlled sandbox / C2 — ❌ not started

**What exists.** The sandbox runs each tool in a hardened, ephemeral container —
`--read-only`, `--security-opt no-new-privileges`, `--cap-drop ALL`, `--pids-limit`,
optional gVisor runtime, joined to one Docker network
([toolrunner/sandbox.py](src/attack_engine/toolrunner/sandbox.py); network from
[config.py `sandbox_network`](src/attack_engine/config.py)).

**The gap.** This is network *placement* + process hardening, **not egress
control**. Nothing restricts a tool container's (or an implant's) **outbound**
traffic to only the authorized target set + the C2 listener. A tool told to hit the
wrong host, an implant that beacons out, or an SSRF pivot has no network-level
backstop. `grep -r egress src/` returns nothing.

**Risk.** Blast radius. On a real engagement an unconstrained container/implant can
reach out-of-scope hosts or the wider internet — an authorization and safety breach
even if the *intent* was in-scope.

**Recommendation.**
- Per-engagement egress firewall: an allowlist derived from the signed scope
  (`allowed_cidrs`/`allowed_hosts`) + the C2 listener, default-deny everything else.
- Implement via a locked-down Docker network + iptables/nftables egress rules on the
  tool network, or a filtering egress proxy the containers are forced through.
- Enforce the same on the C2 channel: an implant may reach only the target + the
  handler. Wire the allowlist from `Scope` so it can never exceed authorization.

---

## 3. Evidence capture — 🟡 output captured, rich artifacts missing

**What exists.** Each audit entry hashes raw tool output (`raw_sha256`) and durably
stores the raw bytes append-only, hash-chained
([governance/audit.py](src/attack_engine/governance/audit.py);
`raw_blob BLOB` in [audit_backends.py](src/attack_engine/governance/audit_backends.py)).
Foothold proof-of-impact (`whoami`/`id`/`hostname`) is recorded as evidence
([c2/foothold.py](src/attack_engine/c2/foothold.py)).

**The gap.** Evidence today is **tool/command output + hashes**. There is no capture
of pcaps, screenshots, or full HTTP request/response pairs — the richer,
"court-grade" artifacts a real engagement report and dispute-resolution need.

**Risk.** Weaker proof that every action was in-bounds, and thinner deliverables.
Not a safety hole per se, but a credibility and defensibility gap for real clients.

**Recommendation.**
- An `Evidence` capture layer that attaches request/response pairs, pcaps (per
  sandboxed run), and screenshots to the audit entry via the existing `raw`/blob path.
- Content-address + hash-chain each artifact so the bundle is tamper-evident.
- Redaction pass so captured artifacts respect data-minimization (§6) before storage.

---

## 4. Credential-vault encryption-at-rest — ❌ in-memory plaintext

**What exists.** `CredentialVault` holds secret material behind opaque refs, with
masked previews and a `purge()`
([credentials/vault.py](src/attack_engine/credentials/vault.py)). The `Credential`
model never carries the raw secret — only a `secret_ref` (good, data-minimizing).

**The gap.** The backing store is `self._store: dict[str, str]` — **plaintext in
process memory**. The docstring says prod "is backed by an encrypted-at-rest,
access-controlled store"; that backend **does not exist**. No encryption, no access
control, no auto-purge at engagement end.

**Risk.** Captured/cracked credentials (NT hashes, passwords, tickets) sit in
plaintext; a memory dump, crash artifact, or process compromise leaks them. On a
real engagement these are the client's live credentials.

**Recommendation.**
- An encrypted vault backend (envelope encryption via KMS, or `cryptography`'s
  Fernet with a per-engagement key) behind the existing `CredentialVault` interface.
- Access-control reads by actor/role; audit every vault access.
- **Auto-purge** all material at engagement teardown (tie into the kill-switch/#5).

---

## 5. Kill-switch tears down live beacons — 🟡 teardown exists, auto-trigger missing

**What exists.** `KillSwitch` ([governance/authorization.py](src/attack_engine/governance/authorization.py)),
trippable over the API ([api/adapter.py](src/attack_engine/api/adapter.py)). When
tripped it **refuses new** controlled actions
([c2/foothold.py `_authorize`](src/attack_engine/c2/foothold.py)). `teardown()`
closes each live session's transport
([c2/foothold.py `teardown()`](src/attack_engine/c2/foothold.py)).

**The gap.** Tripping the switch **does not auto-invoke `teardown()`**. A trip stops
*new* actions, but a caller must explicitly call `teardown()` to kill already-live
beacons/sessions. "Hit the switch → all live implants die" is not yet wired end to
end, and not verified on a real network.

**Risk.** The operator's instant off-switch doesn't actually sever live access — the
one control a regulated buyer most needs to trust.

**Recommendation.**
- Wire trip → teardown: `KillSwitch.trip()` fans out to every engagement's
  `FootholdRunner.teardown()` / `SessionManager.close_all()` (an observer/callback on
  the switch, so tripping it tears down transports immediately).
- Verify on a real network: land a beacon, trip the switch, confirm the channel is
  dead (not just "no new actions"). Add an integration test at the C2 tier.
- Compose with #4: teardown also purges the credential vault.

---

## ✳️ One-click test authorization (shipped) — and why it's safe

To remove per-step friction while testing, the platform ships a **test-only**
authorization:

- `Scope.for_testing(targets, ...)` — a ready, signed, autonomous scope from a list
  of IPs/CIDRs/hostnames/URLs ([schemas/scope.py](src/attack_engine/schemas/scope.py)).
- `Engine.testing_engagement(targets)` — builds that scope and opens a live
  engagement with auto-approving gates ([engine.py](src/attack_engine/engine.py)).

**Its guardrail (explicit opt-in, so it never becomes a real-prod backdoor):**
- It is signed with the sentinel `TEST-AUTH-NOT-FOR-PROD`, and the engine **refuses
  any test-authorization scope unless the deployment opts in** with
  `AE_ALLOW_TEST_AUTH=true` (`Settings.allow_test_authorization`, **off by default**;
  enforced in [engine.py `engagement()`](src/attack_engine/engine.py)).
- The flag is **independent of `env`** on purpose: a testing/staging deployment
  (even a prod-shaped one you drive via the frontend) flips one env var and the
  one-click auth works end-to-end; a real customer-facing deployment simply leaves
  the flag off, so it can never be driven with fake authorization by accident.
- It **auto-expires** (default 8h) and logs a loud warning on every use.
- **Gate-free by design (for testing):** under a test authorization the engine
  auto-wires an approve-all gate responder (when the caller passes none), so the
  *whole offensive chain* — including high-impact actions like `exploit_confirm`
  and foothold — runs on the user's authorization alone, with no gate friction.
  This is scoped to the opted-in test deployment; real scopes keep the deny-all
  default and gate high-impact actions as normal.

**Usage:** on your test deployment set `AE_ALLOW_TEST_AUTH=true`, then
`engine.testing_engagement(["target"])` (or `Scope.for_testing([...])`) just works —
no signed-scope overhead. Real engagements must use a properly signed `Scope`
(see #1) with the flag off — never `for_testing`.

---

## Suggested sequencing (before any real third-party target)

1. **#2 Egress control** — highest blast-radius risk; nothing else matters if a
   container/implant can reach off-scope.
2. **#5 Kill-switch trip → teardown** — the operator must be able to actually stop it.
3. **#4 Vault encryption + auto-purge** — protect the client's credentials.
4. **#1 Cryptographic scope verification** — un-forgeable authorization.
5. **#3 Rich evidence capture** — defensible deliverables.

Then a self-owned real target (a cloud VM / a Windows AD lab you control) is the
right first "real" proving ground — it exercises real networking + these controls
with zero third-party legal exposure — before any external, signed engagement.
