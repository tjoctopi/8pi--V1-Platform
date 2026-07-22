# 8π — Auth-gated & Advanced-Target Capability Plan (living · design-first)

> **Status: DESIGN — not yet implemented.** This is the agreed plan for extending the
> platform from *unauthenticated classic-web-param injection* to *authenticated and
> modern (SPA / API / GraphQL / JWT) targets*. One vertical slice at a time
> (engine → API → console), each tested and proven live before the next. Every slice
> obeys the four non-negotiables (propose-vs-confirm · scope-at-boundary · roles-not-
> tool-copies · model-agnostic) and the safety envelope (scope/gate/audit/kill-switch).

## Where we are (honest baseline, audited from code)

**Works today (autonomous, live-proven):** recon (nmap) → crawl (katana, GET params) →
broad scan (nuclei) → deterministic sweep graduates every candidate → oracles CONFIRM:
LFI, boolean-blind SQLi, reflected XSS, SSTI, OS-command-injection/RCE, open-redirect;
IDOR/BOLA + SSRF partially. Confirmed RCE → live governed C2 session → post-ex → teardown.

**Gaps for auth-gated / advanced targets (verified in code):**
1. **No authentication/session handling** — `http_probe`, `katana`, `web_specialist` carry
   no cookie/login/bearer/CSRF logic; `Scope`/RoE has no credentials field. The crawler
   never gets past a login page → auth-gated apps yield nothing.
2. **No form / API-body discovery** — katana surfaces GET params; HTML form (POST) fields
   and SPA/XHR/JSON API endpoints are not discovered (earlier proofs *seeded* the POST point).
3. **Missing modern-class oracles** — present: LFI/SQLi/XSS/SSTI/cmdi/SSRF/open-redirect/IDOR.
   **Absent: JWT, GraphQL, NoSQL, deserialization, XXE.**
4. **No deployed OOB listener** — `verify/oob.py` has the token/correlation core + an
   `InMemoryOobServer`, but no real DNS/HTTP listener → blind SSRF/SQLi/XXE/RCE can't confirm.
5. **IDOR/BOLA can't fire** — `AccessControlOracle` exists but needs an *authenticated
   baseline* it currently cannot obtain.

---

## Tier 1 — Authenticated attack surface  *(foundational · highest leverage · build first)*

**Goal:** the platform logs into an authorized target, carries the session through the
crawl and every oracle, and discovers POST-form + API/JSON injection points — turning on
the entire authenticated attack surface and making IDOR/BOLA fireable.

### 1A. Target credentials — stored safely (never a secret in scope/audit/logs)
- **Reuse the Phase-E `CredentialVault`** (`credentials/vault.py`): the raw secret lives
  behind an opaque `vault-…` ref; the scope/RoE/audit only ever carry the ref + masked
  preview (data-min rule §6/§8). Target creds are *input* creds (given to us) vs harvested
  creds, but the same vault chokepoint applies.
- **New `schemas/auth.py::AuthProfile`** (attached to the engagement, not the signed scope
  crypto): `{ kind: form|basic|bearer|cookie, login_url, username, secret_ref, csrf_field,
  success_marker, logout_url, headers }`. The signed scope stays a pure authorization
  artifact; the AuthProfile is engagement config bound to it.
- **API/console:** an *"Authenticated Scan"* section in the RoE tab collects auth kind +
  login URL + username + secret + success marker; the API puts the secret in the vault and
  stores the `AuthProfile` on the engagement. `POST /engagements/{id}/auth-profile`.

### 1B. Authenticator — obtain a session (scope-enforced)
- **New `webauth/authenticator.py::Authenticator`**: given an `AuthProfile`, returns a
  `WebSession { cookies, headers }`.
  - `basic` → `Authorization: Basic …`; `bearer` → `Authorization: Bearer <token>`;
    `cookie` → fixed cookie header.
  - `form` → GET the login page (extract CSRF token via `csrf_field`), POST creds through the
    **Tool Runner** (scope-checked, so login only ever hits in-scope hosts), capture
    `Set-Cookie`; verify with `success_marker`.
- Secret read from the vault only at the moment of use, in-memory, never logged/audited
  (mirrors the E4 lateral-secret hygiene).

### 1C. Session propagation — thread the session through crawl + oracles
- **`toolrunner/wrappers/http_probe.py`**: add `headers` / `cookies` profile args (emit
  `-H`/cookie header to the underlying probe). Non-mutating default preserved.
- **`toolrunner/wrappers/katana.py`**: pass `-H`/`-headers` + `-fx`/form + keep `-jc` for
  XHR/API endpoint recovery, so the *authenticated* app is crawled.
- **`verify/context.py::VerifyContext`**: carry an optional `session` (cookies/headers);
  every oracle that builds a `ToolProfile` merges it (one-line change per oracle — they
  already accept nested `params`/`data`).
- **`agents/web_specialist.py`**: the sweep/loop obtains the session via the Authenticator
  once, then all crawls + graduations + oracle runs use it.

### 1D. Form + API-body discovery
- **`WebObserver`**: fold katana form output → POST candidates (per-field, per-class);
  fold discovered XHR/REST endpoints → JSON-body candidates.
- **Oracles + http_probe**: add a JSON body mode (`Content-Type: application/json`,
  inject into a JSON field) so SQLi/cmdi/etc. oracles confirm on API bodies, not just
  query/form params. Extend `WebGraduator._REQUIRES_PARAM` handling for body params.

### 1E. IDOR/BOLA becomes fireable
- With an authenticated baseline available, `AccessControlOracle` auto-graduates: it diffs
  an authorized response vs an anonymous/other-user request for identical protected bytes.
  Add a second (low-priv) credential slot so it can also prove *horizontal* BOLA.

**Tests:** authenticator (form CSRF + basic + bearer, fake sandbox); session propagation
(oracle profile carries the cookie); form/JSON candidate graduation; AccessControlOracle
auto-graduation with a baseline. **Gate:** autonomously confirm an *authenticated* vuln
(authenticated SQLi **or** IDOR/BOLA) on a logged-in range app (DVWA), live.

**Console/API:** Authenticated-Scan RoE section; sessions/creds shown masked; the sweep
auto-authenticates when an AuthProfile is present.

---

## Tier 2 — Modern vuln classes  *(SPA / API era · mostly needs Tier 1 auth)*

Each = a `WebObserver` candidate class + a **registered deterministic oracle** (propose→confirm)
+ graduation wiring. New files under `verify/oracles/`.

- **2A. JWT oracle** (`jwt.py`): capture a JWT from the session/response; prove a forge-accept
  bypass via `alg=none`, weak-HMAC-secret crack (wordlist), or `kid`/`jku` manipulation —
  confirmed by an *authorized-vs-forged* response diff (same style as AccessControlOracle).
  Read-only; forges only our own test token.
- **2B. GraphQL** (`graphql.py`): introspection → type/field map → confirm an authz/injection
  flaw (a field returning data it shouldn't, or an injectable arg) by response diff.
- **2C. NoSQL injection** (`nosql.py`): Mongo operator injection (`[$ne]`, `[$gt]`,
  `[$regex]`) → boolean-differential proof, mirroring `sqli_boolean_blind`.
- **2D. Deserialization** (`deser.py`) + **XXE** (`xxe.py`): gadget/entity probes;
  in-band where the response leaks, **blind via OOB (Tier 3)** otherwise.

**Tests:** each oracle against canned vulnerable/safe responses (zero-FP: safe target must be
rejected). **Gate:** confirm a JWT bypass + a GraphQL/NoSQL flaw on a modern range app
(Juice Shop), live.

---

## Tier 3 — Blind / OOB + evasion

- **3A. Deploy a real OOB listener** — a DNS/HTTP listener service (interactsh-compatible or
  our own) that calls `OobServer.record(token)` on inbound hits; engine selects it by config
  (pluggable-backend pattern) and threads it into `VerifyContext.oob` (today `None`). This
  **activates** SSRF-to-metadata, blind SQLi, XXE, and blind RCE confirmations.
- **3B. Payload encoding / WAF-evasion** — extend `PayloadSynthesizer` with an encoding/
  mutation library (URL / double-URL / unicode / case / comment-break), still behind the
  deterministic shell-metachar safety gate (LLM proposes, code + oracle dispose).

**Tests:** OOB correlation end-to-end (minted token → recorded hit → confirmed);
evasion payloads still pass the safety gate. **Gate:** confirm a blind SSRF-to-metadata
(OOB callback) live; deploy note for the listener.

---

## Tier 4 — Depth (business logic & authenticated privesc)

- **4A. Business-logic flaws** — LLM app-understanding (via the gateway, rule #4) drives
  multi-step stateful request sequences over the world model (e.g. cart→price→checkout);
  a **business-invariant oracle** confirms (e.g. "charged < catalog price") — propose→confirm
  preserved, no LLM output trusted as truth.
- **4B. Authenticated privesc / role-diff** — run two credential sets (low + high priv), diff
  accessible resources/functions → broken function-level authorization.

**Gate:** confirm a business-logic or function-level-authz flaw on a range app, live.

---

## Cross-cutting: safety, governance, model-agnostic

- **Credential hygiene:** all target secrets live in the `CredentialVault`; scope/audit/logs
  carry refs + masked previews only. Login + every authenticated request goes through the
  scope-enforcing Tool Runner (in-scope hosts only) and is audited; RoE intensity still gates
  active/exploit actions; kill-switch tears down sessions.
- **Propose-vs-confirm:** every new class graduates a *proposed* finding and is promoted only
  by a deterministic oracle with real proof (response diff, OOB callback, boolean differential).
- **Model-agnostic:** any app-understanding/JWT-secret reasoning routes through the gateway.
- **Zero-FP discipline:** each oracle ships with a safe-target negative test that must reject.

## Sequencing & dependencies
```
Tier 1 (auth + session + form/API)  ── foundational; unblocks 2 & 4
   └─> Tier 2 (JWT/GraphQL/NoSQL/deser/XXE)   (auth-dependent)
           └─> Tier 3 (OOB) unblocks blind XXE / blind SQLi / SSRF-metadata
   └─> Tier 4 (business logic / privesc)       (auth-dependent)
Tier 3 evasion is independent and can slot in anytime.
```

## Recommended build order
1. **Tier 1** (auth/session + form/API discovery) — the specific blocker for auth-gated targets.
2. **Tier 3A** (OOB listener) — small, unblocks blind classes cheaply.
3. **Tier 2** (modern classes, JWT → GraphQL → NoSQL → deser/XXE).
4. **Tier 4** (business logic / privesc) + Tier 3B evasion.

_Each slice lands as its own PR into `dev`, green (pytest+ruff+mypy+eslint), with a live gate
proof on the range, before the next — same discipline as the phase work to date._
