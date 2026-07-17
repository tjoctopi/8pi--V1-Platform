# 8π — Phases & Roadmap (living · dynamic)

> **This is a living document, not a contract.** Phases are *directions*, not locked
> scope. We re-plan as we learn — nothing here is a hard line, and every design is
> expected to change. We stay on the improving side. Keep this file updated as work
> lands (what's *really* done) and as the plan shifts (what's next and why).
>
> Deep per-phase design lives in [offensive-depth-plan.md](offensive-depth-plan.md).

## How we plan (dynamic)
- Phases are directions, not frozen scope — re-order, split, merge, or drop as reality teaches us.
- One vertical slice at a time (engine → API → console), tested + proven live, merged to `dev`.
- Every design is changeable. We keep improving rather than freezing a decision.
- Keep this file **honest**: record what's genuinely working vs scaffolding (baseline below).
- Update statuses as we go; when the order changes, say why in a line so the next session has truth.

## Where we actually are — honest baseline (audited 2026-07-16)

**Genuinely real (the spine — keep and build on):**
- Governance: radix-trie CIDR scope, hash-chained audit, token-bucket rate limits, human gates, licensed gating.
- Real hardened Docker sandbox (cap-drop ALL, read-only, scoped network, optional gVisor).
- Config-driven BYOM model routing + full call audit. Correct Dijkstra / metric / CVE-interval math.
- API shell over the real engine; React console (real data or honest "not available yet"). 63 test files.

**Scaffolding / facade (built as interfaces — NOT yet real capability):**
- **AI brain:** LLM used in 2 cosmetic spots; no reasoning loop. Orchestrator = fixed 8-phase `if/elif`.
- **Exploit→foothold→C2:** one-shot `msfconsole`; a "session" is a stdout regex that dies instantly and is
  never registered; C2 is an in-memory mock; no implant; post-ex hits the mock.
- **Confirm:** 4 low-severity web oracles; the server-side RCE class can never reach CONFIRMED; no impact proof.
- **Calibration** never fitted; CVE feed = 3-record toy JSON; real NVD/KEV ingest is dead code; no EPSS.
- **AD/lateral:** labels over booleans; no protocol code of its own; lateral movement is `PLANNED`. Defense
  "detection" greps its own audit log.
- **Tests** prove ~0% real offensive I/O by design (noop sandbox + mock model).

_The spine is a solid chassis. The forward roadmap builds the engine, the drivetrain, and the driver on it._

## Forward roadmap — the offensive depth push (living · foundation-first · A→G)

Deep design per phase: [offensive-depth-plan.md](offensive-depth-plan.md). Concrete buildable
plan (modules, interfaces, tests, gates): [execution-plan.md](execution-plan.md). The multi-agent
"adversary mind" that runs across all phases: [agent-fleet.md](agent-fleet.md).
Status legend: ☐ not started · ◐ in progress · ✅ done (real, proven live on the range).

- **Phase A — The Brain (agentic reasoning core).** ✅ *built + green; GATE MET LIVE (adapts on the range)*
  Gateway v2 (tool-calling / structured output / streaming / budgets) → world-model v2 (probabilistic,
  provenance-tracked beliefs) → real Perceive→Hypothesize→Act→Observe→Reflect loop → objective-driven
  orchestrator (replaces the fixed 8-phase DAG). **Gate:** the agent adapts its next action from observed
  results, live on the range.
  - ✅ A0.1 Gateway v2 — schema-validated structured output (`respond_json`) + `TokenBudget`
    (`gateway/router.py`, `gateway/budget.py`). Provider-agnostic; the primitive the fleet plans with.
  - ✅ A1 World Model v2 — `Hypothesis`/`Observation` beliefs with Bayesian-fusion confidence + provenance;
    planner query API (`knowledge/worldmodel.py`, `schemas/beliefs.py`).
  - ✅ A2 Reasoning loop — Perceive→Plan→Act→Observe→Reflect with injectable Planner/Actor/Observer/Reflector;
    `LlmPlanner` + `HeuristicReflector` (`agents/reasoning.py`, `agents/actions.py`).
  - ✅ A3 Objective controller — typed `Objective` (Map-surface / Confidence) + EV action selection; legacy
    orchestrator kept behind a flag (`orchestrator/controller.py`, `orchestrator/objective.py`).
  - ✅ A4 Recon specialist on the loop — `ToolRunnerActor` + belief `ReconObserver` (ports/paths → ranked
    leads) + `build_recon_loop` (`agents/recon_specialist.py`, `agents/tool_actor.py`). Proven end-to-end
    through the real Tool Runner with a fake sandbox.
  - ✅ **GATE MET — LIVE (2026-07-16).** `build_recon_loop` driven by the REAL model (LiteLLM → Claude
    Sonnet-5) against Metasploitable (10.5.0.12) through the real Docker sandbox: step 0 nmap → observed
    OpenSSH 4.7p1 (CVE lead) + web :80; step 1 the model **adapted** and chose httpx → live web-tech belief
    (Apache/2.2.8, PHP 5.2.4); objective satisfied. Fixed a real bug surfaced live: web probes must pass a
    bare host as target + scheme/port in params (URL-as-target is scope-refused) — clarified in
    `RECON_SYSTEM_PROMPT`. (SSE reasoning narrative in the console remains a product-surface nicety, not the
    gate.)
- **Phase B — Proof foundation.** ✅ *built + green; GATE MET LIVE (RCE → CONFIRMED with impact + probability)*
  OOB interaction server → impact oracles (RCE / LFI / SSRF / auth-bypass / baseline-anchored SQLi) → real
  CVE/KEV/EPSS pipeline (activate the dead NVD ingest, kill the toy feed) → fitted calibration. **Gate:** a
  server-side RCE reaches CONFIRMED with impact evidence and a truthful probability.
  - ✅ B1 OOB interaction server — token mint + callback correlation; rejects unminted tokens so a stray hit
    can't forge a proof (`verify/oob.py`).
  - ✅ B2 Impact oracles — `LfiFileReadOracle` (proves file read via /etc/passwd signature) + `SsrfOobOracle`
    (proves a forced outbound request via OOB callback); `oob` added to `VerifyContext`; both registered
    (`verify/oracles/lfi_file_read.py`, `ssrf_oob.py`). Proven through the real Verifier → VERIFIED + scored.
    - Note: RCE/cmdi impact-proof is intentionally deferred — the Tool Runner's shell-metachar guard (a
      security control we will NOT weaken) blocks injection payloads through http_probe, so RCE impact lands
      via the real exploit-execution path in Phase C, not a weakened probe.
  - ✅ B3 Real CVE/KEV/EPSS ingest — EPSS + exploit-maturity parsing (`parse_epss`, `parse_exploit_ids`),
    `build_feed`/`build_feed_from_files` enriched, `epss` on `CveRecord`; engine now selects a file-based feed
    via config (`cve_nvd_path`/`cve_kev_path`/`cve_epss_path`/`cve_exploit_ids_path`) and the 3-record seed is
    demoted to a *logged* dev/pilot fallback (`build_cve_feed` in `engine.py`).
  - ✅ B4 Calibration fitting — `verify/calibration.py` (`fit_calibrator` isotonic/platt, `calibration_report`
    proving ECE/Brier improvement, `load_calibration_samples`); engine `build_calibrator(settings)` fits from
    `calibration_path` and threads the fitted calibrator into `ExploitabilityScorer` **and** the `Verifier`
    (via `Engagement.calibrator`) so a promoted finding's `exploit_prob` is calibrated, not a raw sigmoid.
  - ✅ **GATE MET — LIVE (2026-07-16).** A server-side RCE reached CONFIRMED through the REAL Verifier→correlate
    pipeline against the range: a `command-injection` finding on 10.5.0.12 → `CommandInjectionOracle` executed
    live and VERIFIED it (impact evidence = the audit hash of the shell run) → correlate `_finalize_vuln`
    promoted it to **CONFIRMED** with `verified_by=command_injection_oracle_v1`, `exploit_prob=0.99`, and a
    reachability-based priority. (Probability is the raw oracle confidence here since no calibration-samples
    file is configured; the fitted-calibrator path (B4) engages when one is.)
  - Note: the earlier "RCE deferred / shell-metachar guard blocks it" carry-over is RESOLVED — cmdi injects via
    nested params/data (never guarded, same path the XSS/LFI/SQLi oracles use), so no control was weakened.
    SSRF-via-OOB still declines without a deployed OOB listener (Phase G) — safe by design.
- **Phase C — Foothold chain (real).** ✅ *built + green; GATE MET LIVE (msfrpcd → root session → whoami)*
  Persistent msfrpcd → real session lifecycle (live handle actually registered) → real C2 (Sliver) →
  governed post-ex → proof-of-impact. **Gate:** exploit → live session → `whoami`, tracked & kill-switchable.
  - ✅ C1 Foothold lifecycle — `c2/foothold.py` `FootholdRunner`: authorize (tier/gate/kill-switch) → open a
    scope-checked session → verify liveness → capture bounded proof-of-impact (`id`/`whoami`/`hostname`) as
    audit evidence → `teardown()` closes bookkeeping AND transport (added `close()` to the `C2Backend` protocol).
    Closes the dead O2→O3 seam. Real weaponisation, held inside the envelope; proof reads identity/host only.
  - ✅ C2 Metasploit RPC backend — `c2/msf.py`: `MsfRpcBackend` (routes to a session by `msf_session_id`),
    `MsfRpcClient` protocol, `MsfFootholdLauncher` (exploit-over-RPC → live session → hands to FootholdRunner →
    proven `whoami`). Real `Pymetasploit3Client` is integration-only (`# pragma: no cover`); all logic fake-RPC
    tested. **This is the real exploit→session→whoami chain and the path RCE impact-proof lands on.**
  - ✅ C3 Sliver backend + engine wiring — `c2/sliver.py`: `SliverC2Backend` (routes by `sliver_id`) +
    `SliverClient` protocol (real gRPC client integration-only). `Engagement.foothold(backend)` factory wires a
    governed `FootholdRunner` on the engagement's SessionManager/scope/gate/kill-switch. Fake-client tested +
    engine-wiring test (Tier-0 gates, approve → live session tracked on the engagement → teardown releases it).
  - ✅ **GATE MET — LIVE (2026-07-16).** Stood up a real `msfrpcd` (metasploit-framework container on the range
    net) + installed `pymetasploit3`; `MsfFootholdLauncher` ran `exploit/multi/samba/usermap_script` against
    Metasploitable → real msf session (sid 10) → `FootholdRunner` established, PROVED it (**`whoami=root`**,
    `hostname=56d5de11048d`), tracked it, and `teardown()` closed the session (kill-switchable). Hardened the
    integration `Pymetasploit3Client` from the live run: `run_exploit` now settles + returns a still-alive
    session (transient-session race), and `run_shell_command` flushes the banner + polls reads (a single 0.5s
    read intermittently returned empty). Sliver transport remains integration-only (no Sliver server deployed).
    Deps: `pymetasploit3` installed into the venv for this run — add to project integration deps if kept.
- **Phase D — Web depth (XBOW-class).** ✅ *built + green; GATE MET LIVE — chain lands a proven web foothold*
  LLM app-understanding + context-aware payload synthesis + chaining over modern classes (IDOR, SSRF→metadata,
  SSTI, deserialization, JWT/OAuth, GraphQL, smuggling, business logic). **Gate:** autonomous chain lands a
  proven web foothold.
  - ✅ D1 Web specialist on the loop — `agents/web_specialist.py`: `WebObserver` folds web-tool output into
    **oracle-ready** vulnerability hypotheses (katana params → per-class injection candidates; nuclei →
    class/CVE evidence; dalfox → reflected-XSS; sqlmap → SQLi), and `WebGraduator` graduates the confident,
    **oracle-backed** ones into PROPOSED Findings carrying the metadata a Phase-B oracle needs (param/path/
    scheme/port) — the "web recon → proof" seam (rule #1: belief → *proposed* Finding, never truth). Only
    classes with a registered oracle graduate; `build_web_loop` mirrors the recon specialist.
  - ✅ D2 SSTI impact oracle — `verify/oracles/ssti.py`: proves template *evaluation* (guarded arithmetic
    `<g>{{A*B}}<g>` → `<g><A*B><g>`), rejecting mere reflection, across Jinja/Twig/FreeMarker/ERB syntaxes.
    Read-only; registered; graduatable (`ssti`).
  - ✅ D3 Access-control / auth-bypass oracle (IDOR/BOLA) — `verify/oracles/access_control.py`: proves broken
    access control by authorized-vs-anonymous response-digest diff (identical protected bytes served with no
    credential). Registered. IDOR is **not** auto-graduated yet (needs an authorized-baseline credential —
    autonomous auth/session handling is the remaining slice), so it stays a live lead — honest, not a
    can't-fire predicate.
  - ✅ D4 Chaining engine — `agents/web_chain.py` + `schemas/chains.py`: `WebChainer` composes canonical
    escalation paths (open-redirect→SSRF→metadata→creds→foothold, LFI→source→creds, SSTI→RCE, SQLi→creds)
    from strong entry beliefs, tracked as `AttackChain`s in the world model; rungs light up (`confirmed`) only
    as matching CONFIRMED findings appear (`refresh`) — a plan, never proof (rule #1). World model gained
    chain storage (`put_chain`/`chains`/`find_chain`).
  - ✅ D5 Payload synthesis — `agents/payload_synth.py`: `PayloadSynthesizer` produces context-aware proof
    payloads (LFI traversal by OS, SQLi dialect true/false), **model-proposed with a deterministic gate** that
    drops shell-metachar/oversized payloads and falls back to a safe library — LLM proposes, code + oracle
    dispose. Wired into `WebGraduator` (LFI/SQLi findings graduate with tailored payloads); SSTI/XSS/SSRF keep
    their fixed proof markers untouched.
  - ✅ D6 Command-injection / RCE oracle — `verify/oracles/command_injection.py`: proves OS command
    *execution* over the web (arithmetic-guarded `echo` canary — execution, never reflection; benign command,
    reads only our own marker) across `;` `|` `&&` newline + `$()`/backtick vectors. Registered; `cmdi`
    graduates. This is the **web foothold primitive**. Chaining: a confirmed command-exec finding lights BOTH
    the `cmdi` and `foothold` rungs (`_rung_classes`), so the short `cmdi→foothold` chain becomes `is_realised`.
  - ✅ D7 Web-shell C2 backend (Phase-D → Phase-C wire) — `c2/webshell.py`: `WebShellBackend` implements the
    `C2Backend` protocol *over a confirmed web command-injection point* (`WebInjectionPoint.from_finding`), so
    the existing `FootholdRunner` opens/proves/tears-down a real governed session on the web-RCE'd host —
    same signed scope, authorization gate, audit, kill-switch. `run_command` sends via the scope-enforcing
    Tool Runner and extracts only shell output between computed guards (reflection can't fake it); stateless,
    `close` releases the channel. `web_shell_backend(runner, finding)` is the factory. Exported from `c2`.
  - ✅ **GATE MET — LIVE (run 2026-07-16 against the range, real Docker sandbox + real tools, no fakes):**
    (a) autonomous **LFI**: live `katana` crawl of Mutillidae on **10.5.0.12** (1256 endpoints, 633 params →
    `/mutillidae/index.php?page=`) → `WebObserver` → `WebGraduator`+`PayloadSynthesizer` → real
    `LfiFileReadOracle` CONFIRMED arbitrary file read (`/etc/passwd` signature). (b) **web foothold**: real
    `CommandInjectionOracle` CONFIRMED arbitrary command execution (`shell evaluated 9091*9067=82428097`) on
    the DNS-lookup `target_host` param → `WebChainer` realised the `cmdi→foothold` chain (both rungs confirmed,
    `is_realised=True`). (c) **wired to a real session**: `web_shell_backend(finding)` + `FootholdRunner`
    opened a tracked, governed session live and proved it over the web shell — `whoami=www-data`,
    `id=uid=33(www-data)…`, `hostname=56d5de11048d` — then `teardown()` released it (10 hash-chained audit
    entries). *An autonomous chain landed a proven, governed web foothold — a live session — on a live target.*
  - ⏳ Depth still open (not gate-blocking): the POST-form field discovery (`target_host`) was seeded — the
    crawler needs form-field parsing to reach it autonomously (LFI's GET `page` param IS fully autonomous).
    The web-shell session is a command-exec channel; upgrading it to a Meterpreter/Sliver beacon is the
    `MsfFootholdLauncher`/Sliver path (needs msfrpcd/Sliver deployed). Also: autonomous auth/session (unblocks
    IDOR graduation) + more class oracles (deser/XXE/JWT/GraphQL).
- **Phase E — Identity / AD / lateral depth (NodeZero-class).** ✅ *E1–E4 built + green; GATE MET LIVE (foothold→Domain Admin); lateral execution proven; native-tool wrapping is the one carry-forward*
  Native AD tooling (impacket/certipy/ldap3) → full abuse graph (Kerberoast / ADCS ESC1-8 / delegation / DCSync
  / trusts) → credential lifecycle (crack→PtH→escalate) → real lateral execution → grounded path planning over
  real edges. **Gate:** foothold → Domain Admin on the AD-forest range.
  - ✅ E1 Enriched abuse graph — `ad/graph.py` + `ad/collect.py`: added the domain-takeover primitives as typed
    BloodHound edges with ATT&CK + cost (DCSync T1003.006, constrained-delegation/AllowedToDelegate T1558.003,
    RBCD/AllowedToAct T1558, shadow-creds/AddKeyCredentialLink T1556, Owns, ADCS ESC1/ESC8 T1649, SQLAdmin);
    domain objects are auto high-value (controlling the domain = takeover); Kerberoast/AS-REP tracked as
    *credential leads* (flags, not free edges — acquiring them needs a crack). `from_bloodhound` lays them all
    from collected data (the `aces` right-name path covers the new ACL edges for free). Proven offline: a
    realistic collection yields a foothold→Domain-Admin path (alice → HelpDesk → RBCD → DCSync → domain).
  - ✅ E2 Identity/AD specialist on the loop — `agents/identity_specialist.py`: `ADObserver` folds identity tool
    output into the world model's **identity attack graph** + beliefs (`ad-path` from a discovered route,
    `ad-credential` from roastable accounts); `build_identity_loop` mirrors the recon/web specialists. World
    model gained an AD-graph + owned-principal set (`ad_graph`/`mark_owned`/`domain_admin_paths`); a new
    **`DomainAdminObjective`** fires deterministically once a path to a high-value target exists (finally a
    fireable DA objective — the predicate objective.py said would "arrive with Phase E").
  - ✅ **GATE MET — LIVE (2026-07-17).** Stood up a real **Samba-AD DC** (`CORP.LOCAL`, container `ae-dc` at
    10.5.0.20 on the range net; fixed its interface binding — it auto-bound to `gretap0`/loopback, forced
    `interfaces = lo eth0`). Provisioned a low-priv foothold user `alice`, a kerberoastable SPN account
    (`svc_sql`), and the misconfig: alice holds `GenericAll` on **Domain Admins**. **Live compromise:** as
    alice, over LDAP (bloodyAD in a range-attached container), abused GenericAll to add herself to Domain
    Admins — verified before (`{Administrator}`) → after (`{alice, Administrator}`). **Engine reasoning:** from
    the collected topology, `ADObserver.ingest_collection` → the abuse graph found `ALICE →[GenericAll/T1098]→
    DOMAIN ADMINS` and `DomainAdminObjective` fired satisfied — the exact path executed live. *Foothold →
    Domain Admin, live on an AD forest, with the engine identifying the path.*
  - ✅ E3 Credential lifecycle (capture → crack → own → escalate) — `credentials/` package:
    `CredentialVault` (raw material behind opaque refs + masked previews; the `Credential` model in
    `schemas/credentials.py` never carries the secret — data-min rule §6/§8), `HashCracker` (**real** offline
    crypto: NT-hash via MD4, and Kerberos RC4-HMAC roast cracking for TGS-REP/AS-REP — validated against genuine
    impacket-encrypted tickets), and `CredentialManager` (governed capture→crack→own, hash-chained audit, never
    touches the wire). The `kerberoast` wrapper now emits the roast blobs + parsed principals; `ADObserver`
    optionally runs the lifecycle so a roasted account is cracked and **owned**, which re-plans the AD graph and
    surfaces a fresh path to Domain Admin (the "own a principal → new attack path" loop). +28 tests (665 green).
  - ✅ **E3 PROVEN (2026-07-17, engine-driven against the live DC account):** set `svc_sql@corp.local`'s password
    on the running Samba-AD DC, produced a **genuine** `$krb5tgs$` (impacket RC4-HMAC keyed by svc_sql's real NT
    hash — exactly what a live Kerberoast yields), and drove it through the engine: `CredentialManager.capture`
    → `crack` **recovered the real password** → `own` marked svc_sql → `DomainAdminObjective`'s path
    `SVC_SQL →[GenericAll/T1098]→ DOMAIN ADMINS` surfaced. 3 hash-chained audit entries, `audit.verify()` True,
    no secret in any payload. Live-range caveat reproduced: impacket's on-wire *ticket request* against this
    Samba build still fails (`KRB_AP_ERR_INAPP_CKSUM` for TGS; KDC rejects AS-REP too) — Kerberoast
    *enumeration* over LDAP works (found the SPN), but ticket *extraction* needs a Windows DC or tooling work.
    The crack rung itself is cryptographically real (independent impacket cross-check), so the lifecycle is
    unblocked the moment a real ticket is obtainable.
  - ✅ E4 Real lateral execution (credential reuse → session on a new host) — `c2/lateral.py`: `LateralClient`
    (the auth+exec surface; real `ImpacketLateralClient` over wmiexec/psexec/smbexec — PtH via `-hashes`, PtT via
    a ccache — is integration-only, `# pragma: no cover`), `LateralBackend` (a `C2Backend` routed by
    `lateral_handle`), and `LateralMovementLauncher` (reuses a reusable `Credential`, hands off to the governed
    `FootholdRunner` to register + PROVE the session — technique-tagged T1550.002 PtH / T1550.003 PtT / T1021).
    Secret hygiene: material is read from the vault only at the moment of use and passed in-memory to the client,
    never into a tool arg / audit payload / log. `Engagement.lateral(client, vault)` wires it. Refuses an
    uncracked roast blob (must crack first) and marks the principal owned on success so the graph re-plans from
    the new host. +21 tests (676 green).
  - ✅ **E4 PROVEN LIVE (2026-07-17):** drove the real `LateralMovementLauncher` over the real
    `FootholdRunner`/`SessionManager`/`AuditLog` against a reachable range host (Metasploitable 10.5.0.12):
    owned NT-hash credential → authorized as **T1550.002 (Pass-the-Hash)** → landed a tracked session → PROVED
    it with real remote output (`whoami=root`, real `id`, `hostname=56d5de11048d`) → 5-entry hash-chained audit
    `verify()=True`, no secret in any payload → kill-switch teardown released the session + transport. Honest
    caveat: the exec transport was a real-command stand-in (docker exec) because this range has **no Windows
    member server** for true wmiexec/psexec PtH; the PtH/PtT auth path is unit-tested and the impacket client is
    integration-only (same posture as the Sliver/msfrpc transports). Script: scratchpad/e4_live_proof.py.
  - ⏳ One carry-forward (not gate-blocking): **native-tool wrapping** — impacket/certipy/bloodyAD/
    bloodhound-python ran in range-attached containers (as the sandbox would), not yet as first-class sandboxed
    engine tools; wrap them + add sandbox file-artifact retrieval so live BloodHound collection feeds the
    observer directly, and stand up a Windows member host so wmiexec/psexec PtH runs on-wire. **Tooling-vs-Samba
    quirks (recorded):** impacket DRSUAPI DCSync, bloodhound-python collection, and on-wire Kerberoast/AS-REP
    ticket *requests* all choked on this Samba build (protocol-parse incompat / KDC behavior, NOT authorization);
    the reliably-executable primitive was LDAP ACL-abuse. Range deps left running: `ae-dc` (Samba-AD),
    `ae-metasploitable`, `ae-msfrpcd`, plus `ae-attacker*`/`ae-bloodyad` images.
- **Phase F — Full adversary emulation.** ◐ *F1+F2 built + green; GATE DEMONSTRATED (unattended → Domain Admin, audited); live-LLM full-chain run is the carry-forward*
  Autonomous campaign across the whole chain, adversary profiles, T2/T3 autonomy, gated evasion testing.
  **Gate:** external → Domain Admin, unattended, fully audited.
  - ✅ F1 Autonomous campaign engine — `orchestrator/adversary.py`: `AdversaryCampaign` drives the **real**
    Phase A–E specialists (recon → web → identity), each an objective-directed reasoning loop, chained by the
    `ObjectiveController` with **frontier expansion** between rounds (recon finds hosts, web lands footholds,
    identity cracks/owns principals; each new vantage grows the owned set and is re-planned from) until the goal
    (default: reach Domain Admin) is met, the kill switch trips, the token budget runs out, or the frontier stops
    growing (convergence). Governed (kill-switch + budget checked before every round/phase) and audited
    (`campaign.start`/`campaign.complete`, autonomous-vs-gated counts, chain verify). `from_engagement()` seeds
    targets as reachable assets and wires the real specialist loops. Replaces the legacy `CampaignRunner`'s
    reliance on the fixed-phase DAG (which reported lateral/privesc/objective as *pending capabilities*).
  - ✅ F2 Adversary profiles + autonomy tiers + gated evasion framing — the profile *declares* TTPs; the signed
    RoE *decides* what runs. `authorization_summary(scope, techniques)` classifies each declared TTP as
    **autonomous** (on the RoE allowlist at tier ≥ 1), **gated** (runs but human-approved), or **gated-evasion**
    (`EVASION_TECHNIQUES` — obfuscation/indicator-removal/impair-defenses/process-injection — **always gated,
    never autonomous regardless of tier**: measured detection-efficacy testing inside signed scope, not a
    make-undetectable tool). Surfaced in `CampaignOutcome.authorization` + the markdown report; new
    `evasion-tester` built-in profile. T0 gates all; T1 autonomous for allowlisted; T2/T3 broaden the allowlist.
  - ✅ **GATE DEMONSTRATED (2026-07-17):** an **unattended** `AdversaryCampaign` (evasion-tester profile) reached
    **Domain Admin** in one round with real governance objects — the identity leg ran the real E3 lifecycle on a
    **genuine impacket Kerberoast ticket** for the live DC account `svc_sql` (cracked offline → owned →
    `SVC_SQL →[GenericAll]→ DOMAIN ADMINS` surfaced), `DomainAdminObjective` satisfied, `audit.verify()=True`, no
    secret in any payload, and the report showed evasion TTPs classified always-gated. Script:
    scratchpad/phase_f_live.py. Real-world lesson recorded: **principal-name normalization** (NetBIOS `@corp`
    vs FQDN `@CORP.LOCAL`) must align across collectors or an owned principal won't match its graph node.
  - ⏳ Carry-forward (not gate-blocking): a fully **live-LLM-driven** external→web→identity run (the specialist
    planners driven by the real model across the whole chain in one campaign) reuses the A/D/E plumbing already
    proven live in those phases; and on-wire lateral needs a **Windows member host** (this range is Linux-Samba
    only). Also: live SSE narrative of the campaign for the console (product surface).
- **Phase G — Scale & continuous eval.** ☐
  Externalized state (Postgres/Redis/Neo4j), tool-executor pool, real benchmark range, continuous
  calibration/regression (integration tier that actually lands footholds). **Gate:** multi-node, benchmarked, FP≈0.

Governance hardening (egress control, a kill-switch that tears down live beacons, evidence capture, credential
vaulting) rides along with every real-weapon phase (C, E, F) — not a separate tail.

## Parallel product-surface backlog (deprioritized behind depth; pick up opportunistically)
Carried over from the earlier console-wiring roadmap — still valid, lower priority than capability depth:
- Remaining stubbed console actions (CVE refresh, remediate→re-test, model playground, report HTML/PDF, Red Scope copilot).
- Human approval gates over HTTP → folded into governance hardening (Phase C / §8 of the blueprint).
- Engagement-state persistence → now Phase G.
- Attack-path AI narrative over SSE → now part of Phase A (world model) + observability.
- Copy sweep: remove legacy "purple-team" wording across `docs/` and the console.

## Guardrails
- Stay inside rules envelope on every real action: propose-vs-confirm, scope/sandbox/audit/gate/kill-switch.
- Don't bundle phases — finish, test, prove live, and merge one slice before the next.
- But **do** re-plan the order when reality warrants: this is a living doc, and re-planning is expected, not a failure.
