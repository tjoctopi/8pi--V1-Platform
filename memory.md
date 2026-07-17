# 8π — Living Memory

A running log of current state, decisions, and known gaps. Update this when things
change so the next session starts with truth, not assumptions.

_Last updated: 2026-07-16_

## 2026-07-16 — Phase A (the Brain) built on branch `feat/gateway-v2-structured-output`
- **Branched off `origin/dev`.** Not committed yet (user wants continuous build until they ask for the PR).
- **Built + green (pytest/ruff/mypy, 151 src files):** the whole cognition core.
  - A0.1 Gateway v2: `respond_json` (schema-validated structured output + corrective retry) + `TokenBudget`
    — `gateway/router.py`, `gateway/budget.py`, `gateway/types.py`, `errors.py`, `config.py:model_json_max_retries`.
  - A1 World Model v2: `WorldModel` + `Hypothesis`/`Observation` (Bayesian-fusion confidence, provenance,
    planner queries) — `knowledge/worldmodel.py`, `schemas/beliefs.py`. Reuses `verify/fusion.py` (lazy import).
  - A2 Reasoning loop: `ReasoningLoop` (Perceive→Plan→Act→Observe→Reflect), `LlmPlanner`, `HeuristicReflector`,
    action models — `agents/reasoning.py`, `agents/actions.py`.
  - A3 Objective controller: `ObjectiveController` + typed `Objective`s (MapSurface/Confidence); legacy
    orchestrator kept behind an `AE_ORCHESTRATOR` flag — `orchestrator/controller.py`, `orchestrator/objective.py`.
  - A4 Recon specialist on the loop: `ToolRunnerActor`, `ReconObserver` (ports/paths → ranked beliefs),
    `build_recon_loop` — `agents/recon_specialist.py`, `agents/tool_actor.py`. Proven end-to-end through the
    REAL Tool Runner + fake sandbox (nmap output → asset + CVE/web leads → objective met).
- **Audit corrections (docs were wrong):** fusion lives at `verify/fusion.py` (not `correlate/fusion.py`);
  there is NO `correlate/calibrate.py` — calibration is only measured in `evals/metrics.py`, never fitted
  (that's a Phase B task). No Bedrock provider despite claims — gateway keys are Fireworks + Anthropic (+ a
  keyless Bedrock path added on dev).
- **Remaining to fully close Phase A's gate:** live-range (Docker) run + SSE reasoning narrative in the console.
- **Phase B progress (same branch, green, 154 src files):**
  - B1 OOB interaction server — `verify/oob.py` (token mint + callback correlation; unminted tokens rejected).
  - B2 impact oracles — `verify/oracles/lfi_file_read.py` (proves file read via /etc/passwd sig) +
    `verify/oracles/ssrf_oob.py` (proves forced request via OOB); `oob` added to `VerifyContext`; both
    registered in `default_oracle_registry`. Verified end-to-end through the real `Verifier`.
  - **RCE impact-proof deferred (by design):** `ToolProfile` forbids shell metacharacters (`;|&\`$><`) as a
    security control; do NOT weaken it. RCE/cmdi impact lands via the real exploit-execution path in Phase C.
  - B3 real CVE/KEV/EPSS ingest — `parse_epss`/`parse_exploit_ids` + enriched `build_feed(_from_files)`;
    `epss` field on `CveRecord`; engine `build_cve_feed(settings)` selects a file feed from config
    (`cve_nvd_path`/`cve_kev_path`/`cve_epss_path`/`cve_exploit_ids_path`), seed demoted to a logged fallback.
  - B4 calibration fitting — `verify/calibration.py` (`fit_calibrator` isotonic/platt, `calibration_report`
    proving ECE/Brier improvement); engine `build_calibrator(settings)` fits from `calibration_path` and threads
    the calibrator into `ExploitabilityScorer` + the `Verifier` (new `Engagement.calibrator`). `exploit_prob` is
    now calibrated when a samples file is configured; raw otherwise (unchanged default behavior).
- **Wiring still pending (carry-over):** (a) `Engagement.verify()` passes `ctx.oob=None` (no engine-held OOB
  server) → SSRF activates once the real OOB listener is deployed (Phase G); (b) RCE/cmdi impact-proof lands via
  the exploit-execution path in Phase C (shell-metachar guard, by design). Today both decline safely.
- **Phase B essentially done** (B1–B4). Full suite green, ruff+mypy clean.
- **Phase C progress (same branch, green, 156 src files, 569 tests):**
  - C1 foothold lifecycle — `c2/foothold.py` `FootholdRunner` (authorize→open scope-checked session→liveness→
    bounded proof-of-impact id/whoami/hostname as audit evidence→`teardown()` closes bookkeeping + transport).
    Added `close()` to `C2Backend` protocol + `MockC2Backend`. Closes the dead O2→O3 seam; tested offline.
    Establishing a foothold is authorized as action `establish_foothold` (tier≥1 autonomous if in
    authorized_techniques, else human gate; not in default high_impact_actions).
  - C2 Metasploit RPC backend — `c2/msf.py`: `MsfRpcBackend` (routes by `msf_session_id`), `MsfRpcClient`
    protocol, `MsfFootholdLauncher` (exploit-over-RPC → live session → FootholdRunner → proven whoami). Real
    `Pymetasploit3Client` integration-only (`# pragma: no cover`); logic fake-RPC tested. **RCE impact-proof
    lands on this chain** (deferred from Phase B).
  - C3 Sliver backend + engine wiring — `c2/sliver.py` `SliverC2Backend`/`SliverClient` (real gRPC client
    integration-only); `Engagement.foothold(backend)` factory builds a governed `FootholdRunner`. Fake-tested +
    engine-wiring test.
- **Phase C built + green (158 src files, 576 tests, ruff+mypy clean).** To fully close the C gate: deploy real
  `msfrpcd` + Sliver and run exploit→foothold→whoami live on the range (RPC/gRPC clients are integration-only,
  same posture as Docker sandbox / NVD fetch).
- **Phases A, B, C are all built + green** on branch `feat/gateway-v2-structured-output`. Still uncommitted
  (awaiting PR go-ahead). Remaining to fully close gates = live-range/Docker/msfrpcd/Sliver runs (env can't do).
- **Phase D progress (same branch, green, 164 src files, 613 tests):**
  - D1 Web specialist on the loop — `agents/web_specialist.py`. `WebObserver` turns web-tool output into
    oracle-ready hypotheses: katana params → per-param class candidates (`_param_classes`: SQLi universal +
    LFI/SSRF/open-redirect/IDOR/XSS by param-name heuristics), nuclei → class/CVE evidence
    (`_classify_nuclei`), dalfox → reflected-XSS, sqlmap → SQLi. Subject = canonical injection-point URL
    (round-trippable, so metadata is rebuilt from the belief alone — no side state). `WebGraduator.graduate`
    promotes confident (≥min_confidence), **oracle-backed** hypotheses into PROPOSED Findings via
    `store.propose_finding` + `wm.link_finding`; oracle-readiness gated by `registry.for_finding(...)` so only
    SQLi/XSS/LFI/SSRF/open-redirect graduate (CVE/IDOR stay leads — no oracle yet). `_CLASS_TO_FINDING_TYPE`
    maps kind→finding type (`sqli`→`sqli-boolean-blind`, etc.); `_REQUIRES_PARAM` skips param-less
    SQLi/XSS/SSRF/redirect. `build_web_loop` mirrors `build_recon_loop`. Tested offline through the REAL Tool
    Runner + fake sandbox. This is the "web recon → proof" seam feeding the Phase-B oracles.
  - D2 SSTI impact oracle — `verify/oracles/ssti.py`: proves template *evaluation* via guarded arithmetic
    (`<g>{{A*B}}<g>`→`<g><A*B><g>`, A=9091 B=9067) across Jinja/Twig/FreeMarker/ERB; rejects mere reflection.
    Registered; `ssti` graduates.
  - D3 Access-control/auth-bypass oracle (IDOR/BOLA) — `verify/oracles/access_control.py`: authorized-vs-anon
    response-digest diff (identical protected bytes with NO credential = broken access control). Needs
    `basic_auth` in metadata (declines otherwise). NOT auto-graduated (autonomous auth/session = later slice),
    so IDOR stays a lead — deliberately avoids a can't-fire path.
  - D4 Chaining engine — `agents/web_chain.py` + `schemas/chains.py` (`ChainStep`/`AttackChain`,
    `confirmed_depth`/`is_realised`). `WebChainer.compose` builds canonical escalation paths from strong entry
    beliefs (templates: open-redirect/ssrf→metadata→creds→foothold, lfi→source→creds, ssti→rce, sqli→creds),
    tracked in the world model (added `put_chain`/`chains`/`find_chain`/`get_chain`). `refresh` lights up a rung
    only when a CONFIRMED finding of that class exists on the host (`_rung_class` maps finding-type→rung). Plan,
    never proof.
  - D5 Payload synthesis — `agents/payload_synth.py` `PayloadSynthesizer` (+ `SynthesizedPayloads`): LLM-proposed
    context-aware proof payloads (LFI traversal by OS, SQLi dialect true/false) via `gateway.respond_json`, with
    a **deterministic gate** (`_sanitize` drops shell-metachar `;|&$\`\n\r` / oversized, dedups, caps) + safe
    library fallback (no gateway / model error). `enrich(finding)` merges payloads into oracle metadata for
    LFI/SQLi only; SSTI/XSS/SSRF keep fixed markers. Wired into `WebGraduator(synthesizer=...)`.
  - Capstone e2e (`tests/agents/test_web_depth_e2e.py`): crawl→beliefs→graduate(+synth)→chain→confirm-rung→
    chain lights up, fully offline.
  - D6 Command-injection/RCE oracle — `verify/oracles/command_injection.py`: proves OS command *execution*
    over the web via arithmetic-guarded `echo` canary (`echo <guard>$((9091*9067))<guard>` → guard82428097guard;
    execution not reflection; benign, own-marker-only) across `;`|`&&`\n`$()``` vectors. Injects via nested
    params/data (NOT blocked by the top-level-only shell-metachar guard — same path XSS/LFI/SQLi oracles use;
    guard NOT weakened). Registered; `cmdi` graduates → `command-injection`. web_chain: `_rung_classes` maps a
    confirmed command-exec finding to BOTH `cmdi` and `foothold` rungs → `cmdi→foothold` chain `is_realised`.
  - D7 Web-shell C2 backend (Phase-D→Phase-C WIRE) — `c2/webshell.py` `WebShellBackend` (+ `WebInjectionPoint`,
    `web_shell_backend` factory, exported from `c2`). Implements the `C2Backend` protocol OVER a confirmed
    command-injection point: `run_command` sends via the scope-enforcing Tool Runner (http_probe) and extracts
    only shell output between computed guards `S82428097…82428097E` (reflection-proof); `alive` pings a marker;
    `close` releases the channel (stateless web shell). So the EXISTING `FootholdRunner` opens/proves/tears-down
    a real governed session on the web-RCE'd host (scope/gate/audit/kill-switch unchanged). `Engagement.foothold`
    already accepts any C2Backend, so no engine change needed.
- **Phase D BUILT + GREEN (166 src files, 623 tests, ruff+mypy clean) — GATE MET LIVE incl. real session.**
- **PROVEN LIVE on the range (2026-07-16), real Docker sandbox + real tools, no fakes.** The range IS up in
  this env (Docker running; `ae-juice-shop` 10.5.0.10, `ae-dvwa` 10.5.0.11, `ae-metasploitable` 10.5.0.12 on
  `attack-engine-range_range_net`; all web-tool images pulled) — **this env is NOT zero-service; run gates live,
  don't claim "offline only".** See [[8pi-live-range-available]].
  - LFI (fully autonomous): live katana crawl of Mutillidae 10.5.0.12 (1256 endpoints, 633 params → found
    `/mutillidae/index.php?page=`) → WebObserver → WebGraduator+PayloadSynthesizer → **real LfiFileReadOracle
    CONFIRMED arbitrary file read** (`/etc/passwd` sig). Script: scratchpad/live_phase_d.py.
  - Web FOOTHOLD: **real CommandInjectionOracle CONFIRMED arbitrary command execution** on the DNS-lookup
    `target_host` param (`shell evaluated 9091*9067=82428097`) → WebChainer realised `cmdi→foothold`
    (both rungs confirmed, is_realised=True). Script: scratchpad/live_foothold.py.
  - REAL SESSION (the wire): `web_shell_backend(finding)` + `FootholdRunner` opened a tracked governed session
    live on 10.5.0.12 and proved it over the web shell — whoami=www-data, id=uid=33(www-data)…, hostname=
    56d5de11048d — then teardown() released it (10 hash-chained audit entries). Scripts: scratchpad/live_wire.py,
    real_output.py (raw remote `id;hostname;uname -a` output), real_sandbox_proof.py (backend=DockerSandbox).
  - Honest caveats: the POST-form field `target_host` was seeded (crawler needs form-parsing to reach it
    autonomously; the GET `page` LFI path IS fully autonomous). "Foothold" = proven arbitrary RCE (foothold
    primitive); a persistent C2 beacon over it is the Phase-C handoff. Mutillidae is the clean no-auth target
    (Juice Shop listens on :3000, DVWA redirects on :80 needing a session).
- **Remaining Phase-D depth (not gate-blocking):** autonomous auth/session handling (unblocks IDOR graduation;
  AccessControlOracle already built), crawler form-field discovery, more class oracles (deser/XXE/JWT/GraphQL),
  and wiring web-RCE → Phase-C C2 for a persistent beacon.
- **A, B, C GATES CLOSED LIVE (2026-07-16) — all four phases A–D now gate-met live, green (623 tests).**
  - Phase A: `build_recon_loop` with the REAL model (LiteLLM→claude-sonnet-5; keys in .env) vs Metasploitable
    via real Docker sandbox — nmap → model ADAPTED → httpx → live web-tech belief; objective satisfied.
    Fixed a real bug: web probes need bare-host target + scheme/port in params (URL target = scope-refused);
    clarified in `RECON_SYSTEM_PROMPT`. Script: scratchpad/phase_a_live.py.
  - Phase B: `command-injection` finding → REAL Verifier (CommandInjectionOracle executed live) VERIFIED →
    correlate `_finalize_vuln` → CONFIRMED, exploit_prob=0.99, impact evidence = audit hash. RCE-deferred
    carry-over RESOLVED (cmdi injects via nested params, guard not weakened). Script: phase_b_live.py.
  - Phase C: stood up real msfrpcd (metasploit-framework container on range net, `-P testpass -S -f`, port
    55553, ssl=False) + `uv pip install pymetasploit3`. `MsfFootholdLauncher` ran samba usermap_script vs
    Metasploitable → real msf session → FootholdRunner proved **whoami=root**, tracked, teardown closed it.
    Hardened `Pymetasploit3Client` (integration-only): `run_exploit` settles + returns a still-alive session;
    `run_shell_command` flushes banner + polls reads. Use a BIND payload (cmd/unix/bind_perl) — the client
    can't set LHOST (payload option) for reverse payloads (known gap). Script: phase_c_live.py.
  - **Env notes:** msfrpcd container `ae-msfrpcd` left running; `pymetasploit3` installed in venv (not in
    pyproject — add to integration deps if kept). Metasploitable open: 139/445 (samba), 3632 (distcc); 21
    closed (vsftpd backdoor N/A). msfrpcd LHOST on range = 10.5.0.2.
- **Phases A, B, C built + green; Phase D core built + green.** All on `feat/gateway-v2-structured-output`,
  uncommitted (awaiting PR go-ahead).
- **Next candidates:** Phase E (AD/lateral), remaining Phase D depth (auth/session, more oracles), or close the
  live-range gates — user to steer.

## 2026-07-17 — Phase E started (Identity/AD) on branch `feat/phase-e-identity-ad`
- Branched off the A–D tip (`feat/gateway-v2-structured-output`, PR #12 open into dev) so E builds on A–D.
- **E1 enriched abuse graph** (`ad/graph.py` + `ad/collect.py`): added domain-takeover edge types (DCSync,
  AllowedToDelegate, AllowedToAct, AddKeyCredentialLink, Owns, ADCSESC1/ESC8, SQLAdmin) with ATT&CK+cost;
  DOMAIN-kind principals auto high-value; Kerberoast/AS-REP = credential leads via `mark_roastable`/`roastable()`
  (not free edges). `from_bloodhound`'s existing `aces` right-name path handles the new ACL edges automatically;
  added `domains`/`kerberoastable`/`asrep_roastable` keys. Proven: realistic collection → foothold→DA path.
- **E2 Identity specialist** (`agents/identity_specialist.py`): `ADObserver` (bloodhound data → graph + `ad-path`
  belief; kerberoast → `ad-credential` lead + roastable flag; `ingest_collection` is the tested entry),
  `build_identity_loop` mirrors recon/web. WorldModel gained `ad_graph`/`set_ad_graph`/`mark_owned`/
  `owned_principals`/`domain_admin_paths` (lazy ADGraph, TYPE_CHECKING import to avoid layering weight).
  New `DomainAdminObjective` (orchestrator/objective.py) fires when a path to a high-value target exists.
- **Green: 637 tests, ruff+mypy clean (167 src files).** Uncommitted → will commit on the E branch.
- **GATE MET LIVE (2026-07-17): foothold → Domain Admin on a real AD forest.** Stood up Samba-AD DC image
  `diegogslomp/samba-ad-dc` as `ae-dc` (CORP.LOCAL, 10.5.0.20 on range net, `--privileged` for sysvol NT-ACLs,
  REALM/DOMAIN/ADMIN_PASS/DNS_FORWARDER env). **Gotcha:** it auto-bound samba to `gretap0`/loopback → edit
  smb.conf `interfaces = lo eth0` + `bind interfaces only = no`, restart. Provisioned alice (low-priv foothold),
  svc_sql (SPN/kerberoastable), and granted alice `GenericAll` on Domain Admins via `samba-tool dsacl set`
  (also granted DCSync via the two replication GUID CRs). **Live compromise:** alice added herself to Domain
  Admins over LDAP (bloodyAD, range-attached container) — verified before/after membership. **Engine side:**
  ADObserver.ingest_collection → abuse graph found ALICE→GenericAll→DOMAIN ADMINS, DomainAdminObjective fired.
  Scripts/infra in scratchpad; images `ae-attacker`(impacket+bloodhound), `ae-attacker11/12`, `ae-bloodyad`.
- **Tooling reality (important for next time):** host (macOS Docker Desktop) CANNOT reach range container IPs
  (10.5.0.x) directly → AD tools must run in range-attached containers (like the sandbox does), not the venv.
  impacket DRSUAPI DCSync FAILED against this Samba (`byte indices...`/`ERROR_SUCCESS` parse bugs across
  0.11/0.12/0.13) — a protocol-parse incompat, NOT authorization. bloodhound-python collection also failed on
  Samba LDAP (`server.info None`). Reliable executable primitive = LDAP ACL-abuse via bloodyAD. Kerberoast SPN
  enumerated but TGS had KRB_AP_ERR_INAPP_CKSUM. So: prefer bloodyAD/ldap for Samba; DCSync/collection need
  tooling work or a Windows DC. See [[8pi-live-range-available]].
- **Remaining Phase-E depth (not gate-blocking):** wrap impacket/certipy/bloodyAD/bloodhound-python as
  first-class sandboxed engine tools + sandbox file-artifact retrieval; E4 real lateral execution
  (wmiexec/psexec/winrm over C2 SOCKS) + on-wire credential reuse (PtH/PtT) for multi-host forests.

## 2026-07-17 — Phase E3 (credential lifecycle) built + proven on branch `feat/phase-e-identity-ad`
- **New `credentials/` package** (schema + vault + cracker + manager), the capture→crack→own→escalate lifecycle:
  - `schemas/credentials.py` — `Credential` (metadata only: opaque `secret_ref` + masked preview; the raw
    secret NEVER lives in the model), `SecretKind` (plaintext/nt_hash/aes_key/ticket/kerberos_tgs/kerberos_asrep),
    `CredentialState` (captured/cracked/validated). `is_reusable` = hash/key/ticket (PtH/PtT); roast kinds aren't.
  - `credentials/vault.py` — `CredentialVault`: in-memory store, opaque `vault-…` refs, `mask()` previews, never
    logs raw. The one chokepoint holding material (data-min rule §6/§8).
  - `credentials/cracker.py` — `HashCracker`: **real** offline crypto. `crack_nt` (MD4 utf-16-le over a wordlist);
    `crack_kerberos` (RC4-HMAC per RFC 4757: K1=HMAC-MD5(nt,usageLE), K3=HMAC-MD5(K1,checksum), RC4 decrypt,
    verify HMAC — TGS-REP usage 2 / AS-REP usage 8; auto-detects format). `nt_hash()` + `principal_of()` helpers.
    **Validated against genuine impacket-encrypted tickets** (independent impl) — TGS/AS-REP/NT all crack, neg
    control fails. Only stdlib + pycryptodome (ships via impacket) so it runs in the zero-service test suite.
  - `credentials/manager.py` — `CredentialManager`: governed `capture` (→ vault + Credential, audited, no
    material in payload), `crack` (offline → mints reusable PLAINTEXT cred, audits success/failure with try-count
    only), `own` (marks principal owned in the WorldModel → `domain_admin_paths()` re-plans → fresh DA path).
    Never touches the wire; on-wire reuse (PtH) is E4/FootholdRunner under a gate.
- **Wired into the loop:** `kerberoast` wrapper `parse` now emits `hashes` (roast blobs) + `accounts`
  (parsed principals). `ADObserver(cred_manager=…, wordlist=…)` (opt-in, backward-compatible) runs
  capture→crack→own on roasted tickets and re-surfaces paths. `principal_of` made public in the wrapper.
- **Green: 665 passed, 3 integration skips; ruff+mypy clean (172 src files).** +28 tests (credentials/ +
  identity-specialist wiring + kerberoast wrapper).
- **PROVEN engine-driven on the live DC account (2026-07-17):** set `svc_sql@corp.local` password on the running
  `ae-dc`, forged a GENUINE `$krb5tgs$` (impacket RC4-HMAC keyed by svc_sql's real NT hash), ran it through the
  engine → cracked back to the real password → owned svc_sql → path `SVC_SQL→[GenericAll]→DOMAIN ADMINS` surfaced;
  3 hash-chained audit entries, `audit.verify()` True, no secret in payloads. Script: scratchpad/e3_live_proof.py.
- **Live-range caveat reproduced (as memory predicted):** impacket's on-wire ticket *request* vs this Samba build
  fails — Kerberoast TGS = `KRB_AP_ERR_INAPP_CKSUM`, AS-REP request rejected by the KDC even with
  DONT_REQ_PREAUTH set (restarted DC, LDAP showed the flag, KDC still required preauth). Kerberoast *enumeration*
  over LDAP works (found `MSSQLSvc/db.corp.local:1433`). So ticket *extraction* needs a Windows DC or tooling
  work; the crack rung is cryptographically real regardless. Reverted svc_sql UAC to 66048 (normal SPN account).
- **PR reminder (user ask):** commit on `feat/phase-e-identity-ad`; open the PR into `dev` when Phase E wraps so
  E1–E3 (and E4) land on the deployed version. Pull latest `dev` + rebase before the PR.

## 2026-07-17 — Phase E4 (real lateral execution) built + proven; Phase E COMPLETE
- **New `c2/lateral.py`** — credential reuse (PtH/PtT/valid creds) → proven session on a NEW host, mirroring the
  msf/sliver backend pattern:
  - `LateralClient` (Protocol: open/run/alive/close — the auth+exec surface); real `ImpacketLateralClient`
    (`# pragma: no cover`, integration-only) runs `impacket-wmiexec/psexec/smbexec` one-shot with PtH (`-hashes
    :<nt>`), PtT (`-k -no-pass` + KRB5CCNAME), or plaintext; opaque in-memory handle table keeps the secret out
    of argv that could be logged externally.
  - `LateralBackend` (a `C2Backend` routed by `lateral_handle` in Session.metadata) — so the EXISTING
    `FootholdRunner` opens/proves/tears-down the lateral session (scope/gate/audit/kill-switch unchanged).
  - `LateralMovementLauncher.move(host, credential, *, protocol, world_model)` — guards `is_reusable` (refuses an
    uncracked roast blob), resolves technique (NT_HASH→T1550.002 PtH, TICKET/AES→T1550.003 PtT, PLAINTEXT→T1021),
    reads the secret from the vault ONLY at use (in-memory, never audited), `client.open` → `runner.establish`
    (technique-tagged) → marks principal owned so the graph re-plans from the new host.
  - `Engagement.lateral(client, vault)` factory wires it over the engagement's FootholdRunner+SessionManager.
    Exported from `c2` (LateralBackend/LateralClient/LateralMovementLauncher/LateralProtocol/lateral_backend).
- **Green: 676 passed, 3 integration skips; ruff+mypy clean (173 src files).** +21 tests (tests/c2/test_lateral.py
  + engine `test_engagement_lateral_factory`). Deploy-safe: no new runtime dep (impacket lazy/integration-only,
  subprocess stdlib); verified `attack_engine.c2` + `attack_engine.api.app` import chain boots clean.
- **PROVEN LIVE (2026-07-17):** real `LateralMovementLauncher`/`FootholdRunner`/`SessionManager`/`AuditLog` vs
  reachable Metasploitable (10.5.0.12): owned NT-hash cred → authorized T1550.002 (PtH) → tracked session →
  PROVED with real remote output (whoami=root, real id, hostname=56d5de11048d) → 5-entry hash-chained audit
  verify()=True, no secret in payloads → kill-switch teardown released session + transport. Script:
  scratchpad/e4_live_proof.py.
- **Honest caveat:** the live exec transport was a real-command stand-in (`docker exec`) because THIS range has
  no Windows member server for true wmiexec/psexec PtH; the PtH/PtT auth path is unit-tested and the impacket
  client is integration-only (same posture as Sliver/msfrpc). To run on-wire PtH: add a Windows member host.
- **Phase E COMPLETE (E1 abuse graph, E2 identity specialist, E3 credential lifecycle, E4 lateral execution).**
  Gate (foothold→Domain Admin) met live; the one carry-forward is native-tool wrapping as first-class sandboxed
  engine tools + a Windows member host. **PR #14 `feat/phase-e-identity-ad` → `dev` is OPEN + MERGEABLE.**

## 2026-07-17 — Phase F (full adversary emulation) F1+F2 built + gate demonstrated
- **Branch `feat/phase-f-adversary`** (off the E tip, since F imports E's credentials/lateral). Rebase onto `dev`
  after PR #14 (E) merges, then PR F → dev. Pushed as `furqanali-rgb` (gh auth switch — FurqanGGI is read-only).
- **F1 — `orchestrator/adversary.py` `AdversaryCampaign`:** the real autonomous campaign. Drives the A–E
  specialists (recon→web→identity), each an objective-directed `ReasoningLoop`, chained by `ObjectiveController`
  with **frontier expansion** each round (frontier = reachable_assets + owned_principals; grows via recon hosts +
  identity/lateral owned principals; re-plan from each new vantage). Stops on goal-met / kill-switch / budget /
  convergence (no frontier growth). Governed + audited (`campaign.start`/`campaign.complete`). `CampaignPhase`/
  `PhaseRun`/`CampaignOutcome` (+to_markdown). `from_engagement(targets, profile, goal)` seeds targets as
  reachable assets (`seed_targets`) + builds the real specialist loops from the AgentContext; default goal =
  `DomainAdminObjective`. Left the legacy `campaign.py` `CampaignRunner` intact (added alongside, like the
  ObjectiveController was vs the legacy Orchestrator).
- **F2 — profiles + autonomy tiers + gated evasion:** `authorization_summary(scope, techniques)` classifies each
  profile TTP as autonomous / gated / gated-evasion under the signed RoE (profile declares, RoE decides).
  `EVASION_TECHNIQUES` (T1027/T1070/T1140/T1202/T1218/T1562/T1055) are **always gated, never autonomous even at
  T3** — measured detection-testing framing. `CampaignOutcome.authorization` + report surface it. New
  `evasion-tester` built-in profile (its evasion ids live in `techniques`, NOT `kill_chain`, since kill_chain ids
  must be catalogued in `attack/catalog.py build_library` — a test enforces that).
- **Green: 691 passed, 3 integration skips; ruff+mypy clean (174 src files).** +24 tests
  (tests/orchestrator/test_adversary.py + engine from_engagement wiring test). Deploy-safe: no new runtime dep;
  `attack_engine.orchestrator` + `attack_engine.api.app` import chain boots clean.
- **GATE DEMONSTRATED:** unattended `AdversaryCampaign` (evasion-tester profile) → Domain Admin in 1 round with
  real governance objects; identity leg ran the real E3 lifecycle on a genuine impacket Kerberoast ticket for the
  live DC account svc_sql (cracked → owned → `SVC_SQL→[GenericAll]→DOMAIN ADMINS`), audit verify()=True, evasion
  TTPs shown always-gated. Script: scratchpad/phase_f_live.py.
- **Real-world lesson:** principal-name normalization — NetBIOS `@corp` vs FQDN `@CORP.LOCAL` must align across
  collectors or an owned principal won't match its AD-graph node (hit this in the proof; a normalization pass
  across collectors/roast-parsing is worth a future slice). **Carry-forward:** fully live-LLM-driven full-chain
  run (reuses A/D/E plumbing) + Windows member host for on-wire lateral + campaign SSE narrative.

## 2026-07-17 — One-click TEST authorization (frictionless deploy/test) + governance backlog
- **Why:** user deploys the platform then tests the full offensive pipeline via the frontend; wants the
  offensive chain to run on **user/test authorization alone** with zero deployment friction (they know the real
  security measures; platform is early). So: test auth is the ONLY thing needed to run the pipeline in testing.
- **`Settings.allow_test_authorization`** — env **`AE_ALLOW_TEST_AUTH`** (alias; default False, in `config.py`).
  Engine (`engine.py engagement()`) refuses a test-authorization scope unless this is on — **independent of
  `env`** (a prod-shaped *testing* deploy enables it; a real customer prod leaves it off).
- **`Scope.for_testing(targets, ...)`** (`schemas/scope.py`): ready signed scope from IPs/CIDRs/hosts/URLs,
  signature sentinel `TEST-AUTH-NOT-FOR-PROD` (→ `is_test_authorization`), tier 2, read_only False, broad
  authorized_techniques, auto-expires 8h. `_classify_target` keeps CIDR masks, strips URL scheme/port/path.
- **Gate-free under test auth (the key fix):** `engine.engagement()` auto-wires `approve_all()` gates for a
  test-authorization scope when the caller passes no responder — so the WHOLE offensive chain (incl. high-impact
  `exploit_confirm`/foothold) runs without human gates, via ANY path (Python/CLI/API/frontend). Real scopes keep
  the deny-all default.
- **One-call + API:** `Engine.testing_engagement(targets)`; API `POST /engagements/{eid}/activate-test` (operator
  role) opens from the RoE `scope_allowlist` **without signing** (403 if flag off); adapter
  `EngineAdapter.open_for_testing`.
- **Green: 703 passed, ruff+mypy clean.** Tests: `tests/test_scope_testing_auth.py`, `tests/test_engine.py`
  (opt-in + gate-free), `tests/api/test_adapter.py`.
- **Deploy checklist for frontend testing:** `AE_ALLOW_TEST_AUTH=true` + `AE_API_ADMIN_EMAIL`/`_PASSWORD` +
  a model key (`ANTHROPIC_API_KEY`) or `AE_MODEL_MOCK=true` + Docker socket mounted (docker-out-of-docker) +
  `AE_SANDBOX_BACKEND=docker`/`AE_SANDBOX_NETWORK` (or `noop`) + a reachable target. Postgres/Redis/Neo4j
  optional (sqlite/memory defaults fine single-node). None of the 6 governance guardrails are needed for testing.
- **`governance-hardening.md` (repo root):** honest code-grounded backlog of the guardrails needed before a real
  third-party target (scope crypto-verify, egress control, evidence capture, vault encryption, kill-switch
  trip→teardown) — status + file:line + fix + sequencing. See [[8pi-deploy-readiness]].

## 2026-07-16 — Direction shift: the offensive depth push (living/dynamic planning)
- **New direction (confirmed by the user):** go from starter-level to a top-tier autonomous
  offensive platform — **full adversary emulation** (external web → internal network → AD →
  domain compromise), landing **real footholds inside a signed scope**, with an AI that
  **reasons like a hacker** instead of running a fixed script. Build on the strong spine; add
  deep, advanced, robust layers at every stage. Deep design: [offensive-depth-plan.md](offensive-depth-plan.md).
- **Planning is now dynamic/living:** phases are directions, not a contract. Re-plan the order
  as we learn; every design is changeable; keep improving. [phases.md](phases.md) is a living doc
  I keep updated (honest "what's really done" + shifting "what's next"). Nothing is a hard line.
- **Honest baseline (audited today):** the governance/sandbox/BYOM-routing spine is genuinely
  real and good. The offensive layers claimed "done" (O0–O6) are mostly **scaffolding/interfaces,
  not real capability** — no LLM reasoning loop (fixed 8-phase `if/elif`); exploit "session" is a
  stdout regex that dies; C2 is an in-memory mock; confirm proves only low-sev signals (server-side
  RCE can't reach CONFIRMED); calibration never fitted; CVE feed is a 3-record toy; AD/lateral are
  labels over booleans; tests prove ~0% real offensive I/O. The earlier rosy "Current state" below
  reflects what was *built as interfaces*, not what actually lands — read it with that correction.
- **Forward roadmap (foundation-first, living):** A Brain → B Proof → C Foothold chain → D Web
  depth → E AD/lateral depth → F Full adversary emulation → G Scale/eval. Governance hardening
  rides along with every real-weapon phase. Full detail in phases.md + offensive-depth-plan.md.
- **Masterclass multi-agent fleet ("adversary mind"):** [agent-fleet.md](agent-fleet.md) — model
  how an elite hacker *thinks* as a society of specialized reasoning agents (Mastermind + cognition
  meta-agents + domain specialists + tradecraft + safety agents), spawned dynamically per target.
  Reconciles "as many agents as required" with rule #3 (agents = distinct *cognition/roles*, not
  tool-copies; new tools ≠ new agents). Cognition core is built in Phase A; fleet grows one layer
  per phase. All inside the propose-vs-confirm + scope/audit/gate envelope — it's for platform safety.

## Current state
- **Engine** (`src/attack_engine/`): complete through Sprints 0–3 + offensive O0–O6.
  Full test suite green; ruff + mypy clean; runs with zero external services.
- **API** (`src/attack_engine/api/`): the canonical HTTP layer over the engine. Phase-1
  endpoints driven by the real engine; async recon/vuln-scan (background jobs) + live SSE.
  14 api tests. Not-yet-wired actions return a clean 501 ("not available yet").
- **Console** (`frontend/`): React SPA wired to the API. Tabs show real data or an honest
  "not available yet" notice. `public/index.html` exists; `.env.example` provided.
- **Proven live** against the local range (Juice Shop / DVWA / Metasploitable): real recon →
  assets/services, verify+correlate → findings, threat-map + attack-path populated, audit chain verified.

## Git / repo
- Repo: `tjoctopi/8pi--V1-Platform`.
- `main` = older demo prototype, **untouched**. `dev` = integration branch (has the engine +
  merged frontend wiring). Feature work branches off `dev`, PRs into `dev`.
- **PR #3** (frontend↔engine wiring) — **merged into `dev`**.
- **PR #4** (async scans + live SSE; removed duplicate `api/`) — **open → `dev`**, mergeable/clean.
- Push account: **`furqanali-rgb`** (has write). `FurqanGGI` is read-only. Commit identity:
  `furqanali-rgb <furqan.ali@8pi.ai>`. **No Claude co-author, ever.**

## Key decisions
- **Positioning: offensive / red-team platform** (not purple-team — legacy label). Confirmed by the user.
- **Adapter-in-shell** wiring: the frontend contract is fixed; the real engine is wired behind it.
  No Mongo — SQLite shell store, consistent with the engine's zero-external-services principle.
- Canonical API = `src/attack_engine/api/`. A duplicate top-level `api/` scaffold (built in
  parallel) had a better async job-runner + SSE; those were **ported in, then the duplicate deleted**.
- Governance (scope/gates/kill-switch/audit) is the engine's job; the API never re-implements it.

## Environment / how to run
- Dev API (no Docker/keys): `AE_ENV=dev AE_SANDBOX_BACKEND=noop AE_MODEL_MOCK=true
  AE_AUDIT_BACKEND=memory AE_API_ADMIN_EMAIL=… AE_API_ADMIN_PASSWORD=… python -m attack_engine.api.app`
- Real mode (Docker + range + real model): drop the dev overrides, set `AE_SANDBOX_BACKEND=docker`,
  `AE_SANDBOX_NETWORK=attack-engine-range_range_net`, keys from `.env` (`FIREWORKS_API_KEY`,
  `ANTHROPIC_API_KEY`). Console: set `REACT_APP_BACKEND_URL` (frontend dev port 3007; 3000 is Juice Shop).
- Range: Juice Shop 10.5.0.10, DVWA 10.5.0.11, Metasploitable 10.5.0.12 on `attack-engine-range_range_net`.
- Model keys live in the gitignored `.env`. Never print them.

## Known gaps / TODO (not yet built — see phases.md for order)
- Live engagement state is **in-process** → API needs sticky sessions until state is externalized
  to Postgres/Redis (blocks clean multi-node scaling).
- Approval gates over HTTP (async gate responder) — approvals UI not yet driving real `exploit()`.
- Remaining console actions still stubbed 501: CVE refresh, remediate/re-test, model infer,
  report HTML/PDF, Red Scope chat.
- Attack-path AI narrative (SSE) not wired.
- Legacy "purple-team" wording still in `docs/` + some console copy.
- `deploy/` Terraform/CloudFormation still target the old Mongo prototype — need the real-engine
  (Postgres/Redis/Neo4j) topology + `docs/DEPLOYMENT.md` + `docker-compose.prod.yml`.

## Gotchas learned
- Verification oracles fire rapid probes → scope rate limit must have headroom (set 50/s, burst 20).
- Recon/vuln-scan are minutes-long and Docker-spawning → they MUST run as background jobs, not on
  the request thread (this was a real bug; fixed in PR #4).
- Juice Shop's port 3000 is outside nmap's top-1000, but recon still found it via the tool chain.
