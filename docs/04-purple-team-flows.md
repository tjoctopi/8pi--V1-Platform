# 4 · Purple-team flows

The same engine runs at three intensities against **any authorized target** —
the *only* thing that changes what's allowed is the **signed scope**, never the
target's infrastructure type.

```mermaid
flowchart LR
    subgraph MODES["Intensity is a policy, not a different engine"]
      P["Passive intel<br/>(capture-only)"]
      A["Active / aggressive<br/>(read-only screening)"]
      O["Offensive<br/>(mutating, authorized)"]
    end
    P -->|--active| A -->|read_only:false + tier| O
```

## The finding lifecycle (rule #1) — the spine of everything

```mermaid
stateDiagram-v2
    [*] --> PROPOSED: agent/tool surfaces it
    PROPOSED --> VERIFIED: deterministic oracle<br/>re-checks raw evidence
    PROPOSED --> REJECTED: oracle disproves<br/>(kept for FP study)
    VERIFIED --> CONFIRMED: correlator finalizes<br/>(CVE/KEV + reachability + calibrated prob)
    VERIFIED --> REJECTED
    CONFIRMED --> [*]: the ONLY state a report/gate acts on
```

A model can never write `state="confirmed"`; the transition is guarded in code.
This is why the dossier has **no false-positive noise** — everything shown as a
lead has survived an independent, deterministic check.

## Passive intel (capture-first)

Goal: a rich **attack-surface intelligence dossier** on any target, touching it
as little as possible. `active_injection_screen = off`.

```mermaid
flowchart TB
    T["Target (in scope)"] --> R["Surface Mapper<br/>nmap/httpx recon"]
    R --> BB[("Blackboard")]
    R --> WEB["Web Inquisitor (capture mode)"]
    WEB -->|edge fingerprint| EDGE["Detect CDN/WAF<br/>(cf-ray, akamai, …)"]
    WEB -->|focused nuclei tags| OBS["Observations"]
    WEB -->|katana crawl| EP["Endpoints + params"]
    WEB -->|api specs| API["OpenAPI/Swagger → full endpoint map"]
    EP --> LEADS["Injection leads recorded<br/>(NOT probed)"]
    BB --> DOS["build_attack_surface()"]
    OBS --> DOS
    EP --> DOS
    EDGE --> DOS
    DOS --> OUT["Dossier:<br/>services · tech · endpoints · exposed items ·<br/>leads · observations (with confidence) · coverage"]
```

Two quality mechanisms that make the dossier trustworthy:

- **Corroboration gate (false-positive suppression).** A high/critical scanner
  observation keeps its severity **only if the asset's own fingerprint
  corroborates it**; otherwise it is tagged `unconfirmed`. (Live example: a
  bogus `critical: VMware ESXi SLP` fired off a port mis-fingerprint on an
  nginx/Cloudflare site → correctly quarantined as unconfirmed.)
- **Coverage / tool-health.** The dossier reports which scanners ran, degraded,
  or were skipped — so a `0 leads` result is distinguishable from "0 leads
  because a scanner timed out".

## Active / aggressive scanning

Same flow, but `active_injection_screen = on`: the Web Inquisitor **actively
screens injection points read-only**, and confirmation runs the full battery.

```mermaid
flowchart TB
    subgraph STRAT["Edge-adaptive, lead-gated strategy"]
      EDGE{"CDN/WAF<br/>detected?"}
      EDGE -->|yes| FOCUS["nuclei: focused templates<br/>katana: deeper + headless<br/>dalfox: skip unless param surface"]
      EDGE -->|no origin| FULL["nuclei: full corpus<br/>standard battery"]
    end
    FOCUS --> SCREEN
    FULL --> SCREEN
    SCREEN["Read-only injection screen<br/>(base / odd-quote / true / false via http_probe,<br/>observes only status + size)"]
    SCREEN -->|suspicious differential| HYP["Propose sqli-boolean-blind<br/>HYPOTHESIS"]
    HYP --> ORACLE["SqliBooleanBlind oracle<br/>rigorously re-confirms"]
    ORACLE -->|VERIFIED| CORR["Correlator → CONFIRMED foothold"]
```

> **Detection ≠ exploitation.** The active screen is *read-only* — it observes
> only response metadata (status/size) or our own reflected marker, never target
> data — so it is **ungated**. The gate stays for exploitation (SQLMap data
> extraction, RCE modules, MSF), which is the offensive layer.

**Aggressive without leads is waste.** The strategy is *lead-gated*: heavyweight
fuzzers only run once there's a parameter surface to justify them, and behind a
CDN/WAF the engine focuses templates and crawls deeper (to *find* leads) instead
of blasting a shared edge. This was proven live: dalfox went from burning
2 × 600 s hitting a WAF timeout to being skipped where there was nothing to fuzz.

## The full coordinated loop (Orchestrator)

`engage` runs the whole purple-team loop as a phase DAG, with **Blue Sentry**
tailing the event bus as the defensive view (it suppresses the engine's own
in-scope scans as expected noise, and raises alerts on out-of-scope / RoE
refusals).

```mermaid
flowchart LR
    PLAN["plan"] --> RECON["recon"] --> VERIFY1["verify"] --> WEB["web"] --> CONF["exploit_confirm<br/>(gated)"] --> CORR["correlate"] --> CONV["convert"] --> REP["report"]
    RECON -.events.-> BLUE["Blue Sentry"]
    WEB -.events.-> BLUE
    CONF -.events.-> BLUE
    REP --> KC["Kill-chain plan<br/>(with --objective)"]
    REP --> BREACH["Breach verdict<br/>(breachable iff a confirmed,<br/>reachable access-vector exists)"]
```

Output: a prioritised report (risk map + hardening actions), a **breach
verdict** with the entry→asset route, and — with `--objective HOST:PRIV` — a
goal-directed [kill chain](05-offensive-layer.md).

Continue to [Offensive layer →](05-offensive-layer.md)
