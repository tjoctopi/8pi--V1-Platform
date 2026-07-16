# 8π — Project Requirements

## What we are building
**8π is a fully autonomous, agentic-AI offensive-security platform — an AI red team
that runs itself.** It's not a tool an operator drives step by step; it's a system of
**AI agents** that reason, decide, and act on their own to emulate a real adversary
across the full kill chain: recon → weaponize → exploit → establish a foothold →
escalate privileges → move laterally → reach the objective. A human sets the scope
and authorization; the AI runs the campaign — continuously, end-to-end, no human in
the loop for the routine work. Every action is recorded to an immutable audit log.

**Agentic + AI-driven is the core of the product**, not a feature bolted on:
- The offensive reasoning — what to attack, how, and what to do next — is done by AI agents.
- Each agent is a **reasoning role** (recon, web, exploit, post-exploitation, remediation…),
  coordinated by an orchestrator that drives the campaign toward the objective.
- It is **fully automated**: point it at an authorized scope and it operates autonomously
  (autonomy ladder T0–T3, up to always-on).
- The AI is **model-agnostic (BYOM)** — every model call goes through one gateway.

It is **not a vulnerability scanner.** A scanner produces a list of maybes. 8π
**confirms** exploitability — deterministic code proves the gap is real by safely
exploiting it — so the client gets ground truth, not noise. The AI proposes; the
engine confirms.

## The target (what "winning" means)
**Build the most capable offensive platform in existence — one that can fully
compromise ("paralyze") any authorized target: go deeper into the kill chain than
any other tool or human red team, own the target end-to-end, and expose every gap
they missed.** Capability is the goal. Making money is the natural result of being
the most capable, not the point of the work.

"Paralyze any target" = demonstrate total, proven compromise on an **authorized**
target — initial access → privilege escalation → lateral movement → objective —
so completely that the client sees exactly how an adversary would own them, with
undeniable proof at every step. (Always inside a signed scope; see [rules.md](rules.md) §5.)

How that capability is delivered:
1. **Find** gaps that competing tools/pentests miss — via a real adversary's full kill chain.
2. **Confirm** them (proof, not a guess) — actually exploit them safely so the finding is undeniable.
3. **Own the target** — chain findings into full compromise to the objective, the way a real attacker would.
4. **Report** the whole route with evidence and the fix.

The money follows: sold as a continuous, autonomous red-team platform/service, it's
valuable precisely because it out-performs every alternative at the above.

Our edge is threefold: **depth** (a real adversary's kill chain to full compromise,
not surface scanning), **accuracy** (propose→confirm — no false positives), and
**autonomy** (it runs the whole campaign itself, continuously, not one manual scan at a time).

## Who it's for
Security teams, MSSPs/pentest firms, and companies that want continuous adversary
emulation of their estate — not a once-a-year pentest report.

## Core capabilities (the pillars)
- **Full offensive kill chain** — recon, exploitation with live sessions, C2 /
  post-exploitation, identity/AD attack paths, lateral movement, goal-directed
  attack-path planning to a named objective.
- **Confirm, don't just detect** — deterministic oracles turn a proposed finding
  into a proven, exploitable foothold. Only proof promotes a finding to "confirmed".
- **Autonomy ladder (T0–T3)** — from "ask before every action" up to continuous,
  always-on red-teaming, with authorization set at the engagement boundary.
- **Authorized & auditable** — signed scope, RBAC, kill switch, human gates for the
  highest-impact actions, and a tamper-evident hash-chained audit log as the record
  that every action was in-bounds. This is what makes autonomous offense safe and sellable.
- **Model-agnostic (BYOM)** — every LLM call goes through one gateway; swap providers
  by config; sensitive operations can run on a local model.
- **Operator console** — a web UI to scope, run, watch live, and read the results.

## How features are delivered
**One feature at a time, as vertical slices.** Each feature is built end-to-end
(engine → API → console), tested, and shipped before the next one starts. We do not
build broad half-finished surfaces. The console honestly labels anything not yet
wired as "not available yet" rather than faking it. See [phases.md](phases.md) for
the current order.

## Success criteria
- Finds and **confirms** real, exploitable gaps on an authorized target with **zero
  false positives** in the report.
- Runs the kill chain **autonomously** within a signed scope, gating only high-impact actions.
- Every action is **provably in-scope** via the audit chain.
- Demonstrably surfaces gaps that a competing scanner/pentest missed.
