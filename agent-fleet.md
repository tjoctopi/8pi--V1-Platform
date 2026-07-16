# 8π — The Adversary Mind: masterclass multi-agent fleet

> **Purpose & safety framing.** This is the design for 8π's agent society — a fleet of
> specialized reasoning agents that together emulate how an *elite adversary thinks*, so we
> find and **prove** the gaps in an authorized target before a real attacker does. This is a
> **defensive capability for the safety of the platforms we test.** Everything below runs inside
> the non-negotiable envelope: agents **propose**, deterministic oracles **confirm**; scope / rate /
> RoE are enforced at the Tool Runner boundary, never by an agent; every action is audited and
> high-impact actions are gated. A big fleet does not mean a loose fleet — it means many *minds*
> under one governance spine.
>
> Companion to [offensive-depth-plan.md](offensive-depth-plan.md), [execution-plan.md](execution-plan.md),
> [phases.md](phases.md). Living/dynamic — the roster grows and re-shapes as we learn.

---

## 1. How an elite hacker actually *develops* their thinking (the cognition we model)

A masterclass operator's edge is not tools — it's **cognition**. We model these habits of mind, and
each becomes an agent role or an agent behavior:

1. **Question every assumption / trust boundary.** "What does this system *trust*, and why — and can
   I *become* that trusted thing?" Most breaches are broken trust, not broken code.
2. **Abuse intended functionality.** The exploit is often a feature used in a way the designer never
   imagined. Look at what the system is *for*, then bend it.
3. **Think in chains, not findings.** weak + weak + weak → total compromise. A lone "info" finding is
   a link, not a dead end.
4. **Recon obsessively.** The map wins the fight. Unknown unknowns kill campaigns; expand the surface
   relentlessly before committing.
5. **Hypothesize → cheapest test → update belief.** Bayesian, evidence-driven. Never fall in love with
   a theory; let the response move your priors.
6. **Diverge, then converge.** Generate many wild ideas (creativity/lateral thinking), then ruthlessly
   prune the ones that can't be real (skepticism).
7. **Persistence & adaptation.** A dead end is *data*. Pivot the approach, don't quit the objective.
8. **Model the defender.** Think about detection, logging, and what the blue side sees — both to stay
   quiet and to report honestly what a defender *would* have caught.
9. **Pattern transfer.** "This resembles a target/TTP I've seen before" — reuse hard-won tradecraft.

The fleet below is a direct, deliberate mapping of these nine habits into cooperating agents.

## 2. Design law: roles (cognition), not tool-copies

"Build as many agents as required" is reconciled with the project's rule #3 like this: **an agent is a
distinct way of *thinking / deciding*, not a wrapper around a tool.** Adding a new scanner is a *tool*,
not an agent. The fleet is large because hacker cognition is genuinely multi-faceted — and it is
**dynamic**: the Mastermind spawns only the specialists a given target *requires*, and tears them down
when done. Fleet size ≈ target complexity, bounded by the engagement budget. As many as required — no more.

---

## 3. The fleet (layered)

### Layer 0 — The Mastermind (strategic cognition)
- **Campaign Strategist ("attacker-in-chief").** Owns the objective and the adversary persona/doctrine
  (how loud, which TTP families, which threat actor to emulate). Decides where to press, when to
  escalate, when to gate, when to stop. Delegates to specialists; arbitrates debates.

### Layer 1 — Cognition / meta-agents (the *mind*)
- **Ideator (Hypothesis Generator).** *Divergent thinking* — floods candidate weaknesses/attack ideas
  from the world model ("this trusts X; this feature could be bent; this looks like CVE-class Y").
- **Skeptic (Adversarial Critic / red-team-the-plan).** *Convergent thinking* — tries to *refute* each
  hypothesis before we spend an action, killing weak leads. (Still the *propose* side — real proof is
  the deterministic Oracle's job.)
- **Threat-Model Reasoner.** Maps trust boundaries, assumptions, roles, and data flows; answers "what
  does this trust and why."
- **Attack-Path Planner / Chainer.** Composes steps into multi-stage chains toward the objective;
  EV/graph reasoning over the attack graph; finds the cheapest path to impact.
- **Reflection & Learning agent.** After each step: what worked, stuck/loop detection, backtrack advice,
  playbook + memory updates.
- **Opportunity Scout.** Watches *all* observations for unexpected openings ("hacker intuition") that no
  one explicitly went looking for.
- **Analogy / Pattern-Transfer agent.** Retrieves "this resembles known target/TTP Z" from memory.

### Layer 2 — Domain specialists (the *expertise / hands*)
Spawned as the target requires:
- **Surface:** Recon/OSINT · Attack-Surface Mapper · JS/Client analyzer · API/GraphQL specialist · Cloud-asset discovery.
- **Access:** Web/App exploitation · Injection specialist (SQLi/cmdi/SSTI) · Auth/Session/OAuth/JWT · Deserialization/memory-safety · Exploit-dev.
- **Post-access:** Foothold/C2 operator · Post-ex & situational-awareness · Credential harvester/cracker.
- **Identity / internal:** AD/Kerberos · ADCS/PKI (ESC1-8) · Delegation & ACL abuse · Lateral-movement · Privilege-escalation (Windows/Linux) · Trust/cross-domain.
- **Cloud / container:** Cloud IAM & metadata abuse · Kubernetes/container-escape.
- **Objective:** Data-discovery / crown-jewels hunter (defines and reaches "winning").
- **Scope-gated special surfaces (spawn only if in scope):** Mobile · Wireless · OT/ICS · Social-engineering *simulator* (authorized-only, heavily gated).

### Layer 3 — Tradecraft / support
- **Tool-smith.** Selects/wraps tools and writes throwaway scripts *in the sandbox* — dynamic capability
  without cloning agents (rule #3).
- **Payload Synthesizer.** Context-aware payloads, checked by the Skeptic and proven by the Oracle.
- **Proof / Oracle Driver.** Drives **deterministic** confirmation — the *confirm* half of propose-vs-confirm.
- **Knowledge Librarian.** RAG over the world model, intel, CVE/EPSS, and past engagements.
- **Reporter / Narrator.** Plain-language attack-path narrative + court-grade evidence + remediation.

### Layer 4 — Governance / safety agents (for the safety of the platforms)
- **Scope/RoE Sentinel.** Pre-checks and advises (hard enforcement stays deterministic at the boundary).
- **Safety / Gate Adjudicator.** Routes high-impact actions to human gates; holds the ethics guardrails.
- **Blue / Detection-View agent.** Models what a SIEM/EDR/defender sees — dual value: honest "here's what
  you'd have caught" reporting *and* quiet-path (evasion) testing, gated.
- **Auditor.** Ensures every action is evidence-logged and watches for safety-envelope drift.

---

## 4. Coordination — how many agents behave as *one* mind

- **Shared world model / blackboard is the medium.** Agents read/write structured beliefs (from Phase A),
  not free-floating chatter. The common belief state is what makes them one mind instead of a crowd.
- **The cognition loop:** Strategist sets objective → Ideator proposes → Skeptic prunes → Planner
  sequences → a specialist **Acts** (through the Tool Runner) → Observer updates beliefs → **Oracle
  confirms** → Reflection learns → repeat toward the objective.
- **Interaction patterns (borrowed from how real teams work):**
  - **Fan-out (breadth):** many specialists probe in parallel, like a red team splitting the surface.
  - **Debate / panel (hard calls):** Ideator vs Skeptic; several specialists vote; Strategist decides.
  - **Adversarial verify (zero false positives):** a finding promotes only if the Skeptic can't refute
    it *and* the deterministic Oracle proves it.
  - **Dynamic spawning:** the Mastermind spawns only the specialists the target needs, budget-aware, and
    tears them down when their surface is exhausted.
  - **Escalation:** high-impact actions route through the Safety Adjudicator to a human gate.
- **Memory tiers (shared):** episodic (this engagement) · semantic (learned target facts) · procedural
  (playbooks/TTPs). This is where "developing the thinking" accrues over time.

---

## 5. Mapping the fleet to the build phases (living)

- **Phase A — the *mind* skeleton.** Build the cognition core: Strategist, Ideator, Skeptic, Planner,
  Reflection — on the reasoning loop + shared world model — plus the first specialist (Recon). Layer-4
  safety agents exist from day one.
- **Phase B —** Proof/Oracle Driver + the adversarial-verify pattern made real (zero-FP).
- **Phase C —** Foothold/C2 operator, Post-ex, Credential agents.
- **Phase D —** Web/API/Auth/Injection/Deserialization specialists + Payload Synthesizer + Tool-smith.
- **Phase E —** AD/Kerberos/ADCS/Delegation/Lateral/PrivEsc/Trust specialists.
- **Phase F —** OpSec/Evasion + Blue/Detection-View + adversary-persona doctrine; the full society runs
  a campaign autonomously.
- **Phase G —** scale the fleet on the executor pool; cost controls; continuous learning into procedural memory.

## 6. Safeguards that keep a large fleet safe and sane

- **Budget-governed:** one token/cost budget per engagement; dynamic spawn; cheap/local models for bulk
  cognition, frontier models for the hard planning/critique calls.
- **No bypass:** no agent ever bypasses the Tool Runner boundary; scope and audit stay deterministic.
- **Propose ≠ truth:** no agent's output is treated as fact; the Oracle confirms.
- **Fully traced:** every agent decision (the "why") lands in the audit and the live SSE narrative.
- **Dynamic, not gratuitous:** as many agents as the target *requires*, spawned by need, retired when done.
