# 8π — Operating Rules

Read this before every task. These are how we work, not suggestions.

## 1. Stay on the path (the most important rule)
- Build **only** what the current phase / the task explicitly asks for. See [phases.md](phases.md).
- **Do not add scope.** No "while I'm here" features, no speculative abstractions, no
  refactors nobody asked for. If something tempting is out of scope, **stop and flag it**
  to the user — don't just build it.
- If a task is ambiguous or seems to drift from [project-requirements.md](project-requirements.md),
  ask before proceeding.
- Prefer the smallest change that fully solves the stated problem.

## 2. Test before every PR (no exceptions)
- `.venv/bin/pytest` — full suite green. The suite runs with **zero external services**;
  keep it that way.
- `.venv/bin/ruff check src tests` — clean.
- `.venv/bin/mypy src/attack_engine` — clean.
- **Add tests for new code.** New behavior without a test is not done.
- **Verify live behavior** where it matters (e.g. run the API + a real scan) — tests alone
  don't prove an end-to-end wire works.
- Never open a PR on code you haven't tested.

## 3. Git / PR workflow
- **`main` is untouched** — it's the demo. Never commit or PR to `main`.
- **`dev` is the integration branch.** Branch off `dev`; PR into `dev`.
- **Pull the latest before you start and before you PR** — `git fetch` + rebase/merge the
  latest `dev` so you're never working on stale code and the PR merges clean.
- One focused change per branch/PR. Keep the diff reviewable.
- **Commit as the user. Never list Claude as a co-author or add a "generated with" trailer.**
- Push with the `furqanali-rgb` account (the `FurqanGGI` gh account is read-only).
- Don't commit: `node_modules/`, `data/*.db`, `.env`, build artifacts, stray binaries/docs.
- Before deleting/overwriting anything you didn't create, look at it first and surface it —
  untracked files have no git recovery.

## 4. The engine's four non-negotiables (never violate)
1. **Propose vs. confirm** — model proposes, deterministic code confirms. Never let an agent's
   output be treated as ground truth.
2. **Scope at the boundary** — scope/rate/RoE live in the Tool Runner, never in an agent.
3. **Roles, not tool-copies** — add capability via a registered tool/exploit wrapper, not a new agent clone.
4. **Model-agnostic (BYOM)** — every model call goes through the gateway. Never hardcode a model/provider.

## 5. Safety & authorization (this is offensive tooling)
- Offensive actions run **only** inside a signed, unexpired scope. No scope → no action.
- Governance is always on: audit every action, honor the kill switch, gate high-impact actions.
- Never build working weaponization outside the safety envelope (scope/sandbox/audit/gate).
- The audit log is the proof that every action was authorized — never bypass or mutate it.

## 6. Secrets
- Never put secrets (model keys, DB creds, JWT secret) in code or commits. Env / secrets manager only.
- Never print secret values in logs or output.

## 7. Positioning & language
- This is an **offensive / red-team** platform. Frame it that way.
- "Purple-team" is legacy wording — don't add new purple-team language; sweep it out when you touch it.

## 8. Honesty
- If something isn't wired yet, say so (in the product: a clear "not available yet"; to the user:
  plainly). Don't fake data or hide gaps.
- Report test/verification results faithfully — if it failed or was skipped, say so.
