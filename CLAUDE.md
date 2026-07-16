# 8π — Claude context (read this first)

**8π is a fully autonomous, agentic-AI offensive-security / red-team platform.** A
system of AI agents runs the whole adversary kill chain by itself against an
authorized target — recon → exploit → foothold → escalate → lateral → objective —
finding the gaps other platforms miss and **confirming** them (proving the exploit,
not just detecting). The goal is to be the most capable offensive platform in
existence — able to fully compromise any authorized target. A human sets scope; the
AI does the work.

Before doing any work in this repo, read these — they are the source of truth:

| File | What it is |
|---|---|
| [project-requirements.md](project-requirements.md) | What we're building, the target, the business, the features |
| [architecture.md](architecture.md) | How the system is designed (layers, principles, the API + engine) |
| [rules.md](rules.md) | **Operating rules — how to work here. Read before every task.** |
| [phases.md](phases.md) | What's done, what's next, the one-feature-at-a-time roadmap |
| [memory.md](memory.md) | Living state log — current status, decisions, known gaps |

## The three rules that matter most (full set in rules.md)
1. **Stay on the path.** Build only what the current phase asks for. Do not add scope,
   do not wander into "nice to have" features. If tempted, stop and flag it.
2. **Test before every PR.** `pytest`, `ruff`, and `mypy` must be green; add tests for
   new code; verify live behavior where it matters. Never open a PR on untested code.
3. **Pull latest before you work; `main` is untouched.** Branch off `dev`, PR into `dev`.

## Fast facts
- **Positioning:** offensive / red-team. NOT "purple-team" (legacy wording still in some docs).
- **Repo:** `tjoctopi/8pi--V1-Platform`. Branches: `main` (do not touch) · `dev` (integration) · feature branches.
- **Push account:** `furqanali-rgb` (the `FurqanGGI` gh account is read-only). Commit as the user — **never** add Claude as a co-author.
- **Engine:** `src/attack_engine/` (Python 3.11, pydantic v2). **API:** `src/attack_engine/api/`. **Console:** `frontend/` (React).
- **Run tests:** `.venv/bin/pytest` · `.venv/bin/ruff check src tests` · `.venv/bin/mypy src/attack_engine`.
