# Branching strategy

**Model: trunk-based development with short-lived feature branches.**

One person builds this project, phase by phase. Trunk-based keeps `main` always working while still giving every change a reviewable diff and a CI run.

## Branches

| Branch | Purpose | Lifetime |
|---|---|---|
| `main` | Always passes lint, type check and tests. Each merged checkpoint is tagged. | Permanent |
| `phase-<n>/<task-id>-<slug>` | One task from `PhasedSolutionPlan.md`, e.g. `phase-2/2.3-whoami-tool` | Hours to a couple of days |
| `fix/<slug>` | Bug fix not tied to a plan task | Short |
| `docs/<slug>` | Docs-only change | Short |

## Rules

1. Branch from the latest `main`. Keep a branch to a single task.
2. Commit messages follow Conventional Commits and name the task:
   `feat(phase-2): 2.3 add vulnops_whoami connectivity tool`
   Types: `feat`, `fix`, `test`, `docs`, `refactor`, `chore`, `ci`.
3. Before merging: `ruff check`, `ruff format --check`, `mypy`, `pytest --cov` pass locally (and in CI once the repo is on GitHub).
4. Merge with a squash or fast-forward so `main` stays linear, then delete the branch.
5. When a phase's checkpoint passes, tag `main`: `git tag -a cp<n> -m "CP<n>: <name>"`. Releases use semver tags (`v1.0.0`).
6. Update the Status block and task checkboxes in `PhasedSolutionPlan.md` in the same commit that finishes a task.
7. Never commit `.env`, keys, scan exports, `logs/` or `reports/`.
