# CLAUDE.md: vulnops-mcp

Instructions for any AI coding agent working in this repository. Read this file, `PhasedSolutionPlan.md` and `git log --oneline -15` at the start of every session.

## 1. Project overview

`vulnops-mcp` is a custom MCP server (Python, official `mcp` SDK 2.x, stdio transport) that automates vulnerability management in an Azure lab across **Azure VMs, Tenable, Defender for Endpoint and Sentinel / Log Analytics**. It is written from scratch: do not use, call, wrap or copy any other existing MCP server (including any course-provided "Cyber Range" MCP).

Architecture (full detail in `docs/SolutionDesign.md`):

```
MCP client ──stdio──▶ server.py ─▶ tools/<service>.py ─▶ workflows/ ─▶ clients/<api>.py ─▶ REST APIs
                                       │
                                       └─▶ safety.py (approval, RG allow-list, honeypot skip) + audit.py
```

- Auth: the operator's own `az login` (`AzureCliCredential`) for ARM, Defender and Log Analytics; Tenable API keys from `.env`.
- Read-only by default. Every write needs the user's explicit approval through a preview + `confirm_token` round trip.

## 2. Hard constraints (never break these)

1. **No secrets in git, code, tests, logs or tool output.** Secrets come only from env / `.env`. `.env` is never read, printed, edited or committed by the agent. Use `.env.example` for new keys, with empty values.
2. **Every write tool goes through `safety.require_write()`** and returns a preview + `confirm_token` on the first call. Never add a write path that skips it, and never auto-confirm.
3. **Honeypot VMs are never scanned, changed or isolated.** Respect `VULNOPS_HONEYPOT_NAME_PATTERNS` and the `vulnops:skip=true` / `role=honeypot` tags, including Tenable target IPs.
4. **Only resource groups in `VULNOPS_ALLOWED_RESOURCE_GROUPS`** are visible or actionable.
5. **No live API calls in unit tests or CI.** Mock HTTP with `respx`. Live tests are marked `@pytest.mark.live` and only run when the user asks.
6. **No free-form shell on VMs.** Run Command only executes scripts from `scripts/remediation/`.
7. Writes are never retried automatically.
8. Do not run anything against the real tenant (scans, run command, isolation) on your own initiative. The user approves each one.

## 3. Coding standards

- Python 3.12+, fully type-hinted; `mypy --strict` must pass.
- Format and lint with `ruff` (line length 100). Imports sorted by ruff.
- Naming: modules and functions `snake_case`, classes `PascalCase`, constants `UPPER_SNAKE`.
- MCP tool names: `<service>_<verb>_<noun>` (e.g. `tenable_launch_scan`, `azure_list_vms`). Prefixes: `azure_`, `tenable_`, `defender_`, `sentinel_`, `vulnops_` (meta and workflow).
- Every tool has a docstring written for the model: what it does, when to use it, what it returns, and whether it needs approval.
- Tools are thin: validate, call a client or workflow, shape output. Business logic goes in `workflows/`, HTTP in `clients/`.
- `clients/` must not import `mcp`. Clients are async (`httpx.AsyncClient`), return Pydantic models, and raise `vulnops_mcp.errors` types.
- Tool output is compact JSON (dicts from Pydantic `model_dump()`), paged with `limit` / `offset` (default 50), and includes IDs for follow-up calls.
- Error messages include the upstream status and message verbatim plus a hint.
- No `print()`; use `logging` (stdout is the MCP transport, so logs must go to stderr).

## 4. Testing expectations

- Every new module gets tests in `tests/` mirroring the source path (`src/vulnops_mcp/clients/tenable.py` → `tests/clients/test_tenable.py`).
- Must be tested: config parsing, safety (approval tokens, allow-list, honeypot matching), audit redaction, each client's request shape and error mapping, each tool's registration and output shape, every workflow function.
- Coverage: **≥ 80% overall** (enforced by `pytest --cov`), **100% for `safety.py` and `audit.py`**.
- API response fixtures go in `tests/fixtures/<service>/` as JSON, with fake IDs, hostnames and IPs only.

```bash
uv run pytest --cov            # unit + tool tests (what CI runs)
uv run pytest -m live          # live smoke tests against the lab, manual only
uv run pytest tests/test_config.py::test_defaults_are_read_only   # single test
```

## 5. Build and run commands

```bash
uv sync                        # install deps (creates .venv)
uv run ruff check .            # lint
uv run ruff format .           # format (CI runs --check)
uv run mypy                    # type check
uv run pytest --cov            # tests
uv build                       # wheel + sdist into dist/
uv run vulnops-mcp             # start the server on stdio
```

Definition of done for any task: lint, format check, mypy and tests all pass, and `PhasedSolutionPlan.md` is updated.

## 6. File organization

```
vulnops-mcp/
├── CLAUDE.md                 # this file
├── PhasedSolutionPlan.md     # phases, tasks, checkpoints, status, session log
├── README.md                 # setup and usage
├── pyproject.toml / uv.lock  # package config and locked deps
├── .env.example              # every setting, no values
├── .github/workflows/ci.yml  # lint, test, build, secrets scan
├── docs/
│   ├── SolutionDesign.md     # architecture, auth, safety, tool catalog, checkpoints
│   └── BranchingStrategy.md
├── scripts/remediation/      # the only scripts Run Command may execute
├── src/vulnops_mcp/
│   ├── __main__.py           # entry point (stdio)
│   ├── server.py             # builds MCPServer, registers tool modules
│   ├── config.py             # pydantic-settings
│   ├── errors.py             # error hierarchy
│   ├── auth.py               # credentials (Phase 2)
│   ├── safety.py / audit.py  # approval, allow-list, honeypot, audit log (Phase 2)
│   ├── clients/              # one async client per API
│   ├── tools/                # one module per service, each with register(server, settings)
│   └── workflows/            # cross-check, prioritize, plan, verify, report
├── tests/                    # mirrors src/, fixtures in tests/fixtures/
├── logs/                     # audit.jsonl (git-ignored)
└── reports/                  # generated reports (git-ignored)
```

New tool module checklist: create `tools/<service>.py` with `register()`, call it from `server.build_server()`, add tests, add the tools to the catalog in `docs/SolutionDesign.md` if they changed.

## 7. Workflow for the agent

- Follow `PhasedSolutionPlan.md` in order. Work on one task at a time; do not start a later phase before the current checkpoint passes.
- Plan, then execute: state the plan for the task, then implement it.
- Branching per `docs/BranchingStrategy.md`. Commit messages: `feat(phase-<n>): <task-id> <summary>`.
- After finishing a task: tick its checkbox, update the Status block and add a Session Log line in `PhasedSolutionPlan.md`, in the same commit.
- If a decision in the design must change, update `docs/SolutionDesign.md` (Decisions table) and say so.
