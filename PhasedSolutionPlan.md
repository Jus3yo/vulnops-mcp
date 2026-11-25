# PhasedSolutionPlan.md: vulnops-mcp

The single source of truth for what is done, what is in progress and what is next. Design detail lives in [`docs/SolutionDesign.md`](docs/SolutionDesign.md); agent rules in [`CLAUDE.md`](CLAUDE.md).

## How to use this plan

**Start every session with:**

```
Thoroughly review PhasedSolutionPlan.md and check git log for recent commits.
I'm continuing work on this plan. Tell me:
(1) Which phase and task we're currently on
(2) What was completed in the last session
(3) What's next
```

To answer it, an agent reads the **Status** block below, the **Session Log** at the bottom, and `git log --oneline -15`. Commits name the task they finish (`feat(phase-2): 2.3 ...`), so the log and the checkboxes agree.

**Rules for keeping it accurate**

1. Task states: `[ ]` not started, `[~]` in progress, `[x]` done. Only one task is `[~]` at a time.
2. Finishing a task: tick it, update **Status**, add a **Session Log** line, and commit all of it with the code.
3. A phase is finished only when its **Checkpoint** passes. Record the result under the checkpoint and tag `main` (`cp<n>`).
4. Every write the server makes against the real lab needs the user's approval. Live checks in checkpoints are run by, or with, the user.

---

## Status

| | |
|---|---|
| **Current phase** | Phase 2: Connectivity (whoami) and foundations |
| **Current task** | 2.1 Auth module (`AzureCliCredential` + Tenable keys) |
| **Last completed** | Phase 1, task 1.7 (scaffolding committed, CP1 passed) |
| **Next up** | 2.1 → 2.2 → 2.3 `vulnops_whoami` |
| **Blockers** | None. Needs: user runs `az login` and puts Tenable keys in `.env` before CP2. |
| **Last updated** | 2026-11-25 |

## Phase overview

| Phase | Name | Checkpoint | State |
|---|---|---|---|
| 0 | Solution design | CP0 Design approved | ✅ Done |
| 1 | Project scaffolding | CP1 Scaffolding complete | ✅ Done |
| 2 | Connectivity (whoami) and foundations | CP2 Every service reachable or failure understood | ⏳ Next |
| 3 | Azure VM tools | CP3 VM reads + approved writes on lab VM | ⬜ |
| 4 | Tenable tools | CP4 Scan created, launched, results read | ⬜ |
| 5 | Defender for Endpoint tools | CP5 Machine vulns + hunting query | ⬜ |
| 6 | Sentinel / Log Analytics tools | CP6 KQL evidence + incident comment | ⬜ |
| 7 | Workflow tools | CP7 Full loop on one VM, report generated | ⬜ |
| 8 | Hardening and release | CP8 v1.0.0 tagged | ⬜ |

---

## Phase 0: Solution design ✅

- [x] 0.1 Problem statement, objectives, non-goals
- [x] 0.2 Architecture and technology choices (Python 3.12+, MCP SDK 2.x, stdio, uv, httpx)
- [x] 0.3 Auth design: operator's `az login`, Tenable API keys in `.env`
- [x] 0.4 Safety model: read-only default, approval on every write, RG allow-list, honeypot skip, audit log
- [x] 0.5 Tool catalog and end-to-end workflow
- [x] 0.6 Risks (Defender consent for CLI tokens, Tenable keys) with fallbacks; decisions table

**CP0: Design approved** ✅ 2026-11-25. Spec agreed with the user (local stdio, az login, approval on every write).

## Phase 1: Project scaffolding ✅

- [x] 1.1 `git init`, `.gitignore` (secrets, venv, caches, logs, reports), keep existing local `.env` untracked
- [x] 1.2 Branching strategy: trunk-based + short feature branches (`docs/BranchingStrategy.md`)
- [x] 1.3 Project structure (`src/` layout), `pyproject.toml`, dependencies via `uv`, `uv.lock`
- [x] 1.4 `CLAUDE.md` (overview, standards, testing, commands, file layout, constraints)
- [x] 1.5 Minimal server: `config.py`, `errors.py`, `server.py`, `vulnops_server_info` tool, tests
- [x] 1.6 CI stubs: lint (ruff, mypy), test (pytest + coverage, 3.12/3.13), build (uv build), secrets scan (gitleaks)
- [x] 1.7 Supporting docs (`README.md`, `.env.example`, `docs/SolutionDesign.md`, this plan); commit scaffolding

**CP1: Scaffolding complete** ✅ 2026-11-25
- `uv sync`, `ruff check`, `ruff format --check`, `mypy --strict`, `pytest --cov` (98%), `uv build` all pass.
- Initial commit made on `main`.

## Phase 2: Connectivity (whoami) and foundations

Goal: prove every API is reachable with the agreed auth **before** building service tools, and put the safety rails in place.

- [ ] 2.1 `auth.py`: one shared `AzureCliCredential`; `get_token(scope)` per API (ARM, Defender, Log Analytics); Tenable `X-ApiKeys` header builder. Map credential failures to `AuthError` with the original message kept verbatim.
- [ ] 2.2 `clients/base.py`: async `httpx` base client (auth header hook, timeouts, retry with backoff on 429/5xx for reads only, `Retry-After`, error mapping to `errors.*` keeping status + body message).
- [ ] 2.3 `vulnops_whoami` tool: tests each service **separately** and reports per service `ok` / `error` with the verbatim upstream error:
  - ARM: token + `GET /subscriptions` (shows signed-in user and subscription)
  - Log Analytics: token + query `print ok=1`
  - Defender: token for `api.securitycenter.microsoft.com` + `GET /api/machines?$top=1`
  - Tenable: `GET /session` (shows the Tenable user)
- [ ] 2.4 `safety.py`: `require_write()` with preview + single-use `confirm_token` (5 min TTL, bound to tool name + args hash); RG allow-list; honeypot matcher (name globs, tags, IPs). Write tools hidden when `VULNOPS_ALLOW_WRITES=false`. 100% coverage.
- [ ] 2.5 `audit.py`: JSONL audit log with run ID, tool, redacted args, outcome, duration; wired into every tool call. 100% coverage.
- [ ] 2.6 Register the server in Claude Desktop on the user's machine; README steps verified on Windows.

**CP2: Connectivity (whoami) and foundations**
- [ ] Server starts from Claude Desktop with the user's `az login`.
- [ ] `vulnops_whoami` result recorded here for ARM / Log Analytics / Defender / Tenable.
- [ ] Any failure has its verbatim error recorded and a chosen fallback (Defender: Advanced Hunting tables via Log Analytics, or app registration; Tenable: regenerate keys).
- [ ] `safety.py` and `audit.py` at 100% coverage; CI green.

## Phase 3: Azure VM tools

- [ ] 3.1 `clients/azure_compute.py`: list/get VMs, instance view (power state), NICs (private IP), tags
- [ ] 3.2 Read tools: `azure_list_vms` (with `honeypot` flag), `azure_get_vm`, `azure_get_operation_status`
- [ ] 3.3 `azure_get_update_assessment` (Update Manager assess + results)
- [ ] 3.4 Write tools (approval): `azure_snapshot_os_disk`, `azure_install_updates`
- [ ] 3.5 Write tools (approval): `azure_start_vm`, `azure_stop_vm`, `azure_restart_vm`, `azure_deallocate_vm`
- [ ] 3.6 `azure_run_remediation_script` (approval, allow-listed scripts only) + first scripts in `scripts/remediation/`

**CP3: Azure VM tools**
- [ ] Lists lab VMs; honeypots flagged and refused for writes
- [ ] Update assessment read for one VM
- [ ] One approved snapshot executed; a write without a token only previews
- [ ] VM outside the allow-list refused

## Phase 4: Tenable tools

- [ ] 4.1 `clients/tenable.py`: scanners, templates, scans, scan details, host details, exports
- [ ] 4.2 Read tools: `tenable_list_scanners`, `tenable_list_templates`, `tenable_list_scans`
- [ ] 4.3 Write tools (approval): `tenable_create_scan` (honeypot IPs rejected), `tenable_launch_scan`
- [ ] 4.4 `tenable_get_scan_status`, `tenable_get_scan_results` (summary by severity/host/plugin, paged)
- [ ] 4.5 `tenable_get_host_findings`, `tenable_export_vulns`
- [ ] 4.6 Decide D5 (credentialed scans) and implement if allowed

**CP4: Tenable tools**
- [ ] Scan of one lab VM created, launched (both approved) and polled to completion
- [ ] Results summarized by severity

## Phase 5: Defender for Endpoint tools

Uses the path chosen at CP2 (direct API, or Advanced Hunting via Log Analytics).

- [ ] 5.1 `clients/defender.py`: machines, machine vulnerabilities, software, recommendations, advanced hunting
- [ ] 5.2 Read tools: `defender_list_machines`, `defender_get_machine`, `defender_get_machine_vulnerabilities`
- [ ] 5.3 `defender_get_software_inventory`, `defender_get_recommendations`, `defender_advanced_hunting` (row limit)
- [ ] 5.4 Write tools (approval): `defender_run_av_scan`, `defender_isolate_machine`, `defender_unisolate_machine`

**CP5: Defender tools**
- [ ] Vulnerabilities listed for the same VM used in CP4
- [ ] One Advanced Hunting query returns rows

## Phase 6: Sentinel / Log Analytics tools

- [ ] 6.1 `clients/log_analytics.py` (KQL query API) and `clients/sentinel.py` (ARM incidents)
- [ ] 6.2 `sentinel_query_logs` (time range, row limit)
- [ ] 6.3 `sentinel_list_incidents`, `sentinel_get_incident`
- [ ] 6.4 Write tools (approval): `sentinel_add_incident_comment`, `sentinel_update_incident`

**CP6: Sentinel tools**
- [ ] KQL returns update / run-command events for the lab VM
- [ ] Approved comment added to a test incident

## Phase 7: Workflow tools

- [ ] 7.1 `workflows/cross_check.py` + `vulnops_cross_check`: Tenable vs Defender per host (both / Tenable only / Defender only)
- [ ] 7.2 `workflows/prioritize.py` + `vulnops_prioritize`: de-dupe by CVE; rank by severity, VPR/CVSS, exploitability, exposure
- [ ] 7.3 `workflows/plan.py` + `vulnops_plan_remediation`: ordered steps, reboot, snapshot, risk
- [ ] 7.4 `workflows/verify.py` + `vulnops_verify_remediation`: before/after diff (fixed / open / new)
- [ ] 7.5 `workflows/report.py` + `vulnops_generate_report`: Markdown into `reports/`
- [ ] 7.6 MCP prompt `vuln_cycle` that walks the loop with approval points

**CP7: Workflow loop**
- [ ] One full scan → triage → remediate → verify cycle on a lab VM
- [ ] At least one finding verified fixed; report generated

## Phase 8: Hardening and release

- [ ] 8.1 Error-message review (every failure has a clear hint)
- [ ] 8.2 Audit log review; redaction test with real-looking secrets
- [ ] 8.3 Docs complete (README, tool catalog, troubleshooting)
- [ ] 8.4 Push to GitHub (D7) so CI runs; all jobs green
- [ ] 8.5 Tag `v1.0.0`

**CP8: Release v1.0** ⬜

---

## Session Log

Newest first. One line per session: date, what was done, where it stopped.

| Date | Phase / task | Summary |
|---|---|---|
| 2026-11-25 | Phase 0 → Phase 1 | Solution design written and agreed (az login, local stdio, approval on every write, honeypot skip, whoami first checkpoint). Scaffolding built and committed; CP0 and CP1 passed. Next: 2.1 auth module. |
