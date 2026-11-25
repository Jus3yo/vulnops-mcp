# VulnOps MCP: Solution Design Document

| Field | Value |
|---|---|
| Project | `vulnops-mcp`, a custom Model Context Protocol (MCP) server for vulnerability management |
| Owner | Juseyo (`Jus3yo`) |
| Status | v0.2, spec agreed 2026-11-25 (CP0 passed) |
| Last updated | 2026-11-25 |
| Related | [`PhasedSolutionPlan.md`](../PhasedSolutionPlan.md), [`CLAUDE.md`](../CLAUDE.md), [`docs/BranchingStrategy.md`](BranchingStrategy.md) |

---

## 1. Problem statement

Vulnerability management in the lab is a manual loop across four consoles: Azure (the VMs), Tenable (scanning), Microsoft Defender for Endpoint (endpoint exposure and hunting) and Microsoft Sentinel (logging, incidents, evidence). Each step means switching tools, copying hostnames and IDs between them, and re-checking work by hand.

**Goal:** build an MCP server, written from scratch and owned end to end, that exposes those four services as a small set of safe, well-described tools. An AI client (Claude Desktop, Claude Code) can then drive the full **scan → triage → remediate → verify → report** loop in conversation, with a human approving every change.

### 1.1 Objectives

1. One MCP server, one install, four integrations: Azure Compute, Tenable.io (Vulnerability Management), Defender for Endpoint, Sentinel / Log Analytics.
2. Read-only by default. Any tool that changes a system needs an explicit opt-in and a per-call confirmation.
3. Every call is auditable: who, what, when, arguments and result status, written to a local JSONL log.
4. Tools return compact, structured JSON that a model can reason over, not raw API dumps.
5. Testable without a live tenant: every client is mockable, and CI never touches real services.

### 1.2 Non-goals (for v1)

- Not a replacement for the Tenable, Defender or Azure portals.
- No autonomous remediation. The model proposes, the human approves.
- No multi-tenant hosting. It runs locally on the operator's machine over stdio.
- It does not reuse or wrap any existing third-party or course-provided MCP server. All clients are written in this repo against the vendors' public REST APIs.

---

## 2. Architecture

```
┌────────────────────────┐        stdio (JSON-RPC)        ┌──────────────────────────────────────────┐
│ MCP client             │ ─────────────────────────────▶ │ vulnops-mcp  (Python, MCP SDK MCPServer)│
│ Claude Desktop / Code  │ ◀───────────────────────────── │                                          │
└────────────────────────┘                                │  tools/      tool definitions (thin)     │
                                                          │  workflows/  scan→triage→fix→verify      │
                                                          │  safety.py   write guard + confirmation  │
                                                          │  audit.py    JSONL audit log             │
                                                          │  auth.py     credential providers        │
                                                          │  clients/    one async client per API    │
                                                          └───────┬──────────┬──────────┬──────────┬─┘
                                                                  │          │          │          │
                                                    Azure ARM ◀───┘          │          │          └──▶ Log Analytics / Sentinel
                                              management.azure.com           │          │               api.loganalytics.io + ARM
                                                                   Tenable ◀─┘          └──▶ Defender for Endpoint
                                                              cloud.tenable.com              api.securitycenter.microsoft.com
```

### 2.1 Layers

| Layer | Responsibility | Rules |
|---|---|---|
| `server.py` | Builds the `MCPServer`, registers tool modules, wires lifespan (clients and config). | No business logic. |
| `tools/` | One module per service plus `meta.py`. Each tool validates input, calls a client or workflow, and shapes the output. | Thin. Every tool has a docstring the model will read. Writes go through `safety.require_write()`. |
| `workflows/` | Multi-service logic: correlate Tenable and Defender findings, build a remediation plan, diff before and after scans. | Pure functions where possible, so they are easy to unit test. |
| `clients/` | Async `httpx` clients, one per API. Handle auth headers, paging, retries, throttling (429 / `Retry-After`) and error mapping. | No MCP imports. Return typed models. |
| `auth.py` | Gets tokens: `azure-identity` for Microsoft APIs, API keys for Tenable. | Secrets come only from the environment or `.env`. Never logged. |
| `config.py` | `pydantic-settings` model loaded from env and `.env`. | Fails fast with a clear message when a required setting is missing. |
| `safety.py` / `audit.py` | Write gating, resource-group allow-list, confirmation tokens, audit trail. | Unit tested to 100%. |

### 2.2 Technology choices

| Choice | Decision | Why |
|---|---|---|
| Language | Python 3.12+ | Best Azure and security tooling ecosystem; official MCP SDK. |
| MCP SDK | `mcp` 2.x (`mcp.server.mcpserver.MCPServer`) | Official SDK. Decorator-based tools with typed signatures produce JSON schemas automatically. |
| HTTP | `httpx` (async) | One client style for all four APIs; easy to mock with `respx`. |
| Azure auth | `azure-identity` | One library covers service principal, Azure CLI login and managed identity. |
| Config | `pydantic-settings` | Typed env config with validation. |
| Package and env manager | `uv` | Fast, lockfile, works on Windows. |
| Quality | `ruff` (lint and format), `mypy` (types), `pytest` with `pytest-asyncio`, `respx`, `pytest-cov` | Standard, fast, CI-friendly. |
| Transport and hosting | Local process over stdio (agreed) | See 2.3. |

### 2.3 Hosting decision: local vs hosted (agreed: local)

| | Local stdio (chosen) | Hosted (HTTP, e.g. Azure Container Apps) |
|---|---|---|
| Auth | Reuses the operator's `az login` directly | Needs a service principal or managed identity plus OAuth in front of the MCP endpoint |
| Attack surface | No open ports; only the operator's client can call it | Public endpoint that must be secured and monitored |
| Approval model | The operator is the one approving every write | Must map approvals to whichever user is calling |
| Cost and setup | None | Container, identity, secrets store, TLS |
| Trade-off | Runs only while the operator's machine is on | Always available, shareable |

Local fits a single operator in a lab, keeps the "every write is approved by me" rule simple, and avoids storing Azure secrets anywhere. Hosting can be revisited after v1.0 (section 11).

---

## 3. Authentication design

All secrets live in a local `.env` (git-ignored) or the OS environment. `.env.example` documents every key with no values.

### 3.1 Microsoft APIs (Azure ARM, Defender, Log Analytics)

**Decision (D1, agreed):** the server authenticates as the operator, using their own `az login` session via `azure-identity`'s `AzureCliCredential`. No service principal and no client secret. Calls run with exactly the operator's own Azure RBAC and Defender permissions, so the server can never do more than the operator could in the portal.

One `AzureCliCredential` is created at startup and reused, with a different scope per API:

| API | Token scope |
|---|---|
| Azure Resource Manager (VMs, Sentinel incidents) | `https://management.azure.com/.default` |
| Defender for Endpoint | `https://api.securitycenter.microsoft.com/.default` |
| Log Analytics (KQL) | `https://api.loganalytics.io/.default` |

Operator setup: `az login` before starting the MCP client. The subscriptions to manage are listed in `AZURE_SUBSCRIPTION_IDS` (comma-separated, more than one is supported), so the server does not depend on the CLI's default subscription. When the CLI session expires, tools return an `AuthError` that says to run `az login` again.

Known risk, verified at CP2 by `vulnops_whoami`: the Azure CLI's first-party app may not be consented for the Defender for Endpoint API (`api.securitycenter.microsoft.com`) in the range tenant, so the token request or the first call can fail (typically `AADSTS65001` consent required, or a 401/403). Fallbacks, in order:

1. Read Defender data from the Advanced Hunting tables (`DeviceTvmSoftwareVulnerabilities`, `DeviceInfo`, ...) in Log Analytics, if Defender is connected to Sentinel. This keeps the az login model.
2. Ask the range admins for an app registration with the Defender permissions (`Machine.Read.All`, `Vulnerability.Read.All`, `AdvancedQuery.Read.All`, plus `Machine.Scan` / `Machine.Isolate` for writes) and add an optional `client_secret` auth mode for the Defender client only.
3. Leave the Defender tools disabled and run the loop with Tenable only; `vulnops_cross_check` then reports that Defender is unavailable.

### 3.2 Tenable Vulnerability Management

Header `X-ApiKeys: accessKey=…;secretKey=…` from `TENABLE_ACCESS_KEY` and `TENABLE_SECRET_KEY`. Base URL `TENABLE_BASE_URL` (default `https://cloud.tenable.com`). **Agreed:** the operator generates their own API keys (Tenable console → My Account → API Keys) and puts them in the local `.env`. Only empty placeholders are in `.env.example`. Keys are tied to the operator's own Tenable user, so scan permissions match what that user can do in the console. If the keys are missing or revoked, `vulnops_whoami` reports Tenable as not configured or shows the 401 verbatim.

### 3.3 Least privilege

- Because the server uses the operator's `az login`, it inherits the operator's permissions. It adds its own, stricter limits on top (section 4); it never widens them.
- Tenable keys belong to the operator's own Tenable user.

---

## 4. Safety model

LLM-driven tools that can run commands on a VM or isolate a machine need guard rails that do not depend on the model behaving well. **Agreed rule: read-only by default, and every write needs the user's explicit approval.**

1. **Read-only by default.** With `VULNOPS_ALLOW_WRITES=false` (the default) write tools are not registered, so the model cannot see them.
2. **Every write needs approval, two steps.** A write tool called without `confirm_token` does nothing and returns a preview: the exact action, target, and parameters, plus a single-use token that expires after 5 minutes. Only a second call with that token (after the user says yes in the client) executes. Tokens are bound to the tool name and a hash of the arguments, so a token cannot be reused for a different action.
3. **Writes covered by the approval rule:** Tenable scan create and launch; Azure run command, update install, OS disk snapshot, VM start, stop, restart and deallocate; Defender AV scan, isolate and unisolate; Sentinel incident comments and updates.
4. **Resource-group allow-list.** `VULNOPS_ALLOWED_RESOURCE_GROUPS` (comma-separated). VMs outside it are invisible to every tool and every action on them is refused.
5. **Honeypot skip.** VMs that are lab honeypots or decoys must never be scanned, changed or isolated by this tool. A VM is treated as a honeypot when its name matches `VULNOPS_HONEYPOT_NAME_PATTERNS` (glob list, default `*honeypot*,*hpot*,*decoy*`) or it has the tag `vulnops:skip=true` / `role=honeypot`. Read tools still list them, flagged `honeypot: true`; scan and write tools refuse them with a `SafetyRefusal`. Tenable scan targets are checked against the honeypots' IPs too.
6. **Snapshot before change.** Remediation workflows propose an OS disk snapshot (its own approved write) before updates or scripts.
7. **Command allow-list for run command.** Only scripts in `scripts/remediation/` (reviewed, versioned) can run, chosen by name. No free-form shell in v1.
8. **Audit log.** Every tool call, including previews and refusals, is appended to `logs/audit.jsonl` with timestamp, run ID, tool, sanitized args, outcome and duration. Secrets and tokens are redacted.
9. **Rate limiting and retries.** Clients respect `429` / `Retry-After` and back off exponentially (max 3 retries). Writes are never retried automatically.

---

## 5. Tool catalog (v1)

Naming: `<service>_<verb>_<noun>`, snake_case. **R** = read, **W** = write (gated by section 4).

### 5.1 Meta

| Tool | R/W | Purpose |
|---|---|---|
| `vulnops_server_info` | R | Version, enabled services, write mode, allowed resource groups, honeypot rules. |
| `vulnops_whoami` | R | Connectivity check and first checkpoint. Tests each service **separately**: ARM (token + list subscriptions), Log Analytics (token + `print 1` query), Defender (token for `api.securitycenter.microsoft.com` + `GET /api/machines?$top=1`), Tenable (keys + `GET /session`). Reports who you are signed in as and, per service, OK or the upstream error message **verbatim** (status code, error code, message) so consent and permission problems are obvious. |

### 5.2 Azure VMs (`azure_`)

| Tool | R/W | Purpose |
|---|---|---|
| `azure_list_vms` | R | VMs in allowed resource groups: name, OS, size, power state, private IP, `honeypot` flag. |
| `azure_get_vm` | R | Details for one VM, including OS image and extensions. |
| `azure_get_update_assessment` | R | Trigger or read Azure Update Manager assessment: missing patches by classification. |
| `azure_install_updates` | W | Install patches by classification or KB, with reboot policy. Long-running; returns an operation ID. |
| `azure_run_remediation_script` | W | Run an allow-listed script from `scripts/remediation/` via Run Command. |
| `azure_snapshot_os_disk` | W | Snapshot the OS disk before a change. |
| `azure_start_vm` / `azure_stop_vm` / `azure_restart_vm` / `azure_deallocate_vm` | W | VM power actions. |
| `azure_get_operation_status` | R | Poll a long-running ARM operation. |

### 5.3 Tenable (`tenable_`)

| Tool | R/W | Purpose |
|---|---|---|
| `tenable_list_scanners` | R | Scanners available to the user (cloud or internal). |
| `tenable_list_templates` | R | Scan templates (for example Basic Network Scan, Advanced Network Scan). |
| `tenable_list_scans` | R | Existing scans and last status. |
| `tenable_create_scan` | W | Create a scan for given targets, template, scanner and optional credentials. |
| `tenable_launch_scan` | W | Launch a scan. |
| `tenable_get_scan_status` | R | Status and progress of a running scan. |
| `tenable_get_scan_results` | R | Findings summarized by severity, host and plugin, with paging. |
| `tenable_get_host_findings` | R | Findings for one host in a scan, including plugin output and solution. |
| `tenable_export_vulns` | R | Workbench / export API: vulnerabilities for an asset across scans. |

### 5.4 Defender for Endpoint (`defender_`)

| Tool | R/W | Purpose |
|---|---|---|
| `defender_list_machines` | R | Onboarded machines: name, OS, health, risk and exposure level. |
| `defender_get_machine` | R | One machine by name or ID. |
| `defender_get_machine_vulnerabilities` | R | TVM vulnerabilities (CVE, severity, exploit available) for a machine. |
| `defender_get_software_inventory` | R | Installed software and versions (finds the vulnerable package). |
| `defender_get_recommendations` | R | Security recommendations for a machine. |
| `defender_advanced_hunting` | R | Run a KQL query in Advanced Hunting (row limit enforced). |
| `defender_run_av_scan` | W | Quick or full AV scan. |
| `defender_isolate_machine` / `defender_unisolate_machine` | W | Network isolation for containment. |

### 5.5 Sentinel / Log Analytics (`sentinel_`)

| Tool | R/W | Purpose |
|---|---|---|
| `sentinel_query_logs` | R | KQL over the Log Analytics workspace, with a time range and row limit. |
| `sentinel_list_incidents` | R | Incidents filtered by status, severity and time. |
| `sentinel_get_incident` | R | One incident with alerts and entities. |
| `sentinel_add_incident_comment` | W | Record remediation evidence on an incident. |
| `sentinel_update_incident` | W | Change status, severity or owner; close with a classification. |

### 5.6 Workflow tools and prompts (`vulnops_`)

| Tool / prompt | R/W | Purpose |
|---|---|---|
| `vulnops_cross_check` | R | Compare Tenable and Defender for the same host: found by both, Tenable only, Defender only. Highlights blind spots in either tool. |
| `vulnops_prioritize` | R | Merge Tenable and Defender findings for a host, de-duplicate by CVE, and rank by CVSS / VPR, exploit availability and exposure. Output: a prioritized list with a recommended fix per item. |
| `vulnops_plan_remediation` | R | Turn triage output into an ordered plan: patch classification, script or manual step, reboot needed, risk. |
| `vulnops_verify_remediation` | R | Compare before and after scans (and Defender state): fixed, still open, new. |
| `vulnops_generate_report` | R | Markdown report: scope, findings, actions taken, verification, residual risk. |
| Prompt `vuln_cycle` | n/a | Guides the model through the full loop with approval points. |

---

## 6. End-to-end workflow: scan → triage → remediate → verify

```
 1. Scope        azure_list_vms ─────────────────▶ choose target VM(s) in allowed RGs (honeypots skipped)
 2. Scan         tenable_create_scan → tenable_launch_scan  ◀── approval (each)
                 → tenable_get_scan_status (poll)
 3. Collect      tenable_get_scan_results + defender_get_machine_vulnerabilities
 4. Triage       vulnops_cross_check + vulnops_prioritize ─▶ prioritized, de-duplicated findings
 5. Plan         vulnops_plan_remediation ───────▶ HUMAN REVIEW  ◀── approval point 1
 6. Protect      azure_snapshot_os_disk           ◀── approval
 7. Remediate    azure_install_updates / azure_run_remediation_script  ◀── approval point 2
 8. Restart      azure_restart_vm (if required)   ◀── approval
 9. Verify       tenable_launch_scan (rescan)     ◀── approval
                 → vulnops_verify_remediation
10. Evidence     sentinel_query_logs (update and run-command events) + sentinel_add_incident_comment  ◀── approval
11. Report       vulnops_generate_report ────────▶ reports/<date>-<vm>.md
```

Each run gets a `run_id` stored in the audit log, so every tool call in one cycle can be traced afterwards.

---

## 7. Data shaping and errors

- **Compact output.** Tools return the fields needed to decide the next step, plus IDs for follow-up calls. Large lists are paged (`limit`, `offset`, default 50) and say how many remain.
- **Typed models.** Pydantic models per resource (`Vm`, `Finding`, `Machine`, `Incident`). Tools return `model_dump()` dicts, so the MCP SDK produces structured output.
- **Errors.** Clients raise `VulnOpsError` subclasses (`AuthError`, `PermissionDenied`, `NotFound`, `RateLimited`, `UpstreamError`, `SafetyRefusal`). Tools convert them into a clear message with a hint ("403 from Defender: the app lacks `Vulnerability.Read.All`").

---

## 8. Testing strategy

| Level | What | Tools | Gate |
|---|---|---|---|
| Unit | config, safety, audit, data shaping, workflows | `pytest` | Always in CI |
| Client contract | each client against recorded or handwritten API responses | `respx` mocks, fixtures in `tests/fixtures/` | Always in CI |
| Tool | tools registered, schemas valid, call through `MCPServer.call_tool` with mocked clients | `pytest-asyncio` | Always in CI |
| Live smoke | `vulnops_whoami` and read-only tools against the real lab | `pytest -m live` | Manual only, never in CI |
| End-to-end | full loop on one lab VM | manual, recorded in the report | Final checkpoint |

Coverage: at least 80% overall, 100% for `safety.py` and `audit.py`.

---

## 9. Checkpoints

A checkpoint is a go/no-go gate. Work does not move to the next phase until its checkpoint passes. Each one is also listed in `PhasedSolutionPlan.md` with its exact verification steps.

| # | Checkpoint | Pass criteria |
|---|---|---|
| CP0 | Design approved | This document reviewed; tool catalog and safety model agreed. |
| CP1 | Scaffolding complete | Repo initialized; `uv sync`, `ruff check`, `mypy`, `pytest` all pass locally; CI workflow present; scaffolding committed. |
| CP2 | Connectivity (whoami) and foundations | Server starts in Claude Desktop using the operator's `az login`. `vulnops_whoami` tests ARM, Log Analytics, Defender and Tenable separately and returns OK for each, or a verbatim error that is understood and has a chosen fallback recorded in the plan. Safety and audit at 100% coverage. |
| CP3 | Azure VM tools | Lists lab VMs, reads the update assessment; write tools show a preview and only run with a confirm token; RG allow-list and honeypot skip enforced. |
| CP4 | Tenable tools | Create, launch and poll a scan of one lab VM from the client; results summarized by severity. |
| CP5 | Defender tools | Machine and vulnerability list for the same VM; one Advanced Hunting query returns rows. |
| CP6 | Sentinel tools | KQL query returns update / run-command events; a test incident gets a comment. |
| CP7 | Workflow loop | One full scan → triage → remediate → verify cycle on a lab VM, with at least one finding verified fixed, plus a generated report. |
| CP8 | Release v1.0 | Docs complete, all CI green, tagged `v1.0.0`. |

---

## 10. Risks and mitigations

| Risk | Impact | Mitigation |
|---|---|---|
| Defender API not consented for Azure CLI tokens in the range tenant | Defender tools unusable | `vulnops_whoami` surfaces the exact error at CP2; fall back to Advanced Hunting tables via Log Analytics, or an app registration for Defender only (section 3.1). |
| Tenable API keys missing, expired or regenerated | Tenable tools fail with 401 | Operator generates their own keys; `vulnops_whoami` reports the 401 verbatim; regenerate and update `.env`. |
| Model triggers a destructive action | Lab outage | Read-only default, approval on every write, allow-list, snapshot first. |
| A honeypot VM gets scanned or changed | Breaks the lab exercise or alerts other teams | Honeypot skip by name pattern and tag, checked on VM IDs and on Tenable target IPs. |
| `az login` session expires mid-run | Calls fail with 401 | Clear `AuthError` telling the operator to run `az login`; no silent retry. |
| Tenable scans are slow (minutes to hours) | Long conversations stall | Async pattern: launch returns immediately; a status tool polls. |
| API throttling | Failed calls mid-workflow | Retry with backoff, page sizes, row limits on KQL. |
| Secrets leaked to git or logs | Credential compromise | `.env` git-ignored, `.env.example` only, redaction in the audit logger, secret scanning in CI (`gitleaks`). |
| API changes (Defender endpoint migration to `api.security.microsoft.com`) | Broken calls | Base URLs configurable; contract tests pin expected shapes. |

---

## 11. Decisions

| # | Decision | Status |
|---|---|---|
| D1 | Azure auth | **Agreed:** operator's own `az login` via `AzureCliCredential`. No service principal. |
| D2 | Hosting | **Agreed:** local stdio. Revisit hosted after v1.0. |
| D3 | Write policy | **Agreed:** read-only default; every write needs explicit approval through the confirm token. |
| D4 | Language | **Agreed:** Python 3.12+ with the official MCP SDK. |
| D8 | Tenable auth | **Agreed:** operator's own API keys in local `.env`; placeholders only in `.env.example`. |
| D5 | Tenable credentialed scans | Open. Non-credentialed first; credentialed in Phase 4 if allowed. |
| D6 | Remediation script set | Open. Start with Windows Update and a few registry hardening scripts. |
| D7 | GitHub hosting for the repo | Open. Local git repo for now; push to GitHub later so CI runs. |
