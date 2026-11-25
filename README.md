# vulnops-mcp

A custom [Model Context Protocol](https://modelcontextprotocol.io) server for vulnerability management in an Azure lab. It lets an MCP client (Claude Desktop or Claude Code) run the **scan → triage → remediate → verify → report** loop across:

- **Azure VMs** (Azure Resource Manager)
- **Tenable Vulnerability Management**
- **Microsoft Defender for Endpoint**
- **Microsoft Sentinel / Log Analytics**

It runs locally over stdio, signs in with your own `az login`, is read-only by default, and asks for your approval before every change.

- Design: [docs/SolutionDesign.md](docs/SolutionDesign.md)
- Plan and current status: [PhasedSolutionPlan.md](PhasedSolutionPlan.md)
- Agent rules: [CLAUDE.md](CLAUDE.md)

## Quick start (Windows PowerShell)

```powershell
# 1. Prerequisites: Python 3.12+, uv, Azure CLI
winget install astral-sh.uv
winget install Microsoft.AzureCLI

# 2. Install
cd $HOME\vulnops-mcp
uv sync

# 3. Configure
Copy-Item .env.example .env   # skip if you already have a .env
notepad .env                  # subscription, resource groups, Tenable keys

# 4. Sign in
az login --tenant <tenant-id>
az account set --subscription <subscription-id>

# 5. Run (normally your MCP client starts it for you)
uv run vulnops-mcp
```

## Claude Desktop config

Add to `%APPDATA%\Claude\claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "vulnops": {
      "command": "uv",
      "args": ["--directory", "C:\\Users\\<you>\\vulnops-mcp", "run", "vulnops-mcp"]
    }
  }
}
```

## Claude Code

```powershell
claude mcp add vulnops -- uv --directory C:\Users\<you>\vulnops-mcp run vulnops-mcp
```

## Development

```powershell
uv run ruff check .          # lint
uv run ruff format .         # format
uv run mypy                  # type check
uv run pytest --cov          # tests + coverage
uv build                     # build wheel/sdist
```
