"""Entry point: ``vulnops-mcp`` or ``python -m vulnops_mcp`` (stdio transport)."""

from vulnops_mcp.server import build_server


def main() -> None:
    build_server().run(transport="stdio")


if __name__ == "__main__":
    main()
