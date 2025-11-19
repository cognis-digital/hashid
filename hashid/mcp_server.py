"""HASHID MCP server — exposes scan() as an MCP tool for Cognis.Studio."""
from __future__ import annotations
from hashid.core import scan, to_json

def serve() -> int:
    """Start an MCP stdio server. Requires the optional 'mcp' extra:
        pip install "cognis-hashid[mcp]"
    """
    try:
        from mcp.server.fastmcp import FastMCP
    except Exception:
        print("Install the MCP extra: pip install 'cognis-hashid[mcp]'")
        return 1
    app = FastMCP("hashid")

    @app.tool()
    def hashid_scan(target: str) -> str:
        """Identify hash types and estimate crack cost/feasibility. Returns JSON findings."""
        return to_json(scan(target))

    app.run()
    return 0
