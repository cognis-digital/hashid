"""HASHID MCP server -- exposes analyze() as an MCP tool for Cognis.Studio."""
from __future__ import annotations
import json
from hashid.core import analyze


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
        """Identify hash type and estimate crack feasibility. Returns JSON."""
        return json.dumps(analyze(target), indent=2)

    app.run()
    return 0
