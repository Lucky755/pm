"""Separate read-only Burp History MCP server for Pentest Master.

This runs only when explicitly started and does not modify mcp/server.py.
Requires Python package `mcp` in the project's virtual environment.
"""

from burp_import import health, import_history, list_history
from mcp.server.fastmcp import FastMCP

server = FastMCP("pentest-master-burp-history")

@server.tool()
def burp_bridge_status() -> dict:
    """Check whether the local, authenticated Burp Bridge is running."""
    return health()

@server.tool()
def burp_history_import(task_id: int, limit: int = 50) -> dict:
    """Import redacted Burp Proxy metadata for an authorized task's IPv4 target."""
    return import_history(task_id, limit=limit)

@server.tool()
def burp_history_observations(task_id: int, limit: int = 50) -> dict:
    """Read stored, scoped, metadata-only Burp HTTP observations from SQLite."""
    return list_history(task_id, limit=limit)

if __name__ == "__main__":
    server.run(transport="stdio")
