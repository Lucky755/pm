"""Standalone MCP for scoped, metadata-only Pentest Master evidence.

Run as a registered MCP stdio server. Does not register automatically in the
existing Harness profile. Does not perform active target scanning.
"""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from mcp.server.fastmcp import FastMCP
from orchestrator.evidence_pipeline import connect, summary, load_burp

server = FastMCP('pentest-master-evidence-hub')


@server.tool()
def evidence_status(task_id: int) -> dict:
    """Get verified network observations and redacted Burp HTTP metadata."""
    with connect() as db:
        return summary(db, task_id)


@server.tool()
def evidence_sync_burp(task_id: int, limit: int = 50) -> dict:
    """Import scoped, metadata-only Burp Proxy History, no active target requests."""
    if not 1 <= limit <= 100:
        raise ValueError('limit must be 1..100')
    imported = load_burp().import_history(task_id, limit=limit)
    with connect() as db:
        return {'import': imported, 'evidence': summary(db, task_id)}


if __name__ == '__main__':
    server.run(transport='stdio')
