
"""
Test one-time operator approvals through the MCP server.

Usage:
python tests/test_approval_mcp.py \
    --id APPROVAL_ID \
    --expect completed

or:

python tests/test_approval_mcp.py \
    --id APPROVAL_ID \
    --expect blocked
"""

import argparse
import asyncio
import json
from pathlib import Path

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


ROOT = Path("/home/lucky/pentest-master")

SERVER = ROOT / "mcp/server.py"
PYTHON = ROOT / ".venv/bin/python"

TOOL_NAME = "execute_approved_demo"


async def test_mcp(approval_id, expected_status):
    parameters = StdioServerParameters(
        command=str(PYTHON),
        args=[str(SERVER)],
        cwd=str(ROOT),
    )

    async with stdio_client(parameters) as (
        read,
        write,
    ):
        async with ClientSession(read, write) as session:
            await session.initialize()

            available = await session.list_tools()

            names = [
                tool.name
                for tool in available.tools
            ]

            print("[MCP] Available tools:")
            for name in names:
                print(" -", name)

            if TOOL_NAME not in names:
                raise RuntimeError(
                    "Approval tool was not registered"
                )

            print("\n[MCP] Calling:", TOOL_NAME)

            result = await session.call_tool(
                TOOL_NAME,
                arguments={
                    "approval_id": approval_id,
                },
            )

            payload = None

            for item in result.content:
                if item.type != "text":
                    continue

                try:
                    candidate = json.loads(item.text)
                except (ValueError, TypeError):
                    continue

                if (
                    isinstance(candidate, dict)
                    and "status" in candidate
                ):
                    payload = candidate
                    break

            if payload is None:
                raise RuntimeError(
                    "MCP returned no structured result"
                )

            print(
                "\n[MCP RESULT]",
                json.dumps(
                    payload,
                    ensure_ascii=False,
                    indent=2,
                ),
            )

            actual_status = payload["status"]

            if actual_status != expected_status:
                raise RuntimeError(
                    f"Expected {expected_status}, "
                    f"got {actual_status}"
                )

            if (
                expected_status == "completed"
                and payload["exit_code"] != 0
            ):
                raise RuntimeError(
                    "Completed operation had nonzero exit code"
                )

            if (
                expected_status == "blocked"
                and payload["exit_code"] == 0
            ):
                raise RuntimeError(
                    "Blocked operation had zero exit code"
                )

            print(
                "\n[PASS] MCP approval behavior verified"
            )


def main():
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--id",
        required=True,
    )

    parser.add_argument(
        "--expect",
        choices=["completed", "blocked"],
        required=True,
    )

    args = parser.parse_args()

    asyncio.run(
        test_mcp(
            args.id,
            args.expect,
        )
    )


if __name__ == "__main__":
    main()
