
"""
Pentest Master - MCP Local Tool Integration Test.

Tests:
1. File type detection
2. SHA-256 calculation
3. Blocking outside-workspace paths

No API key required.
No network access to targets.
"""

import argparse
import asyncio
import json
from pathlib import Path

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


ROOT = Path("/home/lucky/pentest-master")
PYTHON = ROOT / ".venv/bin/python"
SERVER = ROOT / "mcp/server.py"

TOOL_NAME = "run_local_tool"


def extract_payload(result):
    for item in result.content:
        if item.type != "text":
            continue

        try:
            payload = json.loads(item.text)
        except (ValueError, TypeError):
            continue

        if (
            isinstance(payload, dict)
            and "status" in payload
        ):
            return payload

    raise RuntimeError(
        "MCP returned no structured result"
    )


async def test_operation(
    session,
    task_id,
    tool_name,
    artifact,
    expected_status,
):
    print()
    print("[TEST]", tool_name, artifact)

    result = await session.call_tool(
        TOOL_NAME,
        arguments={
            "task_id": task_id,
            "tool_name": tool_name,
            "artifact": artifact,
        },
    )

    payload = extract_payload(result)

    print(json.dumps(
        payload,
        ensure_ascii=False,
        indent=2,
    ))

    actual = payload["status"]

    if actual != expected_status:
        raise RuntimeError(
            f"Expected {expected_status}, got {actual}"
        )

    if expected_status == "completed":
        if payload.get("exit_code") != 0:
            raise RuntimeError(
                "Completed tool returned nonzero exit code"
            )

        if payload.get("network") != "disabled":
            raise RuntimeError(
                "Network isolation flag is missing"
            )

        if payload.get("sandbox") != "bubblewrap":
            raise RuntimeError(
                "Bubblewrap sandbox flag is missing"
            )

    print("[PASS]", tool_name, expected_status)

    return payload


async def main_async(task_id):
    parameters = StdioServerParameters(
        command=str(PYTHON),
        args=[str(SERVER)],
        cwd=str(ROOT),
    )

    async with stdio_client(parameters) as (
        read,
        write,
    ):
        async with ClientSession(
            read,
            write,
        ) as session:

            await session.initialize()

            tools = await session.list_tools()

            names = [
                item.name
                for item in tools.tools
            ]

            print("[CONNECTED] MCP Server")
            print("Available tools:", names)

            if TOOL_NAME not in names:
                raise RuntimeError(
                    "run_local_tool is not registered"
                )

            file_result = await test_operation(
                session,
                task_id,
                "file",
                "test.txt",
                "completed",
            )

            if "ASCII text" not in file_result.get(
                "stdout", ""
            ):
                raise RuntimeError(
                    "Unexpected file identification"
                )

            hash_result = await test_operation(
                session,
                task_id,
                "sha256sum",
                "test.txt",
                "completed",
            )

            if len(
                hash_result.get("stdout", "").split()[0]
            ) != 64:
                raise RuntimeError(
                    "SHA-256 output is invalid"
                )

            await test_operation(
                session,
                task_id,
                "file",
                "/etc/passwd",
                "blocked",
            )

            print()
            print(
                "[SUCCESS] All MCP tool execution "
                "tests passed"
            )


def main():
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--task-id",
        type=int,
        default=7,
    )

    args = parser.parse_args()

    asyncio.run(
        main_async(args.task_id)
    )


if __name__ == "__main__":
    main()
