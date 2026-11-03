
"""
Pentest Master - MCP Tool Executor v3 Test.

Tests:
- MCP tool registration
- Available execution profiles
- MIME detection
- Strings extraction
- Bounded hex dump
- Invalid parameter blocking

No Experiential API key required.
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

REQUIRED_TOOLS = {
    "list_workspace",
    "workspace_test",
    "execute_approved_demo",
    "list_available_tools",
    "run_local_tool",
    "list_tool_profiles_v3",
    "run_local_tool_v3",
}


def extract_payload(result):
    if result.isError:
        raise RuntimeError(
            "MCP returned a protocol-level tool error"
        )

    for item in result.content:
        if item.type != "text":
            continue

        try:
            data = json.loads(item.text)
        except (ValueError, TypeError):
            continue

        if isinstance(data, dict):
            return data

    raise RuntimeError(
        "No structured JSON result received"
    )


async def call(
    session,
    tool,
    arguments,
):
    result = await session.call_tool(
        tool,
        arguments=arguments,
    )

    return extract_payload(result)


async def check_operation(
    session,
    name,
    parameters,
    expected,
):
    print("\n[TEST]", name)

    payload = await call(
        session,
        "run_local_tool_v3",
        parameters,
    )

    print(
        json.dumps(
            payload,
            ensure_ascii=False,
            indent=2,
        )
    )

    if payload.get("status") != expected:
        raise RuntimeError(
            f"Expected {expected}, got "
            f"{payload.get('status')}"
        )

    if expected == "completed":
        if payload.get("exit_code") != 0:
            raise RuntimeError(
                "Unexpected nonzero exit code"
            )

        if payload.get("sandbox") != "bubblewrap":
            raise RuntimeError(
                "Unexpected sandbox"
            )

        if payload.get("network") != "disabled":
            raise RuntimeError(
                "Network isolation not confirmed"
            )

    print("[PASS]", name)

    return payload


async def run_tests(task_id):
    params = StdioServerParameters(
        command=str(PYTHON),
        args=[str(SERVER)],
        cwd=str(ROOT),
    )

    async with stdio_client(params) as (
        read,
        write,
    ):
        async with ClientSession(
            read,
            write,
        ) as session:

            await session.initialize()

            listing = await session.list_tools()

            names = {
                tool.name
                for tool in listing.tools
            }

            print("[CONNECTED] MCP Server")
            print(
                "Available tools:",
                sorted(names),
            )

            missing = REQUIRED_TOOLS - names

            if missing:
                raise RuntimeError(
                    f"Missing MCP tools: {missing}"
                )

            catalog = await call(
                session,
                "list_tool_profiles_v3",
                {},
            )

            if catalog.get("status") != "completed":
                raise RuntimeError(
                    "Cannot retrieve Executor v3 profiles"
                )

            profiles = catalog.get("profiles", [])

            print(
                "[PROFILES]",
                len(profiles),
            )

            if len(profiles) != 12:
                raise RuntimeError(
                    "Expected 12 Executor v3 profiles"
                )

            mime = await check_operation(
                session,
                "MIME identification",
                {
                    "task_id": task_id,
                    "tool_name": "file",
                    "artifact": "test.txt",
                    "mode": "mime",
                },
                "completed",
            )

            if mime.get("stdout", "").strip() != "text/plain":
                raise RuntimeError(
                    "Incorrect MIME identification"
                )

            strings = await check_operation(
                session,
                "Strings extraction",
                {
                    "task_id": task_id,
                    "tool_name": "strings",
                    "artifact": "test.txt",
                    "mode": "ascii",
                    "limit": 4,
                },
                "completed",
            )

            if "sandbox test" not in strings.get(
                "stdout", ""
            ):
                raise RuntimeError(
                    "Expected text not found"
                )

            hex_result = await check_operation(
                session,
                "Hex inspection",
                {
                    "task_id": task_id,
                    "tool_name": "xxd",
                    "artifact": "test.txt",
                    "mode": "hex",
                    "limit": 64,
                },
                "completed",
            )

            if "73 61 6e 64" not in hex_result.get(
                "stdout", ""
            ):
                raise RuntimeError(
                    "Unexpected hex output"
                )

            blocked = await check_operation(
                session,
                "Invalid hex limit",
                {
                    "task_id": task_id,
                    "tool_name": "xxd",
                    "artifact": "test.txt",
                    "mode": "hex",
                    "limit": 999999,
                },
                "blocked",
            )

            if "limit" not in blocked.get(
                "error", ""
            ).lower():
                raise RuntimeError(
                    "Unexpected block reason"
                )

            print(
                "\n[SUCCESS] All Executor v3 MCP tests passed"
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
        run_tests(args.task_id)
    )


if __name__ == "__main__":
    main()
