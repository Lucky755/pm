
"""
Pentest Master - Network Executor MCP Integration Test.

Tests:
1. All nine MCP methods registered.
2. Network profile discovery.
3. Authorized Nmap command planning.
4. Out-of-scope destination rejection.
5. Invalid TCP port rejection.
6. Documentation-address live execution blocked.

No external network probes are performed.
"""

import asyncio
import json
from pathlib import Path

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


ROOT = Path("/home/lucky/pentest-master")

PARAMS = StdioServerParameters(
    command=str(ROOT / ".venv/bin/python"),
    args=[str(ROOT / "mcp/server.py")],
    cwd=str(ROOT),
)

REQUIRED = {
    "list_workspace",
    "workspace_test",
    "execute_approved_demo",
    "list_available_tools",
    "run_local_tool",
    "list_tool_profiles_v3",
    "run_local_tool_v3",
    "list_network_profiles",
    "run_network_probe",
}


def decode(result):
    for item in result.content:
        if item.type != "text":
            continue

        try:
            value = json.loads(item.text)

            if isinstance(value, dict):
                return value

        except ValueError:
            continue

    raise RuntimeError(
        "No structured MCP response"
    )


async def invoke(session, name, arguments):
    result = await session.call_tool(
        name,
        arguments=arguments,
    )

    return decode(result)


async def test():
    async with stdio_client(PARAMS) as (
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
                item.name for item in listing.tools
            }

            missing = REQUIRED - names

            if missing:
                raise RuntimeError(
                    f"Missing MCP methods: {sorted(missing)}"
                )

            print(
                "[PASS] All 9 MCP methods registered"
            )

            profiles = await invoke(
                session,
                "list_network_profiles",
                {},
            )

            if profiles.get("status") != "completed":
                raise RuntimeError(
                    "Network profile listing failed"
                )

            profile_names = {
                item["profile"]
                for item in profiles["profiles"]
            }

            if profile_names != {
                "tcp_ports",
                "http_headers",
            }:
                raise RuntimeError(
                    "Unexpected network profiles"
                )

            print(
                "[PASS] Network profiles discovered"
            )

            planned = await invoke(
                session,
                "run_network_probe",
                {
                    "task_id": 7,
                    "profile": "tcp_ports",
                    "target": "192.0.2.10",
                    "ports": "22,80,443",
                    "execute": False,
                },
            )

            if planned.get("status") != "planned":
                raise RuntimeError(
                    f"Planning failed: {planned}"
                )

            argv = planned.get("argv", [])

            if (
                "-p" not in argv
                or "22,80,443" not in argv
                or "192.0.2.10" not in argv
            ):
                raise RuntimeError(
                    "Unexpected Nmap plan"
                )

            print(
                "[PASS] Authorized Nmap plan"
            )

            blocked = await invoke(
                session,
                "run_network_probe",
                {
                    "task_id": 7,
                    "profile": "http_headers",
                    "target": "198.51.100.20",
                    "port": 8080,
                    "execute": False,
                },
            )

            if blocked.get("status") != "blocked":
                raise RuntimeError(
                    "Out-of-scope target not blocked"
                )

            print(
                "[PASS] Out-of-scope target blocked"
            )

            invalid = await invoke(
                session,
                "run_network_probe",
                {
                    "task_id": 7,
                    "profile": "http_headers",
                    "target": "192.0.2.10",
                    "port": 99999,
                    "execute": False,
                },
            )

            if invalid.get("status") != "blocked":
                raise RuntimeError(
                    "Invalid port not blocked"
                )

            print(
                "[PASS] Invalid TCP port blocked"
            )

            documentation = await invoke(
                session,
                "run_network_probe",
                {
                    "task_id": 7,
                    "profile": "tcp_ports",
                    "target": "192.0.2.10",
                    "ports": "22,80",
                    "execute": True,
                },
            )

            if documentation.get("status") != "blocked":
                raise RuntimeError(
                    "Documentation target live execution not blocked"
                )

            print(
                "[PASS] Documentation target live execution blocked"
            )

            print()
            print(
                "[SUCCESS] Network MCP integration verified"
            )


if __name__ == "__main__":
    asyncio.run(test())
