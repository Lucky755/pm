
import asyncio
from pathlib import Path

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

ROOT = Path("/home/lucky/pentest-master")

async def main():
    params = StdioServerParameters(
        command=str(ROOT / ".venv/bin/python"),
        args=[str(ROOT / "mcp/server.py")],
        cwd=str(ROOT),
    )

    async with stdio_client(params) as (reader, writer):
        async with ClientSession(reader, writer) as session:
            await session.initialize()

            tools = await session.list_tools()

            print("[CONNECTED] MCP Server")
            print("Available tools:")

            for tool in tools.tools:
                print("-", tool.name)

            result = await session.call_tool(
                "list_workspace",
                arguments={},
            )

            print("\n[TOOL RESULT]")

            for item in result.content:
                if item.type == "text":
                    print(item.text)

            if result.isError:
                raise RuntimeError("MCP tool failed")

    print("\n[SUCCESS] MCP connection test completed")


if __name__ == "__main__":
    asyncio.run(main())
