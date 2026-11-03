
"""
Pentest Master - Autonomous Tool Selection Test v1.

Tests whether GLM can:
1. Understand a task written in natural language.
2. Choose the appropriate local Kali tool.
3. Call MCP through Harness.
4. Read the real Bubblewrap Executor result.

No target network traffic.
No shell execution.
No changes to Scheduler or database structure.
"""

import getpass
import json
import re
import uuid
from pathlib import Path

from deepseek_harness import DeepSeekHarness


ROOT = Path("/home/lucky/pentest-master")

DSH_HOME = ROOT / "runtime/harness-home"
WORKSPACE = ROOT / "runtime/workspace"

PROVIDER = "experiential"
MODEL = "glm-5.3-uncensored"

TASK_ID = 7
ARTIFACT = "test.txt"

EXPECTED_MCP_TOOL = (
    "mcp__pentest_master__run_local_tool"
)


TEST_CASES = [
    {
        "name": "File identification",
        "request": (
            "Определи реальный тип файла test.txt "
            "в рабочей области исполнителя."
        ),
        "expected_tool": "file",
    },
    {
        "name": "File integrity",
        "request": (
            "Вычисли SHA-256 файла test.txt "
            "и сообщи полученный хеш."
        ),
        "expected_tool": "sha256sum",
    },
]


SYSTEM_INSTRUCTIONS = """
You are a specialized analysis agent in Pentest Master.

This is a local tool selection test.

Your task is to choose an appropriate installed tool
for the user's request and execute it through the
existing MCP tool:

mcp__pentest_master__run_local_tool

Tool arguments:
- task_id: 7
- artifact: test.txt
- tool_name: choose the correct tool profile.

Available relevant profiles include:
file, sha256sum, strings, readelf,
objdump, xxd, nm, exiftool.

Use the actual tool result, not a guessed result.

Important restrictions:
- Do not use shell tools.
- Do not call other MCP tools.
- Do not use network access.
- Do not change files.
- Do not invent execution results.
- Make exactly one MCP tool call per task.

After receiving the tool result,
answer the user's request in Russian.
"""


def get_events(result):
    calls = []
    tool_results = []

    for event in result.events:
        event_type = event.get("type")
        data = event.get("data") or {}

        if event_type == "tool/call":
            calls.append({
                "name": data.get("name"),
                "call_id": data.get("callId"),
                "arguments": data.get("arguments"),
            })

        elif event_type == "tool/result":
            message = data.get("message") or {}

            tool_results.append({
                "call_id": message.get("toolCallId"),
                "message": message,
            })

        elif event_type == "turn/end":
            print("[TURN END]", data, flush=True)

    return calls, tool_results


def decode_arguments(value):
    if isinstance(value, dict):
        return value

    if isinstance(value, str):
        parsed = json.loads(value)

        if isinstance(parsed, dict):
            return parsed

    raise RuntimeError(
        "Tool call arguments are not a JSON object"
    )


def decode_tool_result(message):
    if message.get("isError"):
        raise RuntimeError(
            "MCP returned a tool error"
        )

    for item in message.get("content") or []:
        if item.get("type") != "text":
            continue

        try:
            payload = json.loads(
                item.get("text", "")
            )
        except (ValueError, TypeError):
            continue

        if (
            isinstance(payload, dict)
            and "status" in payload
        ):
            return payload

    raise RuntimeError(
        "No structured Executor result found"
    )


def validate_result(
    result,
    expected_tool,
):
    if result.finish_reason != "completed":
        print(
            "[MODEL RESPONSE]",
            result.final_response or "(empty)",
        )

        raise RuntimeError(
            f"Harness ended with: {result.finish_reason}"
        )

    calls, results = get_events(result)

    print(
        "[TOOL CALLS]",
        [call["name"] for call in calls],
    )

    if len(calls) != 1:
        raise RuntimeError(
            f"Expected one call, received {len(calls)}"
        )

    if len(results) != 1:
        raise RuntimeError(
            f"Expected one result, received {len(results)}"
        )

    call = calls[0]
    tool_result = results[0]

    if call["name"] != EXPECTED_MCP_TOOL:
        raise RuntimeError(
            f"Unexpected MCP tool: {call['name']}"
        )

    if (
        not call["call_id"]
        or call["call_id"] != tool_result["call_id"]
    ):
        raise RuntimeError(
            "Tool call/result ID mismatch"
        )

    arguments = decode_arguments(
        call["arguments"]
    )

    print(
        "[CHOSEN TOOL]",
        arguments.get("tool_name"),
    )

    print(
        "[ARGUMENTS]",
        json.dumps(
            arguments,
            ensure_ascii=False,
        ),
    )

    if arguments.get("task_id") != TASK_ID:
        raise RuntimeError(
            "Incorrect task ID"
        )

    if arguments.get("artifact") != ARTIFACT:
        raise RuntimeError(
            "Incorrect artifact"
        )

    if arguments.get("tool_name") != expected_tool:
        raise RuntimeError(
            "Agent selected an unexpected tool"
        )

    payload = decode_tool_result(
        tool_result["message"]
    )

    print(
        "[EXECUTOR STATUS]",
        payload.get("status"),
    )

    print(
        "[EXECUTOR OUTPUT]",
        payload.get("stdout", "").strip(),
    )

    if payload.get("status") != "completed":
        raise RuntimeError(
            "Executor did not complete successfully"
        )

    if payload.get("exit_code") != 0:
        raise RuntimeError(
            "Nonzero Executor exit code"
        )

    if payload.get("tool") != expected_tool:
        raise RuntimeError(
            "Executed tool does not match selected tool"
        )

    if payload.get("task_id") != TASK_ID:
        raise RuntimeError(
            "Executor reported a different task ID"
        )

    if payload.get("artifact") != ARTIFACT:
        raise RuntimeError(
            "Executor reported a different artifact"
        )

    if payload.get("sandbox") != "bubblewrap":
        raise RuntimeError(
            "Unexpected sandbox"
        )

    if payload.get("network") != "disabled":
        raise RuntimeError(
            "Network isolation flag is missing"
        )

    stdout = payload.get("stdout", "")

    if expected_tool == "file":
        if "ASCII text" not in stdout:
            raise RuntimeError(
                "Unexpected file identification result"
            )

    elif expected_tool == "sha256sum":
        if not re.search(
            r"\b[0-9a-fA-F]{64}\b",
            stdout,
        ):
            raise RuntimeError(
                "Missing SHA-256 digest"
            )

    answer = (
        result.final_response or ""
    ).strip()

    if not answer:
        raise RuntimeError(
            "Agent produced no final answer"
        )

    print(
        "\n[AGENT RESPONSE]\n",
        answer[:2000],
    )

    print(
        "\n[PASS] Correct tool selected and executed"
    )


def main():
    api_key = getpass.getpass(
        "Experiential API key: "
    ).strip()

    if not api_key:
        raise SystemExit(
            "API key is required"
        )

    with DeepSeekHarness(
        profile="sdk-minimal",
        dsh_home=str(DSH_HOME),
        cwd=str(WORKSPACE),
        provider=PROVIDER,
        model=MODEL,
        api_key=api_key,
        max_tokens=1800,
        request_timeout_seconds=120,
    ) as harness:

        for index, case in enumerate(
            TEST_CASES, 1
        ):
            print()
            print("=" * 55)
            print(
                f"[TEST {index}]",
                case["name"],
            )

            print(
                "[USER TASK]",
                case["request"],
            )

            session_id = (
                "tool-selection-"
                + uuid.uuid4().hex[:12]
            )

            session = harness.start_session(
                session_id
            )

            prompt = (
                SYSTEM_INSTRUCTIONS
                + "\n\nUser request:\n"
                + case["request"]
            )

            result = session.run(prompt)

            validate_result(
                result,
                case["expected_tool"],
            )

    print()
    print("=" * 55)
    print(
        "[SUCCESS] Autonomous tool selection verified"
    )


if __name__ == "__main__":
    main()
