
"""
Pentest Master - OpenAI-compatible provider test.

Tests:
Python SDK -> pi-ai -> Experiential Labs -> GLM
and a real MCP tool call.

No shell execution or target network access.
"""

import getpass
import json
import uuid
from pathlib import Path

from deepseek_harness import DeepSeekHarness


ROOT = Path("/home/lucky/pentest-master")
DSH_HOME = ROOT / "runtime/harness-home"
WORKSPACE = ROOT / "runtime/workspace"

MODEL = "glm-5.3-uncensored"
PROVIDER = "experiential"

EXPECTED_TOOL = "mcp__pentest_master__list_workspace"


def inspect_result(result):
    print("\n=== RESULT ===")
    print("Status:", result.finish_reason)
    print("Response:", result.final_response or "(empty)")

    calls = []
    results = []

    for event in result.events:
        event_type = event.get("type", "")
        data = event.get("data") or {}

        if event_type == "tool/call":
            name = data.get("name", "")
            call_id = data.get("callId")

            calls.append((name, call_id))
            print("[TOOL CALL]", name)

        elif event_type == "tool/result":
            message = data.get("message") or {}
            call_id = message.get("toolCallId")

            results.append((call_id, message))
            print("[TOOL RESULT]", call_id)

        elif event_type == "turn/end":
            print("[TURN END]", data)

    if result.finish_reason != "completed":
        raise RuntimeError(
            f"Agent failed: {result.finish_reason}"
        )

    if len(calls) != 1:
        raise RuntimeError(
            f"Expected one tool call, got {len(calls)}"
        )

    if calls[0][0] != EXPECTED_TOOL:
        raise RuntimeError(
            f"Unexpected tool: {calls[0][0]}"
        )

    if len(results) != 1:
        raise RuntimeError(
            f"Expected one tool result, got {len(results)}"
        )

    if calls[0][1] != results[0][0]:
        raise RuntimeError("Tool call/result ID mismatch")

    message = results[0][1]

    if message.get("isError"):
        raise RuntimeError("MCP reported a tool error")

    successful = False

    for item in message.get("content") or []:
        if item.get("type") != "text":
            continue

        try:
            data = json.loads(item.get("text", ""))
        except (ValueError, TypeError):
            continue

        if (
            isinstance(data, dict)
            and data.get("status") == "completed"
            and data.get("exit_code") == 0
        ):
            successful = True

    if not successful:
        raise RuntimeError(
            "MCP did not return successful execution"
        )

    if not (result.final_response or "").strip():
        raise RuntimeError("Model returned an empty response")

    print("\n[SUCCESS] OpenAI provider + MCP working")


def main():
    api_key = getpass.getpass(
        "Experiential API key: "
    ).strip()

    if not api_key:
        raise SystemExit("API key required")

    session_id = (
        "pi-test-" + uuid.uuid4().hex[:12]
    )

    print("[1] Starting Harness...")
    print("Provider:", PROVIDER)
    print("Model:", MODEL)

    with DeepSeekHarness(
        profile="sdk-minimal",
        dsh_home=str(DSH_HOME),
        cwd=str(WORKSPACE),
        provider=PROVIDER,
        model=MODEL,
        api_key=api_key,
        max_tokens=1500,
        request_timeout_seconds=120,
    ) as harness:

        print("[2] Starting session:", session_id)

        session = harness.start_session(session_id)

        print("[3] Requesting MCP tool call")

        result = session.run(
            "This is a local MCP integration test. "
            "Call the tool "
            "mcp__pentest_master__list_workspace "
            "exactly once with empty arguments. "
            "Wait for the actual tool result. "
            "Then summarize the file names in Russian. "
            "Do not execute shell commands. "
            "Do not contact any network target. "
            "Do not call other tools."
        )

        inspect_result(result)


if __name__ == "__main__":
    main()
