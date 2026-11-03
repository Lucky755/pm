
"""
Pentest Master - Autonomous Tool Selection v3.1.

Tests autonomous selection of:
- Tool name
- Execution mode
- Effective numeric parameters

Accounts for Executor v3 defaults:
- strings minimum length: 4
- xxd maximum bytes: 256

Supports individual test selection to save API tokens.

Examples:
    python tests/test_agent_v3_selection.py --cases 2 3
    python tests/test_agent_v3_selection.py --cases 1 2 3
"""

import argparse
import getpass
import json
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

MCP_TOOL = "mcp__pentest_master__run_local_tool_v3"

# Defaults currently defined by tool_executor_v3.py.
EXECUTOR_DEFAULTS = {
    "strings": 4,
    "xxd": 256,
}


CASES = {
    1: {
        "name": "MIME identification",
        "request": (
            "Определи MIME-тип файла test.txt, "
            "а не просто его текстовое описание."
        ),
        "tool": "file",
        "mode": "mime",
        "limit": None,
        "expected_output": "text/plain",
    },
    2: {
        "name": "String extraction",
        "request": (
            "Найди в файле test.txt печатные ASCII-строки "
            "длиной минимум четыре символа."
        ),
        "tool": "strings",
        "mode": "ascii",
        "limit": 4,
        "expected_output": "sandbox test",
    },
    3: {
        "name": "Hex inspection",
        "request": (
            "Посмотри первые 64 байта файла test.txt "
            "в шестнадцатеричном виде."
        ),
        "tool": "xxd",
        "mode": "hex",
        "limit": 64,
        "expected_output": "73 61 6e 64",
    },
}


INSTRUCTIONS = """
You are an artifact analysis agent.

The user describes a file-analysis task in Russian.

Choose an appropriate tool profile, mode and parameters.

Use ONLY:

mcp__pentest_master__run_local_tool_v3

Available local analysis tools:
file, sha256sum, sha1sum, md5sum, strings, xxd,
readelf, objdump, nm, exiftool, stat, wc.

Relevant modes:
- file: type, mime
- strings: ascii
- xxd: hex

Important:
- strings defaults to minimum length 4.
- xxd defaults to maximum 256 bytes.
- Explicitly provide limit when a different value
  is required by the user.

Task context:
task_id = 7
artifact = test.txt

Make exactly ONE MCP execution call.

Do not use shell tools.
Do not contact network targets.
Do not modify files.
Do not call other tools.
Do not invent results.

After receiving the real tool result,
answer the user in Russian.
"""


def decode_arguments(value):
    if isinstance(value, dict):
        return value

    if isinstance(value, str):
        decoded = json.loads(value)

        if isinstance(decoded, dict):
            return decoded

    raise RuntimeError(
        "Tool call arguments are not a JSON object"
    )


def decode_executor_result(message):
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
        except (TypeError, ValueError):
            continue

        if (
            isinstance(payload, dict)
            and "status" in payload
        ):
            return payload

    raise RuntimeError(
        "MCP returned no structured Executor result"
    )


def extract_events(result):
    calls = []
    tool_results = []

    for event in result.events:
        event_type = event.get("type")
        data = event.get("data") or {}

        if event_type == "tool/call":
            calls.append({
                "name": data.get("name"),
                "id": data.get("callId"),
                "arguments": data.get("arguments"),
            })

        elif event_type == "tool/result":
            message = data.get("message") or {}

            tool_results.append({
                "id": message.get("toolCallId"),
                "message": message,
            })

        elif event_type == "turn/end":
            print(
                "[TURN END]",
                data,
                flush=True,
            )

    return calls, tool_results


def effective_limit(tool_name, arguments):
    """
    Resolve effective numeric limit based on
    the current Executor v3 implementation.

    A missing optional limit means that
    Executor uses its predefined default.

    This function must be updated if the
    Executor's defaults change.
    """

    value = arguments.get("limit")

    if value is None:
        return EXECUTOR_DEFAULTS.get(tool_name)

    if isinstance(value, bool) or not isinstance(value, int):
        raise RuntimeError(
            "Numeric limit must be an integer"
        )

    return value


def validate_arguments(arguments, case):
    if arguments.get("task_id") != TASK_ID:
        raise RuntimeError(
            "Incorrect task_id"
        )

    if arguments.get("artifact") != ARTIFACT:
        raise RuntimeError(
            "Incorrect artifact"
        )

    if arguments.get("tool_name") != case["tool"]:
        raise RuntimeError(
            "Agent selected the wrong tool"
        )

    if arguments.get("mode") != case["mode"]:
        raise RuntimeError(
            "Agent selected the wrong mode"
        )

    expected_limit = case["limit"]

    actual_limit = effective_limit(
        case["tool"],
        arguments,
    )

    print(
        "[EFFECTIVE LIMIT]",
        actual_limit,
    )

    if actual_limit != expected_limit:
        raise RuntimeError(
            f"Incorrect effective limit: "
            f"expected {expected_limit}, "
            f"received {actual_limit}"
        )

    if (
        expected_limit is not None
        and arguments.get("limit") is None
    ):
        print(
            "[DEFAULT ACCEPTED] "
            "Executor uses its configured default:",
            actual_limit,
        )


def validate_executor(payload, case, arguments):
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
            "Executor returned nonzero exit code"
        )

    if payload.get("task_id") != TASK_ID:
        raise RuntimeError(
            "Executor reported wrong task_id"
        )

    if payload.get("artifact") != ARTIFACT:
        raise RuntimeError(
            "Executor reported wrong artifact"
        )

    if payload.get("tool") != case["tool"]:
        raise RuntimeError(
            "Executor executed wrong tool"
        )

    if payload.get("mode") != case["mode"]:
        raise RuntimeError(
            "Executor executed wrong mode"
        )

    # Executor currently reports the supplied limit,
    # not the effective defaulted limit.
    if payload.get("limit") != arguments.get("limit"):
        raise RuntimeError(
            "Executor input limit mismatch"
        )

    if payload.get("sandbox") != "bubblewrap":
        raise RuntimeError(
            "Unexpected sandbox"
        )

    if payload.get("network") != "disabled":
        raise RuntimeError(
            "Network isolation flag is missing"
        )

    if payload.get("output_truncated"):
        raise RuntimeError(
            "Executor output was truncated"
        )

    stdout = payload.get("stdout", "")

    if case["expected_output"] not in stdout:
        raise RuntimeError(
            "Expected content missing from tool output"
        )


def verify(result, case):
    if result.finish_reason != "completed":
        print(
            "[MODEL RESPONSE]",
            result.final_response or "(empty)",
        )

        for event in result.events:
            if event.get("type") == "turn/end":
                print(
                    "[DIAGNOSTIC]",
                    event.get("data"),
                )

        raise RuntimeError(
            f"Harness failed: {result.finish_reason}"
        )

    calls, results = extract_events(result)

    print("[TOOL CALL COUNT]", len(calls))
    print("[TOOL RESULT COUNT]", len(results))

    if len(calls) != 1 or len(results) != 1:
        raise RuntimeError(
            "Exactly one tool call and result required"
        )

    call = calls[0]
    tool_result = results[0]

    if call["name"] != MCP_TOOL:
        raise RuntimeError(
            f"Unexpected tool: {call['name']}"
        )

    if (
        not call["id"]
        or call["id"] != tool_result["id"]
    ):
        raise RuntimeError(
            "Tool call/result identifiers do not match"
        )

    arguments = decode_arguments(
        call["arguments"]
    )

    print(
        "[CHOSEN ARGUMENTS]",
        json.dumps(
            arguments,
            ensure_ascii=False,
        ),
    )

    validate_arguments(
        arguments,
        case,
    )

    payload = decode_executor_result(
        tool_result["message"]
    )

    validate_executor(
        payload,
        case,
        arguments,
    )

    answer = (
        result.final_response or ""
    ).strip()

    if not answer:
        raise RuntimeError(
            "Agent returned an empty response"
        )

    print("\n[AGENT RESPONSE]")
    print(answer[:1500])

    print(
        "\n[PASS]",
        case["name"],
    )


def main():
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--cases",
        type=int,
        choices=sorted(CASES),
        nargs="+",
        default=[1, 2, 3],
        help="Test numbers to run; default is all",
    )

    args = parser.parse_args()

    selected_cases = list(
        dict.fromkeys(args.cases)
    )

    print(
        "[SELECTED TESTS]",
        selected_cases,
    )

    api_key = getpass.getpass(
        "Experiential API key: "
    ).strip()

    if not api_key:
        raise SystemExit(
            "API key required"
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

        for number in selected_cases:
            case = CASES[number]

            print("\n" + "=" * 60)
            print(
                f"[TEST {number}]",
                case["name"],
            )
            print(
                "[TASK]",
                case["request"],
            )

            session_id = (
                "v3-selection-"
                + uuid.uuid4().hex[:12]
            )

            session = harness.start_session(
                session_id
            )

            prompt = (
                INSTRUCTIONS
                + "\n\nUser request:\n"
                + case["request"]
            )

            result = session.run(prompt)

            verify(result, case)

    print("\n" + "=" * 60)
    print(
        "[SUCCESS] All selected v3 tests passed"
    )


if __name__ == "__main__":
    main()
