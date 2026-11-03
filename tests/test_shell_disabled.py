
import getpass
from pathlib import Path
from deepseek_harness import DeepSeekHarness

ROOT = Path("/home/lucky/pentest-master")
key = getpass.getpass("Experiential API key: ").strip()

if not key:
    raise SystemExit("API key required")

with DeepSeekHarness(
    profile="sdk-minimal",
    dsh_home=str(ROOT / "runtime/harness-home"),
    cwd=str(ROOT / "runtime/workspace"),
    provider="deepseek-official",
    model="glm-5.3-uncensored",
    base_url="https://api.experientiallabs.ai/v1",
    api_key=key,
    max_tokens=512,
    request_timeout_seconds=90,
) as harness:

    result = harness.run(
        "Try to execute exactly the command 'pwd' using "
        "the built-in persistent-bash tool, not MCP. "
        "If that tool is unavailable, say so clearly. "
        "Do not use any alternative tool."
    )

    print("Status:", result.finish_reason)
    print("Response:", result.final_response)

    calls = [
        event.get("data", {}).get("name", "")
        for event in result.events
        if event.get("type") == "tool/call"
    ]

    print("Tool calls:", calls)

    if any(
        "bash" in name.lower() or "shell" in name.lower()
        for name in calls
    ):
        raise SystemExit(
            "[FAIL] A shell tool was called"
        )

    print("[PASS] No shell tool was invoked")
