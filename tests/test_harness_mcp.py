
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
    max_tokens=1000,
    request_timeout_seconds=90,
) as harness:

    result = harness.run(
        "Call the tool named "
        "mcp__pentest_master__list_workspace "
        "to list files in the isolated workspace. "
        "Do not use the shell or any other tool. "
        "Report the actual result in Russian."
    )

    print("Status:", result.finish_reason)
    print("Response:", result.final_response)

    print("\nTool-related events:")
    for event in result.events:
        event_type = event.get("type", "")
        if "tool" in event_type.lower():
            print(event_type, str(event.get("data", ""))[:500])
        elif event_type == "turn/end":
            print(event_type, event.get("data"))
