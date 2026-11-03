
import getpass
import uuid
from pathlib import Path

from deepseek_harness import DeepSeekHarness

ROOT = Path("/home/lucky/pentest-master")
API_URL = "https://api.experientiallabs.ai/v1"
MODEL = "glm-5.3-uncensored"

api_key = getpass.getpass("Experiential API key: ").strip()

if not api_key:
    raise SystemExit("API key is required")

print("[1] Starting Harness SDK...")

with DeepSeekHarness(
    profile="sdk-minimal",
    dsh_home=str(ROOT / "runtime/harness-home"),
    cwd=str(ROOT / "runtime/workspace"),
    provider="deepseek-official",
    model=MODEL,
    base_url=API_URL,
    api_key=api_key,
    max_tokens=256,
    request_timeout_seconds=90,
) as harness:

    print("[2] Creating agent session...")

    result = harness.run(
        "Reply with exactly: SDK CONNECTION OK. "
        "Do not call tools or execute commands.",
        session_id=f"smoke-{uuid.uuid4().hex[:12]}",
    )

    print("[3] Finished")
    print("Finish reason:", result.finish_reason)
    print("Response:", result.final_response)
    print("Session ID:", result.session_id)
    print("\n[4] Diagnostic events:")

    for event in result.events:
        event_type = event.get("type", "")

        print("Event:", event_type)

        if "error" in event_type.lower() or event_type == "turn/end":
            print("Details:", event.get("data"))
