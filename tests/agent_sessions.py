
import getpass
import uuid
from pathlib import Path

from deepseek_harness import DeepSeekHarness

ROOT = Path("/home/lucky/pentest-master")
MODEL = "glm-5.3-uncensored"
API_URL = "https://api.experientiallabs.ai/v1"

api_key = getpass.getpass("Experiential API key: ").strip()

if not api_key:
    raise SystemExit("API key is required")

# Two independent agent sessions for a safe SDK test.
run_id = uuid.uuid4().hex[:8]

agents = {
    "recon": {
        "session_id": f"recon-{run_id}",
        "prompt": (
            "You are Recon Agent. This is a simulation only. "
            "Your mission is to organize reconnaissance findings. "
            "No target access is available. "
            "Introduce your role in one short Russian sentence. "
            "Do not use tools."
        ),
    },
    "vuln": {
        "session_id": f"vuln-{run_id}",
        "prompt": (
            "You are Vulnerability Analysis Agent. "
            "This is a simulation only. "
            "Your mission is to analyze supplied evidence. "
            "Introduce your role in one short Russian sentence. "
            "Do not use tools."
        ),
    },
}

with DeepSeekHarness(
    profile="sdk-minimal",
    dsh_home=str(ROOT / "runtime/harness-home"),
    cwd=str(ROOT / "runtime/workspace"),
    provider="deepseek-official",
    model=MODEL,
    base_url=API_URL,
    api_key=api_key,
    max_tokens=512,
    request_timeout_seconds=90,
) as harness:

    for name, config in agents.items():
        print(f"\n[START] {name}", flush=True)

        session = harness.start_session(config["session_id"])
        result = session.run(config["prompt"])

        print("Session:", config["session_id"])
        print("Status:", result.finish_reason)
        print("Response:", result.final_response)

        if result.finish_reason != "completed":
            for event in result.events:
                if event.get("type") == "turn/end":
                    print("Error:", event.get("data"))
            raise RuntimeError(f"Agent {name} failed")

        print(f"[DONE] {name}", flush=True)

    # Continue the original recon conversation.
    print("\n[RESUME TEST] Recon Agent", flush=True)

    session = harness.start_session(
        agents["recon"]["session_id"]
    )

    result = session.run(
        "What role were you assigned earlier? "
        "Reply in one short Russian sentence. "
        "Do not use tools."
    )

    print("Status:", result.finish_reason)
    print("Response:", result.final_response)

    if result.finish_reason != "completed":
        raise RuntimeError("Session continuation failed")

print("\n[SUCCESS] Agent sessions test completed")
