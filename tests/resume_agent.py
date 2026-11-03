
import getpass
from pathlib import Path

from deepseek_harness import DeepSeekHarness

ROOT = Path("/home/lucky/pentest-master")

# Recon session from the previous successful test.
SESSION_ID = "recon-27f7b79c"

api_key = getpass.getpass("Experiential API key: ").strip()

if not api_key:
    raise SystemExit("API key is required")

with DeepSeekHarness(
    profile="sdk-minimal",
    dsh_home=str(ROOT / "runtime/harness-home"),
    cwd=str(ROOT / "runtime/workspace"),
    provider="deepseek-official",
    model="glm-5.3-uncensored",
    base_url="https://api.experientiallabs.ai/v1",
    api_key=api_key,
    max_tokens=512,
    request_timeout_seconds=90,
) as harness:

    print("[1] Restoring session:", SESSION_ID)

    session = harness.resume_session(SESSION_ID)

    print("[2] Sending continuation prompt...")

    result = session.run(
        "Вспомни свою роль из предыдущего разговора. "
        "Какую роль тебе назначили? "
        "Ответь одним предложением по-русски. "
        "Не используй инструменты."
    )

    print("Status:", result.finish_reason)
    print("Response:", result.final_response)

    if result.finish_reason != "completed":
        for event in result.events:
            if event.get("type") == "turn/end":
                print("Error:", event.get("data"))
        raise SystemExit(1)

print("[SUCCESS] Session restored")
