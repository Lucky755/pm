
"""
Pentest Master - Network Agent Phase v1.

GLM -> Harness -> MCP -> Network Executor -> SQLite.

The agent chooses network profiles and parameters.
Only validated PLANNED operations are persisted.

For this integration stage, only RFC 5737 documentation
addresses are accepted. No real network probes.

Supports:
- AI-generated network plans
- Structured MCP tool-result validation
- Persistent SQLite records
- Deduplication
- Reopening previous results without API usage
"""

import argparse
import getpass
import ipaddress
import json
import sqlite3
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

from deepseek_harness import DeepSeekHarness


ROOT = Path("/home/lucky/pentest-master")
sys.path.insert(0, str(ROOT))

from executor.task_scope import check_action


DATABASE = ROOT / "storage/tasks.db"
DSH_HOME = ROOT / "runtime/harness-home"
WORKSPACE = ROOT / "runtime/workspace"

MODEL = "glm-5.3-uncensored"
PROVIDER = "experiential"

MCP_PLAN = "mcp__pentest_master__run_network_probe"
MCP_LIST = "mcp__pentest_master__list_network_profiles"

DOCUMENTATION_RANGES = [
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
]

DEFAULT_GOAL = (
    "Составь предварительный план сетевого исследования. "
    "Выбери подходящий профиль для поиска доступных "
    "TCP-сервисов и разумный небольшой набор портов. "
    "Проверь план через MCP, но ничего не сканируй."
)


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def initialize_database(db):
    db.execute("""
        CREATE TABLE IF NOT EXISTS network_phase_plans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            task_id INTEGER NOT NULL,
            goal TEXT NOT NULL,
            profile TEXT NOT NULL,
            target TEXT NOT NULL,
            parameters_json TEXT NOT NULL,
            argv_json TEXT NOT NULL,
            model_summary TEXT NOT NULL,
            status TEXT NOT NULL,
            created_at TEXT NOT NULL,
            UNIQUE (
                task_id,
                goal,
                profile,
                target,
                parameters_json
            )
        )
    """)
    db.commit()


def load_task(db, task_id):
    row = db.execute("""
        SELECT t.target, s.initial_target
        FROM tasks AS t
        JOIN task_scope_settings AS s
          ON t.id = s.task_id
        WHERE t.id = ?
    """, (task_id,)).fetchone()

    if row is None:
        raise ValueError(
            "Task not found or scope not initialized"
        )

    target, initial_target = row

    if target != initial_target:
        raise ValueError(
            "Task target differs from initialized scope"
        )

    address = ipaddress.ip_address(target)

    if not any(
        address in network
        for network in DOCUMENTATION_RANGES
    ):
        raise ValueError(
            "This integration phase currently supports "
            "documentation targets only"
        )

    return str(address)


def decode_arguments(value):
    if isinstance(value, dict):
        return value

    if isinstance(value, str):
        result = json.loads(value)

        if isinstance(result, dict):
            return result

    raise ValueError(
        "Invalid MCP call arguments"
    )


def decode_result(message):
    if message.get("isError"):
        raise ValueError(
            "MCP reported a protocol error"
        )

    for part in message.get("content") or []:
        if part.get("type") != "text":
            continue

        try:
            payload = json.loads(
                part.get("text", "")
            )
        except (TypeError, ValueError):
            continue

        if isinstance(payload, dict):
            return payload

    raise ValueError(
        "MCP returned no structured JSON result"
    )


def collect_events(result):
    calls = []
    results = {}

    for event in result.events:
        kind = event.get("type")
        data = event.get("data") or {}

        if kind == "tool/call":
            calls.append({
                "id": data.get("callId"),
                "name": data.get("name"),
                "arguments": data.get("arguments"),
            })

        elif kind == "tool/result":
            message = data.get("message") or {}

            call_id = message.get("toolCallId")

            if call_id:
                results[call_id] = message

    return calls, results


def validate_plan(
    db,
    task_id,
    target,
    arguments,
    payload,
):
    if arguments.get("task_id") != task_id:
        raise ValueError(
            "Agent used an incorrect task ID"
        )

    if arguments.get("target") != target:
        raise ValueError(
            "Agent attempted a different target"
        )

    if arguments.get("execute", False) is not False:
        raise ValueError(
            "Live network execution was requested"
        )

    profile = arguments.get("profile")

    if profile not in ("tcp_ports", "http_headers"):
        raise ValueError(
            "Unsupported network profile"
        )

    scope = check_action(
        db,
        task_id,
        "connect",
        target,
    )

    if scope["decision"] != "ALLOW":
        raise ValueError(
            "Target is outside authorized scope"
        )

    if payload.get("status") != "planned":
        raise ValueError(
            "Expected a validated plan, not live execution"
        )

    if payload.get("operation") != "network_probe":
        raise ValueError(
            "Unexpected Executor operation"
        )

    if (
        payload.get("task_id") != task_id
        or payload.get("target") != target
        or payload.get("profile") != profile
    ):
        raise ValueError(
            "Executor result does not match the MCP call"
        )

    argv = payload.get("argv")

    if (
        not isinstance(argv, list)
        or not argv
        or not all(isinstance(x, str) for x in argv)
    ):
        raise ValueError(
            "Invalid planned command"
        )

    if profile == "tcp_ports":
        if (
            Path(argv[0]).name != "nmap"
            or argv[-1] != target
            or "-p" not in argv
        ):
            raise ValueError(
                "Unexpected Nmap command"
            )

        selected_ports = argv[argv.index("-p") + 1]

        if not selected_ports:
            raise ValueError(
                "No TCP ports selected"
            )

        parameters = {
            "ports": selected_ports,
        }

    else:
        if (
            Path(argv[0]).name != "curl"
            or not any(
                f"http://{target}:" in item
                for item in argv
            )
        ):
            raise ValueError(
                "Unexpected HTTP command"
            )

        parameters = {
            "port": arguments.get("port", 80),
        }

    return {
        "profile": profile,
        "target": target,
        "parameters": parameters,
        "argv": argv,
    }


def extract_validated_plans(
    db,
    task_id,
    target,
    result,
):
    if result.finish_reason != "completed":
        raise ValueError(
            f"Harness did not complete: {result.finish_reason}"
        )

    calls, results = collect_events(result)

    allowed_tools = {
        MCP_LIST,
        MCP_PLAN,
    }

    plans = []

    for call in calls:
        if call["name"] not in allowed_tools:
            raise ValueError(
                f"Unexpected MCP tool: {call['name']}"
            )

        if not call["id"] or call["id"] not in results:
            raise ValueError(
                "Missing MCP result for tool call"
            )

        payload = decode_result(
            results[call["id"]]
        )

        if call["name"] == MCP_LIST:
            if payload.get("status") != "completed":
                raise ValueError(
                    "Network profile discovery failed"
                )
            continue

        arguments = decode_arguments(
            call["arguments"]
        )

        plan = validate_plan(
            db,
            task_id,
            target,
            arguments,
            payload,
        )

        plans.append(plan)

    if not plans:
        raise ValueError(
            "Agent did not produce a network plan"
        )

    return plans


def save_plans(
    db,
    task_id,
    goal,
    plans,
    model_summary,
):
    created = 0

    with db:
        for plan in plans:
            cursor = db.execute("""
                INSERT OR IGNORE INTO network_phase_plans (
                    task_id,
                    goal,
                    profile,
                    target,
                    parameters_json,
                    argv_json,
                    model_summary,
                    status,
                    created_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                task_id,
                goal,
                plan["profile"],
                plan["target"],
                json.dumps(
                    plan["parameters"],
                    sort_keys=True,
                ),
                json.dumps(plan["argv"]),
                model_summary,
                "planned",
                utc_now(),
            ))

            created += cursor.rowcount

    return created


def show_plans(db, task_id, goal=None):
    if goal is None:
        rows = db.execute("""
            SELECT id, goal, profile, target,
                   parameters_json, argv_json,
                   status, created_at
            FROM network_phase_plans
            WHERE task_id = ?
            ORDER BY id
        """, (task_id,)).fetchall()

    else:
        rows = db.execute("""
            SELECT id, goal, profile, target,
                   parameters_json, argv_json,
                   status, created_at
            FROM network_phase_plans
            WHERE task_id = ? AND goal = ?
            ORDER BY id
        """, (task_id, goal)).fetchall()

    output = []

    for row in rows:
        output.append({
            "id": row[0],
            "goal": row[1],
            "profile": row[2],
            "target": row[3],
            "parameters": json.loads(row[4]),
            "argv": json.loads(row[5]),
            "status": row[6],
            "created_at": row[7],
        })

    return output


def run_agent(task_id, goal, force=False):
    with sqlite3.connect(DATABASE) as db:
        initialize_database(db)

        target = load_task(
            db,
            task_id,
        )

        existing = show_plans(
            db,
            task_id,
            goal,
        )

        if existing and not force:
            print(
                "[RESUME] Existing network plans found. "
                "No API call needed."
            )
            print(json.dumps(
                existing,
                ensure_ascii=False,
                indent=2,
            ))
            return

        print("[TASK]", task_id)
        print("[TARGET]", target)
        print("[GOAL]", goal)
        print("[MODE] Planning only")

        key = getpass.getpass(
            "Experiential API key: "
        ).strip()

        if not key:
            raise ValueError(
                "API key required"
            )

        prompt = f"""
You are the Recon agent in Pentest Master.

Task ID: {task_id}
Authorized target: {target}

Goal:
{goal}

You can use these MCP tools:
- mcp__pentest_master__list_network_profiles
- mcp__pentest_master__run_network_probe

First inspect network profiles if needed.
Then choose suitable network profile parameters
and request at least one validated network plan.

MANDATORY:
- The task_id must be {task_id}.
- The target must be {target}.
- Set execute=false for EVERY network tool call.
- Do not perform live scans.
- Use only the two MCP tools listed above.
- Do not invent open ports or discovered services.
- A planned command is NOT a completed scan.
- Keep the selection modest and relevant.
- Summarize your planned approach in Russian.
"""

        with DeepSeekHarness(
            profile="sdk-minimal",
            dsh_home=str(DSH_HOME),
            cwd=str(WORKSPACE),
            provider=PROVIDER,
            model=MODEL,
            api_key=key,
            max_tokens=2200,
            request_timeout_seconds=120,
        ) as harness:

            session = harness.start_session(
                "network-phase-" + uuid.uuid4().hex[:12]
            )

            result = session.run(prompt)

        plans = extract_validated_plans(
            db,
            task_id,
            target,
            result,
        )

        summary = (
            result.final_response or ""
        ).strip()

        created = save_plans(
            db,
            task_id,
            goal,
            plans,
            summary,
        )

        print()
        print("[AGENT SUMMARY]")
        print(summary[:3000])

        print()
        print("[VALIDATED PLANS]")
        for plan in plans:
            print(json.dumps(
                plan,
                ensure_ascii=False,
                indent=2,
            ))

        print()
        print("[DATABASE] New records:", created)
        print(
            "[SUCCESS] Network planning phase persisted"
        )


def main():
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--task-id",
        type=int,
        default=7,
    )

    parser.add_argument(
        "--goal",
        default=DEFAULT_GOAL,
    )

    parser.add_argument(
        "--show",
        action="store_true",
        help="Display saved plans without using the API",
    )

    parser.add_argument(
        "--force",
        action="store_true",
        help="Run the agent again despite existing plans",
    )

    args = parser.parse_args()

    try:
        if args.show:
            with sqlite3.connect(DATABASE) as db:
                initialize_database(db)

                plans = show_plans(
                    db,
                    args.task_id,
                )

                print(json.dumps(
                    plans,
                    ensure_ascii=False,
                    indent=2,
                ))

        else:
            run_agent(
                args.task_id,
                args.goal,
                args.force,
            )

    except (
        ValueError,
        OSError,
        sqlite3.Error,
    ) as exc:
        print("[ERROR]", exc)
        raise SystemExit(1)


if __name__ == "__main__":
    main()
