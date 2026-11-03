
import argparse
import getpass
import json
import sqlite3
import urllib.error
import urllib.request
from datetime import datetime, timezone

try:
    from orchestrator.planner import DATABASE, MODEL, validate_plan
except ModuleNotFoundError:
    from planner import DATABASE, MODEL, validate_plan


API_URL = "https://api.experientiallabs.ai/v1/chat/completions"

ROLES = {
    "recon": "Recon analyst: organize authorized enumeration tasks.",
    "vuln": "Vulnerability analyst: reason about supplied findings.",
    "access": "Access analyst: outline verification steps and approval needs.",
    "verify": "Verification analyst: check consistency and evidence quality.",
}

AGENT_SYSTEM = """
You are a specialized agent in a multi-agent cybersecurity
planning system.

This is a PLANNING-ONLY evaluation.
You have no access to a terminal, network, filesystem or target.

Use only information supplied by the orchestrator.
Never claim to have scanned, exploited or accessed a target.
Never invent vulnerabilities, credentials or flags.
Do not provide actual exploit commands.

Summarize the assigned task, available evidence, missing
information and a sensible next step.
Clearly state that no real testing has been performed.

Reply concisely in Russian.
"""


def now():
    return datetime.now(timezone.utc).isoformat()


def init_database(db):
    db.execute("""
        CREATE TABLE IF NOT EXISTS agent_runs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            parent_task_id INTEGER NOT NULL,
            step_index INTEGER NOT NULL,
            agent TEXT NOT NULL,
            status TEXT NOT NULL,
            output TEXT,
            updated_at TEXT NOT NULL,
            UNIQUE(parent_task_id, step_index)
        )
    """)


def create_demo(db):
    target = "192.0.2.10"

    plan = {
        "summary": "Синтетический тест распределения задач",
        "target": target,
        "objectives": ["Test multi-agent orchestration"],
        "tasks": [
            {
                "agent": "recon",
                "instruction": "Составить план инвентаризации сервисов учебной цели.",
                "depends_on": []
            },
            {
                "agent": "vuln",
                "instruction": "Оценить, каких данных не хватает для анализа уязвимостей.",
                "depends_on": [0]
            },
            {
                "agent": "access",
                "instruction": "Определить необходимые проверки и контрольные точки для этапа доступа, без выполнения действий.",
                "depends_on": [1]
            },
            {
                "agent": "verify",
                "instruction": "Проверить логическую согласованность результатов трёх агентов.",
                "depends_on": [0, 1, 2]
            }
        ],
        "checkpoints": ["No real operations permitted in demo"]
    }

    validate_plan(plan, target)

    cursor = db.execute("""
        INSERT INTO tasks
        (created_at, target, description, plan_json, status)
        VALUES (?, ?, ?, ?, ?)
    """, (
        now(),
        target,
        "Synthetic scheduler test",
        json.dumps(plan, ensure_ascii=False),
        "ready"
    ))

    return cursor.lastrowid


def get_runs(db, task_id):
    rows = db.execute("""
        SELECT step_index, status, output
        FROM agent_runs
        WHERE parent_task_id = ?
    """, (task_id,)).fetchall()

    return {
        index: {"status": status, "output": output}
        for index, status, output in rows
    }


def set_run(db, task_id, index, agent, status, output=None):
    db.execute("""
        INSERT INTO agent_runs
        (parent_task_id, step_index, agent, status, output, updated_at)
        VALUES (?, ?, ?, ?, ?, ?)
        ON CONFLICT(parent_task_id, step_index)
        DO UPDATE SET
            status = excluded.status,
            output = excluded.output,
            updated_at = excluded.updated_at
    """, (task_id, index, agent, status, output, now()))
    db.commit()


def ask_agent(api_key, agent, instruction, evidence, target):
    messages = [
        {
            "role": "system",
            "content": AGENT_SYSTEM + "\n" + ROLES[agent]
        },
        {
            "role": "user",
            "content": json.dumps({
		"authorized_target": target,
                "assigned_task": instruction,
                "previous_results": evidence,
                "execution_mode": "planning_only"
            }, ensure_ascii=False)
        }
    ]

    payload = {
        "model": MODEL,
        "messages": messages,
        "stream": False,
        "max_tokens": 1500
    }

    request = urllib.request.Request(
        API_URL,
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json"
        },
        method="POST"
    )

    with urllib.request.urlopen(request, timeout=120) as response:
        result = json.load(response)

    content = result["choices"][0]["message"].get("content")
    if not isinstance(content, str) or not content.strip():
        raise ValueError("Agent returned an empty response")

    return content.strip()


def run_scheduler(db, task_id, api_key):
    row = db.execute("""
        SELECT target, plan_json, status
        FROM tasks WHERE id = ?
    """, (task_id,)).fetchone()

    if row is None:
        raise ValueError("Task ID not found")

    target, raw_plan, status = row

    if status not in ("ready", "running", "failed", "completed"):
        raise ValueError(f"Task cannot run from status: {status}")

    plan = json.loads(raw_plan)
    validate_plan(plan, target)

    # Safety: v1 accepts only the synthetic demo.
    if (
        target != "192.0.2.10"
        or plan.get("summary") != "Синтетический тест распределения задач"
    ):
        raise ValueError("Scheduler v1 only accepts its demo fixture")

    tasks = plan["tasks"]

    db.execute(
        "UPDATE tasks SET status = 'running' WHERE id = ?",
        (task_id,)
    )
    db.commit()

    try:
        for index, step in enumerate(tasks):
            runs = get_runs(db, task_id)

            if runs.get(index, {}).get("status") == "completed":
                print(f"[SKIP] Step {index} already completed")
                continue

            dependencies = step.get("depends_on", [])
            if not all(
                runs.get(dep, {}).get("status") == "completed"
                for dep in dependencies
            ):
                raise RuntimeError(
                    f"Dependencies not satisfied for step {index}"
                )

            agent = step["agent"]
            evidence = [
                {
                    "step": dep,
                    "agent": tasks[dep]["agent"],
                    "result": runs[dep]["output"]
                }
                for dep in dependencies
            ]

            print(f"\n[RUN] Step {index}: {agent}", flush=True)
            set_run(db, task_id, index, agent, "running")

            output = ask_agent(
                api_key, agent, step["instruction"], evidence, target
            )

            set_run(db, task_id, index, agent, "completed", output)
            print(output[:1200], flush=True)

        db.execute(
            "UPDATE tasks SET status = 'completed' WHERE id = ?",
            (task_id,)
        )
        db.commit()
        print("\n[SUCCESS] All demo agent tasks completed")

    except Exception:
        db.execute(
            "UPDATE tasks SET status = 'failed' WHERE id = ?",
            (task_id,)
        )
        db.commit()
        raise


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--demo",
        action="store_true",
        help="Create and execute a synthetic test plan"
    )
    parser.add_argument("--task-id", type=int)
    args = parser.parse_args()

    if not args.demo and args.task_id is None:
        parser.error("Use --demo or --task-id")

    with sqlite3.connect(DATABASE) as db:
        init_database(db)

        if args.demo:
            task_id = create_demo(db)
            db.commit()
        else:
            task_id = args.task_id

        print("Task ID:", task_id)
        api_key = getpass.getpass("Experiential API key: ").strip()
        if not api_key:
            raise SystemExit("API key is required")

        try:
            run_scheduler(db, task_id, api_key)
        except (ValueError, RuntimeError, urllib.error.URLError) as exc:
            print(f"\n[ERROR] {exc}")
            raise SystemExit(1)


if __name__ == "__main__":
    main()
