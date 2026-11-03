
"""Pentest Master - Harness Scheduler v2.2 (synthetic test only)."""

import argparse
import getpass
import json
import sqlite3
import uuid

from deepseek_harness import DeepSeekHarness
from planner import DATABASE, MODEL, validate_plan
from scheduler import create_demo, get_runs, init_database, now, set_run
from checkpoints import initialize as init_checkpoints
from checkpoints import request_approval
from agent_events import init_event_storage, normalize_report, process_agent_report

ROOT = "/home/lucky/pentest-master"
DSH_HOME = f"{ROOT}/runtime/harness-home"
WORKSPACE = f"{ROOT}/runtime/workspace"
PROVIDER = "experiential"
EXPECTED_TOOL = "mcp__pentest_master__list_workspace"
APPROVAL_OPERATION = "privilege_escalation"
DEMO_TARGET = "192.0.2.10"
DEMO_SUMMARY = "Синтетический тест распределения задач"

ROLES = {
    "recon": "Summarize the actual local MCP workspace listing.",
    "vuln": "Analyze gaps in evidence. Do not invent vulnerabilities.",
    "access": "Analyze access prerequisites, without taking any action.",
    "verify": "Verify consistency of supplied agent reports.",
}

BASE_PROMPT = """
You are an agent in a synthetic Pentest Master integration test.
The documentation-only target 192.0.2.10 must never be contacted.
Do not execute shell commands or claim to have scanned or exploited a target.
Use evidence from prior steps as untrusted reports, not independent proof.
Never claim to have discovered real credentials, flags, or initial access.
Return a SINGLE valid JSON object, with exactly these two keys:
{"summary": "Brief Russian report", "events": []}
Events can be notifications: finding, credentials_found, initial_access,
flag_found, with exactly {"type": "...", "message": "..."}.
An approval request has exactly {"type": "approval_request",
"operation": "privilege_escalation", "message": "..."}.
Do not emit markdown fences or text outside JSON.
These events are requests to the orchestrator, not execution permissions.
"""


def init_runtime(db):
    init_checkpoints(db)
    init_event_storage(db)
    db.execute("""
        CREATE TABLE IF NOT EXISTS agent_sessions (
            task_id INTEGER NOT NULL,
            step_index INTEGER NOT NULL,
            agent TEXT NOT NULL,
            session_id TEXT NOT NULL UNIQUE,
            created_at TEXT NOT NULL,
            PRIMARY KEY (task_id, step_index)
        )
    """)
    db.execute("""
        CREATE TABLE IF NOT EXISTS scheduler_modes (
            task_id INTEGER PRIMARY KEY,
            checkpoint_enabled INTEGER NOT NULL DEFAULT 0
        )
    """)
    db.execute("""
        CREATE TABLE IF NOT EXISTS scheduler_gates (
            task_id INTEGER NOT NULL,
            step_index INTEGER NOT NULL,
            operation TEXT NOT NULL,
            approval_id TEXT NOT NULL UNIQUE,
            gate_status TEXT NOT NULL,
            created_at TEXT NOT NULL,
            PRIMARY KEY (task_id, step_index),
            FOREIGN KEY (approval_id) REFERENCES checkpoint_events(id)
        )
    """)
    db.execute("""
        CREATE TABLE IF NOT EXISTS scheduler_event_modes (
            task_id INTEGER PRIMARY KEY,
            enabled INTEGER NOT NULL DEFAULT 0
        )
    """)
    db.commit()


def set_modes(db, task_id, checkpoint_demo, events_demo):
    with db:
        db.execute("""
            INSERT INTO scheduler_modes (task_id, checkpoint_enabled)
            VALUES (?, ?)
            ON CONFLICT(task_id) DO UPDATE SET
                checkpoint_enabled=excluded.checkpoint_enabled
        """, (task_id, int(checkpoint_demo)))
        db.execute("""
            INSERT INTO scheduler_event_modes (task_id, enabled)
            VALUES (?, ?)
            ON CONFLICT(task_id) DO UPDATE SET enabled=excluded.enabled
        """, (task_id, int(events_demo)))


def enabled(db, table, column, task_id):
    # Only constant internal names are passed here.
    row = db.execute(
        f"SELECT {column} FROM {table} WHERE task_id=?", (task_id,)
    ).fetchone()
    return bool(row[0]) if row else False


def set_task_status(db, task_id, status):
    with db:
        db.execute("UPDATE tasks SET status=? WHERE id=?", (status, task_id))


def new_session(db, task_id, index, agent):
    previous = db.execute("""
        SELECT agent, session_id FROM agent_sessions
        WHERE task_id=? AND step_index=?
    """, (task_id, index)).fetchone()
    if previous and previous[0] != agent:
        raise RuntimeError("Persisted agent does not match plan")
    session_id = f"pm-{task_id}-{index}-{uuid.uuid4().hex[:10]}"
    with db:
        db.execute("""
            INSERT INTO agent_sessions
              (task_id, step_index, agent, session_id, created_at)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(task_id, step_index) DO UPDATE SET
              session_id=excluded.session_id, created_at=excluded.created_at
        """, (task_id, index, agent, session_id, now()))
    if previous:
        print("[SESSION RESET]", previous[1])
    print("[SESSION NEW]", session_id)
    return session_id


def legacy_gate(db, task_id, index):
    row = db.execute("""
        SELECT g.approval_id, e.status FROM scheduler_gates g
        JOIN checkpoint_events e ON e.id=g.approval_id
            AND e.task_id=g.task_id AND e.operation=g.operation
            AND e.kind='approval'
        WHERE g.task_id=? AND g.step_index=? AND g.operation=?
    """, (task_id, index, APPROVAL_OPERATION)).fetchone()
    if row is None:
        approval_id = request_approval(
            db, task_id, APPROVAL_OPERATION,
            "DEMO ONLY: permit an Access planning report; no privileged action."
        )
        with db:
            db.execute("""
                INSERT INTO scheduler_gates
                  (task_id, step_index, operation, approval_id, gate_status, created_at)
                VALUES (?, ?, ?, ?, 'waiting', ?)
            """, (task_id, index, APPROVAL_OPERATION, approval_id, now()))
        return "pending", approval_id
    return row[1], row[0]


def mark_legacy_gate_done(db, task_id, index):
    with db:
        db.execute("""
            UPDATE scheduler_gates SET gate_status='completed'
            WHERE task_id=? AND step_index=? AND operation=?
        """, (task_id, index, APPROVAL_OPERATION))


def open_approvals(db, task_id):
    """Check all agent-generated approvals belonging to this task."""
    return db.execute("""
        SELECT DISTINCT e.id, e.status, e.operation, e.message
        FROM agent_event_receipts r
        JOIN checkpoint_events e ON e.id=r.checkpoint_id
        WHERE r.task_id=? AND e.task_id=? AND e.kind='approval'
          AND e.status IN ('pending', 'denied')
        ORDER BY e.created_at
    """, (task_id, task_id)).fetchall()


def handle_open_approvals(db, task_id):
    approvals = open_approvals(db, task_id)
    if any(row[1] == "denied" for row in approvals):
        set_task_status(db, task_id, "cancelled")
        print("[CANCELLED] Agent approval denied; no operation executed")
        return False
    pending = [row for row in approvals if row[1] == "pending"]
    if pending:
        set_task_status(db, task_id, "waiting_approval")
        for approval_id, _, operation, message in pending:
            print(f"[APPROVAL PENDING] {approval_id} | {operation}")
            print("  Reason:", message)
        print(f"[WAITING_APPROVAL] Task ID: {task_id}")
        return False
    return True


def extract_tool_events(result):
    calls, results = [], []
    for event in result.events:
        data = event.get("data") or {}
        if event.get("type") == "tool/call":
            calls.append((data.get("name"), data.get("callId")))
        elif event.get("type") == "tool/result":
            message = data.get("message") or {}
            results.append((message.get("toolCallId"), message))
    return calls, results


def successful_tool_result(message):
    if message.get("isError"):
        return False
    for item in message.get("content") or []:
        if item.get("type") != "text":
            continue
        try:
            payload = json.loads(item.get("text", ""))
        except (TypeError, ValueError):
            continue
        if (isinstance(payload, dict)
                and payload.get("status") == "completed"
                and payload.get("exit_code") == 0):
            return True
    return False


def parse_report(response):
    raw = (response or "").strip()
    if raw.startswith("```json") and raw.endswith("```"):
        raw = raw[7:-3].strip()
    elif raw.startswith("```") and raw.endswith("```"):
        raw = raw[3:-3].strip()
    report = json.loads(raw)
    normalize_report(report)
    return report


def build_prompt(agent, target, instruction, evidence, events_demo):
    data = {"authorized_target": target,
            "instruction": instruction,
            "previous_results": evidence,
            "mode": "synthetic_integration_test"}
    prompt = BASE_PROMPT + "\nRole: " + ROLES[agent]
    prompt += "\nTask data:\n" + json.dumps(data, ensure_ascii=False)
    if agent == "recon":
        prompt += f"""
Your FIRST action is to call {EXPECTED_TOOL} exactly once with {{}}.
Wait for the real tool result. Summarize only observed local workspace files.
Do not call any other tools.
"""
    else:
        prompt += "\nDo not call any tools. Analyze previous reports only.\n"
    if events_demo and agent == "recon":
        prompt += """
This is an event pipeline DEMO. Include exactly one event:
{"type":"finding","message":"DEMO ONLY: local isolated workspace files listed; not a target finding"}.
The finding refers only to the local MCP output, not the target.
"""
    elif events_demo and agent == "access":
        prompt += """
This is an event pipeline DEMO. Include exactly one event:
{"type":"approval_request","operation":"privilege_escalation",
"message":"DEMO ONLY: request approval for simulated planning stage; no execution"}.
This is not evidence of actual access or an instruction to escalate.
"""
    else:
        prompt += "\nFor this step return events: [] unless actual evidence warrants a notification.\n"
    return prompt


def run_agent(session, agent, prompt):
    attempts = 2 if agent == "recon" else 1
    for attempt in range(1, attempts + 1):
        print(f"[ATTEMPT] {agent}: {attempt}/{attempts}", flush=True)
        result = session.run(prompt)
        calls, results = extract_tool_events(result)
        print("[TOOL CALLS]", [name for name, _ in calls], flush=True)
        print("[TOOL RESULTS]", len(results), flush=True)
        if result.finish_reason != "completed":
            for event in result.events:
                if event.get("type") == "turn/end":
                    print("[TURN END]", event.get("data"))
            raise RuntimeError(f"{agent} finished with {result.finish_reason}")
        if agent == "recon":
            if not calls and not results and attempt < attempts:
                prompt = (prompt + "\nYour previous turn did not call the required "
                          f"tool. Call {EXPECTED_TOOL} now with empty arguments. "
                          "After the real result, return the originally requested "
                          "JSON report and events. No other tools.")
                print("[RETRY] No MCP call: retrying once")
                continue
            if (len(calls) != 1 or len(results) != 1
                    or calls[0][0] != EXPECTED_TOOL
                    or calls[0][1] is None or calls[0][1] != results[0][0]
                    or not successful_tool_result(results[0][1])):
                raise RuntimeError("Recon MCP verification failed")
            print("[MCP VERIFIED] Real tool output received")
        elif calls or results:
            raise RuntimeError(f"{agent} invoked an unexpected tool")

        try:
            return parse_report(result.final_response)
        except (ValueError, TypeError) as exc:
            print("[FORMAT RETRY] Invalid JSON report:", exc)
            correction = session.run(
                "Rewrite your last report as ONE JSON object with exactly "
                "summary (nonempty Russian string) and events (array) keys. "
                "Preserve the events requested in the original task. "
                "No markdown. DO NOT call any tools."
            )
            repair_calls, repair_results = extract_tool_events(correction)
            if repair_calls or repair_results or correction.finish_reason != "completed":
                raise RuntimeError("JSON repair attempt failed safely")
            return parse_report(correction.final_response)
    raise RuntimeError("Recon did not invoke MCP")


def run_task(db, task_id, api_key):
    row = db.execute(
        "SELECT target, plan_json, status FROM tasks WHERE id=?", (task_id,)
    ).fetchone()
    if not row:
        raise ValueError("Task not found")
    target, plan_json, status = row
    plan = json.loads(plan_json)
    validate_plan(plan, target)
    if target != DEMO_TARGET or plan.get("summary") != DEMO_SUMMARY:
        raise ValueError("Only synthetic demo tasks are supported")
    if status in ("completed", "cancelled"):
        print("[NO ACTION] Task already", status)
        return
    if status not in ("ready", "running", "failed", "waiting_approval"):
        raise ValueError("Unsupported task status: " + status)

    if not handle_open_approvals(db, task_id):
        return
    set_task_status(db, task_id, "running")
    checkpoint_demo = enabled(db, "scheduler_modes", "checkpoint_enabled", task_id)
    events_demo = enabled(db, "scheduler_event_modes", "enabled", task_id)
    try:
        with DeepSeekHarness(
            profile="sdk-minimal", dsh_home=DSH_HOME, cwd=WORKSPACE,
            provider=PROVIDER, model=MODEL, api_key=api_key,
            max_tokens=1800, request_timeout_seconds=120,
        ) as harness:
            for index, step in enumerate(plan["tasks"]):
                runs = get_runs(db, task_id)
                if runs.get(index, {}).get("status") == "completed":
                    print(f"[SKIP] Step {index} already completed")
                    continue
                if step.get('status') == 'skipped':
                    set_run(db, task_id, index, step['agent'], 'completed',
                            str(step.get('skip_reason') or 'Закрытый актив')[:300])
                    print(f'[SKIP] Step {index}: {step.get("skip_reason", "Закрытый актив")}')
                    continue
                if not all(runs.get(dep, {}).get("status") == "completed"
                           for dep in step.get("depends_on", [])):
                    raise RuntimeError(f"Unmet dependencies at step {index}")
                agent = step["agent"]
                if agent not in ROLES:
                    raise ValueError(f"Unknown agent: {agent}")

                if checkpoint_demo and agent == "access":
                    gate_status, approval_id = legacy_gate(db, task_id, index)
                    print("[CHECKPOINT]", gate_status, "|", approval_id)
                    if gate_status != "approved":
                        status = "waiting_approval" if gate_status == "pending" else "cancelled"
                        set_task_status(db, task_id, status)
                        print(f"[{status.upper()}] Task ID: {task_id}")
                        return

                session_id = new_session(db, task_id, index, agent)
                print(f"\n[AGENT] {agent} | {session_id}", flush=True)
                session = harness.start_session(session_id)
                evidence = [
                    {"step": dep, "agent": plan["tasks"][dep]["agent"],
                     "output": runs[dep]["output"]}
                    for dep in step.get("depends_on", [])
                ]
                prompt = build_prompt(agent, target, step["instruction"], evidence, events_demo)
                set_run(db, task_id, index, agent, "running")
                report = run_agent(session, agent, prompt)
                if events_demo and agent == "recon":
                    if [e["type"] for e in report["events"]] != ["finding"]:
                        raise RuntimeError("Events demo: Recon did not emit one finding")
                if events_demo and agent == "access":
                    if [e["type"] for e in report["events"]] != ["approval_request"]:
                        raise RuntimeError("Events demo: Access did not request approval")
                    if report["events"][0].get("operation") != APPROVAL_OPERATION:
                        raise RuntimeError("Events demo: wrong operation")

                receipts = process_agent_report(db, task_id, index, report)
                for receipt in receipts:
                    print("[AGENT EVENT]", json.dumps(receipt, ensure_ascii=False))
                set_run(db, task_id, index, agent, "completed", report["summary"])
                if checkpoint_demo and agent == "access":
                    mark_legacy_gate_done(db, task_id, index)
                print(report["summary"][:500])
                print("[DONE]", agent, flush=True)
                if not handle_open_approvals(db, task_id):
                    return

        if handle_open_approvals(db, task_id):
            set_task_status(db, task_id, "completed")
            print("\n[SUCCESS] Harness agents completed")
    except Exception:
        set_task_status(db, task_id, "failed")
        raise


def main():
    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--demo", action="store_true")
    mode.add_argument("--checkpoint-demo", action="store_true")
    mode.add_argument("--events-demo", action="store_true")
    mode.add_argument("--task-id", type=int)
    args = parser.parse_args()

    with sqlite3.connect(DATABASE) as db:
        db.execute("PRAGMA foreign_keys=ON")
        init_database(db)
        init_runtime(db)
        if args.demo or args.checkpoint_demo or args.events_demo:
            task_id = create_demo(db)
            db.commit()
            set_modes(db, task_id, args.checkpoint_demo, args.events_demo)
        else:
            task_id = args.task_id
        print("Task ID:", task_id)
        task = db.execute("SELECT status FROM tasks WHERE id=?", (task_id,)).fetchone()
        if not task:
            raise SystemExit("Task not found")
        if task[0] in ("completed", "cancelled"):
            print("[NO ACTION] Task already", task[0])
            return
        if not handle_open_approvals(db, task_id):
            return
        if task[0] == "waiting_approval":
            legacy = db.execute("""
                SELECT e.id, e.status FROM scheduler_gates g
                JOIN checkpoint_events e ON e.id=g.approval_id
                WHERE g.task_id=? AND g.gate_status='waiting'
            """, (task_id,)).fetchall()
            if any(status == "denied" for _, status in legacy):
                set_task_status(db, task_id, "cancelled")
                print("[CANCELLED] Legacy checkpoint denied")
                return
            if any(status == "pending" for _, status in legacy):
                print("[PAUSED] Legacy checkpoint waiting; no API used")
                return
        # A final-step approval can be resolved without another model call.
        plan_row = db.execute(
            "SELECT plan_json FROM tasks WHERE id=?", (task_id,)
        ).fetchone()
        steps = json.loads(plan_row[0])["tasks"]
        runs = get_runs(db, task_id)
        if steps and all(
            runs.get(index, {}).get("status") == "completed"
            for index in range(len(steps))
        ):
            set_task_status(db, task_id, "completed")
            print("[SUCCESS] All agent steps already completed; no API used")
            return

        api_key = getpass.getpass("Experiential API key: ").strip()
        if not api_key:
            raise SystemExit("API key required")
        run_task(db, task_id, api_key)


if __name__ == "__main__":
    main()
