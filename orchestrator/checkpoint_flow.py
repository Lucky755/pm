
"""
Pentest Master - Checkpoint Flow Demo v1.

Demonstrates:
- creating an approval checkpoint
- persisting a paused workflow
- resuming after operator approval
- handling operator rejection

No shell commands or target operations are executed.
Does not change the main Scheduler's task status.
"""

import argparse
import sqlite3
import uuid

from checkpoints import (
    DATABASE,
    initialize,
    request_approval,
    require_task,
    utc_now,
)


def connect():
    db = sqlite3.connect(DATABASE)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA foreign_keys = ON")
    return db


def initialize_flow(db):
    initialize(db)

    db.execute("""
        CREATE TABLE IF NOT EXISTS checkpoint_flow_demo (
            id TEXT PRIMARY KEY,
            task_id INTEGER NOT NULL,
            approval_id TEXT NOT NULL UNIQUE,
            operation TEXT NOT NULL,
            status TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY (task_id) REFERENCES tasks(id),
            FOREIGN KEY (approval_id)
                REFERENCES checkpoint_events(id)
        )
    """)

    db.commit()


def start_flow(db, task_id):
    require_task(db, task_id)

    operation = "privilege_escalation"

    approval_id = request_approval(
        db,
        task_id,
        operation,
        "DEMO: approval before simulated privileged stage",
    )

    run_id = uuid.uuid4().hex

    with db:
        db.execute("""
            INSERT INTO checkpoint_flow_demo (
                id,
                task_id,
                approval_id,
                operation,
                status,
                created_at,
                updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            run_id,
            task_id,
            approval_id,
            operation,
            "waiting_approval",
            utc_now(),
            utc_now(),
        ))

    print("\n[WORKFLOW CREATED]")
    print("Run ID:", run_id)
    print("Approval ID:", approval_id)
    print("Status: waiting_approval")
    print("No privileged operation was executed.")


def get_flow(db, run_id):
    row = db.execute("""
        SELECT
            f.id,
            f.task_id,
            f.operation,
            f.status,
            f.approval_id,
            e.status AS approval_status
        FROM checkpoint_flow_demo AS f
        JOIN checkpoint_events AS e
          ON e.id = f.approval_id
         AND e.task_id = f.task_id
         AND e.operation = f.operation
         AND e.kind = 'approval'
        WHERE f.id = ?
    """, (run_id,)).fetchone()

    if row is None:
        raise ValueError("Workflow not found")

    return row


def show_status(db, run_id):
    row = get_flow(db, run_id)

    print("[WORKFLOW STATUS]")
    print("Run ID:", row["id"])
    print("Task ID:", row["task_id"])
    print("Operation:", row["operation"])
    print("Workflow:", row["status"])
    print("Approval:", row["approval_status"])


def resume_flow(db, run_id):
    row = get_flow(db, run_id)

    if row["status"] != "waiting_approval":
        print("[NO ACTION]")
        print("Workflow already finalized:", row["status"])
        return

    approval = row["approval_status"]

    if approval == "pending":
        print("[PAUSED]")
        print("Waiting for operator approval.")
        return

    if approval == "denied":
        new_status = "cancelled"
    elif approval == "approved":
        new_status = "completed"
    else:
        raise ValueError(
            f"Unexpected approval status: {approval}"
        )

    with db:
        cursor = db.execute("""
            UPDATE checkpoint_flow_demo
            SET status = ?, updated_at = ?
            WHERE id = ?
              AND status = 'waiting_approval'
        """, (
            new_status,
            utc_now(),
            run_id,
        ))

    if cursor.rowcount != 1:
        raise RuntimeError("Workflow state changed concurrently")

    if new_status == "completed":
        print("[RESUMED]")
        print("Approval confirmed.")
        print("Simulated stage completed.")
        print("No privileged command was executed.")
    else:
        print("[CANCELLED]")
        print("Operator denied the operation.")

    print("Workflow status:", new_status)


def main():
    parser = argparse.ArgumentParser()

    sub = parser.add_subparsers(
        dest="command",
        required=True,
    )

    start = sub.add_parser("start")
    start.add_argument(
        "--task-id",
        type=int,
        required=True,
    )

    status = sub.add_parser("status")
    status.add_argument(
        "--run-id",
        required=True,
    )

    resume = sub.add_parser("resume")
    resume.add_argument(
        "--run-id",
        required=True,
    )

    args = parser.parse_args()

    try:
        with connect() as db:
            initialize_flow(db)

            if args.command == "start":
                start_flow(db, args.task_id)

            elif args.command == "status":
                show_status(db, args.run_id)

            elif args.command == "resume":
                resume_flow(db, args.run_id)

    except (
        ValueError,
        RuntimeError,
        sqlite3.Error,
    ) as exc:
        print("[ERROR]", exc)
        raise SystemExit(1)


if __name__ == "__main__":
    main()
