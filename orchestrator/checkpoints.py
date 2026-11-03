
"""
Pentest Master - Checkpoint Engine v1.

Notifications do not pause tasks.
Sensitive operations create approval requests.

This module records decisions only.
It does not execute privileged operations.
"""

import argparse
import json
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path("/home/lucky/pentest-master")
DATABASE = ROOT / "storage/tasks.db"

NOTIFICATIONS = {
    "credentials_found",
    "initial_access",
    "flag_found",
    "finding",
}

APPROVAL_OPERATIONS = {
    "privilege_escalation",
    "host_package_install",
    "host_system_change",
    "destructive_operation",
}


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def connect():
    db = sqlite3.connect(DATABASE)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA foreign_keys = ON")
    return db


def initialize(db):
    db.execute("""
        CREATE TABLE IF NOT EXISTS checkpoint_events (
            id TEXT PRIMARY KEY,
            task_id INTEGER NOT NULL,
            kind TEXT NOT NULL,
            operation TEXT NOT NULL,
            message TEXT NOT NULL,
            status TEXT NOT NULL,
            created_at TEXT NOT NULL,
            decided_at TEXT,
            FOREIGN KEY (task_id) REFERENCES tasks(id)
        )
    """)
    db.commit()


def require_task(db, task_id):
    row = db.execute(
        "SELECT id FROM tasks WHERE id = ?",
        (task_id,),
    ).fetchone()

    if row is None:
        raise ValueError(f"Task {task_id} not found")


def notify(db, task_id, event_type, message):
    require_task(db, task_id)

    if event_type not in NOTIFICATIONS:
        raise ValueError("Unknown notification type")

    event_id = uuid.uuid4().hex

    with db:
        db.execute("""
            INSERT INTO checkpoint_events
            (id, task_id, kind, operation, message,
             status, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            event_id,
            task_id,
            "notification",
            event_type,
            message,
            "delivered",
            utc_now(),
        ))

    print("[NOTIFICATION]", event_type)
    print("Message:", message)
    print("Task execution is NOT paused.")
    print("Event ID:", event_id)

    return event_id


def request_approval(db, task_id, operation, message):
    require_task(db, task_id)

    if operation not in APPROVAL_OPERATIONS:
        raise ValueError("Operation is not approval-eligible")

    approval_id = uuid.uuid4().hex

    with db:
        db.execute("""
            INSERT INTO checkpoint_events
            (id, task_id, kind, operation, message,
             status, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            approval_id,
            task_id,
            "approval",
            operation,
            message,
            "pending",
            utc_now(),
        ))

    print("[APPROVAL REQUIRED]")
    print("Task:", task_id)
    print("Operation:", operation)
    print("Reason:", message)
    print("Approval ID:", approval_id)
    print("Sensitive operation must NOT execute yet.")

    return approval_id


def decide(db, approval_id, decision):
    if decision not in ("approved", "denied"):
        raise ValueError("Invalid decision")

    with db:
        cursor = db.execute("""
            UPDATE checkpoint_events
            SET status = ?, decided_at = ?
            WHERE id = ?
              AND kind = 'approval'
              AND status = 'pending'
        """, (
            decision,
            utc_now(),
            approval_id,
        ))

    if cursor.rowcount != 1:
        raise ValueError(
            "Approval not found or already decided"
        )

    print("[DECISION]", decision)
    print("Approval ID:", approval_id)


def check(db, approval_id, task_id, operation):
    row = db.execute("""
        SELECT status
        FROM checkpoint_events
        WHERE id = ?
          AND task_id = ?
          AND kind = 'approval'
          AND operation = ?
    """, (
        approval_id,
        task_id,
        operation,
    )).fetchone()

    status = row["status"] if row else "not_found"

    print("Approval status:", status)

    return status == "approved"


def show_events(db, task_id):
    require_task(db, task_id)

    rows = db.execute("""
        SELECT id, kind, operation, message,
               status, created_at
        FROM checkpoint_events
        WHERE task_id = ?
        ORDER BY created_at, id
    """, (task_id,)).fetchall()

    for row in rows:
        print(json.dumps(
            dict(row),
            ensure_ascii=False,
        ))

    if not rows:
        print("No checkpoint events.")


def main():
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(
        dest="command",
        required=True,
    )

    notification = sub.add_parser("notify")
    notification.add_argument("--task-id", type=int, required=True)
    notification.add_argument("--event", required=True)
    notification.add_argument("--message", required=True)

    request = sub.add_parser("request")
    request.add_argument("--task-id", type=int, required=True)
    request.add_argument("--operation", required=True)
    request.add_argument("--message", required=True)

    approve = sub.add_parser("approve")
    approve.add_argument("--id", required=True)

    deny = sub.add_parser("deny")
    deny.add_argument("--id", required=True)

    verify = sub.add_parser("check")
    verify.add_argument("--id", required=True)
    verify.add_argument("--task-id", type=int, required=True)
    verify.add_argument("--operation", required=True)

    events = sub.add_parser("events")
    events.add_argument("--task-id", type=int, required=True)

    args = parser.parse_args()

    try:
        with connect() as db:
            initialize(db)

            if args.command == "notify":
                notify(
                    db,
                    args.task_id,
                    args.event,
                    args.message,
                )

            elif args.command == "request":
                request_approval(
                    db,
                    args.task_id,
                    args.operation,
                    args.message,
                )

            elif args.command == "approve":
                decide(db, args.id, "approved")

            elif args.command == "deny":
                decide(db, args.id, "denied")

            elif args.command == "check":
                allowed = check(
                    db,
                    args.id,
                    args.task_id,
                    args.operation,
                )
                if not allowed:
                    raise SystemExit(1)

            elif args.command == "events":
                show_events(db, args.task_id)

    except (ValueError, sqlite3.Error) as exc:
        print("[ERROR]", exc)
        raise SystemExit(1)


if __name__ == "__main__":
    main()
