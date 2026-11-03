
"""
Pentest Master: one-use, scoped approval guard (DEMO ONLY).

No host operations, shell commands, network traffic,
or privilege escalation.

This is a standalone integration test,
not a production security boundary.
"""

import argparse
import hashlib
import json
import sqlite3
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path("/home/lucky/pentest-master")
sys.path.insert(0, str(ROOT / "orchestrator"))

from checkpoints import DATABASE, initialize, request_approval

TARGET = "192.0.2.10"
OPERATION = "privilege_escalation"
TTL_MINUTES = 60


def utc_now():
    return datetime.now(timezone.utc)


def canonical(data):
    return json.dumps(
        data,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def action_spec(task_id):
    return {
        "task_id": task_id,
        "target": TARGET,
        "operation": OPERATION,
        "kind": "demo_noop",
        "arguments": {
            "effect": "print_only",
            "stage": "synthetic_executor_gate",
        },
    }


def initialize_guard(db):
    initialize(db)

    db.execute("""
        CREATE TABLE IF NOT EXISTS executor_approval_contracts (
            approval_id TEXT PRIMARY KEY,
            task_id INTEGER NOT NULL,
            target TEXT NOT NULL,
            operation TEXT NOT NULL,
            action_json TEXT NOT NULL,
            action_hash TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            consumed_at TEXT,
            FOREIGN KEY (approval_id)
                REFERENCES checkpoint_events(id),
            FOREIGN KEY (task_id)
                REFERENCES tasks(id)
        )
    """)

    db.commit()


def create_request(db, task_id):
    row = db.execute(
        "SELECT id FROM tasks WHERE id = ?",
        (task_id,),
    ).fetchone()

    if row is None:
        raise ValueError(
            f"Task {task_id} does not exist"
        )

    spec_json = canonical(action_spec(task_id))

    digest = hashlib.sha256(
        spec_json.encode("utf-8")
    ).hexdigest()

    expiration = utc_now() + timedelta(
        minutes=TTL_MINUTES
    )

    approval_id = request_approval(
        db,
        task_id,
        OPERATION,
        (
            "DEMO ONLY: authorize exactly one print-only "
            f"action for target {TARGET}, task {task_id}, "
            f"hash {digest[:16]}. "
            "No privileged operation will execute."
        ),
    )

    with db:
        db.execute("""
            INSERT INTO executor_approval_contracts
            (
                approval_id,
                task_id,
                target,
                operation,
                action_json,
                action_hash,
                expires_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            approval_id,
            task_id,
            TARGET,
            OPERATION,
            spec_json,
            digest,
            expiration.isoformat(),
        ))

    print("\n[CONTRACT CREATED]")
    print("Approval ID:", approval_id)
    print("Exact action:", spec_json)
    print(
        "Expires at (UTC):",
        expiration.isoformat(),
    )
    print(
        "Execution remains blocked until approved."
    )


def load_contract(db, approval_id):
    row = db.execute("""
        SELECT
            c.approval_id,
            c.task_id,
            c.target,
            c.operation,
            c.action_json,
            c.action_hash,
            c.expires_at,
            c.consumed_at,
            e.status,
            e.kind,
            e.task_id,
            e.operation
        FROM executor_approval_contracts AS c
        JOIN checkpoint_events AS e
          ON e.id = c.approval_id
        WHERE c.approval_id = ?
    """, (approval_id,)).fetchone()

    if row is None:
        raise ValueError(
            "Unknown approval contract"
        )

    return row


def check_contract(row):
    (
        approval_id,
        task_id,
        target,
        operation,
        raw,
        digest,
        expires,
        consumed,
        approval_status,
        kind,
        event_task,
        event_operation,
    ) = row

    expected = canonical(
        action_spec(task_id)
    )

    actual_hash = hashlib.sha256(
        raw.encode("utf-8")
    ).hexdigest()

    if not (
        target == TARGET
        and operation == OPERATION
        and raw == expected
        and actual_hash == digest
        and kind == "approval"
        and event_task == task_id
        and event_operation == operation
    ):
        raise ValueError(
            "Contract scope or integrity mismatch"
        )

    if consumed is not None:
        return "consumed"

    if (
        datetime.fromisoformat(expires)
        <= utc_now()
    ):
        return "expired"

    return approval_status


def status(db, approval_id):
    row = load_contract(
        db,
        approval_id,
    )

    state = check_contract(row)

    print(
        "[CONTRACT STATUS]",
        state,
    )
    print(
        "Approval ID:",
        approval_id,
    )
    print(
        "Task:",
        row[1],
        "| Target:",
        row[2],
        "| Operation:",
        row[3],
    )

    return state


def execute_demo(db, approval_id):
    # Lock the SQLite database for writes before
    # checking and consuming the approval.
    db.execute("BEGIN IMMEDIATE")

    try:
        row = load_contract(
            db,
            approval_id,
        )

        state = check_contract(row)

        if state != "approved":
            raise ValueError(
                f"Execution blocked: {state}"
            )

        cursor = db.execute("""
            UPDATE executor_approval_contracts
            SET consumed_at = ?
            WHERE approval_id = ?
              AND consumed_at IS NULL
        """, (
            utc_now().isoformat(),
            approval_id,
        ))

        if cursor.rowcount != 1:
            raise ValueError(
                "Approval already consumed"
            )

        db.commit()

    except Exception:
        db.rollback()
        raise

    # No subprocess, sudo, network operation,
    # or actual privilege escalation.
    print(
        "[AUTHORIZED DEMO] "
        "One-time approval consumed."
    )
    print(
        "Action: demo_noop | "
        "Effect: print_only"
    )
    print(
        "No privileged operation executed."
    )


def main():
    parser = argparse.ArgumentParser()

    sub = parser.add_subparsers(
        dest="command",
        required=True,
    )

    create = sub.add_parser(
        "request"
    )
    create.add_argument(
        "--task-id",
        required=True,
        type=int,
    )

    for name in (
        "status",
        "execute-demo",
    ):
        command = sub.add_parser(name)
        command.add_argument(
            "--id",
            required=True,
        )

    args = parser.parse_args()

    try:
        with sqlite3.connect(
            DATABASE,
            timeout=10,
        ) as db:

            db.execute(
                "PRAGMA foreign_keys=ON"
            )

            initialize_guard(db)

            if args.command == "request":
                create_request(
                    db,
                    args.task_id,
                )

            elif args.command == "status":
                status(
                    db,
                    args.id,
                )

            elif args.command == "execute-demo":
                execute_demo(
                    db,
                    args.id,
                )

    except (
        sqlite3.Error,
        ValueError,
    ) as exc:
        print("[BLOCKED]", exc)
        raise SystemExit(1)


if __name__ == "__main__":
    main()
