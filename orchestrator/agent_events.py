
"""
Pentest Master - Agent Events v1.

Accepts structured agent-reported events and stores them
in the existing checkpoint_events table.

- Findings create notifications without pausing execution.
- Sensitive-operation requests create pending approvals.
- Repeated events from the same agent step are deduplicated.
- The module NEVER executes an operation or grants approval.

Agent reports are untrusted until independently verified.
"""

import argparse
import hashlib
import json
import sqlite3
import uuid
from datetime import datetime, timezone

from checkpoints import (
    DATABASE,
    APPROVAL_OPERATIONS,
    NOTIFICATIONS,
    initialize,
)

ALLOWED_EVENTS = NOTIFICATIONS | {"approval_request"}
MAX_EVENTS = 10
MAX_MESSAGE = 400


def timestamp():
    return datetime.now(timezone.utc).isoformat()


def init_event_storage(db):
    initialize(db)

    db.execute("""
        CREATE TABLE IF NOT EXISTS agent_event_receipts (
            task_id INTEGER NOT NULL,
            step_index INTEGER NOT NULL,
            event_hash TEXT NOT NULL,
            checkpoint_id TEXT NOT NULL UNIQUE,
            created_at TEXT NOT NULL,
            PRIMARY KEY (task_id, step_index, event_hash),
            FOREIGN KEY (task_id) REFERENCES tasks(id),
            FOREIGN KEY (checkpoint_id)
                REFERENCES checkpoint_events(id)
        )
    """)

    db.commit()


def validate_task_step(db, task_id, step_index):
    row = db.execute(
        "SELECT plan_json FROM tasks WHERE id = ?",
        (task_id,),
    ).fetchone()

    if row is None:
        raise ValueError(f"Unknown task ID: {task_id}")

    plan = json.loads(row[0])
    steps = plan.get("tasks")

    if (
        not isinstance(steps, list)
        or not (0 <= step_index < len(steps))
    ):
        raise ValueError(
            f"Invalid step_index: {step_index}"
        )


def normalize_report(report):
    if (
        not isinstance(report, dict)
        or set(report) != {"summary", "events"}
    ):
        raise ValueError(
            "Report must contain exactly summary and events"
        )

    summary = report["summary"]

    if (
        not isinstance(summary, str)
        or not summary.strip()
        or len(summary) > 4000
    ):
        raise ValueError(
            "Report summary must be a nonempty string "
            "of at most 4000 characters"
        )

    events = report["events"]

    if (
        not isinstance(events, list)
        or len(events) > MAX_EVENTS
    ):
        raise ValueError(
            "events must be a list of up to 10 entries"
        )

    normalized = []

    for event in events:
        if not isinstance(event, dict):
            raise ValueError(
                "Each event must be an object"
            )

        event_type = event.get("type")
        message = event.get("message")

        if (
            not isinstance(event_type, str)
            or event_type not in ALLOWED_EVENTS
        ):
            raise ValueError(
                f"Unsupported event type: {event_type}"
            )

        if (
            not isinstance(message, str)
            or not (1 <= len(message.strip()) <= MAX_MESSAGE)
        ):
            raise ValueError(
                "Event message must contain 1..400 characters"
            )

        if event_type == "approval_request":
            if set(event) != {
                "type",
                "message",
                "operation",
            }:
                raise ValueError(
                    "Approval event must have "
                    "type, message, operation"
                )

            operation = event["operation"]

            if (
                not isinstance(operation, str)
                or operation not in APPROVAL_OPERATIONS
            ):
                raise ValueError(
                    f"Unsupported approval operation: {operation}"
                )

        else:
            if set(event) != {"type", "message"}:
                raise ValueError(
                    "Notification event must have "
                    "only type and message"
                )

            operation = event_type

        normalized.append({
            "type": event_type,
            "operation": operation,
            "message": message.strip(),
        })

    return normalized


def process_agent_report(
    db,
    task_id,
    step_index,
    report,
):
    """
    Record events produced by an agent.

    The Scheduler must supply task_id and step_index.
    Never trust IDs supplied by the model.

    This function does not execute tools or grant approvals.
    """

    validate_task_step(
        db,
        task_id,
        step_index,
    )

    events = normalize_report(report)
    receipts = []

    for event in events:
        canonical = json.dumps(
            event,
            sort_keys=True,
            ensure_ascii=False,
        )

        event_hash = hashlib.sha256(
            canonical.encode("utf-8")
        ).hexdigest()

        event_id = uuid.uuid4().hex

        if event["type"] == "approval_request":
            kind = "approval"
            status = "pending"
        else:
            kind = "notification"
            status = "recorded"

        # Insert checkpoint first to satisfy
        # SQLite foreign key constraints.
        #
        # Both writes are enclosed in one transaction.
        with db:
            db.execute("""
                INSERT INTO checkpoint_events
                (
                    id,
                    task_id,
                    kind,
                    operation,
                    message,
                    status,
                    created_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                event_id,
                task_id,
                kind,
                event["operation"],
                event["message"],
                status,
                timestamp(),
            ))

            cursor = db.execute("""
                INSERT OR IGNORE INTO agent_event_receipts
                (
                    task_id,
                    step_index,
                    event_hash,
                    checkpoint_id,
                    created_at
                )
                VALUES (?, ?, ?, ?, ?)
            """, (
                task_id,
                step_index,
                event_hash,
                event_id,
                timestamp(),
            ))

            is_new = cursor.rowcount == 1

            if not is_new:
                # The same event was recorded earlier.
                # Remove the newly inserted duplicate.
                db.execute("""
                    DELETE FROM checkpoint_events
                    WHERE id = ?
                """, (event_id,))

                event_id = db.execute("""
                    SELECT checkpoint_id
                    FROM agent_event_receipts
                    WHERE task_id = ?
                      AND step_index = ?
                      AND event_hash = ?
                """, (
                    task_id,
                    step_index,
                    event_hash,
                )).fetchone()[0]

        receipts.append({
            "type": event["type"],
            "checkpoint_id": event_id,
            "status": (
                status if is_new
                else "duplicate_skipped"
            ),
        })

    return receipts


def main():
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--task-id",
        type=int,
        required=True,
    )

    parser.add_argument(
        "--demo",
        action="store_true",
        required=True,
    )

    args = parser.parse_args()

    # These reports are deliberately synthetic.
    # They do not describe real agent discoveries.
    demo_cases = [
        (
            0,
            {
                "summary": "DEMO: synthetic Recon event",
                "events": [
                    {
                        "type": "finding",
                        "message": (
                            "DEMO ONLY: synthetic observation; "
                            "no real target evidence"
                        ),
                    }
                ],
            },
        ),
        (
            2,
            {
                "summary": (
                    "DEMO: synthetic Access approval request"
                ),
                "events": [
                    {
                        "type": "approval_request",
                        "operation": "privilege_escalation",
                        "message": (
                            "DEMO ONLY: request for a fictional "
                            "privileged stage; no execution"
                        ),
                    }
                ],
            },
        ),
    ]

    try:
        with sqlite3.connect(DATABASE) as db:
            db.execute("PRAGMA foreign_keys = ON")
            init_event_storage(db)

            for step_index, report in demo_cases:
                receipts = process_agent_report(
                    db,
                    args.task_id,
                    step_index,
                    report,
                )

                for receipt in receipts:
                    print(json.dumps(
                        {
                            "step": step_index,
                            **receipt,
                        },
                        ensure_ascii=False,
                    ))

        print(
            "[DONE] Events recorded. "
            "No agent operation executed."
        )

    except (
        ValueError,
        TypeError,
        sqlite3.Error,
    ) as exc:
        print("[ERROR]", exc)
        raise SystemExit(1)


if __name__ == "__main__":
    main()
