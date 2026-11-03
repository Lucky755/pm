
"""
Pentest Master - Task Scope Manager v1.

Stores the authorized target and optional lab networks.

Pivoting and port forwarding are allowed automatically
when both the intermediate host and destination
are already in the task's authorized scope.

This module does not execute networking commands.
"""

import argparse
import ipaddress
import json
import sqlite3
from pathlib import Path


DATABASE = Path("/home/lucky/pentest-master/storage/tasks.db")

OPERATIONS = {
    "scan",
    "connect",
    "pivot",
    "port_forward",
}


def parse_ip(value):
    try:
        return ipaddress.ip_address(value)
    except ValueError as exc:
        raise ValueError(
            f"Invalid IP address: {value}"
        ) from exc


def parse_network(value):
    try:
        network = ipaddress.ip_network(
            value,
            strict=True,
        )
    except ValueError as exc:
        raise ValueError(
            f"Invalid network: {value}"
        ) from exc

    if network.prefixlen == 0:
        raise ValueError(
            "Unrestricted /0 networks are not allowed"
        )

    return network


def initialize(db):
    db.execute("""
        CREATE TABLE IF NOT EXISTS task_scope_settings (
            task_id INTEGER PRIMARY KEY,
            initial_target TEXT NOT NULL,
            allow_pivot INTEGER NOT NULL DEFAULT 1,
            allow_port_forward INTEGER NOT NULL DEFAULT 1,
            FOREIGN KEY (task_id) REFERENCES tasks(id)
        )
    """)

    db.execute("""
        CREATE TABLE IF NOT EXISTS task_scope_networks (
            task_id INTEGER NOT NULL,
            network TEXT NOT NULL,
            PRIMARY KEY (task_id, network),
            FOREIGN KEY (task_id) REFERENCES tasks(id)
        )
    """)

    db.commit()


def init_task_scope(db, task_id):
    row = db.execute(
        "SELECT target FROM tasks WHERE id = ?",
        (task_id,),
    ).fetchone()

    if row is None:
        raise ValueError("Task not found")

    target = str(parse_ip(row[0]))

    existing = db.execute("""
        SELECT initial_target
        FROM task_scope_settings
        WHERE task_id = ?
    """, (task_id,)).fetchone()

    if existing is not None:
        if existing[0] != target:
            raise ValueError(
                "Task target changed after scope initialization"
            )

        print("[EXISTS] Scope already initialized")
        return

    with db:
        db.execute("""
            INSERT INTO task_scope_settings
            (task_id, initial_target, allow_pivot, allow_port_forward)
            VALUES (?, ?, 1, 1)
        """, (task_id, target))

    print("[SCOPE CREATED]")
    print("Task:", task_id)
    print("Initial authorized target:", target)
    print("Pivoting within scope: enabled")
    print("Port forwarding within scope: enabled")


def require_scope(db, task_id):
    row = db.execute("""
        SELECT initial_target, allow_pivot, allow_port_forward
        FROM task_scope_settings
        WHERE task_id = ?
    """, (task_id,)).fetchone()

    if row is None:
        raise ValueError(
            "Scope not initialized for this task"
        )

    return row


def add_network(db, task_id, value):
    require_scope(db, task_id)

    network = parse_network(value)

    with db:
        db.execute("""
            INSERT OR IGNORE INTO task_scope_networks
            (task_id, network)
            VALUES (?, ?)
        """, (
            task_id,
            str(network),
        ))

    print("[SCOPE UPDATED]")
    print("Task:", task_id)
    print("Authorized network:", network)


def allowed_networks(db, task_id):
    rows = db.execute("""
        SELECT network
        FROM task_scope_networks
        WHERE task_id = ?
    """, (task_id,)).fetchall()

    return [
        parse_network(row[0])
        for row in rows
    ]


def address_allowed(db, task_id, address):
    initial_target, _, _ = require_scope(
        db, task_id
    )

    ip = parse_ip(address)

    if ip == parse_ip(initial_target):
        return True

    return any(
        ip in network
        for network in allowed_networks(db, task_id)
    )


def check_action(
    db,
    task_id,
    operation,
    destination,
    via=None,
):
    if operation not in OPERATIONS:
        raise ValueError(
            f"Unsupported operation: {operation}"
        )

    _, allow_pivot, allow_forward = require_scope(
        db, task_id
    )

    destination = str(parse_ip(destination))

    if not address_allowed(
        db,
        task_id,
        destination,
    ):
        return {
            "decision": "DENY",
            "reason": "Destination outside authorized scope",
        }

    if operation in ("pivot", "port_forward"):
        if not via:
            return {
                "decision": "DENY",
                "reason": "Intermediate host is required",
            }

        via = str(parse_ip(via))

        if not address_allowed(
            db,
            task_id,
            via,
        ):
            return {
                "decision": "DENY",
                "reason": "Intermediate host outside scope",
            }

        if operation == "pivot" and not allow_pivot:
            return {
                "decision": "DENY",
                "reason": "Pivoting disabled",
            }

        if (
            operation == "port_forward"
            and not allow_forward
        ):
            return {
                "decision": "DENY",
                "reason": "Port forwarding disabled",
            }

    return {
        "decision": "ALLOW",
        "reason": "Operation within authorized task scope",
    }


def show_scope(db, task_id):
    target, allow_pivot, allow_forward = require_scope(
        db, task_id
    )

    result = {
        "task_id": task_id,
        "initial_target": target,
        "additional_networks": [
            str(network)
            for network in allowed_networks(db, task_id)
        ],
        "allow_pivot": bool(allow_pivot),
        "allow_port_forward": bool(allow_forward),
    }

    print(json.dumps(
        result,
        ensure_ascii=False,
        indent=2,
    ))


def main():
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(
        dest="command",
        required=True,
    )

    init_cmd = sub.add_parser("init")
    init_cmd.add_argument("--task-id", type=int, required=True)

    show_cmd = sub.add_parser("show")
    show_cmd.add_argument("--task-id", type=int, required=True)

    add_cmd = sub.add_parser("allow-network")
    add_cmd.add_argument("--task-id", type=int, required=True)
    add_cmd.add_argument("--network", required=True)

    check_cmd = sub.add_parser("check")
    check_cmd.add_argument("--task-id", type=int, required=True)
    check_cmd.add_argument(
        "--operation",
        required=True,
        choices=sorted(OPERATIONS),
    )
    check_cmd.add_argument("--destination", required=True)
    check_cmd.add_argument("--via")

    args = parser.parse_args()

    try:
        with sqlite3.connect(DATABASE) as db:
            db.execute("PRAGMA foreign_keys = ON")
            initialize(db)

            if args.command == "init":
                init_task_scope(db, args.task_id)

            elif args.command == "show":
                show_scope(db, args.task_id)

            elif args.command == "allow-network":
                add_network(
                    db,
                    args.task_id,
                    args.network,
                )

            elif args.command == "check":
                decision = check_action(
                    db,
                    args.task_id,
                    args.operation,
                    args.destination,
                    args.via,
                )

                print(json.dumps(
                    decision,
                    ensure_ascii=False,
                ))

                if decision["decision"] != "ALLOW":
                    raise SystemExit(2)

    except (ValueError, sqlite3.Error) as exc:
        print("[ERROR]", exc)
        raise SystemExit(1)


if __name__ == "__main__":
    main()
