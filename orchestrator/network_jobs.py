
"""
Pentest Master - Network Job Manager v1.

Turns saved, validated network plans into
persistent execution jobs and observations.

No model API calls are made by this module.

Important:
- No shell=True.
- Commands are rebuilt from typed parameters.
- Task scope is checked again before execution.
- RFC 5737 documentation addresses are not scanned.
- Results are distinguished from planned operations.
- Existing successful jobs are not rerun by default.
"""

import argparse
import ipaddress
import json
import re
import sqlite3
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path("/home/lucky/pentest-master")
DATABASE = ROOT / "storage/tasks.db"
PYTHON = ROOT / ".venv/bin/python"
EXECUTOR = ROOT / "executor/network_executor_isolated.py"

sys.path.insert(0, str(ROOT))

from executor.task_scope import check_action


DOCUMENTATION_NETWORKS = (
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
)


def now():
    return datetime.now(timezone.utc).isoformat()


def emit(value):
    print(json.dumps(
        value,
        ensure_ascii=False,
        indent=2,
    ))


def initialize(db):
    db.execute("""
        CREATE TABLE IF NOT EXISTS network_job_runs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            plan_id INTEGER NOT NULL,
            attempt INTEGER NOT NULL,
            status TEXT NOT NULL,
            command_json TEXT NOT NULL,
            result_json TEXT,
            error TEXT,
            started_at TEXT NOT NULL,
            finished_at TEXT,
            UNIQUE(plan_id, attempt),
            FOREIGN KEY(plan_id)
                REFERENCES network_phase_plans(id)
        )
    """)

    db.execute("""
        CREATE TABLE IF NOT EXISTS network_observations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            run_id INTEGER NOT NULL,
            task_id INTEGER NOT NULL,
            target TEXT NOT NULL,
            kind TEXT NOT NULL,
            data_json TEXT NOT NULL,
            observed_at TEXT NOT NULL,
            FOREIGN KEY(run_id)
                REFERENCES network_job_runs(id)
        )
    """)

    db.execute("""
        CREATE INDEX IF NOT EXISTS
        idx_network_observations_task
        ON network_observations(task_id)
    """)

    db.commit()


def load_plan(db, plan_id):
    row = db.execute("""
        SELECT
            id,
            task_id,
            goal,
            profile,
            target,
            parameters_json,
            status
        FROM network_phase_plans
        WHERE id = ?
    """, (plan_id,)).fetchone()

    if row is None:
        raise ValueError(
            "Network plan not found"
        )

    plan = {
        "id": row[0],
        "task_id": row[1],
        "goal": row[2],
        "profile": row[3],
        "target": row[4],
        "parameters": json.loads(row[5]),
        "status": row[6],
    }

    if plan["status"] != "planned":
        raise ValueError(
            "Source plan has an unexpected status"
        )

    return plan


CAPABILITY_ALLOWED_ARGS = {
    "exec": {"argv", "timeout"},
    "poc_run": {"poc_file", "interp", "timeout"},
    "research": {"host", "path", "timeout"},
}

RESEARCH_HOSTS = (
    "nvd.nist.gov",
    "services.nvd.nist.gov",
    "exploit-db.com",
    "www.exploit-db.com",
    "api.github.com",
)

POC_INTERPRETERS = ("bash", "sh", "python3", "perl")

PROFILE_TIMEOUTS = {
    "exec": 200,
    "poc_run": 200,
    "research": 60,
    "callback": 60,
}


def build_capability_args(command, profile, params):
    """Validate agent-supplied capability parameters before handing them to the broker."""
    allowed = CAPABILITY_ALLOWED_ARGS[profile]

    if not set(params) <= allowed:
        raise ValueError("Unexpected capability profile parameters")

    timeout = params.get("timeout", 0)

    if timeout and (
        isinstance(timeout, bool)
        or not isinstance(timeout, int)
        or not 1 <= timeout <= 600
    ):
        raise ValueError("Invalid profile timeout")

    if profile == "exec":
        argv = params.get("argv")

        if (
            not isinstance(argv, list)
            or not argv
            or not all(isinstance(item, str) and item for item in argv)
        ):
            raise ValueError("exec requires a non-empty argv list")

        if len(argv) > 64 or any(len(item) > 4096 for item in argv):
            raise ValueError("exec argv is too large")

        if not argv[0].startswith("/"):
            raise ValueError("exec argv[0] must be absolute")

        command.extend([
            "--argv-json",
            json.dumps(argv, ensure_ascii=False),
        ])

    elif profile == "poc_run":
        poc_file = params.get("poc_file")
        interp = params.get("interp", "bash")

        if not isinstance(poc_file, str) or not poc_file.startswith("/"):
            raise ValueError("poc_run requires an absolute poc_file")

        if interp not in POC_INTERPRETERS:
            raise ValueError("Unsupported PoC interpreter")

        command.extend([
            "--poc-file",
            poc_file,
            "--poc-interp",
            interp,
        ])

    else:
        host = params.get("host")
        path = params.get("path", "/")

        if host not in RESEARCH_HOSTS:
            raise ValueError("Research host is not allowlisted")

        if (
            not isinstance(path, str)
            or not path.startswith("/")
            or len(path) > 512
        ):
            raise ValueError("Invalid research path")

        command.extend([
            "--research-host",
            host,
            "--path",
            path,
        ])

    if timeout:
        command.extend(["--timeout", str(timeout)])


def build_callback_command(plan, params):
    if not set(params) <= {"action", "port", "bind", "timeout"}:
        raise ValueError("Unexpected callback parameters")

    action = params.get("action")

    if action not in ("open", "read", "close"):
        raise ValueError("Invalid callback action")

    command = [
        str(PYTHON),
        str(EXECUTOR),
        "callback",
        "--task-id",
        str(plan["task_id"]),
        "--action",
        action,
    ]

    port = params.get("port", 0)

    if port:
        if (
            isinstance(port, bool)
            or not isinstance(port, int)
            or not 1024 <= port <= 65535
        ):
            raise ValueError("Invalid callback port")

        command.extend(["--port", str(port)])

    bind = params.get("bind", "")

    if bind:
        if not isinstance(bind, str):
            raise ValueError("Invalid callback bind address")

        ipaddress.ip_address(bind)
        command.extend(["--bind", bind])

    timeout = params.get("timeout", 0)

    if timeout:
        if (
            isinstance(timeout, bool)
            or not isinstance(timeout, int)
            or not 10 <= timeout <= 3600
        ):
            raise ValueError("Invalid callback timeout")

        command.extend(["--timeout", str(timeout)])

    return command


def validate_plan(db, plan):
    address = ipaddress.ip_address(
        plan["target"]
    )

    if address.version != 4:
        raise ValueError(
            "Only IPv4 is supported"
        )

    decision = check_action(
        db,
        plan["task_id"],
        "connect",
        str(address),
    )

    if decision["decision"] != "ALLOW":
        raise ValueError(
            decision["reason"]
        )

    params = plan["parameters"]

    if not isinstance(params, dict):
        raise ValueError(
            "Invalid stored parameters"
        )

    profile = plan["profile"]

    if profile == "callback":
        return build_callback_command(
            plan,
            params,
        )

    command = [
        str(PYTHON),
        str(EXECUTOR),
        "run",
        "--task-id",
        str(plan["task_id"]),
        "--profile",
        profile,
        "--target",
        str(address),
    ]

    if profile == "tcp_ports":
        if set(params) != {"ports"}:
            raise ValueError(
                "Unexpected TCP profile parameters"
            )

        raw = params["ports"]

        if not isinstance(raw, str):
            raise ValueError(
                "TCP ports must be a string"
            )

        parts = raw.split(",")

        if not 1 <= len(parts) <= 32:
            raise ValueError(
                "Expected 1..32 TCP ports"
            )

        numbers = []

        for item in parts:
            if not re.fullmatch(
                r"[0-9]{1,5}",
                item,
            ):
                raise ValueError(
                    "Invalid TCP port specification"
                )

            number = int(item)

            if not 1 <= number <= 65535:
                raise ValueError(
                    "TCP port outside valid range"
                )

            numbers.append(number)

        if len(set(numbers)) != len(numbers):
            raise ValueError(
                "Duplicate TCP ports"
            )

        command.extend([
            "--ports",
            ",".join(str(x) for x in numbers),
        ])

    elif profile == "http_headers":
        if set(params) != {"port"}:
            raise ValueError(
                "Unexpected HTTP profile parameters"
            )

        port = params["port"]

        if (
            isinstance(port, bool)
            or not isinstance(port, int)
            or not 1 <= port <= 65535
        ):
            raise ValueError(
                "Invalid HTTP port"
            )

        command.extend([
            "--port",
            str(port),
        ])

    elif profile in (
        "exec",
        "poc_run",
        "research",
    ):
        build_capability_args(
            command,
            profile,
            params,
        )

    else:
        raise ValueError(
            "Unknown network profile"
        )

    return command


def documentation_address(target):
    address = ipaddress.ip_address(target)

    return any(
        address in network
        for network in DOCUMENTATION_NETWORKS
    )


def parse_observations(profile, target, stdout, params=None, result=None):
    """
    Extract conservative factual observations.

    Nmap's SERVICE column without -sV is treated
    as a hint, not verified service identification.
    """

    observations = []
    params = params or {}
    result = result or {}

    if profile == "tcp_ports":
        pattern = re.compile(
            r"^(\d+)/tcp\s+open\s+(\S+)",
            re.MULTILINE,
        )

        for match in pattern.finditer(stdout):
            observations.append({
                "kind": "tcp_port_open",
                "data": {
                    "port": int(match.group(1)),
                    "protocol": "tcp",
                    "state": "open",
                    "service_hint": match.group(2),
                    "service_verified": False,
                },
            })

    elif profile == "http_headers":
        lines = stdout.splitlines()

        status_line = next(
            (
                line.strip()
                for line in lines
                if line.startswith("HTTP/")
            ),
            None,
        )

        if status_line:
            headers = {}

            for name in (
                "Server",
                "Content-Type",
                "Location",
            ):
                for line in lines:
                    if line.lower().startswith(
                        name.lower() + ":"
                    ):
                        headers[name] = (
                            line.split(":", 1)[1].strip()
                        )
                        break

            observations.append({
                "kind": "http_response",
                "data": {
                    "status_line": status_line,
                    "headers": headers,
                },
            })

    elif profile in ("exec", "poc_run"):
        body = result.get("stdout") or ""

        observations.append({
            "kind": "exec_output" if profile == "exec" else "poc_output",
            "data": {
                "executable": result.get("executable"),
                "exit_code": result.get("exit_code"),
                "status": result.get("status"),
                "argv": (
                    params.get("argv")
                    if profile == "exec"
                    else params.get("poc_file")
                ),
                "interpreter": params.get("interp"),
                "stdout": body[:120000],
                "stdout_truncated": bool(result.get("stdout_truncated")),
                "stderr": (result.get("stderr") or "")[:4000],
            },
        })

    elif profile == "research":
        body = result.get("stdout") or ""

        observations.append({
            "kind": "research_result",
            "data": {
                "host": params.get("host"),
                "path": params.get("path"),
                "status": result.get("status"),
                "bytes": len(body),
                "truncated": bool(result.get("stdout_truncated")),
                "body": body[:200000],
            },
        })

    elif profile == "callback":
        observations.append({
            "kind": "callback_state",
            "data": {
                "action": params.get("action"),
                "port": params.get("port"),
                "status": result.get("status"),
                "accepts_from": result.get("accepts_from"),
                "pid": result.get("pid"),
                "entries": result.get("entries") or [],
                "killed": result.get("killed") or [],
            },
        })

    return observations


def completed_run(db, plan_id):
    return db.execute("""
        SELECT id
        FROM network_job_runs
        WHERE plan_id = ?
          AND status = 'completed'
        ORDER BY id DESC
        LIMIT 1
    """, (plan_id,)).fetchone()


def execute_job(db, plan_id):
    plan = load_plan(db, plan_id)
    command = validate_plan(db, plan)

    if documentation_address(plan["target"]):
        raise ValueError(
            "Documentation target: live execution disabled"
        )

    if completed_run(db, plan_id):
        raise ValueError(
            "Plan already completed. "
            "Existing result can be inspected."
        )

    running = db.execute("""
        SELECT id
        FROM network_job_runs
        WHERE plan_id = ?
          AND status = 'running'
        LIMIT 1
    """, (plan_id,)).fetchone()

    if running:
        raise ValueError(
            "Plan already has a running attempt. "
            "Inspect or recover it before retrying."
        )

    command.append("--execute")

    try:
        db.execute("BEGIN IMMEDIATE")

        row = db.execute("""
            SELECT COALESCE(MAX(attempt), 0)
            FROM network_job_runs
            WHERE plan_id = ?
        """, (plan_id,)).fetchone()

        attempt = row[0] + 1

        cursor = db.execute("""
            INSERT INTO network_job_runs (
                plan_id,
                attempt,
                status,
                command_json,
                started_at
            )
            VALUES (?, ?, 'running', ?, ?)
        """, (
            plan_id,
            attempt,
            json.dumps(command),
            now(),
        ))

        run_id = cursor.lastrowid
        db.commit()

    except Exception:
        db.rollback()
        raise

    result = None
    error = None
    status = "failed"

    try:
        completed = subprocess.run(
            command,
            cwd=str(ROOT),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            errors="replace",
            timeout=PROFILE_TIMEOUTS.get(plan["profile"], 40),
            check=False,
        )

        try:
            result = json.loads(
                completed.stdout.strip()
            )
        except (ValueError, TypeError):
            error = (
                "Executor returned invalid JSON: "
                + completed.stderr[-1500:]
            )

        if isinstance(result, dict):
            executor_status = result.get(
                "status"
            )

            if (
                plan["profile"] == "callback"
                and completed.returncode == 0
                and executor_status in (
                    "listening",
                    "ok",
                    "closed",
                    "listener_exit",
                )
            ):
                status = "completed"

            elif (
                executor_status in ("completed", "error")
                and completed.returncode == 0
                and result.get("task_id") == plan["task_id"]
                and result.get("target") == plan["target"]
                and result.get("profile") == plan["profile"]
                and (
                    result.get("exit_code") == 0
                    or plan["profile"] in ("exec", "poc_run")
                )
            ):
                status = "completed"

            elif executor_status == "timeout":
                status = "timeout"
                error = "Executor operation timed out"

            else:
                error = (
                    result.get("error")
                    or result.get("stderr")
                    or "Executor operation failed"
                )

    except subprocess.TimeoutExpired:
        status = "timeout"
        error = "Network Executor timed out"

    except OSError as exc:
        error = str(exc)

    observations = []

    if status == "completed":
        observations = parse_observations(
            plan["profile"],
            plan["target"],
            result.get("stdout", ""),
            # load_plan() already decodes parameters_json into plan["parameters"].
            result.get("parameters") or plan.get("parameters") or {},
            result,
        )

    with db:
        db.execute("""
            UPDATE network_job_runs
            SET status = ?,
                result_json = ?,
                error = ?,
                finished_at = ?
            WHERE id = ?
        """, (
            status,
            json.dumps(
                result,
                ensure_ascii=False,
            ) if result is not None else None,
            error,
            now(),
            run_id,
        ))

        for observation in observations:
            db.execute("""
                INSERT INTO network_observations (
                    run_id,
                    task_id,
                    target,
                    kind,
                    data_json,
                    observed_at
                )
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                run_id,
                plan["task_id"],
                plan["target"],
                observation["kind"],
                json.dumps(
                    observation["data"],
                    ensure_ascii=False,
                ),
                now(),
            ))

    return {
        "run_id": run_id,
        "plan_id": plan_id,
        "status": status,
        "observations_saved": len(observations),
        "error": error,
    }


def list_jobs(db, task_id):
    rows = db.execute("""
        SELECT
            p.id,
            p.profile,
            p.target,
            p.status,
            r.id,
            r.status
        FROM network_phase_plans AS p
        LEFT JOIN network_job_runs AS r
          ON r.id = (
              SELECT MAX(r2.id)
              FROM network_job_runs AS r2
              WHERE r2.plan_id = p.id
          )
        WHERE p.task_id = ?
        ORDER BY p.id
    """, (task_id,)).fetchall()

    return [
        {
            "plan_id": row[0],
            "profile": row[1],
            "target": row[2],
            "plan_status": row[3],
            "last_run_id": row[4],
            "last_run_status": row[5],
        }
        for row in rows
    ]


def list_observations(db, task_id):
    rows = db.execute("""
        SELECT
            o.id,
            o.run_id,
            o.target,
            o.kind,
            o.data_json,
            o.observed_at
        FROM network_observations AS o
        JOIN network_job_runs AS r
          ON r.id = o.run_id
        WHERE o.task_id = ?
          AND r.status = 'completed'
        ORDER BY o.id
    """, (task_id,)).fetchall()

    return [
        {
            "id": row[0],
            "run_id": row[1],
            "target": row[2],
            "kind": row[3],
            "data": json.loads(row[4]),
            "observed_at": row[5],
        }
        for row in rows
    ]


def self_test():
    nmap_sample = (
        "PORT     STATE SERVICE\n"
        "22/tcp   open  ssh\n"
        "8080/tcp open  http-proxy\n"
    )

    http_sample = (
        "HTTP/1.0 200 OK\n"
        "Content-Type: text/plain\n"
        "Server: TestServer\n"
    )

    ports = parse_observations(
        "tcp_ports",
        "127.0.0.1",
        nmap_sample,
    )

    http = parse_observations(
        "http_headers",
        "127.0.0.1",
        http_sample,
    )

    assert len(ports) == 2
    assert ports[0]["data"]["port"] == 22
    assert ports[1]["data"]["port"] == 8080
    assert ports[0]["data"]["service_verified"] is False

    assert len(http) == 1
    assert http[0]["data"]["status_line"] == (
        "HTTP/1.0 200 OK"
    )

    emit({
        "status": "completed",
        "test": "observation_parsing",
        "tcp_observations": ports,
        "http_observations": http,
        "note": (
            "Synthetic parser fixtures only. "
            "No live network probe was performed."
        ),
    })


def main():
    parser = argparse.ArgumentParser()

    sub = parser.add_subparsers(
        dest="command",
        required=True,
    )

    sub.add_parser("self-test")

    show = sub.add_parser("list")
    show.add_argument(
        "--task-id",
        type=int,
        required=True,
    )

    evidence = sub.add_parser("observations")
    evidence.add_argument(
        "--task-id",
        type=int,
        required=True,
    )

    inspect = sub.add_parser("inspect")
    inspect.add_argument(
        "--plan-id",
        type=int,
        required=True,
    )

    run = sub.add_parser("run")
    run.add_argument(
        "--plan-id",
        type=int,
        required=True,
    )

    args = parser.parse_args()

    try:
        if args.command == "self-test":
            self_test()
            return

        with sqlite3.connect(DATABASE) as db:
            db.execute(
                "PRAGMA foreign_keys = ON"
            )

            initialize(db)

            if args.command == "list":
                emit(list_jobs(
                    db,
                    args.task_id,
                ))

            elif args.command == "observations":
                emit(list_observations(
                    db,
                    args.task_id,
                ))

            elif args.command == "inspect":
                plan = load_plan(
                    db,
                    args.plan_id,
                )

                command = validate_plan(
                    db,
                    plan,
                )

                emit({
                    "status": "ready_for_execution",
                    "plan_id": plan["id"],
                    "target": plan["target"],
                    "profile": plan["profile"],
                    "command": command,
                    "live_execution_allowed": (
                        not documentation_address(
                            plan["target"]
                        )
                    ),
                })

            elif args.command == "run":
                emit(execute_job(
                    db,
                    args.plan_id,
                ))

    except (
        ValueError,
        AssertionError,
        OSError,
        sqlite3.Error,
        json.JSONDecodeError,
    ) as exc:
        emit({
            "status": "blocked",
            "error": str(exc),
        })
        raise SystemExit(1)


if __name__ == "__main__":
    main()
