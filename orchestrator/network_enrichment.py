
"""
Pentest Master: evidence-driven Network Executor v2 queue integration.

Uses existing network_phase_plans, network_job_runs,
and network_observations tables.

Nothing executes until the operator explicitly
invokes the execute command.
"""

import argparse
import hashlib
import ipaddress
import json
import re
import sqlite3
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path("/home/lucky/pentest-master")
sys.path.insert(0, str(ROOT))

from executor.task_scope import check_action
from orchestrator.network_jobs import initialize
from orchestrator.network_workflow import build_evidence_bundle


DB_PATH = ROOT / "storage/tasks.db"
PYTHON = ROOT / ".venv/bin/python"
EXECUTOR = ROOT / "executor/network_executor_isolated.py"

DOC_NETS = tuple(
    ipaddress.ip_network(network)
    for network in (
        "192.0.2.0/24",
        "198.51.100.0/24",
        "203.0.113.0/24",
    )
)

MAX_SUGGESTIONS = 12


def timestamp():
    return datetime.now(timezone.utc).isoformat()


def output(value):
    print(json.dumps(
        value,
        indent=2,
        ensure_ascii=False,
    ))


def get_target(db, task_id):
    row = db.execute("""
        SELECT t.target, s.initial_target
        FROM tasks t
        JOIN task_scope_settings s
          ON s.task_id = t.id
        WHERE t.id = ?
    """, (task_id,)).fetchone()

    if not row or row[0] != row[1]:
        raise ValueError(
            "Task missing or initial target changed"
        )

    return row[0]


def verify_scope(db, task_id, target):
    ipaddress.IPv4Address(target)

    decision = check_action(
        db,
        task_id,
        "connect",
        target,
    )

    if decision["decision"] != "ALLOW":
        raise ValueError(
            "Target outside task scope"
        )


def get_candidates(db, task_id):
    """
    Derive follow-up candidates only from observations
    linked to completed network jobs.
    """

    get_target(db, task_id)

    rows = db.execute("""
        SELECT
            o.id,
            o.kind,
            o.target,
            o.data_json,
            p.profile,
            p.parameters_json
        FROM network_observations o
        JOIN network_job_runs r
          ON r.id = o.run_id
        JOIN network_phase_plans p
          ON p.id = r.plan_id
        WHERE o.task_id = ?
          AND p.task_id = ?
          AND r.status = 'completed'
          AND p.target = o.target
        ORDER BY o.id
    """, (task_id, task_id)).fetchall()

    candidates = {}

    for (
        obs_id,
        kind,
        target,
        data_raw,
        source_profile,
        raw_params,
    ) in rows:

        verify_scope(
            db,
            task_id,
            target,
        )

        data = json.loads(data_raw)
        params = json.loads(raw_params)

        if (
            kind == "tcp_port_open"
            and data.get("state") == "open"
            and data.get("protocol") == "tcp"
        ):
            port = data.get("port")

            if type(port) is int and 1 <= port <= 65535:
                key = (
                    "service_versions",
                    target,
                    port,
                )

                candidates.setdefault(key, {
                    "profile": "service_versions",
                    "target": target,
                    "parameters": {
                        "ports": str(port),
                    },
                    "source_observation_id": obs_id,
                })

        elif (
            kind == "http_response"
            and source_profile in (
                "http_headers",
                "https_headers",
            )
        ):
            port = params.get("port")

            if (
                type(port) is int
                and 1 <= port <= 65535
                and str(
                    data.get("status_line", "")
                ).startswith("HTTP/")
            ):
                scheme = (
                    "https"
                    if source_profile == "https_headers"
                    else "http"
                )

                key = (
                    "http_get",
                    target,
                    port,
                    scheme,
                )

                candidates.setdefault(key, {
                    "profile": "http_get",
                    "target": target,
                    "parameters": {
                        "port": port,
                        "scheme": scheme,
                    },
                    "source_observation_id": obs_id,
                })

    return list(candidates.values())[:MAX_SUGGESTIONS]


def command_for(
    task_id,
    profile,
    target,
    parameters,
    execute=False,
):
    """
    Build an invocation of Network Executor v2
    from strictly typed parameters.

    Stored argv strings are never executed directly.
    """

    if profile == "service_versions":
        if set(parameters) != {"ports"}:
            raise ValueError(
                "Unexpected service_versions parameters"
            )

        raw = parameters["ports"]

        if (
            not isinstance(raw, str)
            or not re.fullmatch(r"[0-9]{1,5}", raw)
            or not 1 <= int(raw) <= 65535
        ):
            raise ValueError(
                "Invalid service port"
            )

        extra = [
            "--ports",
            str(int(raw)),
        ]

    elif profile == "http_get":
        if set(parameters) != {
            "port",
            "scheme",
        }:
            raise ValueError(
                "Unexpected http_get parameters"
            )

        port = parameters["port"]
        scheme = parameters["scheme"]

        if (
            type(port) is not int
            or not 1 <= port <= 65535
            or scheme not in ("http", "https")
        ):
            raise ValueError(
                "Invalid HTTP parameters"
            )

        extra = [
            "--port",
            str(port),
            "--scheme",
            scheme,
        ]

    else:
        raise ValueError(
            "Unsupported enrichment profile"
        )

    command = [
        str(PYTHON),
        str(EXECUTOR),
        "run",
        "--task-id",
        str(task_id),
        "--profile",
        profile,
        "--target",
        target,
        *extra,
    ]

    if execute:
        command.append("--execute")

    return command


def executor_call(command, timeout):
    process = subprocess.run(
        command,
        cwd=str(ROOT),
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        errors="replace",
        timeout=timeout,
        check=False,
    )

    try:
        result = json.loads(
            process.stdout
        )

    except json.JSONDecodeError as exc:
        raise ValueError(
            "Executor returned invalid JSON: "
            + process.stderr[-500:]
        ) from exc

    if not isinstance(result, dict):
        raise ValueError(
            "Executor returned non-object JSON"
        )

    return process.returncode, result


def plan_followups(db, task_id, *, include_http_get=True):
    created = []

    for candidate in get_candidates(db, task_id):
        profile = candidate["profile"]
        if profile == 'http_get' and not include_http_get:
            continue
        target = candidate["target"]
        params = candidate["parameters"]

        encoded = json.dumps(
            params,
            sort_keys=True,
        )

        existing = db.execute("""
            SELECT id
            FROM network_phase_plans
            WHERE task_id = ?
              AND profile = ?
              AND target = ?
              AND parameters_json = ?
            LIMIT 1
        """, (
            task_id,
            profile,
            target,
            encoded,
        )).fetchone()

        if existing:
            continue

        command = command_for(
            task_id,
            profile,
            target,
            params,
        )

        exitcode, planned = executor_call(
            command,
            timeout=15,
        )

        if (
            exitcode != 0
            or planned.get("status") != "planned"
            or planned.get("profile") != profile
            or planned.get("target") != target
            or not isinstance(
                planned.get("argv"), list
            )
        ):
            raise ValueError(
                f"Executor rejected plan: {planned}"
            )

        goal = (
            "Auto enrichment from observation "
            f"#{candidate['source_observation_id']}: "
            f"{profile}"
        )

        with db:
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
                VALUES (?, ?, ?, ?, ?, ?, ?, 'planned', ?)
            """, (
                task_id,
                goal,
                profile,
                target,
                encoded,
                json.dumps(planned["argv"]),
                (
                    "Deterministic follow-up; "
                    "not a confirmed result"
                ),
                timestamp(),
            ))

        if cursor.rowcount:
            created.append({
                **candidate,
                "plan_id": cursor.lastrowid,
            })

    return created


def parse_facts(profile, text, parameters):
    """
    Extract conservative observations.

    Version detection is heuristic.
    HTTP response bodies are untrusted data.
    """

    facts = []

    if profile == "service_versions":
        pattern = re.compile(
            r"(?m)^(\d+)/tcp\s+open\s+"
            r"(\S+)(?:\s+([^\r\n]+))?"
        )

        requested = int(
            parameters["ports"]
        )

        for match in pattern.finditer(text):
            port = int(match.group(1))

            if port != requested:
                continue

            service = match.group(2)
            version = (
                match.group(3) or ""
            ).strip()

            facts.append((
                "service_probe",
                {
                    "port": port,
                    "protocol": "tcp",
                    "service_hint": service.rstrip("?"),
                    "version_hint": version or None,
                    "identification_uncertain": (
                        service.endswith("?")
                        or not bool(version)
                    ),
                    "identification_source": (
                        "nmap_service_detection"
                    ),
                    "verified_product": False,
                },
            ))

    elif profile == "http_get":
        normalized = text.replace(
            "\r\n",
            "\n",
        )

        header, separator, body = (
            normalized.partition("\n\n")
        )

        lines = header.splitlines()

        status_line = (
            lines[0].strip()
            if lines
            else ""
        )

        if (
            separator
            and re.match(
                r"^HTTP/\d(?:\.\d)?\s+\d{3}\b",
                status_line,
            )
        ):
            facts.append((
                "http_content",
                {
                    "port": parameters["port"],
                    "scheme": parameters["scheme"],
                    "status_line": status_line,
                    "body_sha256": hashlib.sha256(
                        body.encode("utf-8")
                    ).hexdigest(),
                    "body_preview": body[:300],
                    "body_text_chars": len(body),
                    "content_is_untrusted": True,
                    "note": (
                        "Digest covers decoded captured "
                        "text, not raw wire bytes"
                    ),
                },
            ))

    return facts


def run_plan(db, plan_id):
    row = db.execute("""
        SELECT
            id,
            task_id,
            profile,
            target,
            parameters_json,
            status
        FROM network_phase_plans
        WHERE id = ?
    """, (plan_id,)).fetchone()

    if not row:
        raise ValueError(
            "Plan does not exist"
        )

    (
        _,
        task_id,
        profile,
        target,
        params_raw,
        status,
    ) = row

    if status != "planned":
        raise ValueError(
            "Plan is not in planned state"
        )

    verify_scope(
        db,
        task_id,
        target,
    )

    if any(
        ipaddress.ip_address(target) in network
        for network in DOC_NETS
    ):
        raise ValueError(
            "No live execution against "
            "documentation addresses"
        )

    params = json.loads(params_raw)

    command = command_for(
        task_id,
        profile,
        target,
        params,
        execute=True,
    )

    db.execute("BEGIN IMMEDIATE")

    try:
        latest = db.execute("""
            SELECT status
            FROM network_job_runs
            WHERE plan_id = ?
            ORDER BY id DESC
            LIMIT 1
        """, (plan_id,)).fetchone()

        if latest and latest[0] == "completed":
            db.rollback()

            return {
                "status": "already_completed",
                "plan_id": plan_id,
            }

        if latest and latest[0] == "running":
            raise ValueError(
                "Previous attempt still running; "
                "inspect before retry"
            )

        next_attempt = db.execute("""
            SELECT COALESCE(MAX(attempt), 0) + 1
            FROM network_job_runs
            WHERE plan_id = ?
        """, (plan_id,)).fetchone()[0]

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
            next_attempt,
            json.dumps(command),
            timestamp(),
        ))

        run_id = cursor.lastrowid

        db.commit()

    except Exception:
        db.rollback()
        raise

    payload = None
    error = None
    run_status = "failed"

    try:
        code, payload = executor_call(
            command,
            timeout=60,
        )

        if (
            code == 0
            and payload.get("status") == "completed"
            and payload.get("exit_code") == 0
            and payload.get("task_id") == task_id
            and payload.get("profile") == profile
            and payload.get("target") == target
        ):
            run_status = "completed"

        elif payload.get("status") == "timeout":
            run_status = "timeout"
            error = "Network executor timed out"

        else:
            error = str(
                payload.get("error")
                or payload.get("stderr")
                or "Executor failed"
            )[:2000]

    except (
        subprocess.TimeoutExpired,
        ValueError,
        OSError,
    ) as exc:
        run_status = (
            "timeout"
            if isinstance(
                exc,
                subprocess.TimeoutExpired,
            )
            else "failed"
        )

        error = str(exc)[:2000]

    facts = (
        parse_facts(
            profile,
            payload.get("stdout", ""),
            params,
        )
        if run_status == "completed"
        else []
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
            run_status,
            (
                json.dumps(
                    payload,
                    ensure_ascii=False,
                )
                if payload is not None
                else None
            ),
            error,
            timestamp(),
            run_id,
        ))

        for kind, data in facts:
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
                task_id,
                target,
                kind,
                json.dumps(
                    data,
                    ensure_ascii=False,
                ),
                timestamp(),
            ))

    return {
        "status": run_status,
        "plan_id": plan_id,
        "run_id": run_id,
        "observations_saved": len(facts),
        "error": error,
    }


def show_status(db, task_id):
    get_target(db, task_id)

    rows = db.execute("""
        SELECT
            p.id,
            p.profile,
            p.target,
            p.parameters_json,
            (
                SELECT r.status
                FROM network_job_runs r
                WHERE r.plan_id = p.id
                ORDER BY r.id DESC
                LIMIT 1
            )
        FROM network_phase_plans p
        WHERE p.task_id = ?
          AND p.profile IN (
              'service_versions',
              'http_get'
          )
        ORDER BY p.id
    """, (task_id,)).fetchall()

    return [
        {
            "plan_id": row[0],
            "profile": row[1],
            "target": row[2],
            "parameters": json.loads(row[3]),
            "last_run_status": row[4],
        }
        for row in rows
    ]


def main():
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "command",
        choices=(
            "suggest",
            "plan",
            "status",
            "execute",
            "evidence",
        ),
    )

    parser.add_argument(
        "--task-id",
        type=int,
    )

    parser.add_argument(
        "--plan-id",
        type=int,
    )

    args = parser.parse_args()

    try:
        with sqlite3.connect(
            DB_PATH,
            timeout=10,
        ) as db:

            db.execute(
                "PRAGMA foreign_keys = ON"
            )

            db.execute(
                "PRAGMA busy_timeout = 5000"
            )

            initialize(db)

            if args.command == "execute":
                if args.plan_id is None:
                    raise ValueError(
                        "--plan-id required"
                    )

                output(run_plan(
                    db,
                    args.plan_id,
                ))

            else:
                if (
                    args.task_id is None
                    or args.task_id < 1
                ):
                    raise ValueError(
                        "--task-id required"
                    )

                if args.command == "suggest":
                    output(get_candidates(
                        db,
                        args.task_id,
                    ))

                elif args.command == "plan":
                    output({
                        "new_plans": plan_followups(
                            db,
                            args.task_id,
                        ),
                        "all_enrichment_plans": (
                            show_status(
                                db,
                                args.task_id,
                            )
                        ),
                    })

                elif args.command == "status":
                    output(show_status(
                        db,
                        args.task_id,
                    ))

                else:
                    output(build_evidence_bundle(
                        db,
                        args.task_id,
                    ))

    except (
        ValueError,
        OSError,
        sqlite3.Error,
        subprocess.SubprocessError,
    ) as exc:
        output({
            "status": "blocked",
            "error": str(exc),
        })

        raise SystemExit(1)


if __name__ == "__main__":
    main()
