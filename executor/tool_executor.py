
"""
Pentest Master - Tool Executor v2.0

Controlled execution of local analysis tools.

Features:
- Uses installed Kali tool catalog
- Requires an initialized task scope
- Executes only predefined tool profiles
- Isolates execution with Bubblewrap
- Disables networking
- Mounts the artifact workspace read-only
- Enforces timeout and file-size limits
- Saves execution audit records

This stage does not permit network operations,
arbitrary shell commands or privilege escalation.
"""

import argparse
import json
import os
import signal
import sqlite3
import subprocess
from datetime import datetime, timezone
from pathlib import Path

from tool_catalog import detect_tools


ROOT = Path("/home/lucky/pentest-master")
DATABASE = ROOT / "storage/tasks.db"
WORKSPACE = ROOT / "runtime/executor-workspace"
AUDIT_FILE = ROOT / "logs/tool_executor.jsonl"

BWRAP = "/usr/bin/bwrap"

TIMEOUT_SECONDS = 12
MAX_FILE_SIZE = 2 * 1024 * 1024
MAX_OUTPUT = 12000


# Fixed command templates.
# Agent-controlled command-line arguments are not accepted.
TOOL_PROFILES = {
    "file": ["-b", "--"],
    "sha256sum": ["--"],
    "strings": ["-a", "--"],
    "readelf": ["-h", "--"],
    "objdump": ["-f", "--"],
    "xxd": ["-l", "256"],
    "nm": ["-a", "--"],
    "exiftool": ["--"],
}


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def write_audit(record):
    AUDIT_FILE.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    with AUDIT_FILE.open(
        "a",
        encoding="utf-8",
    ) as stream:
        stream.write(
            json.dumps(
                record,
                ensure_ascii=False,
            ) + "\n"
        )


def require_task_scope(task_id):
    with sqlite3.connect(DATABASE) as db:
        row = db.execute("""
            SELECT
                t.target,
                s.initial_target
            FROM tasks AS t
            JOIN task_scope_settings AS s
              ON s.task_id = t.id
            WHERE t.id = ?
        """, (task_id,)).fetchone()

    if row is None:
        raise ValueError(
            "Task or initialized scope not found"
        )

    if row[0] != row[1]:
        raise ValueError(
            "Task target differs from initialized scope"
        )

    return row[0]


def resolve_artifact(artifact):
    relative = Path(artifact)

    if relative.is_absolute():
        raise ValueError(
            "Absolute artifact paths are not permitted"
        )

    workspace = WORKSPACE.resolve(strict=True)

    path = (workspace / relative).resolve(
        strict=True
    )

    if not path.is_relative_to(workspace):
        raise ValueError(
            "Artifact outside executor workspace"
        )

    if not path.is_file():
        raise ValueError(
            "Artifact is not a regular file"
        )

    if path.stat().st_size > MAX_FILE_SIZE:
        raise ValueError(
            "Artifact exceeds 2 MiB limit"
        )

    sandbox_path = (
        Path("/work") / path.relative_to(workspace)
    )

    return path, str(sandbox_path)


def installed_catalog():
    result = detect_tools(
        category="all",
        installed_only=True,
    )

    return {
        item["name"]: item
        for item in result["tools"]
    }


def resolve_executable(tool):
    if tool not in TOOL_PROFILES:
        raise ValueError(
            f"Unsupported execution profile: {tool}"
        )

    catalog = installed_catalog()
    entry = catalog.get(tool)

    if entry is None:
        raise ValueError(
            f"Tool is not installed: {tool}"
        )

    path = Path(entry["path"]).resolve(
        strict=True
    )

    if not (
        path.is_relative_to(Path("/usr"))
        or path.is_relative_to(Path("/bin"))
    ):
        raise ValueError(
            "Tool executable is outside trusted system paths"
        )

    return str(path)


def build_sandbox_command(executable, tool, artifact):
    command = [
        BWRAP,
        "--unshare-all",
        "--die-with-parent",
        "--new-session",
        "--clearenv",
        "--setenv", "PATH", "/usr/bin:/bin",
        "--setenv", "HOME", "/tmp",
        "--setenv", "LC_ALL", "C",
        "--tmpfs", "/",
        "--ro-bind", "/usr", "/usr",
        "--ro-bind-try", "/bin", "/bin",
        "--ro-bind-try", "/lib", "/lib",
        "--ro-bind-try", "/lib64", "/lib64",
        "--proc", "/proc",
        "--dev", "/dev",
        "--dir", "/tmp",
        "--dir", "/work",
        "--ro-bind", str(WORKSPACE), "/work",
        "--chdir", "/work",
        executable,
    ]

    command.extend(
        TOOL_PROFILES[tool]
    )

    command.append(artifact)

    return command


def execute_tool(task_id, tool, artifact):
    target = require_task_scope(task_id)

    _, sandbox_artifact = resolve_artifact(
        artifact
    )

    executable = resolve_executable(tool)

    command = build_sandbox_command(
        executable,
        tool,
        sandbox_artifact,
    )

    process = subprocess.Popen(
        command,
        cwd=str(ROOT),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=True,
    )

    timed_out = False

    try:
        stdout, stderr = process.communicate(
            timeout=TIMEOUT_SECONDS
        )
    except subprocess.TimeoutExpired:
        timed_out = True

        try:
            os.killpg(
                process.pid,
                signal.SIGKILL,
            )
        except ProcessLookupError:
            pass

        stdout, stderr = process.communicate()

    exit_code = (
        124 if timed_out
        else process.returncode
    )

    if timed_out:
        status = "timeout"
    elif exit_code == 0:
        status = "completed"
    else:
        status = "error"

    result = {
        "status": status,
        "operation": "local_tool",
        "task_id": task_id,
        "authorized_target": target,
        "tool": tool,
        "artifact": artifact,
        "exit_code": exit_code,
        "sandbox": "bubblewrap",
        "network": "disabled",
        "stdout": stdout[:MAX_OUTPUT],
        "stderr": stderr[:MAX_OUTPUT],
        "created_at": utc_now(),
    }

    write_audit(result)

    return result


def list_profiles():
    catalog = installed_catalog()

    profiles = []

    for name in sorted(TOOL_PROFILES):
        entry = catalog.get(name)

        profiles.append({
            "tool": name,
            "installed": entry is not None,
            "path": (
                entry["path"]
                if entry
                else None
            ),
            "execution_enabled": entry is not None,
            "network": "disabled",
            "mode": "local_read_only",
        })

    return {
        "status": "completed",
        "operation": "list_tool_profiles",
        "profiles": profiles,
    }


def main():
    parser = argparse.ArgumentParser()

    sub = parser.add_subparsers(
        dest="command",
        required=True,
    )

    sub.add_parser("list")

    run = sub.add_parser("run")
    run.add_argument(
        "--task-id",
        type=int,
        required=True,
    )
    run.add_argument(
        "--tool",
        required=True,
        choices=sorted(TOOL_PROFILES),
    )
    run.add_argument(
        "--artifact",
        required=True,
    )

    args = parser.parse_args()

    try:
        if args.command == "list":
            result = list_profiles()
        else:
            result = execute_tool(
                args.task_id,
                args.tool,
                args.artifact,
            )

        print(json.dumps(
            result,
            ensure_ascii=False,
            indent=2,
        ))

        if result["status"] != "completed":
            raise SystemExit(1)

    except (
        ValueError,
        OSError,
        sqlite3.Error,
        subprocess.SubprocessError,
    ) as exc:
        print(json.dumps(
            {
                "status": "blocked",
                "error": str(exc),
            },
            ensure_ascii=False,
        ))
        raise SystemExit(1)


if __name__ == "__main__":
    main()
