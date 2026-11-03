
"""
Pentest Master - Tool Executor v3.

Read-only local artifact analysis with typed tool options.

No arbitrary shell commands.
No network access.
No privilege escalation.
"""

import argparse
import json
import os
import shutil
import signal
import sqlite3
import subprocess
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path("/home/lucky/pentest-master")
DATABASE = ROOT / "storage/tasks.db"
WORKSPACE = ROOT / "runtime/executor-workspace"
AUDIT = ROOT / "logs/tool_executor_v3.jsonl"

BWRAP = "/usr/bin/bwrap"

MAX_FILE_BYTES = 2 * 1024 * 1024
MAX_OUTPUT_CHARS = 12000
TIMEOUT_SECONDS = 15


# Tool profiles define permitted modes and options.
# The agent cannot supply arbitrary command-line switches.

PROFILES = {
    "file": {
        "binary": "file",
        "default": "type",
        "modes": {
            "type": ["-b"],
            "mime": ["-b", "--mime-type"],
        },
    },
    "sha256sum": {
        "binary": "sha256sum",
        "default": "hash",
        "modes": {"hash": []},
    },
    "sha1sum": {
        "binary": "sha1sum",
        "default": "hash",
        "modes": {"hash": []},
    },
    "md5sum": {
        "binary": "md5sum",
        "default": "hash",
        "modes": {"hash": []},
    },
    "strings": {
        "binary": "strings",
        "default": "ascii",
        "modes": {
            "ascii": ["-a"],
        },
        "limit_kind": "min_chars",
    },
    "xxd": {
        "binary": "xxd",
        "default": "hex",
        "modes": {
            "hex": ["-g", "1"],
        },
        "limit_kind": "max_bytes",
        "supports_double_dash": False,
    },
    "readelf": {
        "binary": "readelf",
        "default": "header",
        "modes": {
            "header": ["-h"],
            "sections": ["-S"],
            "symbols": ["-s"],
        },
    },
    "objdump": {
        "binary": "objdump",
        "default": "header",
        "modes": {
            "header": ["-f"],
            "sections": ["-h"],
            "symbols": ["-t"],
        },
    },
    "nm": {
        "binary": "nm",
        "default": "symbols",
        "modes": {
            "symbols": ["-a"],
            "defined": ["--defined-only"],
        },
    },
    "exiftool": {
        "binary": "exiftool",
        "default": "metadata",
        "modes": {
            "metadata": ["-j"],
            "short": ["-s", "-j"],
        },
    },
    "stat": {
        "binary": "stat",
        "default": "summary",
        "modes": {
            "summary": [
                "--format=%n | %s bytes | %F"
            ],
        },
    },
    "wc": {
        "binary": "wc",
        "default": "bytes",
        "modes": {
            "bytes": ["-c"],
            "lines": ["-l"],
        },
    },
}


def now():
    return datetime.now(
        timezone.utc
    ).isoformat()


def scope_target(task_id):
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

    if not row or row[0] != row[1]:
        raise ValueError(
            "Task scope is missing or does not match "
            "the target"
        )

    return row[0]


def artifact_path(name):
    relative = Path(name)

    if (
        relative.is_absolute()
        or not name
        or "\x00" in name
    ):
        raise ValueError(
            "Absolute or invalid artifact path"
        )

    root = WORKSPACE.resolve(
        strict=True
    )

    resolved = (
        root / relative
    ).resolve(strict=True)

    if (
        not resolved.is_relative_to(root)
        or not resolved.is_file()
    ):
        raise ValueError(
            "Artifact must be a regular file "
            "within workspace"
        )

    if resolved.stat().st_size > MAX_FILE_BYTES:
        raise ValueError(
            "Artifact exceeds 2 MiB"
        )

    return str(
        Path("/work")
        / resolved.relative_to(root)
    )


def compile_arguments(
    tool,
    mode,
    limit,
    sandbox_file,
):
    profile = PROFILES.get(tool)

    if profile is None:
        raise ValueError(
            "Unsupported tool profile: " + tool
        )

    selected_mode = (
        mode or profile["default"]
    )

    if selected_mode not in profile["modes"]:
        raise ValueError(
            f"Unsupported mode for {tool}: "
            f"{selected_mode}"
        )

    binary = shutil.which(
        profile["binary"]
    )

    if not binary:
        raise ValueError(
            "Tool not installed: "
            + profile["binary"]
        )

    executable = Path(binary).resolve(
        strict=True
    )

    if not (
        executable.is_relative_to(
            Path("/usr")
        )
        or executable.is_relative_to(
            Path("/bin")
        )
    ):
        raise ValueError(
            "Executable is outside system "
            "tool directories"
        )

    args = list(
        profile["modes"][selected_mode]
    )

    option_kind = profile.get(
        "limit_kind"
    )

    if option_kind == "min_chars":
        value = 4 if limit is None else limit

        if not 3 <= value <= 64:
            raise ValueError(
                "strings min length must be "
                "between 3 and 64"
            )

        args.extend([
            "-n",
            str(value),
        ])

    elif option_kind == "max_bytes":
        value = 256 if limit is None else limit

        if not 1 <= value <= 8192:
            raise ValueError(
                "xxd byte limit must be "
                "between 1 and 8192"
            )

        args.extend([
            "-l",
            str(value),
        ])

    elif limit is not None:
        raise ValueError(
            f"{tool} does not accept --limit"
        )

    if profile.get(
        "supports_double_dash",
        True,
    ):
        args.append("--")

    args.append(sandbox_file)

    return (
        str(executable),
        args,
        selected_mode,
    )


def sandbox_command(
    executable,
    arguments,
):
    return [
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
        "--ro-bind",
        str(WORKSPACE),
        "/work",
        "--chdir", "/work",
        executable,
        *arguments,
    ]


def execute(
    task_id,
    tool,
    artifact,
    mode="",
    limit=None,
):
    target = scope_target(task_id)

    sandbox_file = artifact_path(
        artifact
    )

    executable, args, selected_mode = (
        compile_arguments(
            tool,
            mode,
            limit,
            sandbox_file,
        )
    )

    proc = subprocess.Popen(
        sandbox_command(
            executable,
            args,
        ),
        cwd=str(ROOT),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        errors="replace",
        start_new_session=True,
    )

    timed_out = False

    try:
        stdout, stderr = proc.communicate(
            timeout=TIMEOUT_SECONDS
        )

    except subprocess.TimeoutExpired:
        timed_out = True

        try:
            os.killpg(
                proc.pid,
                signal.SIGKILL,
            )
        except ProcessLookupError:
            pass

        stdout, stderr = proc.communicate()

    exit_code = (
        124 if timed_out
        else proc.returncode
    )

    result = {
        "status": (
            "timeout"
            if timed_out
            else "completed"
            if exit_code == 0
            else "error"
        ),
        "operation": "local_tool_v3",
        "task_id": task_id,
        "authorized_target": target,
        "tool": tool,
        "mode": selected_mode,
        "limit": limit,
        "artifact": artifact,
        "exit_code": exit_code,
        "sandbox": "bubblewrap",
        "network": "disabled",
        "stdout": stdout[:MAX_OUTPUT_CHARS],
        "stderr": stderr[:MAX_OUTPUT_CHARS],
        "output_truncated": (
            len(stdout) > MAX_OUTPUT_CHARS
            or len(stderr) > MAX_OUTPUT_CHARS
        ),
        "created_at": now(),
    }

    AUDIT.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    with AUDIT.open(
        "a",
        encoding="utf-8",
    ) as file:
        file.write(
            json.dumps(
                result,
                ensure_ascii=False,
            ) + "\n"
        )

    return result


def profiles():
    return {
        "status": "completed",
        "operation": "list_profiles_v3",
        "profiles": [
            {
                "tool": name,
                "installed": (
                    shutil.which(
                        cfg["binary"]
                    ) is not None
                ),
                "modes": sorted(
                    cfg["modes"]
                ),
                "default_mode": cfg["default"],
                "bounded_option": cfg.get(
                    "limit_kind"
                ),
                "network": "disabled",
            }
            for name, cfg in sorted(
                PROFILES.items()
            )
        ],
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
    )

    run.add_argument(
        "--artifact",
        required=True,
    )

    run.add_argument(
        "--mode",
        default="",
    )

    run.add_argument(
        "--limit",
        type=int,
    )

    args = parser.parse_args()

    try:
        if args.command == "list":
            result = profiles()

        else:
            result = execute(
                args.task_id,
                args.tool,
                args.artifact,
                args.mode,
                args.limit,
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
