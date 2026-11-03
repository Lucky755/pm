
"""
Pentest Master - Network Executor v1.1.

Fixes:
- Mounts Debian alternatives for dynamically linked tools.
- Makes ld.so.cache available read-only.
- Self-tests both curl and Nmap on a local HTTP fixture.

Structured network probes only.
No shell execution or arbitrary command-line arguments.
"""

import argparse
import http.server
import ipaddress
import json
import os
import re
import shutil
import signal
import sqlite3
import subprocess
import threading
from datetime import datetime, timezone
from pathlib import Path

from task_scope import check_action


ROOT = Path("/home/lucky/pentest-master")
DATABASE = ROOT / "storage/tasks.db"
AUDIT = ROOT / "logs/network_executor.jsonl"
BWRAP = "/usr/bin/bwrap"

MAX_PORTS = 32
TIMEOUT = 25


def validate_target(value):
    address = ipaddress.ip_address(value)

    if (
        address.version != 4
        or address.is_multicast
        or address.is_unspecified
    ):
        raise ValueError(
            "Only unicast IPv4 targets are supported in v1"
        )

    return str(address)


def validate_port(value):
    number = int(value)

    if not 1 <= number <= 65535:
        raise ValueError(
            "Port must be in range 1..65535"
        )

    return number


def validate_ports(raw):
    parts = raw.split(",")

    if not 1 <= len(parts) <= MAX_PORTS:
        raise ValueError(
            "Specify 1..32 individual TCP ports"
        )

    numbers = [
        validate_port(part.strip())
        for part in parts
    ]

    if len(set(numbers)) != len(numbers):
        raise ValueError(
            "Duplicate ports are not permitted"
        )

    return ",".join(
        str(port) for port in numbers
    )


def check_scope(task_id, target):
    with sqlite3.connect(DATABASE) as db:
        decision = check_action(
            db,
            task_id,
            "connect",
            target,
        )

    if decision["decision"] != "ALLOW":
        raise ValueError(
            decision["reason"]
        )


def tool_command(profile, target, port, ports):
    if profile == "http_headers":
        number = validate_port(port)
        binary = shutil.which("curl")

        args = [
            "--silent",
            "--show-error",
            "--head",
            "--noproxy", "*",
            "--max-redirs", "0",
            "--connect-timeout", "3",
            "--max-time", "8",
            "--",
            f"http://{target}:{number}/",
        ]

    elif profile == "tcp_ports":
        selected = validate_ports(ports)
        binary = shutil.which("nmap")

        args = [
            "-sT",
            "-Pn",
            "-n",
            "--open",
            "--max-retries", "1",
            "--host-timeout", "15s",
            "-p", selected,
            target,
        ]

    else:
        raise ValueError(
            "Unknown network profile"
        )

    if not binary:
        raise ValueError(
            f"{profile} required binary is not installed"
        )

    binary = str(
        Path(binary).resolve()
    )

    if not Path(binary).is_relative_to("/usr"):
        raise ValueError(
            "Unexpected executable location"
        )

    return [binary, *args]


def sandbox_command(command):
    return [
        BWRAP,
        "--unshare-all",
        "--share-net",
        "--die-with-parent",
        "--new-session",
        "--clearenv",
        "--setenv", "PATH", "/usr/bin:/bin",
        "--setenv", "HOME", "/tmp",
        "--setenv", "LC_ALL", "C",
        "--tmpfs", "/",

        # System binaries and libraries.
        "--ro-bind", "/usr", "/usr",
        "--ro-bind-try", "/bin", "/bin",
        "--ro-bind-try", "/lib", "/lib",
        "--ro-bind-try", "/lib64", "/lib64",

        # Debian alternatives may form part of
        # a shared library's symlink chain.
        # Mount only the needed configuration paths,
        # not the entire host /etc directory.
        "--dir", "/etc",
        "--ro-bind-try",
        "/etc/alternatives",
        "/etc/alternatives",
        "--ro-bind-try",
        "/etc/ld.so.cache",
        "/etc/ld.so.cache",

        "--proc", "/proc",
        "--dev", "/dev",
        "--dir", "/tmp",
        "--dir", "/work",
        "--chdir", "/work",

        *command,
    ]


def audit(record):
    AUDIT.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    with AUDIT.open(
        "a",
        encoding="utf-8",
    ) as stream:
        stream.write(
            json.dumps(
                record,
                ensure_ascii=False,
            ) + "\n"
        )


def execute(
    profile,
    target,
    *,
    task_id=None,
    port=None,
    ports=None,
    execute_now=False,
    loopback_selftest=False,
):
    if execute_now and not loopback_selftest:
        raise ValueError("Direct live execution disabled: use network_executor_isolated.py")
    target = validate_target(target)

    if loopback_selftest:
        if (
            target != "127.0.0.1"
            or task_id is not None
        ):
            raise ValueError(
                "Self-test is loopback only"
            )

    else:
        if task_id is None:
            raise ValueError(
                "A task ID is required"
            )

        check_scope(
            task_id,
            target,
        )

    command = tool_command(
        profile,
        target,
        port,
        ports,
    )

    result = {
        "operation": "network_probe",
        "task_id": task_id,
        "profile": profile,
        "target": target,
        "network": "shared_kali_network_namespace",
        "sandbox": "bubblewrap",
        "created_at": datetime.now(
            timezone.utc
        ).isoformat(),
    }

    if not execute_now:
        result.update(
            status="planned",
            exit_code=None,
            argv=command,
        )
        return result

    process = subprocess.Popen(
        sandbox_command(command),
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
        stdout, stderr = process.communicate(
            timeout=TIMEOUT
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

    code = (
        124 if timed_out
        else process.returncode
    )

    result.update(
        status=(
            "timeout"
            if timed_out
            else "completed"
            if code == 0
            else "error"
        ),
        exit_code=code,
        stdout=stdout[:12000],
        stderr=stderr[:5000],
        output_truncated=(
            len(stdout) > 12000
            or len(stderr) > 5000
        ),
    )

    audit(result)

    return result


class FixtureHandler(
    http.server.BaseHTTPRequestHandler
):
    def do_HEAD(self):
        self.send_response(200)
        self.send_header(
            "Content-Type",
            "text/plain",
        )
        self.send_header(
            "X-Pentest-Master-Test",
            "loopback",
        )
        self.end_headers()

    def log_message(self, format, *args):
        pass


def self_test():
    """
    Test both network tools against the same
    temporary HTTP server on 127.0.0.1.

    This verifies connectivity AND the Nmap
    dynamic-library environment in Bubblewrap.
    """

    server = http.server.ThreadingHTTPServer(
        ("127.0.0.1", 0),
        FixtureHandler,
    )

    thread = threading.Thread(
        target=server.serve_forever,
        daemon=True,
    )

    thread.start()

    try:
        port = server.server_address[1]

        print(
            "[FIXTURE]",
            f"http://127.0.0.1:{port}/",
            flush=True,
        )

        print(
            "\n[TEST 1] curl HTTP headers",
            flush=True,
        )

        http_result = execute(
            "http_headers",
            "127.0.0.1",
            port=port,
            execute_now=True,
            loopback_selftest=True,
        )

        print(json.dumps(
            http_result,
            ensure_ascii=False,
            indent=2,
        ))

        if (
            http_result["status"] != "completed"
            or "X-Pentest-Master-Test: loopback"
            not in http_result["stdout"]
        ):
            raise RuntimeError(
                "curl loopback probe failed"
            )

        print("[PASS] curl", flush=True)

        print(
            "\n[TEST 2] Nmap TCP connect scan",
            flush=True,
        )

        nmap_result = execute(
            "tcp_ports",
            "127.0.0.1",
            ports=str(port),
            execute_now=True,
            loopback_selftest=True,
        )

        print(json.dumps(
            nmap_result,
            ensure_ascii=False,
            indent=2,
        ))

        expected = re.compile(
            rf"(?m)^{port}/tcp\s+open\b"
        )

        if (
            nmap_result["status"] != "completed"
            or not expected.search(
                nmap_result["stdout"]
            )
        ):
            raise RuntimeError(
                "Nmap did not confirm the local open port"
            )

        print("[PASS] Nmap", flush=True)

        print()
        print(
            "[SUCCESS] Both network profiles "
            "executed successfully in Bubblewrap",
            flush=True,
        )

    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def main():
    parser = argparse.ArgumentParser()

    sub = parser.add_subparsers(
        dest="command",
        required=True,
    )

    sub.add_parser("self-test")

    run = sub.add_parser("run")

    run.add_argument(
        "--task-id",
        type=int,
        required=True,
    )
    run.add_argument(
        "--profile",
        choices=("tcp_ports", "http_headers"),
        required=True,
    )
    run.add_argument(
        "--target",
        required=True,
    )
    run.add_argument(
        "--ports",
        default="80,443",
    )
    run.add_argument(
        "--port",
        type=int,
        default=80,
    )
    run.add_argument(
        "--execute",
        action="store_true",
        help=(
            "Perform live probe; "
            "otherwise only plan"
        ),
    )

    args = parser.parse_args()

    try:
        if args.command == "self-test":
            self_test()

        else:
            outcome = execute(
                args.profile,
                args.target,
                task_id=args.task_id,
                port=args.port,
                ports=args.ports,
                execute_now=args.execute,
            )

            print(json.dumps(
                outcome,
                ensure_ascii=False,
                indent=2,
            ))

            if outcome["status"] not in (
                "planned",
                "completed",
            ):
                raise SystemExit(1)

    except (
        ValueError,
        OSError,
        sqlite3.Error,
        RuntimeError,
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
