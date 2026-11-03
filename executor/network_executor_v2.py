
"""
Pentest Master - Network Executor v2.

Extended structured network probing.

Profiles:
    tcp_ports
    service_versions
    http_headers
    http_get
    https_headers

The existing network_executor.py is reused for:
- Bubblewrap isolation
- Debian library mount configuration
- IPv4 and port validation
- Task Scope validation

No shell commands.
No arbitrary CLI switches.
No automatic redirects.
No proxy environment inheritance.

IMPORTANT:
Bubblewrap shares Kali's network namespace.
Scope enforcement remains application-level.
Kernel-enforced egress filtering is not yet implemented.
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

import network_executor as legacy


ROOT = Path("/home/lucky/pentest-master")
AUDIT = ROOT / "logs/network_executor_v2.jsonl"

TIMEOUT = 45
MAX_OUTPUT = 24000

PROFILES = {
    "tcp_ports": {
        "binary": "nmap",
        "description": "TCP connect port discovery",
        "kind": "tcp",
    },
    "service_versions": {
        "binary": "nmap",
        "description": "Nmap light service version detection",
        "kind": "tcp",
    },
    "http_headers": {
        "binary": "curl",
        "description": "HTTP HEAD request",
        "kind": "http",
    },
    "http_get": {
        "binary": "curl",
        "description": "Bounded HTTP or HTTPS GET request",
        "kind": "http",
    },
    "https_headers": {
        "binary": "curl",
        "description": "HTTPS HEAD request",
        "kind": "http",
    },
}


DOCUMENTATION_NETWORKS = (
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
)


def utc_now():
    return datetime.now(
        timezone.utc
    ).isoformat()


def is_documentation_target(address):
    ip = ipaddress.ip_address(address)

    return any(
        ip in network
        for network in DOCUMENTATION_NETWORKS
    )


def installed_binary(name):
    executable = shutil.which(name)

    if executable is None:
        raise ValueError(
            f"Required binary is not installed: {name}"
        )

    resolved = Path(executable).resolve(
        strict=True
    )

    if not resolved.is_relative_to(
        Path("/usr")
    ):
        raise ValueError(
            "Executable is outside /usr"
        )

    return str(resolved)


def build_command(
    profile,
    target,
    port=80,
    ports="80,443",
    scheme="http",
    insecure=False,
):
    if profile not in PROFILES:
        raise ValueError(
            "Unsupported network profile"
        )

    target = legacy.validate_target(
        target
    )

    kind = PROFILES[profile]["kind"]

    if kind == "tcp":
        selected_ports = legacy.validate_ports(
            ports
        )

        if insecure:
            raise ValueError(
                "TLS options do not apply to Nmap profiles"
            )

        nmap = installed_binary("nmap")

        if profile == "tcp_ports":
            return [
                nmap,
                "-sT",
                "-Pn",
                "-n",
                "--open",
                "--max-retries", "1",
                "--host-timeout", "25s",
                "-p", selected_ports,
                target,
            ]

        return [
            nmap,
            "-sT",
            "-sV",
            "--version-light",
            "-Pn",
            "-n",
            "--open",
            "--max-retries", "1",
            "--host-timeout", "30s",
            "-p", selected_ports,
            target,
        ]

    number = legacy.validate_port(
        port
    )

    if scheme not in ("http", "https"):
        raise ValueError(
            "Unsupported HTTP scheme"
        )

    if profile == "http_headers":
        scheme = "http"

    if profile == "https_headers":
        scheme = "https"

    if insecure and scheme != "https":
        raise ValueError(
            "TLS verification cannot be disabled "
            "for a non-TLS request"
        )

    curl = installed_binary("curl")

    args = [
        curl,
        "--silent",
        "--show-error",
        "--noproxy", "*",
        "--proto", "=http,https",
        "--max-redirs", "0",
        "--connect-timeout", "3",
        "--max-time", "12",
    ]

    if insecure:
        args.append("--insecure")

    if profile in (
        "http_headers",
        "https_headers",
    ):
        args.append("--head")

    elif profile == "http_get":
        args.extend([
            "--include",
            "--max-filesize", "32768",
        ])

    url = f"{scheme}://{target}:{number}/"

    args.extend([
        "--",
        url,
    ])

    return args


def validate_execution(
    target,
    task_id,
    local_selftest,
):
    if local_selftest:
        if (
            target != "127.0.0.1"
            or task_id is not None
        ):
            raise ValueError(
                "Local self-test only accepts "
                "127.0.0.1 without a task ID"
            )

        return

    if task_id is None or task_id < 1:
        raise ValueError(
            "An initialized task ID is required"
        )

    legacy.check_scope(
        task_id,
        target,
    )


def record_audit(result):
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
                result,
                ensure_ascii=False,
            ) + "\n"
        )


def execute(
    profile,
    target,
    *,
    task_id=None,
    port=80,
    ports="80,443",
    scheme="http",
    insecure=False,
    execute_now=False,
    local_selftest=False,
):
    if execute_now and not local_selftest:
        raise ValueError("Direct live execution disabled: use network_executor_isolated.py")
    target = legacy.validate_target(
        target
    )

    validate_execution(
        target,
        task_id,
        local_selftest,
    )

    if (
        execute_now
        and is_documentation_target(target)
    ):
        raise ValueError(
            "Live execution against RFC 5737 "
            "documentation addresses is disabled"
        )

    command = build_command(
        profile,
        target,
        port,
        ports,
        scheme,
        insecure,
    )

    result = {
        "operation": "network_probe_v2",
        "task_id": task_id,
        "profile": profile,
        "target": target,
        "sandbox": "bubblewrap",
        "network": "shared_kali_network_namespace",
        "scope_enforcement": "application_level",
        "created_at": utc_now(),
    }

    if not execute_now:
        result.update({
            "status": "planned",
            "exit_code": None,
            "argv": command,
        })

        return result

    process = subprocess.Popen(
        legacy.sandbox_command(command),
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

    exit_code = (
        124
        if timed_out
        else process.returncode
    )

    if timed_out:
        status = "timeout"
    elif exit_code == 0:
        status = "completed"
    else:
        status = "error"

    result.update({
        "status": status,
        "exit_code": exit_code,
        "stdout": stdout[:MAX_OUTPUT],
        "stderr": stderr[:MAX_OUTPUT],
        "output_truncated": (
            len(stdout) > MAX_OUTPUT
            or len(stderr) > MAX_OUTPUT
        ),
        "finished_at": utc_now(),
    })

    record_audit(result)

    return result


class LabHandler(
    http.server.BaseHTTPRequestHandler
):
    server_version = "PentestMasterLab/2.0"
    sys_version = ""

    def do_HEAD(self):
        self.send_response(200)
        self.send_header(
            "Content-Type",
            "text/plain",
        )
        self.send_header(
            "X-Pentest-Master-Test",
            "network-v2",
        )
        self.end_headers()

    def do_GET(self):
        self.send_response(200)
        self.send_header(
            "Content-Type",
            "text/plain",
        )
        self.send_header(
            "X-Pentest-Master-Test",
            "network-v2",
        )
        self.end_headers()

        self.wfile.write(
            b"Pentest Master Network Executor v2\n"
        )

    def log_message(self, format, *args):
        pass


class LabHTTPServer(
    http.server.ThreadingHTTPServer
):
    def handle_error(self, request, client_address):
        # Nmap can connect and immediately reset a socket.
        # Suppress only the expected reset/broken-pipe noise.
        typ = __import__("sys").exc_info()[0]

        if typ in (
            ConnectionResetError,
            BrokenPipeError,
        ):
            return

        super().handle_error(
            request,
            client_address,
        )


def self_test():
    server = LabHTTPServer(
        ("127.0.0.1", 0),
        LabHandler,
    )

    worker = threading.Thread(
        target=server.serve_forever,
        daemon=True,
    )

    worker.start()

    port = server.server_address[1]

    tests = [
        (
            "tcp_ports",
            {"ports": str(port)},
            rf"(?m)^{port}/tcp\s+open\b",
        ),
        (
            "http_headers",
            {"port": port},
            "HTTP/1.0 200 OK",
        ),
        (
            "http_get",
            {"port": port},
            "Pentest Master Network Executor v2",
        ),
        (
            "service_versions",
            {"ports": str(port)},
            rf"(?m)^{port}/tcp\s+open\b",
        ),
    ]

    try:
        print(
            "[FIXTURE]",
            f"http://127.0.0.1:{port}/",
            flush=True,
        )

        for profile, options, expected in tests:
            print(
                "\n[TEST]",
                profile,
                flush=True,
            )

            result = execute(
                profile,
                "127.0.0.1",
                execute_now=True,
                local_selftest=True,
                **options,
            )

            print(json.dumps(
                result,
                ensure_ascii=False,
                indent=2,
            ), flush=True)

            stdout = result.get(
                "stdout", ""
            )

            if (
                result["status"] != "completed"
                or re.search(
                    expected,
                    stdout,
                ) is None
            ):
                raise RuntimeError(
                    f"Self-test failed: {profile}"
                )

            print(
                "[PASS]",
                profile,
                flush=True,
            )

        print()
        print(
            "[SUCCESS] Network Executor v2 "
            "local integration passed",
            flush=True,
        )

    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=3)


def list_profiles():
    return {
        "status": "completed",
        "operation": "list_network_profiles_v2",
        "profiles": [
            {
                "name": name,
                "description": config["description"],
                "binary": config["binary"],
                "installed": (
                    shutil.which(
                        config["binary"]
                    ) is not None
                ),
                "kind": config["kind"],
            }
            for name, config
            in PROFILES.items()
        ],
    }


def main():
    parser = argparse.ArgumentParser()

    sub = parser.add_subparsers(
        dest="command",
        required=True,
    )

    sub.add_parser("list")
    sub.add_parser("self-test")

    run = sub.add_parser("run")

    run.add_argument(
        "--task-id",
        type=int,
        required=True,
    )

    run.add_argument(
        "--profile",
        choices=sorted(PROFILES),
        required=True,
    )

    run.add_argument(
        "--target",
        required=True,
    )

    run.add_argument(
        "--port",
        type=int,
        default=80,
    )

    run.add_argument(
        "--ports",
        default="80,443",
    )

    run.add_argument(
        "--scheme",
        choices=("http", "https"),
        default="http",
    )

    run.add_argument(
        "--insecure",
        action="store_true",
        help=(
            "Skip HTTPS certificate verification. "
            "Only for explicitly authorized lab targets."
        ),
    )

    run.add_argument(
        "--execute",
        action="store_true",
        help=(
            "Perform live network probe. "
            "Default is planning only."
        ),
    )

    args = parser.parse_args()

    try:
        if args.command == "list":
            result = list_profiles()

        elif args.command == "self-test":
            self_test()
            return

        else:
            result = execute(
                args.profile,
                args.target,
                task_id=args.task_id,
                port=args.port,
                ports=args.ports,
                scheme=args.scheme,
                insecure=args.insecure,
                execute_now=args.execute,
            )

        print(json.dumps(
            result,
            ensure_ascii=False,
            indent=2,
        ))

        if result["status"] not in (
            "completed",
            "planned",
        ):
            raise SystemExit(1)

    except (
        ValueError,
        OSError,
        RuntimeError,
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
