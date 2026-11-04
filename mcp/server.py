
"""
Pentest Master - MCP Server v6.

Preserves existing tools and adds:
- list_network_profiles
- run_network_probe

The network executor accepts fixed command profiles,
not arbitrary shell arguments.

Task scope is checked by network_executor.py.
"""

import ipaddress
import fcntl
import hashlib
import json
import os
import re
import sqlite3
import subprocess
import stat
import sys
import time
from pathlib import Path

from mcp.server.fastmcp import FastMCP


ROOT = Path(__file__).resolve().parents[1]
PYTHON = ROOT / ".venv/bin/python"

sys.path.insert(0, str(ROOT))

from executor.tool_catalog import detect_tools
from executor.tool_executor_v3 import PROFILES
from orchestrator import fact_state, diagnostics


mcp = FastMCP("pentest-master")
ASSET_DB = ROOT / 'storage/tasks.db'


def guard_explicit_assets(task_id, assets, hypothesis_key='', new_evidence_id=''):
    """Gate structured probes; opaque shell and PoC internals remain advisory."""
    if not assets:
        return None
    if not ASSET_DB.is_file():
        return 'Реестр активов недоступен'
    records = fact_state.capability_index(
        task_id, ROOT / 'storage/capability_log' / f'task_{task_id}.jsonl')
    with sqlite3.connect(ASSET_DB, timeout=10) as db:
        db.execute('BEGIN IMMEDIATE')
        fact_state.ensure_schema(db)
        for kind, key in assets:
            decision = fact_state.may_probe_asset(
                db, task_id, kind, key, hypothesis_key, new_evidence_id,
                records, consume=False)
            if not decision['allowed']:
                return decision['reason']
        for kind, key in assets:
            fact_state.may_probe_asset(
                db, task_id, kind, key, hypothesis_key, new_evidence_id,
                records, consume=True)
    return None


NETWORK_PROFILES = {
    "tcp_ports": {
        "binary": "nmap",
        "description": (
            "TCP connect scan of explicitly specified ports "
            "on an authorized IPv4 target."
        ),
        "parameter": "ports",
        "default": "80,443",
        "max_ports": 32,
    },
    "http_headers": {
        "binary": "curl",
        "description": (
            "Single HTTP HEAD request to an authorized "
            "IPv4 target and TCP port. No redirects."
        ),
        "parameter": "port",
        "default": 80,
    },
}


def response(
    operation,
    status,
    exit_code,
    stdout="",
    stderr="",
):
    return tool_response(
        {
            "status": status,
            "operation": operation,
            "exit_code": exit_code,
            "stdout": str(stdout)[-12000:],
            "stderr": str(stderr)[-5000:],
        },
    )


def run_internal(
    command,
    operation,
    timeout=20,
    structured=False,
):
    try:
        result = subprocess.run(
            command,
            cwd=str(ROOT),
            capture_output=True,
            text=True,
            errors="replace",
            timeout=timeout,
            stdin=subprocess.DEVNULL,
            check=False,
        )

        if structured:
            try:
                payload = json.loads(
                    result.stdout.strip()
                )
            except (ValueError, TypeError):
                return response(
                    operation,
                    "error",
                    result.returncode or 1,
                    stderr=(
                        "Executor returned invalid JSON: "
                        + result.stderr[-2000:]
                    ),
                )

            if not isinstance(payload, dict):
                return response(
                    operation,
                    "error",
                    1,
                    stderr="Executor returned a non-object result",
                )

            status = payload.get("status")

            if status not in (
                "completed",
                "planned",
                "blocked",
                "error",
                "timeout",
            ):
                return response(
                    operation,
                    "error",
                    1,
                    stderr="Unexpected Executor status",
                )

            if (
                result.returncode != 0
                and status in ("completed", "planned")
            ):
                return response(
                    operation,
                    "error",
                    result.returncode,
                    stderr="Executor exit/status mismatch",
                )

            if (
                result.returncode == 0
                and status not in ("completed", "planned")
            ):
                return response(
                    operation,
                    "error",
                    1,
                    stderr="Executor exit/status mismatch",
                )

            return tool_response(payload)

        return response(
            operation,
            (
                "completed"
                if result.returncode == 0
                else "blocked"
            ),
            result.returncode,
            result.stdout,
            result.stderr,
        )

    except subprocess.TimeoutExpired:
        return response(
            operation,
            "timeout",
            124,
            stderr="Operation timed out",
        )

    except OSError as exc:
        return response(
            operation,
            "error",
            1,
            stderr=str(exc),
        )


@mcp.tool()
@diagnostics.tool
def list_workspace() -> str:
    """List files in the isolated executor workspace."""

    return run_internal(
        [
            str(PYTHON),
            "-m",
            "executor.runner",
            "--operation",
            "read_findings",
        ],
        "read_findings",
    )


@mcp.tool()
@diagnostics.tool
def workspace_test() -> str:
    """Write a harmless test file inside the sandbox."""

    return run_internal(
        [
            str(PYTHON),
            "-m",
            "executor.runner",
            "--operation",
            "workspace_write",
        ],
        "workspace_write",
    )


@mcp.tool()
@diagnostics.tool
def execute_approved_demo(approval_id: str) -> str:
    """
    Consume a one-use approved demonstration contract.
    This tool does not perform privilege escalation.
    """

    if not re.fullmatch(r"[0-9a-f]{32}", approval_id):
        return response(
            "approved_demo",
            "blocked",
            1,
            stderr="Invalid approval ID",
        )

    return run_internal(
        [
            str(PYTHON),
            str(ROOT / "executor/approval_guard.py"),
            "execute-demo",
            "--id",
            approval_id,
        ],
        "approved_demo",
        timeout=15,
    )


@mcp.tool()
@diagnostics.tool
def list_available_tools(
    category: str = "all",
    installed_only: bool = True,
) -> str:
    """
    Discover Kali tools without executing them.
    """

    try:
        result = detect_tools(
            category=category,
            installed_only=installed_only,
        )

        return tool_response(result)

    except ValueError as exc:
        return response(
            "tool_catalog",
            "blocked",
            1,
            stderr=str(exc),
        )


@mcp.tool()
@diagnostics.tool
def run_local_tool(
    task_id: int,
    tool_name: str,
    artifact: str,
) -> str:
    """Compatibility interface for Tool Executor v2."""

    if task_id < 1:
        return response(
            "local_tool",
            "blocked",
            1,
            stderr="Invalid task ID",
        )

    if (
        not tool_name
        or len(tool_name) > 64
        or not artifact
        or len(artifact) > 500
        or "\x00" in artifact
    ):
        return response(
            "local_tool",
            "blocked",
            1,
            stderr="Invalid arguments",
        )

    return run_internal(
        [
            str(PYTHON),
            str(ROOT / "executor/tool_executor.py"),
            "run",
            "--task-id",
            str(task_id),
            "--tool",
            tool_name,
            "--artifact",
            artifact,
        ],
        "local_tool",
        timeout=20,
        structured=True,
    )


@mcp.tool()
@diagnostics.tool
def list_tool_profiles_v3() -> str:
    """List local Executor v3 profiles and modes."""

    return run_internal(
        [
            str(PYTHON),
            str(ROOT / "executor/tool_executor_v3.py"),
            "list",
        ],
        "list_profiles_v3",
        timeout=10,
        structured=True,
    )


@mcp.tool()
@diagnostics.tool
def run_local_tool_v3(
    task_id: int,
    tool_name: str,
    artifact: str,
    mode: str = "",
    limit: int | None = None,
) -> str:
    """
    Run a controlled local analysis tool in Bubblewrap.

    Use list_tool_profiles_v3 to discover valid modes.
    Network access is disabled.
    """

    if task_id < 1:
        return response(
            "local_tool_v3",
            "blocked",
            1,
            stderr="Invalid task ID",
        )

    if tool_name not in PROFILES:
        return response(
            "local_tool_v3",
            "blocked",
            1,
            stderr="Unsupported tool profile",
        )

    if (
        not isinstance(artifact, str)
        or not artifact
        or len(artifact) > 500
        or "\x00" in artifact
    ):
        return response(
            "local_tool_v3",
            "blocked",
            1,
            stderr="Invalid artifact argument",
        )

    if (
        not isinstance(mode, str)
        or len(mode) > 64
    ):
        return response(
            "local_tool_v3",
            "blocked",
            1,
            stderr="Invalid mode",
        )

    if limit is not None and (
        isinstance(limit, bool)
        or not isinstance(limit, int)
    ):
        return response(
            "local_tool_v3",
            "blocked",
            1,
            stderr="Invalid numeric limit",
        )

    command = [
        str(PYTHON),
        str(ROOT / "executor/tool_executor_v3.py"),
        "run",
        "--task-id",
        str(task_id),
        "--tool",
        tool_name,
        "--artifact",
        artifact,
    ]

    if mode:
        command.extend([
            "--mode",
            mode,
        ])

    if limit is not None:
        command.extend([
            "--limit",
            str(limit),
        ])

    return run_internal(
        command,
        "local_tool_v3",
        timeout=25,
        structured=True,
    )


@mcp.tool()
@diagnostics.tool
def list_network_profiles() -> str:
    """
    List the controlled network probe profiles.

    This operation does not generate network traffic.
    """

    inventory = detect_tools(
        installed_only=True
    )

    installed_names = {
        item["binary"]
        for item in inventory["tools"]
    }

    profiles = []

    for name, config in NETWORK_PROFILES.items():
        profiles.append({
            "profile": name,
            "binary": config["binary"],
            "description": config["description"],
            "parameter": config["parameter"],
            "default": config["default"],
            "installed": (
                config["binary"] in installed_names
            ),
            "scope_required": True,
            "live_execution_supported": True,
        })

    return tool_response(
        {
            "status": "completed",
            "operation": "list_network_profiles",
            "profiles": profiles,
            "default_execution": "plan_only",
            "note": (
                "Live operations share Kali's network namespace. "
                "Task scope checks are application-level, "
                "not kernel-enforced egress restrictions."
            ),
        },
    )


@mcp.tool()
@diagnostics.tool
def run_network_probe(
    task_id: int,
    profile: str,
    target: str,
    ports: str = "80,443",
    port: int = 80,
    execute: bool = False,
    hypothesis_key: str = "",
    new_evidence_id: str = "",
) -> str:
    """
    Plan or execute a network probe inside the task scope.

    Profiles:

    tcp_ports:
      nmap TCP connect scan.
      Set ports to comma-separated individual TCP ports,
      for example "22,80,443".

    http_headers:
      curl HTTP HEAD request.
      Set port to a TCP port, for example 8080.

    Required:
      task_id: existing task with initialized scope
      target: IPv4 address already authorized by that task

    execute=False:
      Validate and return planned command only.

    execute=True:
      Perform live network operation.

    No arbitrary shell commands or custom flags.
    """

    if task_id < 1:
        return response(
            "network_probe",
            "blocked",
            1,
            stderr="Invalid task ID",
        )

    if profile not in NETWORK_PROFILES:
        return response(
            "network_probe",
            "blocked",
            1,
            stderr="Unsupported network profile",
        )

    try:
        address = ipaddress.ip_address(target)

        if address.version != 4:
            raise ValueError(
                "Only IPv4 targets are supported"
            )

        target = str(address)

    except ValueError:
        return response(
            "network_probe",
            "blocked",
            1,
            stderr="Invalid IPv4 target",
        )

    if (
        isinstance(execute, bool) is False
        or isinstance(port, bool)
        or not isinstance(port, int)
        or not 1 <= port <= 65535
        or not isinstance(ports, str)
        or len(ports) > 255
    ):
        return response(
            "network_probe",
            "blocked",
            1,
            stderr="Invalid network probe arguments",
        )

    # Documentation ranges are used for test tasks.
    # Do not perform live probes against these placeholders.
    documentation_ranges = [
        ipaddress.ip_network("192.0.2.0/24"),
        ipaddress.ip_network("198.51.100.0/24"),
        ipaddress.ip_network("203.0.113.0/24"),
    ]

    if execute and any(
        address in network
        for network in documentation_ranges
    ):
        return response(
            "network_probe",
            "blocked",
            1,
            stderr=(
                "Live execution against documentation "
                "addresses is disabled"
            ),
        )

    if execute:
        requested = ([('port', value) for value in ports.split(',')]
                     if profile == 'tcp_ports' else [('port', str(port))])
        try:
            blocked = guard_explicit_assets(task_id, requested,
                                            hypothesis_key, new_evidence_id)
        except (sqlite3.Error, ValueError, OSError) as exc:
            blocked = 'Не удалось проверить матрицу активов: ' + str(exc)[:160]
        if blocked:
            return response('network_probe', 'blocked', 1, stderr=blocked)

    command = [
        str(PYTHON),
        str(ROOT / "executor/network_executor_isolated.py"),
        "run",
        "--task-id",
        str(task_id),
        "--profile",
        profile,
        "--target",
        target,
    ]

    if profile == "tcp_ports":
        command.extend([
            "--ports",
            ports,
        ])

    elif profile == "http_headers":
        command.extend([
            "--port",
            str(port),
        ])

    if execute:
        command.append("--execute")

    return run_internal(
        command,
        "network_probe",
        timeout=32 if execute else 10,
        structured=True,
    )


# ---------------------------------------------------------------------------
# Capability tools.
#
# These give the role agents real action inside the task's isolated network
# namespace: arbitrary argv, agent-written PoC scripts, lookups against a fixed
# research allowlist, and a scoped callback listener for blind results.
#
# Every call goes through executor/network_executor_isolated.py, which re-checks
# the task scope, and then through the root broker whose nft rules allow only
# the task's authorized /32 inside the namespace.
# ---------------------------------------------------------------------------

POC_ROOT = ROOT / "storage/pocs"
CAPABILITY_LOG = ROOT / "storage/capability_log"
TASK_WORK_BASE = Path("/var/lib/pentest-master/work")
ISOLATED_EXECUTOR = ROOT / "executor/network_executor_isolated.py"
NETWORK_JOBS = ROOT / "orchestrator/network_jobs.py"
POC_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")
POC_SUFFIXES = (".sh", ".py", ".pl", ".rb", ".txt")
POC_MAX_BYTES = 256 * 1024
RESEARCH_HOSTS = (
    "nvd.nist.gov",
    "services.nvd.nist.gov",
    "exploit-db.com",
    "www.exploit-db.com",
    "api.github.com",
)
POC_INTERPRETERS = ("bash", "sh", "python3", "perl")


def valid_task(task_id):
    return (
        isinstance(task_id, int)
        and not isinstance(task_id, bool)
        and 1 <= task_id <= 200
    )


def valid_ipv4(text):
    try:
        return str(ipaddress.IPv4Address(text))
    except (ipaddress.AddressValueError, ValueError, TypeError):
        return None


def capability_provenance(tool, payload, command):
    """Classify the source when writing the record, before argv is truncated."""
    if tool == 'poc_run':
        return ('network' if payload.get('network_isolated') and
                payload.get('network_contact') else 'local')
    if tool == 'net_exec':
        argv = list(command)
        if '--argv-json' in argv:
            try:
                inner = json.loads(argv[argv.index('--argv-json') + 1])
            except (ValueError, IndexError):
                inner = []
            if inner and Path(inner[0]).name in (
                    'grep', 'rg', 'cat', 'sed', 'awk', 'head', 'tail', 'find',
                    'ls', 'unzip', 'tar', '7z', 'strings'):
                return 'local'
        return 'network'
    if tool in ('session', 'network_probe', 'http_get', 'http_headers',
                'http_path', 'http_document', 'http_capture'):
        return 'network'
    if tool in ('write_poc', 'read_file', 'grep', 'unpack', 'capability_read'):
        return 'local'
    return 'unknown'


def log_capability(tool, task_id, payload, elapsed, command=()):
    """Append every capability call to a per-task audit log.

    The orchestrator reads this log as evidence, so nothing an agent did inside
    the namespace is lost when its step budget runs out.
    """
    if not isinstance(task_id, int) or not 1 <= task_id <= 200:
        return None

    try:
        CAPABILITY_LOG.mkdir(parents=True, exist_ok=True, mode=0o700)
        path = CAPABILITY_LOG / f"task_{task_id}.jsonl"
        full_argv = [str(item) for item in command]
        audit_argv = [item[:4096] for item in full_argv[:64]]

        record = {
            "id": os.urandom(12).hex(),
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "tool": tool,
            "task_id": task_id,
            "elapsed_seconds": round(elapsed, 3),
            "argv": audit_argv,
            "argv_truncated": len(full_argv) > 64 or any(
                len(item) > 4096 for item in full_argv),
            "argv_sha256": hashlib.sha256(json.dumps(
                full_argv, ensure_ascii=False, separators=(",", ":")
            ).encode("utf-8")).hexdigest(),
            "result": payload,
            "provenance": capability_provenance(tool, payload, full_argv),
        }
        record["input_flag_literals"] = sorted(set(re.findall(
            r"\b[A-Z][A-Z0-9_]{1,19}\{[A-Za-z0-9_!@#$%^&*+.:-]{3,120}\}",
            " ".join(full_argv)
        )))[:20]
        if tool == "poc_run":
            record["network_isolated"] = bool(payload.get("network_isolated"))
            for key in ("poc_sha256", "poc_bytes", "poc_path", "poc_changed_during_run"):
                if key in payload:
                    record[key] = payload[key]
            if isinstance(payload.get("poc_source_flag_literals"), list):
                record["source_flag_literals"] = payload["poc_source_flag_literals"][:20]
            elif not payload.get("poc_path"):
                # Historical broker responses describe only the host original.
                argv = full_argv
                if "--poc-file" in argv:
                    index = argv.index("--poc-file") + 1
                    if index < len(argv):
                        poc = Path(argv[index]).resolve()
                        allowed = (POC_ROOT / f"task_{task_id}").resolve()
                        try:
                            if poc.is_relative_to(allowed) and poc.is_file() and poc.stat().st_size <= POC_MAX_BYTES:
                                source = poc.read_text(encoding="utf-8", errors="replace")
                                record["source_flag_literals"] = sorted(set(re.findall(
                                    r"\b[A-Z][A-Z0-9_]{1,19}\{[A-Za-z0-9_!@#$%^&*+.:-]{3,120}\}", source
                                )))[:20]
                        except OSError:
                            pass

        text = json.dumps(record, ensure_ascii=False)

        descriptor = os.open(path, os.O_RDWR | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW, 0o600)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            try:
                if os.lseek(descriptor, 0, os.SEEK_END):
                    os.lseek(descriptor, -1, os.SEEK_END)
                    if os.read(descriptor, 1) != b"\n":
                        os.write(descriptor, b"\n")
                data = (text + "\n").encode("utf-8")
                while data:
                    data = data[os.write(descriptor, data):]
            finally:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)
        diagnostics.capability_result(record["id"], payload)
        return record["id"]

    except OSError:
        # Auditing must never break a capability call.
        return None


def capability_digest(payload, record_id, tool):
    """Keep evidence in the audit log while bounding the model-facing reply."""
    budget = 11500 if tool == "poc_run" else 3500
    raw = json.dumps(payload, ensure_ascii=False)
    if len(raw.encode("utf-8")) <= budget:
        return {**payload, "result_id": record_id,
                "full_bytes": len(raw.encode("utf-8"))}
    fields = {key: value for key, value in payload.items()
              if key not in ("stdout", "stderr", "output", "items", "payload")}
    fields.update({"result_id": record_id, "full_bytes": len(raw.encode("utf-8")),
                   "digest": True})
    text = '\n'.join(str(payload.get(key) or '') for key in ("stdout", "stderr", "output"))
    lines = text.splitlines()
    pattern = r'THM\{[^}]{0,120}\}?|0x[0-9a-fA-F]{4,}|\b[0-9a-fA-F]{8,}\b'
    evidence = [line for line in lines if re.search(pattern, line)]
    evidence.sort(key=lambda line: ('THM{' not in line, len(line)))
    keep = (lines[:8] + evidence[:24] + lines[-8:])
    def clip_line(line):
        if len(line) <= 500:
            return line
        matches = list(re.finditer(pattern, line))
        matches.sort(key=lambda match: ('THM{' not in match.group(0), match.start()))
        snippets = [line[max(0, match.start() - 120):match.end() + 120]
                    for match in matches[:3]]
        return line[:160] + ' … ' + ' … '.join(snippets) + ' … ' + line[-160:]
    seen = set()
    selected = [clip_line(line) for line in keep if not (line in seen or seen.add(line))]
    fields["stdout"] = '\n'.join(selected)
    limit = budget - len(json.dumps(fields, ensure_ascii=False).encode("utf-8")) + len(fields["stdout"].encode("utf-8")) - 100
    encoded = fields["stdout"].encode("utf-8")
    if len(encoded) > max(0, limit):
        fields["stdout"] = encoded[:max(0, limit)].decode("utf-8", "ignore")
    fields["note"] = "Полный вывод: pm_capability_read(task_id, result_id, offset)"
    return fields


def stage_budget_notice(payload):
    path = os.environ.get("PM_AGENT_STATS_FILE", "")
    if path and isinstance(payload, dict):
        try:
            stats = json.loads(Path(path).read_text())
            remaining = int(stats.get("remaining"))
            if 0 <= remaining <= 4:
                unit = "шаг" if remaining == 1 else "шага" if 2 <= remaining <= 4 else "шагов"
                payload["budget_warning"] = (
                    f"Осталось {remaining} {unit}; закругляйтесь и пишите JSON-отчёт"
                )
            recent = stats.get("recent_tools") or []
            recent = recent[-10:] if isinstance(recent, list) else []
            if len(recent) >= 5 and recent.count("session") / len(recent) > 0.6:
                payload["session_warning"] = (
                    "Много вызовов через pm_session; для разовых команд "
                    "используй pm_poc_run или pm_net_exec"
                )
        except (OSError, ValueError, TypeError):
            pass
    return payload


def tool_response(payload):
    """Keep result first and warnings as structured fields in one JSON reply."""
    payload = stage_budget_notice(payload)
    return json.dumps(payload, ensure_ascii=False)


def parse_tool_response(value):
    """Decode our own response when a tool needs to adjust broker output."""
    return json.loads(value)


def run_capability(command, timeout, tool="capability", task_id=None):
    """Run a capability helper and return its own JSON payload verbatim."""
    started = time.monotonic()
    try:
        result = subprocess.run(
            command,
            cwd=str(ROOT),
            env={**os.environ, **diagnostics.child_env()},
            capture_output=True,
            text=True,
            errors="replace",
            timeout=timeout,
            stdin=subprocess.DEVNULL,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        # subprocess.run keeps whatever it already read on the exception. A
        # long nmap that hits the timeout must not disappear from the prompt
        # (and from the audit log) as an empty payload.
        partial_out = exc.stdout or ""
        partial_err = exc.stderr or ""
        if isinstance(partial_out, bytes):
            partial_out = partial_out.decode("utf-8", "replace")
        if isinstance(partial_err, bytes):
            partial_err = partial_err.decode("utf-8", "replace")
        payload = {
            "status": "timeout",
            "kind": "timeout",
            "error": "Capability call timed out",
            "timeout_seconds": timeout,
            "stdout": str(partial_out)[:6000],
            "stderr": str(partial_err)[:2000],
            "partial_output": bool(partial_out or partial_err),
        }
        log_capability(tool, task_id, payload, time.monotonic() - started, command)
        return tool_response(payload)
    except OSError as exc:
        payload = {
            "status": "error",
            "kind": "broker",
            "error": str(exc),
        }
        log_capability(tool, task_id, payload, time.monotonic() - started, command)
        return tool_response(payload)

    diagnostics.execution_exit(result.returncode)
    text = (result.stdout or "").strip()

    try:
        payload = json.loads(text)
    except ValueError:
        payload = {
            "status": "error",
            "kind": "broker",
            "error": (result.stderr or text)[-1000:],
        }

    if isinstance(payload, list):
        # Some helpers (network_jobs observations) print an array of rows. It is
        # a valid answer, not a malformed one: wrap it so the agent can use it.
        payload = {"status": "completed", "count": len(payload), "items": payload}
    elif not isinstance(payload, dict):
        payload = {"status": "error", "kind": "broker",
                   "error": "Malformed helper output"}

    if payload.get("status") == "timeout" and not payload.get("kind"):
        payload["kind"] = "timeout"

    if (
        result.returncode != 0
        and payload.get("status") not in ("blocked", "error", "timeout")
    ):
        payload = {
            "status": "error",
            "error": payload.get("error") or "Helper failed",
            "kind": payload.get("kind", "broker"),
            "payload": payload,
        }

    record_id = log_capability(tool, task_id, payload, time.monotonic() - started, command)
    visible = dict(payload)
    visible.pop("poc_source_flag_literals", None)
    return tool_response(capability_digest(visible, record_id, tool))


@mcp.tool()
@diagnostics.tool
def pm_evidence_index(task_id: int, offset: int = -1, limit: int = 40) -> str:
    """List saved result IDs; offset=-1 selects the latest page without a charged step."""
    if not valid_task(task_id) or type(offset) is not int or offset < -1 or type(limit) is not int:
        return tool_response({'status': 'blocked', 'error': 'Invalid index arguments'})
    data = fact_state.evidence_index(
        task_id, CAPABILITY_LOG / f'task_{task_id}.jsonl',
        None if offset == -1 else offset, limit)
    return tool_response({'status': 'completed', **data})


@mcp.tool()
@diagnostics.tool
def pm_capability_read(task_id: int, result_id: str, offset: int = 0) -> str:
    """Read up to 12 KiB of a saved capability result by ID, with byte offset."""
    if not valid_task(task_id) or not re.fullmatch(r"[a-f0-9]{24}", str(result_id)):
        return tool_response({"status": "blocked", "error": "Invalid task or result ID"})
    if not isinstance(offset, int) or isinstance(offset, bool) or offset < 0:
        return tool_response({"status": "blocked", "error": "Invalid offset"})
    path = CAPABILITY_LOG / f"task_{task_id}.jsonl"
    if path.is_file():
        for line in path.open(encoding="utf-8", errors="replace"):
            try:
                record = json.loads(line)
            except ValueError:
                continue
            if record.get("id") == result_id:
                raw = json.dumps(record.get("result"), ensure_ascii=False).encode("utf-8")
                try:
                    raw[:offset].decode("utf-8")
                except UnicodeDecodeError:
                    return tool_response({"status": "blocked", "error": "Offset splits UTF-8"})
                end = min(len(raw), offset + 12000)
                while end > offset:
                    try:
                        part = raw[offset:end].decode("utf-8")
                        break
                    except UnicodeDecodeError:
                        end -= 1
                else:
                    part = ""
                return tool_response({"status": "completed", "result_id": result_id,
                                      "offset": offset, "next_offset": end,
                                      "total_bytes": len(raw), "text": part})
    return tool_response({"status": "blocked", "error": "Result not found"})


@mcp.tool()
@diagnostics.tool
def pm_write_poc(task_id: int, filename: str, content: str) -> str:
    """Save a PoC or helper script for this task, then run it with pm_poc_run.

    filename: letters, digits, dot, underscore, hyphen, up to 64 chars, with
    suffix .sh, .py, .pl, .rb or .txt. content: at most 256 KiB of text.
    The host original is stored under storage/pocs. The first pm_poc_run copies
    it to writable /work/poc/<filename> inside the sandbox.
    """
    if not valid_task(task_id):
        return response("write_poc", "blocked", 1, stderr="Invalid task ID")

    if (
        not isinstance(filename, str)
        or not POC_NAME.fullmatch(filename)
        or not filename.endswith(POC_SUFFIXES)
    ):
        return response(
            "write_poc",
            "blocked",
            1,
            stderr="Invalid filename (allowed suffixes: .sh .py .pl .rb .txt)",
        )

    if not isinstance(content, str) or not content.strip():
        return response("write_poc", "blocked", 1, stderr="Empty content")

    encoded = content.encode("utf-8")

    if len(encoded) > POC_MAX_BYTES:
        return response(
            "write_poc",
            "blocked",
            1,
            stderr="Content exceeds 256 KiB",
        )

    directory = POC_ROOT / f"task_{task_id}"
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    path = directory / filename

    if path.is_symlink() or (path.exists() and not path.is_file()):
        return response(
            "write_poc",
            "blocked",
            1,
            stderr="Refusing to replace a symlink or special file",
        )

    path.write_text(content, encoding="utf-8")
    path.chmod(0o600)

    sandbox_path = f"/work/poc/{filename}"
    record_id = log_capability("write_poc", task_id,
                   {"status": "completed", "host_path": str(path),
                    "poc_path": sandbox_path, "bytes": len(encoded),
                    "sha256": hashlib.sha256(encoded).hexdigest()},
                   0, ("pm_write_poc", str(path)))
    return tool_response({
        "status": "completed",
        "operation": "write_poc",
        "path": sandbox_path,
        "bytes": len(encoded),
        "result_id": record_id,
        "next": f"pm_poc_run(task_id={task_id}, poc_file='{sandbox_path}')",
    })


@mcp.tool()
@diagnostics.tool
def pm_poc_run(
    task_id: int,
    target: str,
    poc_file: str,
    interp: str = "bash",
    timeout: int = 60,
) -> str:
    """Run a PoC written with pm_write_poc inside the task's isolated namespace.

    The script sees only the task network namespace: the authorized target is
    reachable, the local host and the rest of the network are not. It runs as an
    unprivileged user with no capabilities. On first run the host original is
    copied to /work/poc/<name>; later runs use the editable local version.
    Pass that sandbox path, its basename, or the legacy host path. Output,
    exit code, and the local file's SHA-256 and byte count are returned.
    """
    if not valid_task(task_id):
        return response("poc_run", "blocked", 1, stderr="Invalid task ID")

    address = valid_ipv4(target)

    if not address:
        return response("poc_run", "blocked", 1, stderr="Invalid IPv4 target")

    if interp not in POC_INTERPRETERS:
        return response(
            "poc_run",
            "blocked",
            1,
            stderr="Unsupported interpreter",
        )

    if not isinstance(poc_file, str) or not poc_file:
        return response("poc_run", "blocked", 1, stderr="Invalid PoC path")

    if poc_file.startswith("/work/poc/"):
        name = poc_file.removeprefix("/work/poc/")
        if "/" in name or "\\" in name:
            return response("poc_run", "blocked", 1, stderr="Invalid PoC path")
        path = POC_ROOT / f"task_{task_id}" / name
    else:
        path = Path(poc_file)

    # Agents routinely pass the bare filename pm_write_poc just returned. Resolve
    # it inside this task's PoC directory; the containment check below still
    # applies, so this cannot reach another task's files or the host.
    if not path.is_absolute():
        name = poc_file.strip()
        if not name or "/" in name or "\\" in name or name in (".", ".."):
            return response(
                "poc_run",
                "blocked",
                1,
                stderr="Invalid PoC path; use /work/poc/<name> or a filename",
            )
        path = POC_ROOT / f"task_{task_id}" / name

    if not POC_NAME.fullmatch(path.name) or not path.name.endswith(POC_SUFFIXES):
        return response("poc_run", "blocked", 1, stderr="Invalid PoC filename or suffix")

    if path.is_symlink() or not path.is_file():
        return response("poc_run", "blocked", 1, stderr="PoC file not found")

    allowed = (POC_ROOT / f"task_{task_id}").resolve()

    if not path.resolve().is_relative_to(allowed):
        return response(
            "poc_run",
            "blocked",
            1,
            stderr="PoC must be created with pm_write_poc for this task",
        )

    if not isinstance(timeout, int) or isinstance(timeout, bool) or not 5 <= timeout <= 300:
        return response("poc_run", "blocked", 1, stderr="Invalid timeout")

    command = [
        str(PYTHON),
        str(ISOLATED_EXECUTOR),
        "run",
        "--task-id",
        str(task_id),
        "--profile",
        "poc_run",
        "--target",
        address,
        "--poc-file",
        str(path.resolve()),
        "--poc-interp",
        interp,
        "--timeout",
        str(timeout),
        "--execute",
    ]

    return run_capability(command, timeout + 40, tool="poc_run", task_id=task_id)


@mcp.tool()
@diagnostics.tool
def pm_net_exec(
    task_id: int,
    target: str,
    argv_json: str,
    timeout: int = 60,
    hypothesis_key: str = "",
    new_evidence_id: str = "",
) -> str:
    """Run any installed Kali tool inside the task's isolated namespace.

    argv_json: JSON array of strings, argv[0] an absolute binary path, e.g.
    ["/usr/bin/nmap","-sV","-p","80,3306","10.0.0.5"]. No shell is used:
    pipes, redirection and globbing do not apply. Reachable network is limited
    to the task's authorized target; there is no access to the host filesystem.
    """
    if not valid_task(task_id):
        return response("net_exec", "blocked", 1, stderr="Invalid task ID")

    address = valid_ipv4(target)

    if not address:
        return response("net_exec", "blocked", 1, stderr="Invalid IPv4 target")

    try:
        argv = json.loads(argv_json)
    except (ValueError, TypeError):
        return response(
            "net_exec",
            "blocked",
            1,
            stderr="argv_json must be a JSON array of strings",
        )

    if (
        not isinstance(argv, list)
        or not argv
        or not all(isinstance(item, str) and item for item in argv)
        or len(argv) > 64
        or any(len(item) > 4096 for item in argv)
        or not argv[0].startswith("/")
    ):
        return response(
            "net_exec",
            "blocked",
            1,
            stderr="Invalid argv (absolute argv[0], up to 64 tokens)",
        )

    if not isinstance(timeout, int) or isinstance(timeout, bool) or not 5 <= timeout <= 180:
        return response("net_exec", "blocked", 1, stderr="Invalid timeout")

    try:
        blocked = guard_explicit_assets(
            task_id, fact_state.explicit_assets_from_argv(argv),
            hypothesis_key, new_evidence_id)
    except (sqlite3.Error, ValueError, OSError) as exc:
        blocked = 'Не удалось проверить матрицу активов: ' + str(exc)[:160]
    if blocked:
        return response('net_exec', 'blocked', 1, stderr=blocked)

    command = [
        str(PYTHON),
        str(ISOLATED_EXECUTOR),
        "run",
        "--task-id",
        str(task_id),
        "--profile",
        "exec",
        "--target",
        address,
        "--argv-json",
        json.dumps(argv, ensure_ascii=False),
        "--timeout",
        str(timeout),
        "--execute",
    ]

    return run_capability(command, timeout + 40, tool="net_exec", task_id=task_id)


@mcp.tool()
@diagnostics.tool
def pm_research(task_id: int, target: str, host: str, path: str = "/") -> str:
    """Fetch CVE and exploit data from the fixed research allowlist.

    Allowed hosts: nvd.nist.gov, services.nvd.nist.gov, exploit-db.com,
    www.exploit-db.com, api.github.com. path may carry
    a query string, e.g. /rest/json/cves/2.0?cveId=CVE-2023-30258 or
    /search?q=MagnusBilling. Only HTTPS/443 to that host is permitted.
    """
    if not valid_task(task_id):
        return response("research", "blocked", 1, stderr="Invalid task ID")

    address = valid_ipv4(target)

    if not address:
        return response("research", "blocked", 1, stderr="Invalid IPv4 target")

    if host not in RESEARCH_HOSTS:
        return response(
            "research",
            "blocked",
            1,
            stderr="Host not in research allowlist: " + ", ".join(RESEARCH_HOSTS),
        )

    if (
        not isinstance(path, str)
        or not path.startswith("/")
        or len(path) > 512
        or any(ord(char) < 32 for char in path)
    ):
        return response("research", "blocked", 1, stderr="Invalid research path")

    command = [
        str(PYTHON),
        str(ISOLATED_EXECUTOR),
        "run",
        "--task-id",
        str(task_id),
        "--profile",
        "research",
        "--target",
        address,
        "--research-host",
        host,
        "--path",
        path,
        "--execute",
    ]

    return run_capability(command, 90, tool="research", task_id=task_id)


@mcp.tool()
@diagnostics.tool
def pm_callback(
    task_id: int,
    action: str,
    target: str = "",
    port: int = 4444,
    bind: str = "",
    timeout: int = 300,
) -> str:
    """Scoped listener that collects blind results from the target.

    action: open | read | close. open starts a listener that accepts connections
    only from the task's authorized target and stores received bytes.
    read returns what arrived; close stops the listener. Run the reverse-shell
    or exfiltrating part of the PoC with pm_poc_run, then read the result here.
    bind: optional local address (for example the VPN interface address).
    target: required for open (scope of accepted peers); optional for read/close.
    """
    if not valid_task(task_id):
        return response("callback", "blocked", 1, stderr="Invalid task ID")

    address = ""

    if target:
        address = valid_ipv4(target)

        if not address:
            return response("callback", "blocked", 1, stderr="Invalid IPv4 target")

    elif action == "open":
        return response(
            "callback",
            "blocked",
            1,
            stderr="target is required to open a scoped listener",
        )

    if action not in ("open", "read", "close"):
        return response(
            "callback",
            "blocked",
            1,
            stderr="action must be open, read or close",
        )

    command = [
        str(PYTHON),
        str(ISOLATED_EXECUTOR),
        "callback",
        "--task-id",
        str(task_id),
        "--action",
        action,
    ]

    if isinstance(port, int) and not isinstance(port, bool) and 1024 <= port <= 65535:
        command.extend(["--port", str(port)])

    if action == "open":
        # 0.0.0.0 means "every interface", which is what the listener already
        # does. Passing it through made the broker reject the call with a
        # confusing "Bind address is not configured on this host".
        if bind and bind not in ("0.0.0.0",):
            if not valid_ipv4(bind):
                return response("callback", "blocked", 1, stderr="Invalid bind address")

            command.extend(["--bind", bind])

        if isinstance(timeout, int) and not isinstance(timeout, bool) and 10 <= timeout <= 3600:
            command.extend(["--timeout", str(timeout)])

    command.append("--execute")

    result = run_capability(command, 60, tool="callback", task_id=task_id)

    if action == "open":
        # A listener on that port is already running, which is exactly the state
        # the agent asked for. Reporting it as "blocked" made the agent retry and
        # burn steps (three times on task 17), so answer what is true instead.
        try:
            payload = parse_tool_response(result)
        except (ValueError, TypeError):
            return result

        if isinstance(payload, dict) and "already running" in str(payload.get("error", "")):
            payload["status"] = "listening"
            payload["already_running"] = True
            payload["note"] = "listener already running on this port; use action=read"
            payload.pop("error", None)

            return tool_response(payload)

    return result


@mcp.tool()
@diagnostics.tool
def pm_session(
    task_id: int,
    action: str,
    session_id: str = "",
    argv_json: str = "",
    data: str | list[str] = "",
    wait: float = 0.8,
    idle: int = 1800,
) -> str:
    """A process that keeps running between calls, inside the task namespace.

    A normal call starts a sandbox, runs one command and throws it away, so a
    half-finished exploit, a downloaded binary or a gdb session is lost in
    between. This keeps one alive:

    - action=open starts it. argv_json selects the program, e.g.
      '["/usr/bin/gdb","/work/beacon"]'; empty means an interactive bash.
      Returns session_id.
    - action=send types text or a list of commands into it; a list is sent
      together as one PTY write and one tool step.
    - action=read returns output produced since the last read.
    - action=interrupt sends Ctrl-C without closing the session.
    - action=close stops it. action=list shows all sessions of the task.

    /work is shared with pm_poc_run and pm_net_exec and now persists for the
    whole task, so files written here are still there on the next call. The
    session inherits the same network isolation: only the authorized target is
    reachable. Idle sessions expire after `idle` seconds (60..7200); teardown of
    the task kills them automatically.
    """
    def blocked(reason):
        log_capability("session", task_id,
                       {"status": "blocked", "action": action, "error": reason},
                       0.0)
        return response("session", "blocked", 1, stderr=reason)

    if not valid_task(task_id):
        return blocked("Invalid task ID")

    if action not in ("open", "send", "read", "interrupt", "close", "list"):
        return blocked("action must be open, send, read, interrupt, close or list")

    command = [
        str(PYTHON),
        str(ISOLATED_EXECUTOR),
        "session",
        "--task-id",
        str(task_id),
        "--action",
        action,
    ]

    if action in ("send", "read", "interrupt", "close"):
        if not re.fullmatch(r"[a-f0-9]{8}", str(session_id or "")):
            return blocked("Invalid session_id")

        command.extend(["--session-id", session_id])

    if action == "open":
        if argv_json:
            try:
                parsed = json.loads(argv_json)
            except ValueError:
                return blocked("argv_json is not JSON")

            if not isinstance(parsed, list) or not all(isinstance(item, str) for item in parsed):
                return blocked("argv_json must be an array of strings")

            if len(parsed) > 64 or any(len(item) > 4096 for item in parsed):
                return blocked("argv_json is too large")

            command.extend(["--argv-json", json.dumps(parsed)])

        if isinstance(idle, int) and not isinstance(idle, bool):
            if not 60 <= idle <= 7200:
                return blocked("idle must be 60..7200")

            command.extend(["--idle", str(idle)])

    if action == "send":
        if isinstance(data, list):
            if not data or not all(isinstance(item, str) for item in data):
                return blocked("Invalid command list")
            data = "\n".join(item.rstrip("\n") for item in data) + "\n"
        if len(str(data).encode("utf-8")) > 65536:
            return blocked("data is too large")

        command.extend(["--data", data])

    if action in ("send", "read", "interrupt") and isinstance(wait, (int, float)) and not isinstance(wait, bool):
        command.extend(["--wait", str(min(max(float(wait), 0.0), 5.0))])

    command.append("--execute")

    result = run_capability(command, 120 if action == "open" else 60,
                            tool="session", task_id=task_id)
    return result


@mcp.tool()
@diagnostics.tool
def pm_worknote(task_id: int, append: str = "") -> str:
    """Read or append 0-7 evidence-backed facts in this task's /work/NOTES.md.

    Prefix a withdrawn fact with [ОПРОВЕРГНУТО] and state the new evidence.
    This is a host-side file operation; no network broker is invoked.
    """
    if not valid_task(task_id):
        return tool_response({"status": "blocked", "error": "Invalid task ID"})
    directory = TASK_WORK_BASE / str(task_id)
    try:
        if not directory.exists() and not directory.is_symlink():
            try:
                directory.mkdir(mode=0o700)
            except PermissionError:
                # WORK_BASE is root-owned 0711. A missing leaf needs one scoped
                # broker call; ordinary note reads/writes stay host-side.
                result = subprocess.run(
                    ["sudo", "-n", "/usr/local/sbin/pm-netguard", "workdir",
                     "--task-id", str(task_id)], capture_output=True, text=True,
                    timeout=20, check=False,
                )
                if result.returncode:
                    raise OSError("Task workspace could not be initialized")
        info = directory.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise ValueError("Unsafe task work directory")
        path = directory / "NOTES.md"
        if append:
            lines = append.splitlines()
            if not 1 <= len(lines) <= 7 or len(append.encode("utf-8")) > 4096:
                raise ValueError("Append 0-7 lines, at most 4096 bytes")
            if any("→" not in line for line in lines):
                raise ValueError("Each line needs fact → supporting evidence")
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW, 0o600)
            try:
                current = os.fstat(fd)
                if not stat.S_ISREG(current.st_mode) or current.st_uid != os.getuid() or current.st_size > 131072:
                    raise ValueError("Unsafe or full NOTES.md")
                os.write(fd, (append.rstrip("\n") + "\n").encode("utf-8"))
            finally:
                os.close(fd)
        if path.is_file() and not path.is_symlink():
            tail = path.read_text(encoding="utf-8", errors="replace").splitlines()[-40:]
        else:
            tail = []
        return tool_response({"status": "completed", "path": "/work/NOTES.md",
                              "lines": tail, "appended": bool(append)})
    except (OSError, ValueError) as exc:
        return tool_response({"status": "blocked", "error": str(exc)})


@mcp.tool()
@diagnostics.tool
def pm_observations(task_id: int) -> str:
    """Return saved network observations and capability outputs for a task."""
    if not valid_task(task_id):
        return response("observations", "blocked", 1, stderr="Invalid task ID")

    return run_capability([
        str(PYTHON),
        str(NETWORK_JOBS),
        "observations",
        "--task-id",
        str(task_id),
    ], 60, tool="observations", task_id=None)


if __name__ == "__main__":
    mcp.run(transport="stdio")
