
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
from contextlib import closing
from functools import wraps
from contextvars import ContextVar
from pathlib import Path

from mcp.server.fastmcp import FastMCP


ROOT = Path(__file__).resolve().parents[1]
PYTHON = ROOT / ".venv/bin/python"

sys.path.insert(0, str(ROOT))

from executor.tool_catalog import detect_tools
from executor.tool_executor_v3 import PROFILES
from executor.netguard_root import reject_password_change
from orchestrator import fact_state, diagnostics, task_memory


mcp = FastMCP("pentest-master")
ASSET_DB = ROOT / 'storage/tasks.db'
from orchestrator import target_availability
network_guard=target_availability.guard(lambda:ASSET_DB)
from orchestrator import research_budgets
budget_guard=research_budgets.tool_guard(lambda:ASSET_DB)


_memory_operation_id=ContextVar('pm_memory_operation_id',default=None)


def guard_explicit_assets(task_id, assets, hypothesis_key='', new_evidence_id=''):
    """Gate structured probes; opaque shell and PoC internals remain advisory."""
    if not assets:
        return None
    if not ASSET_DB.is_file():
        return 'Реестр активов недоступен'
    records = fact_state.capability_index(
        task_id, CAPABILITY_LOG / f'task_{task_id}.jsonl')
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
        "max_ports": 50,
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
@budget_guard
@network_guard
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
POC_MAX_BYTES = 64 * 1024 * 1024
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
        return str(ipaddress.ip_address(text))
    except (ipaddress.AddressValueError, ValueError, TypeError):
        return None


def capability_provenance(tool, payload, command):
    """Classify the source when writing the record, before argv is truncated."""
    if payload.get('cached') is True:return 'local'
    if tool=='check_series':return 'network' if payload.get('checks_started',0) else 'local'
    if tool == 'poc_run':
        if payload.get('network_isolated') is True:
            if payload.get('network_contact') is True:return 'network'
            if payload.get('network_contact') is False:return 'local'
        return 'unknown'
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
    if tool=='session' and '--action' in command:
        action=list(command)[list(command).index('--action')+1]
        if action in ('read','list'):return 'local'
        if action=='open':
            def option(key):
                try:return command[list(command).index(key)+1]
                except (ValueError,IndexError):return ''
            try:args=json.loads(option('--argv-json') or '[]')
            except ValueError:args=None
            if not option('--ssh-json') and args in ([],['/bin/bash','--noprofile','--norc','-i']):return 'local'
            return 'unknown' # starting an SSH/client process does not prove contact/authentication
        if payload.get('network_contact') is True:return 'network'
        if payload.get('network_contact') is False:return 'local'
        return 'unknown' # a generic PTY may run local code or a nested client
    if tool in ('callback','transfer') and '--action' in command:
        action=list(command)[list(command).index('--action')+1]
        if action in ('read','diagnose'):return 'local'
    if tool=='pivot_probe':return 'network' if payload.get('probe_performed') else 'local'
    if tool in ('pivot_request','pivot_status'):return 'local'
    if tool in ('session', 'network_probe', 'privileged_scan', 'http_get', 'http_headers',
                'http_path', 'http_document', 'http_capture'):
        return 'network'
    if tool in ('write_poc', 'read_file', 'grep', 'unpack', 'capability_read', 'tool_request', 'tool_acquire','material_process','material_import'):
        return 'local'
    return 'unknown'


def log_capability(tool, task_id, payload, elapsed, command=()):
    """Append every capability call to a per-task audit log.

    The orchestrator reads this log as evidence, so nothing an agent did inside
    the namespace is lost when its step budget runs out.
    """
    if tool=='poc_run':
        from orchestrator.check_series import poc_events
        payload.setdefault('internal_checks',poc_events(payload))
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
        if _memory_operation_id.get():record['memory_operation_id']=_memory_operation_id.get()
        if os.environ.get('PM_BUDGET_ROLE'):record['actor_role']=os.environ['PM_BUDGET_ROLE']
        if os.environ.get('PM_COORDINATOR_STEP_ID'):record['coordinator_step_id']=int(os.environ['PM_COORDINATOR_STEP_ID'])
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
        diagnostics.capability_result(record["id"], payload,evidence_path=path)
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


def supports_automatic_refresh(tool, command, target):
    """Positive grammar for the supported bounded TCP read check, not a grant.

    Generic curl (including HEAD/GET) can load config, send data or upload files;
    it receives no automatic TTL exception. Unknown nmap flags/scripts/paths
    also need new conditions or explicit review, rather than a name heuristic.
    Inspect the original argv, before canonicalization removes output options.
    """
    if tool != 'net_exec':return False
    try:
        argv = json.loads(command[list(command).index('--argv-json') + 1])
    except (ValueError, IndexError, TypeError):
        return False
    if not isinstance(argv, list) or not argv or argv[0] != '/usr/bin/nmap':return False
    if not all(isinstance(arg, str) for arg in argv) or argv[-1] != target:return False
    ports = None
    index = 1
    while index < len(argv) - 1:
        arg = argv[index]
        if arg in ('-sT', '-Pn', '-n', '--open'):
            index += 1
            continue
        if arg == '-p' and index + 1 < len(argv) - 1:
            value = argv[index + 1]
            index += 2
        elif arg.startswith('-p') and len(arg) > 2:
            value = arg[2:]
            index += 1
        else:return False
        if ports is not None or not re.fullmatch(r'[0-9]+(?:,[0-9]+)*', value):return False
        ports = [int(port) for port in value.split(',')]
        if len(ports) > NETWORK_PROFILES['tcp_ports']['max_ports'] or any(not 1 <= port <= 65535 for port in ports):
            return False
    return ports is not None


def track_memory_operation(function):
    @wraps(function)
    def tracked(command,timeout,tool='capability',task_id=None):
        # Test/alternate logs must never cause writes to a different task DB.
        if not ASSET_DB.is_file() or CAPABILITY_LOG.parent!=ASSET_DB.parent:
            return function(command,timeout,tool,task_id)
        with closing(sqlite3.connect(ASSET_DB,timeout=10)) as db:
            if not task_memory.exists(db,'tasks'):
                return function(command,timeout,tool,task_id)
            row=db.execute('SELECT target FROM tasks WHERE id=?',(task_id,)).fetchone()
            if not row:return function(command,timeout,tool,task_id)
            from orchestrator import resources
            def option(name,default=''):
                try:return command[list(command).index('--'+name)+1]
                except (ValueError,IndexError):return default
            profile=option('profile',tool)
            if profile!='research' and not (tool in ('session','callback','transfer') and option('action') in ('read','list','close','interrupt','diagnose')):
                try:
                    resources.authorize(db,task_id,'http' if profile.startswith(('http','https')) else profile,
                        option('target',row[0]),scheme=option('scheme','http'),hostname=option('hostname'),
                        port=int(option('port','80')),path=option('path','/'))
                except ValueError as exc:return response(tool,'blocked',1,stderr=str(exc))
            # Provenance is known only after a result; it never grants a retry.
            description=task_memory.canonical_operation(tool,command,row[0],provenance='unknown')
            task_memory.sync(db,task_id,CAPABILITY_LOG/f'task_{task_id}.jsonl',reason='execution_reconcile')
            conditions={'target':row[0], 'access':[
                [r.get('level'),r.get('signal')] for r in task_memory.rows(db,'pm_access_state',task_id)]}
            from orchestrator import service_inventory
            services=service_inventory.collect_full(db,task_id)['entries']
            conditions['services']=[{
                **{k:entry[k] for k in ('protocol','port','state','identification_conflict','identification_uncertain')},
                'identifications':[{k:v for k,v in identity.items() if k!='source'} for identity in entry['identifications']]}
                for entry in services if not description['ports'] or entry['port'] in description['ports']]
            if tool=='session' and option('session-id'):
                from orchestrator import task_sessions
                saved=next((s for s in task_sessions.listing(db,task_id) if s['session_id']==option('session-id')),None)
                conditions['session_stream_state']=saved['details'].get('stream_state_sha256') if saved else None
            if tool=='poc_run' and '--poc-file' in command:
                poc=Path(command[list(command).index('--poc-file')+1])
                allowed=(POC_ROOT/f'task_{task_id}').resolve()
                if (poc.resolve().is_relative_to(allowed) and poc.is_file() and not poc.is_symlink()
                        and poc.stat().st_size<=POC_MAX_BYTES):
                    conditions['poc_source_sha256']=hashlib.sha256(poc.read_bytes()).hexdigest()
                if '--stdin-file' in command:
                    data=Path(command[list(command).index('--stdin-file')+1])
                    if data.resolve().is_relative_to(allowed) and data.is_file() and not data.is_symlink() and data.stat().st_size<=POC_MAX_BYTES:
                        digest=hashlib.sha256()
                        with data.open('rb') as stream:
                            for block in iter(lambda:stream.read(65536),b''):digest.update(block)
                        conditions['stdin_sha256']=digest.hexdigest()
            fresh=False
            if task_memory.exists(db,'pm_memory_operations'):
                previous=db.execute('SELECT created_at FROM pm_memory_operations WHERE task_id=? AND signature=? '
                                    'ORDER BY rowid DESC LIMIT 1',(task_id,description['signature'])).fetchone()
                if previous:
                    from orchestrator import service_inventory
                    from datetime import datetime,timezone
                    stamp=service_inventory.timestamp(previous[0])
                    fresh=bool(stamp and supports_automatic_refresh(tool,command,row[0]) and
                        (datetime.now(timezone.utc)-stamp).total_seconds()>service_inventory.age_minutes()*60)
            with task_memory.atomic(db):
                intent=task_memory.begin_operation(db,task_id,description,conditions=conditions,
                    require_fresh=fresh,reason='saved freshness policy expired' if fresh else '')
                if intent['allowed']:
                    task_memory.sync(db,task_id,CAPABILITY_LOG/f'task_{task_id}.jsonl',reason='operation_intent')
            if not intent['allowed']:
                payload={'status':'blocked','kind':'repeat_guard','execution_started':False,**intent}
                log_capability('check_guard',task_id,payload,0,command)
                return tool_response(payload)
            oid=intent['operation_id']
            with task_memory.atomic(db):
                task_memory.transition(db,task_id,oid,'dispatching',expected_phase='intent')
                task_memory.sync(db,task_id,CAPABILITY_LOG/f'task_{task_id}.jsonl',reason='operation_dispatching')
            try:
                token=_memory_operation_id.set(oid)
                try:reply=function(command,timeout,tool,task_id)
                finally:_memory_operation_id.reset(token)
            except BaseException:
                try:
                    with task_memory.atomic(db):
                        task_memory.transition(db,task_id,oid,'unknown',expected_phase='dispatching',outcome='exception_or_interrupt')
                        task_memory.sync(db,task_id,CAPABILITY_LOG/f'task_{task_id}.jsonl',reason='operation_unknown')
                except Exception as failure:
                    diagnostics.emit('memory.update_failed',task_id=task_id,reason='original_exception_retained',
                                     error_type=type(failure).__name__,identifiers={'operation_id':oid})
                    print('[MEMORY-ERROR] '+type(failure).__name__+'; original operation error retained',file=sys.stderr,flush=True)
                raise
            payload=json.loads(reply)
            outcome=payload.get('status','unknown')
            not_started=payload.get('execution_started') is False
            if not_started:outcome=payload.get('error_type') or outcome
            if payload.get('exit_code') not in (None,0) and outcome=='completed':outcome='nonzero_exit'
            phase='cancelled' if not_started else 'unknown' if outcome in ('timeout','unknown') else 'finished'
            try:
                with task_memory.atomic(db):
                    if not not_started:
                        task_memory.transition(db,task_id,oid,'started',expected_phase='dispatching')
                    task_memory.transition(db,task_id,oid,phase,expected_phase='dispatching' if not_started else 'started',outcome=outcome,result_id=payload.get('result_id'))
                    if tool=='session' and phase=='finished' and (payload.get('stream_state_sha256') or isinstance(payload.get('output'),str) and payload['output']):
                        # Compare the next command with the previous *post* state.
                        # Its own identical reply is not a reason to repeat it.
                        after={**conditions,'session_stream_state':payload.get('stream_state_sha256') or task_memory.digest(payload['output'])}
                        db.execute('UPDATE pm_memory_operations SET conditions_sha256=? WHERE id=? AND task_id=?',
                                   (task_memory.digest(after),oid,task_id))
                    task_memory.sync(db,task_id,CAPABILITY_LOG/f'task_{task_id}.jsonl',reason='operation_'+phase)
            except (sqlite3.Error,task_memory.VersionConflict) as exc:
                print('[MEMORY-ERROR] '+type(exc).__name__+'; completed evidence retained',file=sys.stderr,flush=True)
                diagnostics.emit('memory.update_failed',task_id=task_id,reason='completed_evidence_retained',
                                 identifiers={'operation_id':oid},error_type=type(exc).__name__)
                return tool_response({**payload,'memory_warning':'state_commit_failed_evidence_preserved'})
            return reply
    return tracked


@track_memory_operation
def run_capability(command, timeout, tool="capability", task_id=None):
    """Run a capability helper and return its own JSON payload verbatim."""
    started = time.monotonic()
    if tool=='poc_run' and ASSET_DB.is_file() and CAPABILITY_LOG.parent==ASSET_DB.parent:
        with sqlite3.connect(ASSET_DB,timeout=10) as db:
            try:
                research_budgets.ensure(db,task_id,'poc',os.environ.get('PM_BUDGET_ROLE','manual'),capability_log=CAPABILITY_LOG/f'task_{task_id}.jsonl')
                research_budgets.consume(db,task_id,'poc',os.environ.get('PM_BUDGET_ROLE','manual'),unit='poc_executor_dispatch',
                    details={'coordinator_step_id':int(os.environ.get('PM_COORDINATOR_STEP_ID') or 0)})
                db.commit()
            except research_budgets.Exhausted:
                payload={'status':'blocked','execution_started':False,'reason_category':'poc_budget_exhausted','reason':'15 PoC dispatches reached; return results to coordinator'}
                rid=log_capability(tool,task_id,payload,0,command)
                return tool_response({**payload,'result_id':rid})
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
            "error_type": "executor_unavailable" if isinstance(exc,FileNotFoundError) else "launch_error",
            "error": str(exc),
            "execution_started": False,
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

    if tool=='poc_run':
        from orchestrator.check_series import poc_events
        payload['internal_checks']=poc_events(payload)
    record_id = log_capability(tool, task_id, payload, time.monotonic() - started, command)
    visible = dict(payload)
    visible.pop("poc_source_flag_literals", None)
    return tool_response(capability_digest(visible, record_id, tool))


@mcp.tool()
@diagnostics.tool
@budget_guard
def pm_publish_candidate(task_id:int,service_ref:str,username:str,secret:str,source_ref:str,quote:str,expected_version:int=-1)->str:
    """Publish a source-linked credential candidate, never access or permission.

    Existing task memory is the only store. Exact saved source bytes are
    required; publication may wake another bounded specialist on that service.
    """
    from orchestrator import service_inventory
    if not valid_task(task_id) or (os.environ.get('PM_TASK_ID') or str(task_id))!=str(task_id):return tool_response({'status':'blocked'})
    try:
        if not all(isinstance(v,str) and v and len(v)<=4096 for v in (username,secret,source_ref,quote)):raise ValueError('Bounded candidate/source required')
        with closing(sqlite3.connect(ASSET_DB,timeout=10)) as db,task_memory.atomic(db):
            target=db.execute('SELECT target FROM tasks WHERE id=?',(task_id,)).fetchone()[0]
            known={f"service:{target}:{e['protocol']}:{e['port']}" for e in service_inventory.collect_full(db,task_id)['entries']}
            if service_ref not in known:raise ValueError('Unknown current-task service')
            original=task_memory.material(db,task_id,source_ref,CAPABILITY_LOG/f'task_{task_id}.jsonl')
            if quote.encode() not in original or username not in quote or secret not in quote:raise ValueError('Candidate is absent from quoted saved source')
            key='candidate:'+task_memory.digest([service_ref,username,secret])
            head=task_memory.current(db,task_id);old=head['state']['credentials'].get(key)
            value=old or {'kind':'credential_candidate','service_ref':service_ref,'username':username,'secret':secret,
                'source_ref':source_ref,'quote':quote,'trust':'candidate','access_established':False}
            version=task_memory.apply(db,task_id,head['version'] if expected_version==-1 else expected_version,
                [{'section':'credentials','key':key,'value':value}],reason='specialist_candidate_publication',actor='specialist')
        diagnostics.emit('memory.published',task_id=task_id,identifiers={'reference':key,'version':version})
        return tool_response({'status':'completed','reference':key,'version':version,'trust':'candidate','access_established':False,'provenance':'local'})
    except (ValueError,OSError,sqlite3.Error) as exc:return tool_response({'status':'blocked','execution_started':False,'reason_category':'candidate_publication_failed','error_type':type(exc).__name__})


@mcp.tool()
@diagnostics.tool
def pm_budget_status(task_id:int)->str:
    if not valid_task(task_id) or (os.environ.get('PM_TASK_ID') or str(task_id))!=str(task_id):return tool_response({'status':'blocked'})
    with closing(sqlite3.connect(f'file:{ASSET_DB}?mode=ro',uri=True)) as db:
        return tool_response({'status':'completed','accounts':research_budgets.listing(db,task_id),'provenance':'local'})


@mcp.tool()
@diagnostics.tool
@budget_guard
@network_guard
def pm_check_series(task_id:int,plan_json:str)->str:
    """Bounded HTTP Basic pairs or paths/traversal, each check saved separately.

    Plan kind,url,hypothesis,max_requests(<=50),seconds(<=600),criterion and
    either <=5 pairs [{username,password,source_ref}] or explicit paths.
    Criterion: kind=authenticated|find_file|inventory, status list and exact
    body_contains/sha256 for authentication/file. First 200 is insufficient.
    Existing scope/HTTP/storage/repeat budgets apply to every inner request.
    replan=true needs a different running saved coordinator step and new checks.
    """
    from orchestrator import check_series
    try:
        if not valid_task(task_id) or (os.environ.get('PM_TASK_ID') or str(task_id))!=str(task_id):raise ValueError('Wrong task')
        with closing(sqlite3.connect(ASSET_DB,timeout=10)) as db:
            payload=check_series.run(db,task_id,json.loads(plan_json),CAPABILITY_LOG/f'task_{task_id}.jsonl',
                request=lambda value,name,bound:json.loads(pm_http_request(task_id,json.dumps(value),name,request_limit=bound)))
            task_memory.sync(db,task_id,CAPABILITY_LOG/f'task_{task_id}.jsonl',reason='internal_check_series');db.commit()
    except (ValueError,OSError,sqlite3.Error) as exc:payload={'status':'blocked','execution_started':False,'reason':str(exc)[:240]}
    rid=log_capability('check_series',task_id,payload,0)
    return tool_response({**payload,'result_id':rid})


@mcp.tool()
@diagnostics.tool
def pm_checks_status(task_id:int)->str:
    from orchestrator import check_series
    if not valid_task(task_id) or (os.environ.get('PM_TASK_ID') or str(task_id))!=str(task_id):return tool_response({'status':'blocked'})
    with closing(sqlite3.connect(f'file:{ASSET_DB}?mode=ro',uri=True)) as db:
        return tool_response({'status':'completed','directions':check_series.state(db,task_id),'provenance':'local'})


@mcp.tool()
@diagnostics.tool
@budget_guard
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
@budget_guard
def pm_task_memory(task_id:int,section:str='resources',offset:int=0,limit:int=20,version:int=-1)->str:
    """Page complete task state/history; a local read creates no network observation."""
    expected=os.environ.get('PM_TASK_ID','')
    if expected and expected!=str(task_id):
        return tool_response({'status':'blocked','error':'Memory task differs from active SDK task'})
    if (not valid_task(task_id) or section not in (*task_memory.SECTIONS,'history')
            or type(offset) is not int or offset<0 or type(limit) is not int or not 1<=limit<=40
            or type(version) is not int or version < -1):
        return tool_response({'status':'blocked','error':'Invalid memory page'})
    try:
        with closing(sqlite3.connect(f'file:{ASSET_DB}?mode=ro',uri=True,timeout=10)) as db,task_memory.atomic(db):
            head=task_memory.current(db,task_id,None if version==-1 else version)
            if section=='history':
                values=[]
                if task_memory.exists(db,'pm_memory_revisions'):
                    values=[{'version':r[0],'reason':r[1],'actor':r[2],'sha256':r[3]} for r in db.execute(
                        'SELECT version,reason,actor,sha256 FROM pm_memory_revisions WHERE task_id=? ORDER BY version',(task_id,))]
            else:
                state=task_memory.source_state(db,task_id,CAPABILITY_LOG/f'task_{task_id}.jsonl') if version==-1 else head['state']
                for key,value in head['state'][section].items():
                    if not value.get('source_owned'):state[section][key]=value
                values=[{'reference':key,'value':value} for key,value in sorted(state[section].items())]
            part=values[offset:offset+limit]
            return tool_response({'status':'completed','task_id':task_id,'version':head['version'],
                'section':section,'items':part,'total':len(values),'next_offset':offset+len(part) if offset+len(part)<len(values) else None,
                'provenance':'local_read'})
    except (sqlite3.Error,ValueError,OSError) as exc:
        return tool_response({'status':'blocked','error_type':type(exc).__name__})


@mcp.tool()
@diagnostics.tool
@budget_guard
def pm_material_read(task_id:int,reference:str,offset:int=0,limit:int=4096,sha256:str='')->str:
    """Read one verified original byte range with coverage metadata; never a GET."""
    expected=os.environ.get('PM_TASK_ID','')
    if expected and expected!=str(task_id):
        return tool_response({'status':'blocked','error':'Memory task differs from active SDK task'})
    if not valid_task(task_id):return tool_response({'status':'blocked','error':'Invalid task'})
    try:
        with closing(sqlite3.connect(f'file:{ASSET_DB}?mode=ro',uri=True,timeout=10)) as db,task_memory.atomic(db):
            chunk=task_memory.read_chunk(db,task_id,reference,CAPABILITY_LOG/f'task_{task_id}.jsonl',
                offset=offset,limit=limit,sha256=sha256 or None)
        # Delivery is separate from claimed analysis and from evidence status.
        with closing(sqlite3.connect(ASSET_DB,timeout=10)) as db,db:
            task_memory.record_coverage(db,task_id,chunk,kind='delivered')
        return tool_response({'status':'completed','provenance':'local_read',**chunk})
    except (sqlite3.Error,ValueError,OSError) as exc:
        return tool_response({'status':'blocked','error_type':type(exc).__name__})


@mcp.tool()
@diagnostics.tool
@budget_guard
def pm_material_import(task_id:int,path:str)->str:
    """Snapshot one regular task-workspace file (<=64 MiB), never a host path.

    Source bytes are preserved. Directories can be supplied as a saved archive;
    no checkout, specimen execution, remote Git clone or submodule/LFS fetch.
    """
    from orchestrator import material_processing as files
    from executor.netguard_root import WORK_BASE
    try:
        if not valid_task(task_id) or (os.environ.get('PM_TASK_ID') or str(task_id))!=str(task_id):raise ValueError('Wrong task')
        parts=path.split('/')
        if not path or len(path)>4096 or any(p in ('','..','.') for p in parts):raise ValueError('Expected a relative workspace file')
        directory=os.open(WORK_BASE/str(task_id),os.O_DIRECTORY|os.O_NOFOLLOW)
        try:
            for component in parts[:-1]:
                child=os.open(component,os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=directory);os.close(directory);directory=child
            fd=os.open(parts[-1],os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=directory)
            with os.fdopen(fd,'rb') as stream:
                info=os.fstat(stream.fileno())
                if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.getuid():raise ValueError('Unsafe workspace file')
                data=stream.read(files.MAX_BYTES+1)
        finally:os.close(directory)
        with closing(sqlite3.connect(ASSET_DB,timeout=10)) as db:
            item=files.save(db,task_id,data,name=path,source_ref='workspace:'+path,metadata={'origin':'workspace_snapshot','network_origin':'unknown'})
            task_memory.sync(db,task_id,CAPABILITY_LOG/f'task_{task_id}.jsonl',reason='material_import');db.commit()
        payload={'status':'completed','task_id':task_id,'material':item,'fresh_observation':False}
    except (ValueError,OSError,sqlite3.Error) as exc:payload={'status':'blocked','reason':str(exc)[:200],'execution_started':False}
    rid=log_capability('material_import',task_id,payload,0)
    return tool_response({**payload,'result_id':rid})


@mcp.tool()
@diagnostics.tool
@budget_guard
def pm_material_process(task_id:int,reference:str,operation:str='auto',options_json:str='{}')->str:
    """Actual-type local text/archive/PDF/OCR/static-binary/Git processing.

    options: encoding, object_id, ocr, language, page_start/page_end (<=8 OCR
    pages), related:[{reference,path}] for original Git pack/index/loose data.
    No network, supplied executable execution, checkout, LFS/submodule fetch.
    Missing supported analyzers request the operator through pm_tool_request.
    Read outputs by file_material:ID with pm_material_read; local derivations
    do not establish working credentials, access, flags or independent evidence.
    """
    from orchestrator import material_processing as files
    try:
        if not valid_task(task_id) or (os.environ.get('PM_TASK_ID') or str(task_id))!=str(task_id):raise ValueError('Wrong task')
        with closing(sqlite3.connect(ASSET_DB,timeout=10)) as db:
            payload=files.process(db,task_id,reference,CAPABILITY_LOG/f'task_{task_id}.jsonl',operation=operation,options=json.loads(options_json))
            task_memory.sync(db,task_id,CAPABILITY_LOG/f'task_{task_id}.jsonl',reason='material_processing');db.commit()
        if payload.get('required_tool'):
            request=json.loads(pm_tool_request(task_id,json.dumps(payload['required_tool'])))
            payload['operator_question']={k:request.get(k) for k in ('status','question_id','tool_request','reason_category','error')}
    except (ValueError,OSError,sqlite3.Error) as exc:payload={'status':'blocked','reason':str(exc)[:200],'execution_started':False}
    rid=log_capability('material_process',task_id,payload,0)
    return tool_response({**payload,'result_id':rid})


@mcp.tool()
@diagnostics.tool
@budget_guard
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
@budget_guard
def pm_write_poc(task_id: int, filename: str, content: str='', material_ref: str='',instrument_checks:bool=False) -> str:
    """Save a PoC or helper script for this task, then run it with pm_poc_run.

    filename: letters, digits, dot, underscore, hyphen, up to 64 chars, with
    suffix .sh, .py, .pl, .rb or .txt. content or material_ref: <=64 MiB explicit file resource bound.
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

    source_bytes=None
    if material_ref:
        if content:return response('write_poc','blocked',1,stderr='Choose content or material_ref')
        try:
            with closing(sqlite3.connect(f'file:{ASSET_DB}?mode=ro',uri=True)) as db:
                source_bytes=task_memory.material(db,task_id,material_ref,CAPABILITY_LOG/f'task_{task_id}.jsonl')
        except (ValueError,OSError,UnicodeError,sqlite3.Error) as exc:return response('write_poc','blocked',1,stderr=type(exc).__name__)
    if source_bytes is None and (not isinstance(content, str) or not content.strip()):
        return response("write_poc", "blocked", 1, stderr="Empty content")

    encoded = source_bytes if source_bytes is not None else content.encode("utf-8")
    original=encoded
    if instrument_checks:
        try:
            if not filename.endswith('.py'):raise ValueError('Automatic instrumentation supports Python; other interpreters must emit PM_CHECK explicitly')
            from orchestrator.check_series import instrument_python
            encoded=instrument_python(encoded.decode('utf-8')).encode('utf-8')
        except (ValueError,SyntaxError,UnicodeError) as exc:return response('write_poc','blocked',1,stderr=str(exc))

    if len(encoded) > POC_MAX_BYTES:
        return response(
            "write_poc",
            "blocked",
            1,
            stderr="Content exceeds explicit 64 MiB file resource bound",
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

    if instrument_checks:
        original_path=directory/(filename+'.source-'+hashlib.sha256(original).hexdigest())
        if original_path.is_symlink():return response('write_poc','blocked',1,stderr='Unsafe original source path')
        original_path.write_bytes(original);original_path.chmod(0o600)
    path.write_bytes(encoded)
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
        "internal_check_protocol":"PM_CHECK JSON start/end per check; arbitrary uninstrumented code remains unmeasured",
        "instrumented":instrument_checks,
        "result_id": record_id,
        "next": f"pm_poc_run(task_id={task_id}, poc_file='{sandbox_path}')",
    })


@mcp.tool()
@diagnostics.tool
@budget_guard
@network_guard
def pm_poc_run(
    task_id: int,
    target: str,
    poc_file: str,
    interp: str = "bash",
    timeout: int = 60,
    operation_reason: str = '',
    stdin_file: str = '',
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

    if not isinstance(timeout, int) or isinstance(timeout, bool) or not 5 <= timeout <= 600:
        return response("poc_run", "blocked", 1, stderr="Invalid timeout")
    try:
        from executor.netguard_root import operation_timeout
        operation_timeout('poc_run',timeout,operation_reason)
    except ValueError as exc:return response('poc_run','blocked',1,stderr=str(exc))
    try:reject_password_change(text=path.read_text(encoding='utf-8',errors='replace'))
    except ValueError as exc:return response('poc_run','blocked',1,stderr=str(exc))

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

    if operation_reason:command+=['--operation-reason',operation_reason]
    if stdin_file:
        name=stdin_file.removeprefix('/work/poc/')
        data=POC_ROOT/f'task_{task_id}'/name
        if not POC_NAME.fullmatch(name) or data.is_symlink() or not data.is_file():return response('poc_run','blocked',1,stderr='stdin_file must be a saved task PoC/data basename')
        command+=['--stdin-file',str(data.resolve())]
    return run_capability(command, timeout + 40, tool="poc_run", task_id=task_id)


@mcp.tool()
@diagnostics.tool
@budget_guard
def pm_tool_request(task_id: int, spec_json: str, branch_id: str = 'task') -> str:
    """Request one bounded tool/doc/package acquisition; never approve it for the operator.

    spec_json: kind=user_tool|documentation with name,purpose,version,source,
    channel=internet|kali_local|local_file,filename,sha256,interpreter;
    or kind=system_package with name,purpose,version (exact or candidate).
    Read the returned source/actions/destination/rights and wait for that branch.
    """
    from orchestrator import tool_requests, service_inventory, resources
    if not valid_task(task_id) or (os.environ.get('PM_TASK_ID') or str(task_id)) != str(task_id):
        return tool_response({'status':'blocked','reason_category':'scope_denied','error':'Tool task differs from active SDK task'})
    try:
        spec=tool_requests.tool_spec(json.loads(spec_json))
        with closing(sqlite3.connect(ASSET_DB,timeout=10)) as db:
            row=db.execute('SELECT target FROM tasks WHERE id=?',(task_id,)).fetchone()
            if not row:raise ValueError('Unknown task')
            target=row[0];scope='scope:'+target
            allowed={scope}|{f"service:{target}:{e['protocol']}:{e['port']}" for e in service_inventory.collect_full(db,task_id)['entries']}
            graph=resources.graph(db,task_id)
            allowed.update(graph.get('authorized_resources',[]))
            if branch_id!='task' and branch_id not in allowed:raise ValueError('Unknown or unauthorized dependent branch')
            decision={'operator_question':{'kind':'tool','request':spec},'question':spec['purpose'],'reason':spec['purpose'],
                'branch_id':branch_id,'references':['intent'],
                'boundaries':{'task_id':task_id,'target':target,'intent_ref':'intent','resource_refs':[scope if branch_id=='task' else branch_id]}}
            question=tool_requests.request(db,task_id,target,decision)
            task_memory.sync(db,task_id,CAPABILITY_LOG/f'task_{task_id}.jsonl',reason='tool_request')
            db.commit()
        item=question['tool_request']
        payload={'status':'waiting_operator' if question['status']=='pending' else item['status'],
                 'question_id':question['id'],'task_id':task_id,'tool_request':item,
                 'execution_started':False,'provenance':'local'}
    except (ValueError,OSError,sqlite3.Error) as exc:
        payload={'status':'blocked','reason_category':getattr(exc,'category','invalid_request'),'error':str(exc)}
    rid=log_capability('tool_request',task_id,payload,0)
    return tool_response({**payload,'result_id':rid})


@mcp.tool()
@diagnostics.tool
@budget_guard
def pm_tool_status(task_id: int) -> str:
    """Local saved installation state, source/version/invocation and failures; no network or sudo."""
    from orchestrator import tool_requests
    if not valid_task(task_id) or (os.environ.get('PM_TASK_ID') or str(task_id)) != str(task_id):
        return tool_response({'status':'blocked','reason_category':'scope_denied'})
    with closing(sqlite3.connect(f'file:{ASSET_DB}?mode=ro',uri=True,timeout=10)) as db:
        return tool_response({'status':'completed','task_id':task_id,'provenance':'local_read',
            'tools':[tool_requests.describe(item) for item in tool_requests.listing(db,task_id)]})


@mcp.tool()
@diagnostics.tool
@budget_guard
def pm_tool_read(task_id: int, request_id: int, offset: int = 0, limit: int = 4096) -> str:
    """Read a bounded, hash-verified saved tool/doc range without network/sudo; not new target evidence."""
    from orchestrator import tool_requests
    if not valid_task(task_id) or (os.environ.get('PM_TASK_ID') or str(task_id)) != str(task_id):
        return tool_response({'status':'blocked','reason_category':'scope_denied'})
    try:
        with closing(sqlite3.connect(f'file:{ASSET_DB}?mode=ro',uri=True,timeout=10)) as db:
            return tool_response(tool_requests.read_material(db,task_id,request_id,offset,limit))
    except (ValueError,sqlite3.Error,OSError) as exc:
        return tool_response({'status':'blocked','error':str(exc),'reason_category':'integrity_error'})


@mcp.tool()
@diagnostics.tool
@budget_guard
def pm_tool_acquire(task_id: int, request_id: int) -> str:
    """Apply an operator-authorized receipt. Cannot authorize; failed/unknown installs are not replayed."""
    from orchestrator import tool_requests
    if not valid_task(task_id) or (os.environ.get('PM_TASK_ID') or str(task_id)) != str(task_id):
        return tool_response({'status':'blocked','reason_category':'scope_denied'})
    try:
        with closing(sqlite3.connect(ASSET_DB,timeout=10)) as db:
            item=tool_requests.acquire(db,task_id,request_id)
            task_memory.sync(db,task_id,CAPABILITY_LOG/f'task_{task_id}.jsonl',reason='tool_acquire')
            db.commit()
        payload={'status':item['status'],'task_id':task_id,'tool_request':tool_requests.describe(item),
                 'provenance':'local','reason':item.get('reason'),
                 'reason_category':(item['receipt'].get('result') or {}).get('reason_category',item['receipt'].get('reason_category'))}
    except (ValueError,sqlite3.Error,OSError) as exc:
        payload={'status':'error','reason_category':getattr(exc,'category','installation_failed'),'error':str(exc)}
    rid=log_capability('tool_acquire',task_id,payload,0)
    return tool_response({**payload,'result_id':rid})


@mcp.tool()
@diagnostics.tool
@budget_guard
def pm_port_status(task_id:int,offset:int=0,limit:int=50)->str:
    """Read aggregated saved discovery states, no target/broker/API requests."""
    from orchestrator import port_research
    if not valid_task(task_id) or (os.environ.get('PM_TASK_ID') or str(task_id))!=str(task_id):return tool_response({'status':'blocked','reason':'Wrong task'})
    with closing(sqlite3.connect(f'file:{ASSET_DB}?mode=ro',uri=True)) as db:
        if not task_memory.exists(db,'network_observations'):return tool_response({'status':'completed','items':[],'total':0})
        target=db.execute('SELECT target FROM tasks WHERE id=?',(task_id,)).fetchone()[0]
        return tool_response({'status':'completed',**port_research.summary(db,task_id,target,offset=offset,limit=limit)})


@mcp.tool()
@diagnostics.tool
@budget_guard
@network_guard
def pm_port_survey(task_id:int,protocol:str,ports:str,max_jobs:int=1)->str:
    """Separate explicit TCP/UDP discovery queue (1..50 ports), no service identity.

    Persists before next job, resumes only unstarted jobs, UDP silence is
    open|filtered, not open. No two scans guarantee all services. URL scope
    does not authorize scanning a host. Model interprets aggregated saved data.
    """
    from orchestrator import port_research
    try:
        if max_jobs!=1:raise ValueError('MCP discovery executes one job per tool step; use the next step to resume')
        if not valid_task(task_id) or (os.environ.get('PM_TASK_ID') or str(task_id))!=str(task_id):raise ValueError('Wrong task')
        selected=[int(p) for p in ports.split(',')]
        with closing(sqlite3.connect(ASSET_DB,timeout=10)) as db:
            target=db.execute('SELECT target FROM tasks WHERE id=?',(task_id,)).fetchone()[0]
            result=port_research.run(db,task_id,target,protocol,selected,max_jobs)
            # An actual MCP capability receipt; original runs/observations stay
            # in their existing tables. Reusing the queue is a local read.
            record=log_capability('network_probe',task_id,result,0)
            return tool_response({**result,'result_id':record})
    except (ValueError,OSError,sqlite3.Error) as exc:return tool_response({'status':'blocked','reason':str(exc)[:200]})


@mcp.tool()
@diagnostics.tool
@budget_guard
@network_guard
def pm_privileged_scan(task_id: int, target: str, profile: str, ports: str) -> str:
    """Fixed nmap_syn/nmap_udp/nmap_os through broker; scope/NetGuard/repeat budgets still apply.

    1..50 explicit ports (UDP <=8), bounded runtime, no NSE/custom arguments or root PoC.
    """
    from executor.netguard_root import RAW_SCAN_PROFILES, tool_args
    try:
        if not valid_task(task_id) or (os.environ.get('PM_TASK_ID') or str(task_id)) != str(task_id):raise ValueError('Invalid task')
        address=str(ipaddress.ip_address(target))
        if profile not in RAW_SCAN_PROFILES:raise ValueError('Unsupported privileged profile')
        tool_args(profile,address,80,ports,'http')
    except ValueError as exc:return tool_response({'status':'blocked','error':str(exc),'execution_started':False})
    return run_capability(['sudo','-n','/usr/local/sbin/pm-netguard','run','--task-id',str(task_id),
        '--profile',profile,'--target',address,'--ports',ports],60,tool='privileged_scan',task_id=task_id)


@mcp.tool()
@diagnostics.tool
@budget_guard
@network_guard
def pm_net_exec(
    task_id: int,
    target: str,
    argv_json: str,
    timeout: int = 60,
    hypothesis_key: str = "",
    new_evidence_id: str = "",
    operation_reason: str = '',
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

    if not isinstance(timeout, int) or isinstance(timeout, bool) or not 5 <= timeout <= 600:
        return response("net_exec", "blocked", 1, stderr="Invalid timeout")
    try:
        from executor.netguard_root import operation_timeout
        operation_timeout('exec',timeout,operation_reason)
    except ValueError as exc:return response('net_exec','blocked',1,stderr=str(exc))
    try:reject_password_change(argv)
    except ValueError as exc:return response('net_exec','blocked',1,stderr=str(exc))

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

    if operation_reason:command+=['--operation-reason',operation_reason]
    return run_capability(command, timeout + 40, tool="net_exec", task_id=task_id)


@mcp.tool()
@diagnostics.tool
@budget_guard
@network_guard
def pm_browser(task_id:int,action:str,session_id:str='',action_json:str='{}',url:str='',username:str='',purpose:str='',proxy:str='')->str:
    """Managed JavaScript browser, with scoped PM HTTP as its only network path.

    open creates an isolated user context (no navigation); control JSON has
    action=open(url), fill(selector,value), click(selector), wait(selector), read.
    Retain the ID between roles and read after handoff. Different users need
    different sessions. status/release/close use the common session manager.
    proxy=burp requires operator-configured task-local Burp; empty works without it.
    """
    from orchestrator import browser,task_sessions
    if not valid_task(task_id) or (os.environ.get('PM_TASK_ID') or str(task_id))!=str(task_id):return tool_response({'status':'blocked','error':'Wrong task'})
    try:
        with closing(sqlite3.connect(ASSET_DB,timeout=10)) as db:
            if action=='open':payload=browser.open_session(db,task_id,url,username,purpose,proxy or None)
            elif action=='restore':
                payload=browser.call(task_id,'restore',session_id=session_id)
                task_sessions.record_result(db,task_id,'open',payload,session_id=session_id);db.commit()
            elif action=='control':payload=browser.execute(db,task_id,session_id,json.loads(action_json),log=CAPABILITY_LOG/f'task_{task_id}.jsonl')
            elif action in ('status','release','close'):
                payload=task_sessions.call(task_id,'read' if action=='status' else action,session_id)
                task_sessions.record_result(db,task_id,'read' if action=='status' else action,payload,session_id=session_id);db.commit()
            else:raise ValueError('Invalid browser action')
            if action=='control':
                ids=[]
                from orchestrator import http_artifacts
                for eid in payload.get('http_exchanges',[]):
                    saved=db.execute('SELECT result_id FROM pm_browser_network WHERE task_id=? AND session_id=? AND exchange_id=?',(task_id,session_id,eid)).fetchone()
                    existing=saved[0] if saved else None
                    if existing:ids.append(existing);continue
                    row=db.execute('SELECT target,artifact_id,metadata_json FROM pm_http_exchanges WHERE id=? AND task_id=?',(eid,task_id)).fetchone()
                    if not row or row[1] is None:continue
                    meta=json.loads(row[2]);body,info=http_artifacts.load(db,task_id,row[1])
                    text=http_artifacts.decode_body(body,info.get('headers',{}))[0]
                    data={'task_id':task_id,'target':row[0],'artifact_id':row[1],'artifact_ref':'http_artifact:'+str(row[1]),
                        'status':'completed' if meta['transport_complete'] else 'incomplete','exit_code':0 if meta['transport_complete'] else 1,
                        'browser_session_id':session_id,'exchange_id':eid,'stdout':http_artifacts.diagnostic_text(text[:4096]),
                        'stdout_truncated':len(text)>4096,'observed_at':meta['observed_at']}
                    reference=log_capability('http_capture',task_id,data,0)
                    db.execute('UPDATE pm_browser_network SET result_id=? WHERE task_id=? AND exchange_id=?',(reference,task_id,eid));ids.append(reference)
                db.commit();payload['network_result_ids']=ids
                if payload.get('http_exchanges'):
                    from orchestrator import task_memory
                    with task_memory.atomic(db):
                        row=db.execute('SELECT id,result_json FROM pm_browser_actions WHERE task_id=? AND session_id=? AND id=?',(task_id,session_id,payload.get('browser_action_id'))).fetchone()
                        if row:
                            saved_result=json.loads(row[1]);saved_result['network_result_ids']=ids
                            db.execute('UPDATE pm_browser_actions SET result_json=? WHERE id=?',(json.dumps(saved_result),row[0]))
                        task_memory.sync(db,task_id,CAPABILITY_LOG/f'task_{task_id}.jsonl',reason='browser_evidence_references')
    except browser.CaptureImportError as exc:payload=exc.payload
    except (ValueError,KeyError,TypeError) as exc:payload={'status':'blocked','reason_category':getattr(exc,'category','policy'),'reason':str(exc)[:160]}
    except (OSError,sqlite3.Error,subprocess.SubprocessError) as exc:payload={'status':'unknown','reason_category':'outcome_unknown','error_type':type(exc).__name__}
    rid=log_capability('browser',task_id,payload,0)
    return tool_response({**payload,'result_id':rid})


@mcp.tool()
@diagnostics.tool
@budget_guard
def pm_browser_read(task_id:int,session_id:str,offset:int=0,limit:int=10,action_id:int=0)->str:
    """Read saved browser observations only. No live DOM/JS, target, browser or Burp calls."""
    from orchestrator import browser
    if not valid_task(task_id) or (os.environ.get('PM_TASK_ID') or str(task_id))!=str(task_id):return tool_response({'status':'blocked','error':'Wrong task'})
    if offset<0 or not 1<=limit<=65536:return tool_response({'status':'blocked','error':'Invalid range'})
    with closing(sqlite3.connect(f'file:{ASSET_DB}?mode=ro',uri=True,timeout=10)) as db:
        rows=browser.observations(db,task_id,session_id)
        if action_id:
            from orchestrator import http_artifacts
            row=next((r for r in rows if r['id']==action_id),None)
            if not row or not row['result'].get('dom_ref'):return tool_response({'status':'blocked','error':'No saved DOM for this task/session/action'})
            body=http_artifacts.load_material(task_id,row['result']['dom_ref']);chunk=body[offset:offset+limit]
            return tool_response({'status':'completed','provenance':'local','data_b64':base64.b64encode(chunk).decode(),
                'bytes':len(body),'has_more':offset+len(chunk)<len(body)})
        size=min(limit,20)
        return tool_response({'status':'completed','provenance':'local','observations':rows[offset:offset+size],
            'has_more':offset+size<len(rows)})


@mcp.tool()
@diagnostics.tool
@budget_guard
def pm_burp(task_id:int,action:str='status',url:str='',after:int=0,limit:int=1)->str:
    """Burp Professional capability and passive history import/read.

    This PM-owned Montoya bridge is not a native Burp REST/MCP API. No target
    requests are sent by status/import/read. Fresh requests use HTTP/browser
    proxy=burp with the configured guarded task-local Proxy listener.
    """
    from orchestrator import burp_adapter
    if not valid_task(task_id) or (os.environ.get('PM_TASK_ID') or str(task_id))!=str(task_id):return tool_response({'status':'blocked','error':'Wrong task'})
    try:
        if action=='status':payload=burp_adapter.status(task_id)
        elif action=='import':
            with closing(sqlite3.connect(ASSET_DB,timeout=10)) as db:payload=burp_adapter.import_history(db,task_id,url,after,limit)
        elif action=='read':
            with closing(sqlite3.connect(f'file:{ASSET_DB}?mode=ro',uri=True,timeout=10)) as db:
                payload={'status':'completed','provenance':'local','messages':burp_adapter.read(db,task_id)}
        else:raise ValueError('Invalid Burp action')
    except (ValueError,OSError,sqlite3.Error) as exc:payload={'status':'blocked','reason':str(exc)[:160]}
    return tool_response(payload)


@mcp.tool()
@diagnostics.tool
@budget_guard
@network_guard
def pm_http_request(task_id:int,request_json:str,session_id:str='default',request_limit:int=6)->str:
    """Fresh task-scoped HTTP exchange with methods, bodies, cookies and uploads.

    JSON fields: url,method,headers,query,cookies,auth,body/body_b64/json/form/files,
    ssrf,timeout,tls_verify,proxy(optional burp). Files name task /work paths. No implicit response
    cache. Redirects are checked individually; credentials are origin/session
    bound. HTTP completion/status does not confirm login or a research goal.
    Use pm_http_read for saved original ranges, not another network operation.
    """
    from orchestrator import http_client
    started=time.monotonic()
    try:
        if not valid_task(task_id) or (os.environ.get('PM_TASK_ID') or str(task_id))!=str(task_id):raise ValueError('Wrong HTTP task')
        request=json.loads(request_json)
        if isinstance(request,dict) and request.get('proxy')=='burp':
            from orchestrator import burp_adapter
            if burp_adapter.status(task_id)['status']!='available':raise ValueError('burp_unavailable: dedicated Burp Professional bridge v3 is required')
        with closing(sqlite3.connect(ASSET_DB,timeout=10)) as db:
            from orchestrator import check_series
            payload=check_series.direct_http(db,task_id,request,session_id,request_limit)
    except http_client.HTTPExecutionError as exc:
        payload={'status':'unknown','reason_category':'outcome_unknown','reason':str(exc),'task_id':task_id}
    except (ValueError,TypeError,KeyError) as exc:
        payload={'status':'blocked','error_type':type(exc).__name__,'reason':str(exc)[:240],'task_id':task_id}
    except (OSError,sqlite3.Error,subprocess.SubprocessError) as exc:
        payload={'status':'error','error_type':type(exc).__name__,'reason':'HTTP operation outcome unknown; inspect saved exchange, no automatic retry','task_id':task_id}
    rid=log_capability('http_capture',task_id,payload,time.monotonic()-started,
        ['http_request','--task-id',str(task_id),'--session-id',session_id])
    return tool_response({**payload,'result_id':rid})


@mcp.tool()
@diagnostics.tool
@budget_guard
def pm_http_read(task_id:int,exchange_id:int,part:str='body',offset:int=0,limit:int=4096)->str:
    """Read a saved HTTP request/response/body range. No network or new evidence."""
    from orchestrator import http_client
    if not valid_task(task_id) or (os.environ.get('PM_TASK_ID') or str(task_id))!=str(task_id):return tool_response({'status':'blocked','error':'Wrong task'})
    try:
        with closing(sqlite3.connect(f'file:{ASSET_DB}?mode=ro',uri=True,timeout=10)) as db:
            return tool_response(http_client.read(db,task_id,exchange_id,part,offset,limit))
    except (ValueError,OSError,sqlite3.Error,KeyError):return tool_response({'status':'blocked','reason':'Saved HTTP material unavailable'})


@mcp.tool()
@diagnostics.tool
@budget_guard
@network_guard
def pm_http_capture(
    task_id: int,
    target: str,
    port: int = 80,
    path: str = "/",
    scheme: str = "http",
    hostname: str = "",
    hypothesis_key: str = "",
    new_evidence_id: str = "",
) -> str:
    """Legacy cached GET discovery. Use pm_http_request for a fresh/current response.

    Authorized task resource and pinned Host/SNI. Query is preserved; a fragment
    is browser-only. No body, custom headers, redirects or shell. Returns artifact_ref and result_id.
    A previously saved URL is read from the artifact store without another GET.
    """
    from contextlib import closing
    from orchestrator import http_discovery as web
    started=time.monotonic()
    address=valid_ipv4(target)
    phase='validation'
    command=['http_capture','--task-id',str(task_id),'--target',str(target),
             '--scheme',scheme,'--hostname',hostname or str(target),'--port',str(port),'--path',path]
    try:
        if not valid_task(task_id) or not address or not ASSET_DB.is_file():
            raise web.CaptureRefused('Invalid task, target or missing task database')
        with closing(sqlite3.connect(ASSET_DB,timeout=10)) as db:
            # Permission validation precedes asset-recheck consumption and I/O.
            host=hostname or address
            web.validate_endpoint(db,task_id,address,scheme,host,port,path)
            path=web._safe_path(path)
            if type(port) is not int or not 1 <= port <= 65535:
                raise web.CaptureRefused('Invalid TCP port')
            phase='capture'
            payload=web.capture_explicit(db,task_id,address,scheme,host,port,path,
                hypothesis_key=hypothesis_key,new_evidence_id=new_evidence_id,
                records=fact_state.capability_index(task_id,CAPABILITY_LOG / f'task_{task_id}.jsonl'))
    except (web.CaptureRefused, ValueError) as exc:
        # Input/scope refusals are separate from capture protocol/IO failures.
        refused=phase=='validation' or isinstance(exc,web.CaptureRefused)
        payload={'status':'blocked' if refused else 'error','kind':'policy' if refused else 'capture_protocol',
                 'error':str(exc)[:240],'task_id':task_id,'target':target}
    except (OSError,sqlite3.Error,subprocess.SubprocessError) as exc:
        payload={'status':'error','kind':'broker','error':str(exc)[:240],'task_id':task_id,'target':target}
    record_id=log_capability('http_capture',task_id,payload,time.monotonic()-started,command)
    return tool_response(capability_digest(payload,record_id,'http_capture'))


@mcp.tool()
@diagnostics.tool
@budget_guard
@network_guard
def pm_http_ssrf(task_id:int,application:str,destination:str,parameter:str='url',context:str='') -> str:
    """Legacy cached SSRF GET. Use pm_http_request.ssrf for fresh query/form/JSON checks.

    The destination is reached by the target application, never by Kali directly.
    Target-relative loopback needs an explicit grant; arbitrary destinations are denied.
    """
    from orchestrator import resources, http_discovery as web
    start=time.monotonic();command=['http_ssrf','--application',application,'--destination',destination]
    try:
        if not valid_task(task_id) or not re.fullmatch(r'[A-Za-z][A-Za-z0-9_.-]{0,63}',parameter):raise ValueError('Invalid SSRF parameters')
        source=resources.parse(application);inner=resources.parse(destination)
        if source['kind']!='url' or inner['kind']!='url':raise ValueError('SSRF requires explicit application and destination URLs')
        with closing(sqlite3.connect(ASSET_DB,timeout=10)) as db:
            scope=resources.saved(db,task_id)
            if not scope:raise ValueError('SSRF requires saved resource scope')
            endpoint=next((o for o in scope['policy']['origins'] if o['origin']==source['origin']),None)
            if not endpoint:raise ValueError('SSRF application is not an authorized origin')
            target=endpoint['addresses'][0];context=context or scope['policy']['machine']
            route={'destination':inner['request_url'],'context':context,'parameter':parameter}
            web.validate_endpoint(db,task_id,target,source['scheme'],source['host'],source['port'],source['request_path'],
                                  destination=inner['request_url'],context=context)
            payload=web.capture_explicit(db,task_id,target,source['scheme'],source['host'],source['port'],source['request_path'],ssrf=route)
    except (ValueError,web.CaptureRefused) as exc:
        payload={'status':'blocked','kind':'policy','error':str(exc),'task_id':task_id}
    except (OSError,sqlite3.Error,subprocess.SubprocessError) as exc:
        payload={'status':'error','kind':'broker','error':str(exc)[:240],'task_id':task_id}
    rid=log_capability('http_ssrf',task_id,payload,time.monotonic()-start,command)
    return tool_response(capability_digest(payload,rid,'http_ssrf'))


@mcp.tool()
@diagnostics.tool
@budget_guard
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
@budget_guard
@network_guard
def pm_callback(
    task_id: int,
    action: str,
    target: str = "",
    port: int = 4444,
    bind: str = "",
    timeout: int = 300,
) -> str:
    """Interactive callbacks from scoped peers on the current laboratory route.

    action=open/read/close/diagnose. read returns accepted session IDs; use
    pm_session for bidirectional I/O. Use pm_transfer for streamed files.
    The listener binds the current VPN route source, not guessed NAT/old VPN.
    An operator can correct topology with callback-config. Diagnose the address,
    receiver and saved preflight; silence alone does not prove egress filtering.
    Accepted sockets are peer-bound; no arbitrary host execution is provided.
    """
    if not valid_task(task_id) or (os.environ.get('PM_TASK_ID') or str(task_id))!=str(task_id):
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

    if action=='diagnose':
        command=['sudo','-n','/usr/local/sbin/pm-netguard','callback','--task-id',str(task_id),'--action','diagnose','--port',str(port)]
        reply=json.loads(run_capability(command,15,tool='callback',task_id=task_id))
        if ASSET_DB.is_file():
            from orchestrator import task_sessions
            with closing(sqlite3.connect(f'file:{ASSET_DB}?mode=ro',uri=True,timeout=10)) as db:
                reply=task_sessions.callback_assessment(db,task_id,reply)
        diagnostics.emit('callback.assessment',task_id=task_id,result_id=reply.get('result_id'),reason=reply.get('diagnosis'))
        return tool_response(reply)
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
    if action=='read' and ASSET_DB.is_file() and CAPABILITY_LOG.parent==ASSET_DB.parent:
        from orchestrator import task_sessions
        with closing(sqlite3.connect(ASSET_DB,timeout=10)) as db:
            task_sessions.record_result(db,task_id,'list',json.loads(result));db.commit()

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
@budget_guard
@network_guard
def pm_transfer(task_id:int,action:str,port:int=4445,expected_bytes:int=-1,sha256:str='',
                max_bytes:int=536870912,timeout:int=300)->str:
    """Separate streamed file receiver. No interactive terminal and no universal 4 MiB limit.

    Known size + EOF establishes size completeness; optional SHA256 verifies content.
    Unknown size/timeout/disk exhaustion remain explicitly unverified/incomplete.
    """
    if not valid_task(task_id) or (os.environ.get('PM_TASK_ID') or str(task_id))!=str(task_id):return tool_response({'status':'blocked','error':'Wrong task'})
    if action not in ('open','read','close','diagnose') or not 1024<=port<=65535:return tool_response({'status':'blocked','error':'Invalid transfer action/port'})
    if not 1<=max_bytes<=1073741824 or expected_bytes < -1 or expected_bytes>max_bytes or not 10<=timeout<=3600:
        return tool_response({'status':'blocked','error':'Invalid transfer budget'})
    if sha256 and not re.fullmatch(r'[a-f0-9]{64}',sha256):return tool_response({'status':'blocked','error':'Invalid expected SHA256'})
    command=['sudo','-n','/usr/local/sbin/pm-netguard','callback','--task-id',str(task_id),'--action',action,'--port',str(port),'--mode','transfer']
    if action=='open':
        command+=['--timeout',str(timeout),'--max-bytes',str(max_bytes)]
        if expected_bytes>=0:command+=['--expected-bytes',str(expected_bytes)]
        if sha256:command+=['--expected-sha256',sha256]
    return run_capability(command,20,tool='transfer',task_id=task_id)


@mcp.tool()
@diagnostics.tool
@budget_guard
@network_guard
def pm_pivot_request(task_id:int,spec_json:str)->str:
    """Request one scoped SSH forward through an existing managed SSH session.

    spec: source_session,resource_ref,destination (saved internal address),port,
    local_port,probe=http_headers|banner,purpose. Operator approval is required.
    """
    from orchestrator import pivoting
    if not valid_task(task_id) or (os.environ.get('PM_TASK_ID') or str(task_id))!=str(task_id):return tool_response({'status':'blocked','error':'Wrong task'})
    try:
        spec=pivoting.pivot_spec(json.loads(spec_json))
        with closing(sqlite3.connect(ASSET_DB,timeout=10)) as db:
            target=db.execute('SELECT target FROM tasks WHERE id=?',(task_id,)).fetchone()[0]
            decision={'operator_question':{'kind':'pivoting','request':spec},'question':spec['purpose'],'reason':spec['purpose'],
                'branch_id':spec['resource_ref'],'references':[spec['resource_ref'],'session:'+spec['source_session']],
                'boundaries':{'task_id':task_id,'target':target,'intent_ref':'intent','resource_refs':[spec['resource_ref']]}}
            question=pivoting.request(db,task_id,target,decision)
            task_memory.sync(db,task_id,CAPABILITY_LOG/f'task_{task_id}.jsonl',reason='pivot_request');db.commit()
        payload={'status':'waiting_operator' if question['status']=='pending' else question['pivot_request']['state'],
                 'question_id':question['id'],'route':question['pivot_request'],'execution_started':False}
    except (ValueError,sqlite3.Error,OSError) as exc:payload={'status':'blocked','error':str(exc),'execution_started':False}
    rid=log_capability('pivot_request',task_id,payload,0)
    return tool_response({**payload,'result_id':rid})


@mcp.tool()
@diagnostics.tool
@budget_guard
@network_guard
def pm_pivot(task_id:int,route_id:int,action:str='status')->str:
    """Status/apply an operator-authorized SSH forward; cannot authorize or recreate broken/unknown forwards.

    action=probe performs a bounded check of the saved destination through the
    existing forward, not a new tunnel. Use the saved local endpoint only for its
    specified resource. status is local metadata/control health, not fresh target evidence.
    """
    from orchestrator import pivoting
    if not valid_task(task_id) or (os.environ.get('PM_TASK_ID') or str(task_id))!=str(task_id):return tool_response({'status':'blocked','error':'Wrong task'})
    if action not in ('status','apply','probe','close'):return tool_response({'status':'blocked','error':'Invalid route action'})
    with closing(sqlite3.connect(ASSET_DB,timeout=10)) as db:
        route=next((r for r in pivoting.listing(db,task_id) if r['id']==route_id),None)
        if not route:return tool_response({'status':'blocked','error':'Unknown task route'})
        if route.get('diagnostic'):return tool_response(pivoting.blocked(route))
        log=CAPABILITY_LOG/f'task_{task_id}.jsonl'
        if action=='probe' and route['state'] in ('active','established_unverified'):
            reply=json.loads(run_capability(['sudo','-n','/usr/local/sbin/pm-netguard','pivot','--task-id',str(task_id),
                '--action','probe','--request-id',route['receipt']['request_id']],15,tool='pivot_probe',task_id=task_id))
            saved=pivoting.record_reply(db,route,reply,'probe',capability_log=log)
            db.commit()
            return tool_response(saved['receipt'])
        if action=='close':
            payload=pivoting.close(db,task_id,route_id,capability_log=log)
        else:payload=pivoting.apply(db,task_id,route_id,perform=action=='apply',capability_log=log)
        payload={**payload,'status':payload.get('status',payload['state']),
                 **{k:payload['receipt'][k] for k in ('reason_category','reason_summary') if k in payload['receipt']}}
    rid=log_capability('pivot_status',task_id,payload,0)
    return tool_response({**payload,'result_id':rid})


@mcp.tool()
@diagnostics.tool
@budget_guard
@network_guard
def pm_session(
    task_id: int,
    action: str,
    session_id: str = "",
    argv_json: str = "",
    data: str | list[str] = "",
    wait: float = 0.8,
    idle: int = 1800,
    resource: str = '', username: str = '', purpose: str = '', retain: bool | None = None,
    ssh_json: str = '',
) -> str:
    """Shared task PTY/managed SSH or an already accepted peer-bound callback.

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

    Up to ten live connections survive roles. One live agent owns a terminal;
    read after handoff before send. retain=false closes unused sessions at role
    end unless a route depends on them. resource/username/purpose are metadata,
    not proof of access. ssh_json={target,user,port,identity} selects managed SSH
    instead of argv_json, for supported operator-approved pivoting. Unknown
    prior input is never automatically replayed. Saved DB/PID is not liveness.

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
    if (os.environ.get('PM_TASK_ID') or str(task_id))!=str(task_id):return blocked('Session task differs from active SDK task')

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
            try:reject_password_change(parsed)
            except ValueError as exc:return blocked(str(exc))

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

        try:reject_password_change(text=data)
        except ValueError as exc:return blocked(str(exc))
        command.extend(["--data", data])

    if action in ("send", "read", "interrupt") and isinstance(wait, (int, float)) and not isinstance(wait, bool):
        command.extend(["--wait", str(min(max(float(wait), 0.0), 5.0))])

    command.append("--execute")
    from orchestrator import task_sessions
    command+=['--owner',task_sessions.owner(),'--owner-pid',str(os.getpid())]
    if action=='open':
        if ssh_json:
            try:
                ssh=json.loads(ssh_json)
                if not isinstance(ssh,dict) or set(ssh)!={'target','user','port','identity'}:raise ValueError('Invalid managed SSH')
            except ValueError:return blocked('Invalid ssh_json')
            if argv_json:return blocked('Choose argv_json or ssh_json')
            try:ssh['target']=str(ipaddress.ip_address(ssh['target']))
            except ValueError:return blocked('Managed SSH requires a scoped numeric address')
            command+=['--ssh-json',json.dumps(ssh,sort_keys=True,separators=(',',':'))]
        purpose=purpose or os.environ.get('PM_SESSION_PURPOSE','interactive task work')
        command+=['--resource',resource,'--username',username,'--purpose',purpose[:1000]]
    result = run_capability(command, 120 if action == "open" else 60,
                            tool="session", task_id=task_id)
    if ASSET_DB.is_file() and CAPABILITY_LOG.parent==ASSET_DB.parent:
        with closing(sqlite3.connect(ASSET_DB,timeout=10)) as db:
            task_sessions.record_result(db,task_id,action,json.loads(result),session_id=session_id,
                resource=json.loads(result).get('resource') or resource,username=json.loads(result).get('username') or username,purpose=purpose,retain=retain)
            task_memory.sync(db,task_id,CAPABILITY_LOG/f'task_{task_id}.jsonl',reason='session_'+action)
            db.commit()
    return result


@mcp.tool()
@diagnostics.tool
@budget_guard
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
@budget_guard
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
