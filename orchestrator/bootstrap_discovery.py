"""Bounded, resumable TCP discovery bootstrap for an authorized task.

Creates 32-port Nmap plans in the existing SQLite queue, ordered by the
installed Nmap service-frequency database. Makes no target network calls.
Root-owned NetGuard remains the sole live execution path.

Use via: master_scheduler.py auto --bootstrap --execute ...
"""
import ipaddress
import json
import re
import sqlite3
import subprocess
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EXECUTOR = ROOT / 'executor/network_executor_isolated.py'
PYTHON = ROOT / '.venv/bin/python'
SERVICES = (
    Path('/usr/share/nmap/nmap-services'),
    Path('/usr/local/share/nmap/nmap-services'),
)
PORTS_PER_PLAN = 32
MAX_DISCOVERY_PORTS = 1024
BATCHES_PER_ROUND = 2


def ranking(source=None):
    """Read Nmap's LOCAL tcp service probabilities; never fetch the network."""
    path = Path(source) if source else next((p for p in SERVICES if p.is_file()), None)
    if path is None or not path.is_file():
        raise ValueError('nmap-services is missing: install nmap package or check /usr/share/nmap')
    freqs = {}
    for line in path.read_text(encoding='utf-8', errors='replace').splitlines():
        if not line or line.startswith('#'):
            continue
        fields = line.split()
        if len(fields) < 3:
            continue
        port_proto = fields[1]
        if not re.fullmatch(r'[0-9]{1,5}/tcp', port_proto):
            continue
        port = int(port_proto[:-4])
        if not 1 <= port <= 65535:
            continue
        try:
            probability = float(fields[2])
        except ValueError:
            continue
        if not 0 <= probability <= 1:
            continue
        freqs[port] = max(probability, freqs.get(port, 0))
    if len(freqs) < MAX_DISCOVERY_PORTS:
        raise ValueError('nmap-services has insufficient TCP frequency entries for bootstrap')
    return sorted(freqs, key=lambda port: (-freqs[port], port))[:MAX_DISCOVERY_PORTS]


def scan_state(db, task_id, target):
    rows = db.execute('''SELECT parameters_json FROM network_phase_plans
                         WHERE task_id=? AND target=? AND profile='tcp_ports' ''',
                      (task_id, target)).fetchall()
    covered = set()
    for (raw,) in rows:
        try:
            params = json.loads(raw)
            if set(params) != {'ports'} or not isinstance(params['ports'], str):
                continue
            for part in params['ports'].split(','):
                if re.fullmatch(r'[0-9]{1,5}', part) and 1 <= int(part) <= 65535:
                    covered.add(int(part))
        except (TypeError, ValueError):
            pass
    open_port = db.execute('''SELECT 1 FROM network_observations o
      JOIN network_job_runs r ON o.run_id=r.id
      JOIN network_phase_plans p ON r.plan_id=p.id
      WHERE o.task_id=? AND p.task_id=? AND p.target=? AND r.status='completed'
        AND o.kind='tcp_port_open' LIMIT 1''', (task_id, task_id, target)).fetchone() is not None
    pending = db.execute('''SELECT COUNT(*) FROM network_phase_plans p
      WHERE p.task_id=? AND p.profile='tcp_ports' AND p.target=? AND p.status='planned'
      AND NOT EXISTS (SELECT 1 FROM network_job_runs r WHERE r.plan_id=p.id)''',
      (task_id, target)).fetchone()[0]
    return covered, open_port, pending


def safe_task_target(db, task_id):
    from orchestrator import network_workflow as workflow
    from orchestrator import network_enrichment as enrichment
    target = workflow.load_task_target(db, task_id)
    ip = ipaddress.ip_address(target)
    if ip.version != 4 or ip.is_loopback or ip.is_unspecified or ip.is_multicast:
        raise ValueError('Bootstrap needs an authorized non-loopback IPv4 task target')
    enrichment.verify_scope(db, task_id, target)
    return target


def has_more(db, task_id):
    target = safe_task_target(db, task_id)
    covered, found, _ = scan_state(db, task_id, target)
    return not found and any(p not in covered for p in ranking())


def validate_plan(task_id, target, ports):
    cmd = [str(PYTHON), str(EXECUTOR), 'run', '--task-id', str(task_id),
           '--profile', 'tcp_ports', '--target', target, '--ports', ports]
    process = subprocess.run(cmd, cwd=str(ROOT), stdin=subprocess.DEVNULL,
                             capture_output=True, text=True, errors='replace', timeout=20)
    try:
        reply = json.loads(process.stdout)
    except ValueError as exc:
        raise ValueError('Isolated Executor plan returned invalid JSON: ' + process.stderr[-500:]) from exc
    if (process.returncode != 0 or not isinstance(reply, dict)
        or reply.get('status') != 'planned'
        or reply.get('task_id') != task_id or reply.get('target') != target
        or reply.get('profile') != 'tcp_ports'
        or not isinstance(reply.get('argv'), list)):
        raise ValueError(f'Isolated Executor refused bootstrap plan: {reply}')
    return reply['argv']


def queue_next(db, task_id, batches=BATCHES_PER_ROUND):
    if type(batches) is not int or not 1 <= batches <= 4:
        raise ValueError('Bootstrap batches must be 1..4')
    target = safe_task_target(db, task_id)
    covered, found, pending = scan_state(db, task_id, target)
    if found or pending:
        return []
    unknown = [p for p in ranking() if p not in covered]
    if not unknown:
        return []
    created = []
    for batch in range(batches):
        ports = unknown[batch * PORTS_PER_PLAN:(batch + 1) * PORTS_PER_PLAN]
        if not ports:
            break
        port_string = ','.join(str(p) for p in ports)
        params = json.dumps({'ports': port_string}, sort_keys=True)
        argv = validate_plan(task_id, target, port_string)
        with db:
            row = db.execute('''SELECT id FROM network_phase_plans
                  WHERE task_id=? AND profile='tcp_ports' AND target=? AND parameters_json=?
                  LIMIT 1''', (task_id, target, params)).fetchone()
            if row:
                continue
            cursor = db.execute('''INSERT INTO network_phase_plans
                  (task_id, goal, profile, target, parameters_json, argv_json,
                   model_summary, status, created_at)
                  VALUES (?, ?, 'tcp_ports', ?, ?, ?, ?, 'planned', ?)''',
                  (task_id, 'Bounded TCP discovery from installed Nmap service frequencies',
                   target, params, json.dumps(argv),
                   'Evidence-free bootstrap. No brute force. Ports chosen by Nmap frequency.',
                   datetime.now(timezone.utc).isoformat()))
        created.append({'plan_id': cursor.lastrowid, 'ports': len(ports),
                        'ranked_port_range': [batch * PORTS_PER_PLAN + 1,
                                              batch * PORTS_PER_PLAN + len(ports)]})
    return created


def progress(db, task_id):
    target = safe_task_target(db, task_id)
    ranked = set(ranking())
    covered, found, pending = scan_state(db, task_id, target)
    executed = db.execute('''SELECT parameters_json FROM network_phase_plans p
         WHERE task_id=? AND target=? AND profile='tcp_ports'
         AND EXISTS (SELECT 1 FROM network_job_runs r WHERE r.plan_id=p.id)
    ''', (task_id, target)).fetchall()
    attempted = set()
    for (raw,) in executed:
        try:
            attempted.update(int(x) for x in json.loads(raw)['ports'].split(',') if x.isdigit())
        except (ValueError, KeyError, TypeError):
            pass
    return {'ranked_pool': len(ranked), 'planned_ranked_ports': len(covered & ranked),
            'attempted_ranked_ports': len(attempted & ranked),
            'pending_tcp_batches': pending, 'open_port_observed': found,
            'more_available': not found and bool(ranked - covered)}
