"""Read saved operator state without opening the executor or migrating SQLite."""
from contextlib import closing, contextmanager
from datetime import datetime, timezone
import json
from pathlib import Path
import re
import sqlite3

from orchestrator import operator_questions, resources, task_memory, task_outcome

WAL_ERROR = 'Просмотр WAL-базы требует отдельной копии SQLite в режиме DELETE.'


class WalDatabaseError(sqlite3.OperationalError):
    """SQLite may create sidecars next to a WAL database even in mode=ro."""


@contextmanager
def read_database(path):
    with path.open('rb') as source:
        header = source.read(20)
    # The SQLite header's write/read version bytes are 2 in WAL mode.
    if header.startswith(b'SQLite format 3\x00') and 2 in header[18:20]:
        raise WalDatabaseError(WAL_ERROR)
    with closing(sqlite3.connect(path.resolve().as_uri() + '?mode=ro', uri=True)) as db:
        db.row_factory = sqlite3.Row
        db.execute('PRAGMA query_only=ON')
        db.execute('BEGIN')
        yield db


def section(read, *, available=True):
    if not available:
        return {'state': 'missing', 'data': None}
    try:
        value = read()
        return {'state': 'ok' if value else 'empty', 'data': value}
    except (sqlite3.Error, OSError, ValueError, TypeError, KeyError, IndexError, AttributeError) as exc:
        return {'state': 'error', 'data': None, 'error': type(exc).__name__}


def table(db, name, read):
    return section(read, available=task_memory.exists(db, name))


def fields(row, *names):
    return {name: row[name] for name in names if row.get(name) is not None}


def list_tasks(path):
    def read():
        try:
            with read_database(path) as db:
                if not task_memory.exists(db, 'tasks'):
                    return None
                return [fields(dict(row), 'id', 'target', 'status', 'created_at')
                        for row in db.execute('SELECT * FROM tasks ORDER BY id DESC')]
        except FileNotFoundError:
            return None

    result = section(read)
    if result['state'] == 'empty' and result['data'] is None:
        result['state'] = 'missing'
    return result


def one_row(db, name, task_id):
    rows = task_memory.rows(db, name, task_id)
    return rows[0] if rows else {}


def scope(db, task_id):
    saved = resources.saved(db, task_id)
    if saved is None:
        return None
    policy = saved['policy']
    result = fields(policy, 'area', 'addresses', 'host_addresses', 'networks', 'denied')
    result['entry'] = saved['entry'].get('input') or saved['entry'].get('original')
    result['origins'] = [fields(origin, 'origin', 'addresses', 'path_prefix', 'purpose', 'request_path')
                         for origin in policy.get('origins', [])]
    result['ssrf'] = policy.get('ssrf', [])
    return result


def steps(db, task_id):
    result = []
    for row in db.execute('SELECT * FROM pm_coordinator_steps WHERE task_id=? ORDER BY step_no', (task_id,)):
        step = fields(dict(row), 'id', 'step_no', 'status', 'error', 'report_iteration', 'outcome_uncertain')
        try:
            decision = json.loads(row['decision_json'])
            step.update(fields(decision, 'role', 'profile', 'action', 'question'))
        except (ValueError, TypeError, IndexError, AttributeError):
            step['decision_error'] = 'Не удалось прочитать сохранённое решение.'
        result.append(step)
    return result


def questions(db, task_id):
    return [fields(q, 'id', 'status', 'kind', 'branch_id', 'question', 'reason', 'created_at') |
            {'boundaries': fields(q['boundaries'] or {}, 'target', 'resource_refs')}
            for q in operator_questions.listing(db, task_id, pending=True)]


def report_rows(db, task_id, name):
    reports = []
    for row in task_memory.rows(db, name, task_id):
        if name == 'pm_agent_action_reports':
            role, number = row['role'], row['iteration']
            if not re.fullmatch(r'[a-z]+', role) or type(number) is not int or number < 1:
                continue
            reference = f'{role}-{number}'
        else:
            role, number = row['stage'], None
            if not re.fullmatch(r'[a-z]+', role):
                continue
            if name == 'evidence_agent_reports':
                digest = row['evidence_sha256']
                if not re.fullmatch(r'[a-f0-9]{64}', digest):
                    continue
                reference = f'evidence-{digest}-{role}'
            else:
                reference = f'lab-{role}'
        report = {'reference': reference, 'role': role, 'iteration': number,
                  **fields(row, 'created_at', 'target')}
        try:
            data = json.loads(row['report_json'])
            if not isinstance(data, dict):
                raise ValueError('report JSON must be an object')
            report.update(fields(data, 'summary', 'report_warning', 'stage_aborted', 'report_incomplete'))
            report['quality'] = fields(data.get('report_quality') or {}, 'status', 'reason')
            report['execution'] = (data.get('execution_outcome') or {}).get('status')
        except (ValueError, TypeError, AttributeError):
            report['read_error'] = 'Не удалось прочитать сохранённый отчёт.'
        reports.append(report)
    return sorted(reports, key=lambda item: (item['created_at'] or '', item['reference']), reverse=True)


REPORT_TABLES = ('pm_agent_action_reports', 'evidence_agent_reports', 'lab_agent_reports')


def saved_report(db, task_id, reference):
    name = ('evidence_agent_reports' if reference.startswith('evidence-') else
            'lab_agent_reports' if reference.startswith('lab-') else 'pm_agent_action_reports')
    return table(db, name, lambda: next(
        (item for item in report_rows(db, task_id, name) if item['reference'] == reference), None))


def last_run(directory, task_id):
    """Use diagnostic run records. A start without an end stays unresolved."""
    latest = None
    damaged_runs = []
    for path in directory.iterdir():
        if path.suffix != '.jsonl' or not re.fullmatch(r'[a-f0-9]{32}', path.stem) or path.is_symlink():
            continue
        linked = False
        damaged = False
        start = end = summary = None
        try:
            # Decode one line at a time, so a torn UTF-8 sequence does not
            # prevent Python from returning earlier intact events.
            with path.open('rb') as stream:
                for line in stream:
                    try:
                        event = json.loads(line.decode('utf-8'))
                        if not isinstance(event, dict):
                            raise ValueError('event JSON must be an object')
                    except ValueError:
                        damaged = True
                        continue
                    if event.get('run_id') != path.stem:
                        continue
                    task_ids = event.get('task_ids')
                    linked |= event.get('task_id') == task_id or (
                        isinstance(task_ids, list) and task_id in task_ids)
                    if event.get('kind') == 'run.start':
                        start = event
                    elif event.get('kind') == 'run.end':
                        end = event
                    elif event.get('kind') == 'run.summary':
                        summary = event
        except OSError:
            damaged = True
        if not linked:
            continue
        if damaged:
            damaged_runs.append(path.stem)
        first = start or summary or end or {}
        timestamp = first.get('timestamp')
        if type(timestamp) not in (int, float):
            continue
        try:
            started_at = datetime.fromtimestamp(timestamp, timezone.utc).isoformat()
        except (ValueError, OverflowError, OSError):
            if not damaged:
                damaged_runs.append(path.stem)
            continue
        final = summary or end or {}
        if latest is None or (timestamp, path.stem) > latest[0]:
            latest = ((timestamp, path.stem), {'id': path.stem, 'name': first.get('name'),
                'status': final.get('status'), 'reason': final.get('reason'),
                'started_at': started_at})
    if latest or damaged_runs:
        return {'latest': latest[1] if latest else None, 'damaged': bool(damaged_runs),
                'damaged_runs': sorted(damaged_runs)}
    return None


def valid_port(value):
    return type(value) is int and 1 <= value <= 65535


def snapshot_findings(bundle):
    services = {'tcp': {}, 'udp': {}}
    http_headers = []
    for record in bundle.get('network_observations') or []:
        if not isinstance(record, dict) or not isinstance(record.get('data'), dict):
            continue
        item = record['data']
        kind = record.get('kind')
        if kind in ('tcp_port_open', 'service_probe'):
            port = item.get('port')
            # Older snapshots omit protocol on TCP records and state on positive probes.
            protocol = item.get('protocol', 'tcp')
            if not valid_port(port) or protocol not in ('tcp', 'udp') or item.get('state', 'open') != 'open':
                continue
            if kind == 'tcp_port_open' and protocol != 'tcp':
                continue
            ports = services[protocol]
            service = item.get('service_hint')
            ports.setdefault(port, None)
            if isinstance(service, str) and service:
                ports[port] = service
        elif kind in ('http_response', 'http_content'):
            observation = fields(item, 'status_line', 'status_code', 'path', 'title')
            if observation:
                http_headers.append(observation)
    web = [fields(item, 'scheme', 'hostname', 'port', 'path', 'status_code', 'title')
           for item in bundle.get('web_observations') or [] if isinstance(item, dict)]
    findings = {protocol: [{'port': port, 'service': service} for port, service in sorted(ports.items())]
                for protocol, ports in services.items()}
    return {**findings, 'http_headers': http_headers, 'web': [item for item in web if item]}


def legacy_snapshot(db, task_id):
    row = db.execute('SELECT evidence_sha256,evidence_json FROM evidence_snapshots WHERE task_id=? '
                     'ORDER BY created_at DESC,evidence_sha256 DESC LIMIT 1', (task_id,)).fetchone()
    if row is None:
        return None
    data = json.loads(row[1])
    return {'evidence_sha256': row[0], 'network_observations': len(data.get('network_observations') or []),
            'burp_observations': len(data.get('burp_http_metadata') or []),
            'findings': snapshot_findings(data)}


def full_scan_ports(db, task_id, target):
    if not target:
        return []
    ports = set()
    for row in task_memory.rows(db, 'pm_tcp_full_scans', task_id, target=target):
        if row.get('target') != target or row.get('status') != 'completed':
            continue
        try:
            saved = json.loads(row['open_ports_json'])
        except (KeyError, ValueError, TypeError):
            continue
        if isinstance(saved, list):
            ports.update(value for value in saved if valid_port(value))
    return sorted(ports)


def saved_plan(raw):
    if raw is None:
        return None
    plan = json.loads(raw)
    return [fields(item, 'agent', 'instruction', 'status') for item in plan['tasks']]


def task(db, task_id):
    original = db.execute('SELECT * FROM tasks WHERE id=?', (task_id,)).fetchone()
    if original is None:
        return None
    original = dict(original)
    views = {
        'intent': table(db, 'pm_task_intents', lambda: one_row(db, 'pm_task_intents', task_id).get('intent')),
        'goals': table(db, 'pm_objectives', lambda: [
            fields(g, 'key', 'title', 'status', 'role') for g in task_memory.rows(db, 'pm_objectives', task_id)]),
        'outcome': section(lambda: task_outcome.saved(db, task_id)),
        'scope': table(db, 'pm_resource_scope', lambda: scope(db, task_id)),
        'scope_settings': table(db, 'task_scope_settings', lambda: fields(
            one_row(db, 'task_scope_settings', task_id), 'allow_pivot', 'allow_port_forward')),
        'approval': table(db, 'pm_operator_approvals', lambda: fields(
            one_row(db, 'pm_operator_approvals', task_id), 'allowed', 'egress', 'closed_at')),
        'runtime': table(db, 'pm_task_runtime', lambda: fields(
            one_row(db, 'pm_task_runtime', task_id), 'mode', 'recon_status', 'pause_reason')),
        'availability': table(db, 'pm_target_availability', lambda: fields(
            one_row(db, 'pm_target_availability', task_id), 'state', 'reason')),
        'coordinator': table(db, 'pm_coordinator_runs', lambda: fields(
            one_row(db, 'pm_coordinator_runs', task_id), 'id', 'status', 'stop_reason', 'updated_at')),
        'legacy_run': table(db, 'master_auto_runs', lambda: [fields(dict(row),
            'id', 'status', 'stop_reason', 'started_at', 'finished_at') for row in db.execute(
                'SELECT * FROM master_auto_runs WHERE task_id=? ORDER BY id DESC LIMIT 1', (task_id,))]),
        'steps': table(db, 'pm_coordinator_steps', lambda: steps(db, task_id)),
        'legacy_steps': table(db, 'agent_runs', lambda: [fields(dict(row), 'step_index', 'agent', 'status')
            for row in db.execute('SELECT * FROM agent_runs WHERE parent_task_id=? ORDER BY step_index', (task_id,))]),
        'plan': section(lambda: saved_plan(original.get('plan_json')), available='plan_json' in original),
        'questions': table(db, 'pm_operator_questions', lambda: questions(db, task_id)),
        'reports': {name: table(db, name, lambda: report_rows(db, task_id, name)) for name in REPORT_TABLES},
        'snapshot': table(db, 'evidence_snapshots', lambda: legacy_snapshot(db, task_id)),
    }
    approval = views['approval']['data'] or {}
    closed = original.get('status') == 'closed' or bool(approval.get('closed_at'))
    return {**fields(original, 'id', 'target', 'status', 'created_at', 'description'),
            'closure': 'closed' if closed else 'open' if approval.get('allowed') else 'unknown',
            **views}


def cli_metadata(db, task_id, data):
    """Preserve status --json fields using the last saved Evidence Hub snapshot."""
    from orchestrator import master_scheduler as scheduler

    snapshot = data['snapshot']['data'] or {}
    findings = snapshot.get('findings', {})
    ports = {row['port']: row for row in findings.get('tcp', [])}
    for port in full_scan_ports(db, task_id, data.get('target')):
        ports.setdefault(port, {'port': port, 'service': None})
    digest = snapshot.get('evidence_sha256')
    reports = data['reports']['evidence_agent_reports']
    stages = [name for name in scheduler.evidence.STAGES if any(
        row['reference'] == f'evidence-{digest}-{name}' and not row.get('read_error')
        for row in reports['data'] or [])]
    queues_available = all(task_memory.exists(db, table_name) for table_name in
                           ('network_phase_plans', 'network_job_runs'))
    previous = table(db, 'pm_task_lineage', lambda: [
        dict(row) for row in db.execute('SELECT previous_task_id,previous_target FROM pm_task_lineage '
                                        'WHERE successor_task_id=?', (task_id,))])
    successor = table(db, 'pm_task_lineage', lambda: [
        dict(row) for row in db.execute('SELECT successor_task_id,successor_target FROM pm_task_lineage '
                                        'WHERE previous_task_id=?', (task_id,))])
    aliases = table(db, 'pm_task_hostnames', lambda: json.loads(
        one_row(db, 'pm_task_hostnames', task_id).get('hostnames_json', '[]')))
    return {
        **{key: snapshot.get(key) for key in ('evidence_sha256', 'network_observations', 'burp_observations')},
        'agents_completed': stages if digest and reports['state'] != 'error' else None,
        'agents_pending': [stage for stage in scheduler.evidence.STAGES if stage not in stages]
        if digest and reports['state'] != 'error' else None,
        'pending_baseline': section(lambda: scheduler.pending(db, task_id, scheduler.BASE_PROFILES),
                                    available=queues_available)['data'],
        'pending_enrichment': section(lambda: scheduler.pending(db, task_id, scheduler.ENRICHMENT_PROFILES),
                                      available=queues_available)['data'],
        'stop_reason': None,
        'previous_task': (previous['data'] or [None])[0],
        'successor_task': (successor['data'] or [None])[0],
        'aliases': aliases['data'],
        'findings': {**findings, 'tcp': [ports[port] for port in sorted(ports)], 'udp': findings.get('udp', [])},
    }


def load_task(path, task_id, *, for_cli=False):
    try:
        with read_database(path) as db:
            data = task(db, task_id) if task_memory.exists(db, 'tasks') else None
            if data and for_cli:
                data.update(cli_metadata(db, task_id, data))
            elif data:
                from orchestrator import operator_context
                data['intent_provenance'] = section(lambda: operator_context.intent_provenance(db, task_id))
    except FileNotFoundError:
        return None
    if data is not None:
        directory = path.parent / 'run_events'
        try:
            directory.stat()
        except FileNotFoundError:
            data['last_run'] = {'state': 'missing', 'data': None}
        except OSError as exc:
            data['last_run'] = {'state': 'error', 'data': None, 'error': type(exc).__name__}
        else:
            data['last_run'] = section(lambda: last_run(directory, task_id))
    return data
