"""Task-scoped, evidence-linked facts. Raw capability output remains authoritative."""

import json
import hashlib
import re
import sqlite3
from datetime import datetime, timezone
from urllib.parse import urlsplit, urlunsplit

CLAIM_KINDS = frozenset({'observation', 'inference', 'hypothesis'})
HYPOTHESIS_STATES = frozenset({'untested', 'confirmed', 'refuted', 'dropped'})


def now():
    return datetime.now(timezone.utc).isoformat()


def claim_key(claim):
    text = re.sub(r'\s+', ' ', str(claim or '').casefold()).strip()
    return re.sub(r'^[^\w]+|[^\w]+$', '', text)[:300]


def bounded_cost(value):
    try:
        return max(0, min(3, int(value)))
    except (ValueError, TypeError):
        return 2


def ensure_schema(db):
    db.execute('''CREATE TABLE IF NOT EXISTS pm_hypotheses (
        task_id INTEGER NOT NULL, claim_key TEXT NOT NULL, claim TEXT NOT NULL,
        kind TEXT NOT NULL, status TEXT NOT NULL, probe_result_id TEXT NOT NULL DEFAULT '',
        quote TEXT NOT NULL DEFAULT '', reason TEXT NOT NULL DEFAULT '',
        test TEXT NOT NULL DEFAULT '', cost INTEGER NOT NULL DEFAULT 2,
        stage TEXT NOT NULL, updated_at TEXT NOT NULL,
        PRIMARY KEY(task_id, claim_key))''')
    db.execute('CREATE INDEX IF NOT EXISTS pm_hypotheses_status '
               'ON pm_hypotheses(task_id,status,updated_at)')
    columns = {row[1] for row in db.execute('PRAGMA table_info(pm_hypotheses)')}
    if 'test' not in columns:
        db.execute("ALTER TABLE pm_hypotheses ADD COLUMN test TEXT NOT NULL DEFAULT ''")
    if 'cost' not in columns:
        db.execute('ALTER TABLE pm_hypotheses ADD COLUMN cost INTEGER NOT NULL DEFAULT 2')
    if 'objective_key' not in columns:
        db.execute('ALTER TABLE pm_hypotheses ADD COLUMN objective_key TEXT')
    db.execute('''CREATE TABLE IF NOT EXISTS pm_assets (
        task_id INTEGER NOT NULL, kind TEXT NOT NULL, key TEXT NOT NULL,
        status TEXT NOT NULL, last_probe_result_id TEXT NOT NULL DEFAULT '',
        evidence_quote TEXT NOT NULL DEFAULT '', origin_task_id INTEGER NOT NULL,
        origin_target TEXT NOT NULL DEFAULT '', rechecks INTEGER NOT NULL DEFAULT 0,
        updated_at TEXT NOT NULL, PRIMARY KEY(task_id,kind,key))''')
    db.execute('CREATE INDEX IF NOT EXISTS pm_assets_status '
               'ON pm_assets(task_id,status,updated_at)')
    asset_columns = {row[1] for row in db.execute('PRAGMA table_info(pm_assets)')}
    if 'objective_key' not in asset_columns:
        db.execute('ALTER TABLE pm_assets ADD COLUMN objective_key TEXT')
    db.execute('''CREATE TABLE IF NOT EXISTS pm_access_state (
        task_id INTEGER PRIMARY KEY, level TEXT NOT NULL DEFAULT 'none',
        signal TEXT NOT NULL DEFAULT 'none', access_result_id TEXT NOT NULL DEFAULT '',
        triage_done INTEGER NOT NULL DEFAULT 0, updated_at TEXT NOT NULL)''')
    db.execute('''CREATE TABLE IF NOT EXISTS pm_access_triage (
        task_id INTEGER NOT NULL, level TEXT NOT NULL, category TEXT NOT NULL,
        summary TEXT NOT NULL, result_id TEXT NOT NULL, quote TEXT NOT NULL,
        updated_at TEXT NOT NULL, PRIMARY KEY(task_id,level,category))''')


ASSET_KINDS = frozenset({'port', 'url', 'path', 'service', 'file', 'credential', 'host'})
ASSET_STATES = frozenset({'discovered', 'probed', 'dead', 'exploitable', 'compromised'})
ACCESS_LEVELS = ('none', 'exec', 'user', 'privileged')
TRIAGE_FIELDS = ('who', 'where', 'boundary', 'reachable', 'credentials', 'next_level')


def asset_key(kind, raw):
    """Preserve protocol and path case: distinct endpoints must not be merged."""
    if kind not in ASSET_KINDS:
        raise ValueError('Unknown asset kind')
    value = str(raw or '').strip()
    if not value or len(value) > 1024:
        raise ValueError('Invalid asset key')
    if kind == 'port':
        port = int(value)
        if not 1 <= port <= 65535:
            raise ValueError('Invalid port')
        return str(port)
    if kind == 'url':
        parsed = urlsplit(value)
        if parsed.scheme.lower() not in ('http', 'https') or not parsed.hostname:
            raise ValueError('URL requires scheme and host')
        host = parsed.hostname.lower()
        port = parsed.port or (443 if parsed.scheme.lower() == 'https' else 80)
        return urlunsplit((parsed.scheme.lower(), f'{host}:{port}',
                           parsed.path or '/', parsed.query, ''))
    if kind == 'host':
        return value.lower().rstrip('.')
    if kind == 'credential':
        return 'sha256:' + hashlib.sha256(value.encode()).hexdigest()
    if kind == 'service':
        return re.sub(r'\s+', ' ', value.casefold())
    return value  # file and path names may be case-sensitive and slash-sensitive


def list_assets(db, task_id, statuses=None, limit=200):
    ensure_schema(db)
    query = ('SELECT kind,key,status,last_probe_result_id,evidence_quote,origin_task_id,'
             'origin_target,rechecks,updated_at,objective_key FROM pm_assets WHERE task_id=?')
    params = [task_id]
    if statuses:
        marks = ','.join('?' for _ in statuses)
        query += f' AND status IN ({marks})'
        params.extend(statuses)
    query += ' ORDER BY updated_at DESC LIMIT ?'
    params.append(limit)
    return [dict(zip(('kind','key','status','last_probe_result_id','evidence_quote',
                      'origin_task_id','origin_target','rechecks','updated_at','objective_key'), row))
            for row in db.execute(query, params)]


def record_asset(db, task_id, kind, raw_key, status, result_id='', quote='',
                 records=None, origin_task_id=None, origin_target='', objective_key=None):
    ensure_schema(db)
    key = asset_key(kind, raw_key)
    if status not in ASSET_STATES:
        raise ValueError('Invalid asset status')
    if status in ('dead', 'exploitable', 'compromised'):
        record = (records or {}).get(result_id)
        if (not result_id or not quote or not record or
                quote not in str(record.get('text') or '')):
            status = 'probed'  # an unsupported closure must not hide the asset
            result_id = ''
            quote = ''
    db.execute('''INSERT INTO pm_assets
        (task_id,kind,key,status,last_probe_result_id,evidence_quote,
         origin_task_id,origin_target,updated_at,objective_key) VALUES (?,?,?,?,?,?,?,?,?,?)
        ON CONFLICT(task_id,kind,key) DO UPDATE SET
        status=excluded.status,last_probe_result_id=excluded.last_probe_result_id,
        evidence_quote=excluded.evidence_quote,
        origin_task_id=excluded.origin_task_id,origin_target=excluded.origin_target,
        objective_key=COALESCE(excluded.objective_key,pm_assets.objective_key),
        updated_at=excluded.updated_at''',
        (task_id, kind, key, status, result_id, str(quote)[:400],
         task_id if origin_task_id is None else origin_task_id,
         origin_target, now(), objective_key))
    return status


def inherit_assets(db, old_id, new_id, old_target=''):
    """Copy hints, retaining the address where their status was established."""
    ensure_schema(db)
    count = 0
    for item in list_assets(db, old_id, limit=1000):
        cursor = db.execute('''INSERT OR IGNORE INTO pm_assets
            (task_id,kind,key,status,last_probe_result_id,evidence_quote,
             origin_task_id,origin_target,rechecks,updated_at,objective_key)
            VALUES (?,?,?,?,?,?,?,?,0,?,?)''',
            (new_id, item['kind'], item['key'], item['status'],
             item['last_probe_result_id'], item['evidence_quote'],
             item['origin_task_id'], item['origin_target'] or old_target, now(),
             item.get('objective_key')))
        count += cursor.rowcount
    return count


def may_probe_asset(db, task_id, kind, raw_key, hypothesis_key='',
                    new_evidence_id='', records=None, consume=False):
    """Guard explicit asset probes; opaque shell/PoC commands need advisory handling."""
    ensure_schema(db)
    key = asset_key(kind, raw_key)
    row = db.execute('SELECT status,origin_task_id,rechecks,last_probe_result_id '
                     'FROM pm_assets WHERE task_id=? AND kind=? AND key=?',
                     (task_id, kind, key)).fetchone()
    if not row or row[0] != 'dead':
        return {'allowed': True, 'reason': ''}
    status, origin, rechecks, previous_id = row
    if origin != task_id:
        open_question = db.execute('SELECT 1 FROM pm_hypotheses WHERE task_id=? '
                                   "AND claim_key=? AND status='untested'",
                                   (task_id, hypothesis_key)).fetchone()
        allowed = bool(open_question and rechecks == 0)
        reason = '' if allowed else 'Унаследованный закрытый актив: нужна открытая гипотеза; одна перепроверка уже использована'
    else:
        witness = (records or {}).get(new_evidence_id) if new_evidence_id else None
        allowed = bool(new_evidence_id and new_evidence_id != previous_id and
                       witness and key in str(witness.get('text') or ''))
        reason = '' if allowed else 'Закрытый актив: укажи новое свидетельство до повторного зонда'
    if allowed and consume:
        db.execute('UPDATE pm_assets SET rechecks=rechecks+1,updated_at=? '
                   'WHERE task_id=? AND kind=? AND key=?', (now(), task_id, kind, key))
    return {'allowed': allowed, 'reason': reason}


def import_capability_assets(db, task_id, log_path):
    """Import only unambiguous single-port nmap lines; never infer dead from prose."""
    ensure_schema(db)
    try:
        stream = open(log_path, encoding='utf-8', errors='replace')
    except FileNotFoundError:
        return 0
    count = 0
    with stream:
        for line in stream:
            try:
                record = json.loads(line)
            except ValueError:
                continue
            result = record.get('result') or {}
            if (record.get('task_id') != task_id or record.get('tool') != 'net_exec'
                    or result.get('executable') != 'nmap'
                    or result.get('status') != 'completed'
                    or not isinstance(record.get('id'), str)):
                continue
            output = str(result.get('stdout') or '')
            for row in output.splitlines():
                match = re.match(r'^\s*(\d{1,5})/tcp\s+(open|closed)\b', row, re.I)
                if not match:
                    continue
                status = 'discovered' if match.group(2).lower() == 'open' else 'dead'
                before = db.execute('SELECT status FROM pm_assets WHERE task_id=? '
                                    "AND kind='port' AND key=?",
                                    (task_id, str(int(match.group(1))))).fetchone()
                # Never overwrite a later or stronger conclusion on re-import.
                if before:
                    continue
                record_asset(db, task_id, 'port', match.group(1), status,
                             record['id'], row.strip(),
                             {record['id']: {'text': output}}, origin_target=str(result.get('target') or ''))
                count += 1
    return count


def capability_index(task_id, log_path):
    """Result IDs with text for validating an explicit later witness."""
    records = {}
    try:
        stream = open(log_path, encoding='utf-8', errors='replace')
    except FileNotFoundError:
        return records
    with stream:
        for line in stream:
            try:
                item = json.loads(line)
            except ValueError:
                continue
            if item.get('task_id') != task_id or not item.get('id'):
                continue
            result = item.get('result') or {}
            records[item['id']] = {'status': result.get('status'),
                                   'text': '\n'.join(str(result.get(field) or '') for field in
                                                     ('stdout', 'stderr', 'response', 'output'))}
    return records


def evidence_index(task_id, log_path, offset=0, limit=40):
    """Bounded display of an immutable, complete capability-log index."""
    entries = []
    try:
        stream = open(log_path, encoding='utf-8', errors='replace')
    except FileNotFoundError:
        return {'total': 0, 'offset': offset, 'entries': []}
    with stream:
        for line in stream:
            try:
                item = json.loads(line)
            except ValueError:
                continue
            if item.get('task_id') != task_id or not item.get('id'):
                continue
            result = item.get('result') or {}
            text = '\n'.join(str(result.get(field) or '') for field in
                             ('stdout', 'stderr', 'response', 'output'))
            lines = [re.sub(r'\s+', ' ', row).strip() for row in text.splitlines()
                     if row.strip()]
            summary = ((lines[0][:70] + (' … ' + lines[-1][:70] if len(lines) > 1 else ''))
                       if lines else str(result.get('error') or result.get('status') or ''))
            entries.append({'result_id': item['id'], 'tool': item.get('tool'),
                            'status': result.get('status'), 'summary': summary[:160],
                            'bytes': len(line.encode('utf-8'))})
    if offset is None:
        offset = max(0, len(entries) - max(1, min(limit, 40)))
    return {'total': len(entries), 'offset': offset,
            'entries': entries[offset:offset + max(1, min(limit, 40))]}


def explicit_assets_from_argv(argv):
    """Recognise only single-purpose direct commands, never parse shell scripts."""
    if not isinstance(argv, list) or not argv:
        return []
    binary = str(argv[0]).rsplit('/', 1)[-1]
    if binary == 'nmap' and '-p' in argv:
        index = argv.index('-p') + 1
        if index < len(argv) and re.fullmatch(r'\d{1,5}', str(argv[index])):
            return [('port', str(argv[index]))]
    if binary == 'curl':
        urls = [item for item in argv[1:] if isinstance(item, str)
                and re.match(r'^https?://', item, re.I)]
        if len(urls) == 1:
            return [('url', urls[0])]
    return []


def access_state(db, task_id):
    ensure_schema(db)
    row = db.execute('SELECT level,signal,access_result_id,triage_done FROM pm_access_state '
                     'WHERE task_id=?', (task_id,)).fetchone()
    if not row:
        return {'level': 'none', 'signal': 'none', 'access_result_id': '',
                'triage_done': False, 'pending': False}
    return {'level': row[0], 'signal': row[1], 'access_result_id': row[2],
            'triage_done': bool(row[3]),
            'pending': row[1] != 'none' and not bool(row[3])}


def validate_access_report(report, records, prior_ids=()):
    """Accept state changes only when a fresh output contains the exact quote."""
    prior_ids = set(prior_ids)
    level = str(report.get('access_level') or 'none').lower()
    signal = str(report.get('access_signal') or 'none').lower()
    if level not in ACCESS_LEVELS:
        level = 'none'
    if signal not in ('none', 'credential', 'execution', 'shell'):
        signal = 'none'
    result_id = str(report.get('access_probe_result_id') or '')
    quote = str(report.get('access_quote') or '').strip()[:400]
    record = records.get(result_id) if result_id not in prior_ids else None
    if signal != 'none' and (not record or not quote or
                             quote not in str(record.get('text') or '') or
                             (signal != 'credential' and level == 'none')):
        report['access_warning'] = 'Заявление о доступе без нового вывода и точной цитаты'
        signal, level, result_id, quote = 'none', 'none', '', ''
    report.update(access_level=level, access_signal=signal,
                  access_probe_result_id=result_id if signal != 'none' else '',
                  access_quote=quote if signal != 'none' else '')
    triage = report.get('triage') if isinstance(report.get('triage'), dict) else {}
    checked = {}
    for category in TRIAGE_FIELDS:
        item = triage.get(category)
        if not isinstance(item, dict):
            continue
        rid = str(item.get('result_id') or '')
        excerpt = str(item.get('quote') or '').strip()[:400]
        source = records.get(rid) if rid not in prior_ids else None
        if source and excerpt and excerpt in str(source.get('text') or ''):
            checked[category] = {'summary': str(item.get('summary') or '')[:300],
                                 'result_id': rid, 'quote': excerpt}
    report['triage'] = checked
    return report


def save_access_report(db, task_id, report):
    ensure_schema(db)
    state = access_state(db, task_id)
    level, signal = report.get('access_level', 'none'), report.get('access_signal', 'none')
    if signal != 'none':
        if ACCESS_LEVELS.index(level) < ACCESS_LEVELS.index(state['level']):
            level = state['level']
        db.execute('''INSERT INTO pm_access_state
            (task_id,level,signal,access_result_id,triage_done,updated_at)
            VALUES (?,?,?,?,0,?) ON CONFLICT(task_id) DO UPDATE SET
            level=excluded.level,signal=excluded.signal,
            access_result_id=excluded.access_result_id,
            triage_done=CASE WHEN pm_access_state.level=excluded.level
                             THEN pm_access_state.triage_done ELSE 0 END,
            updated_at=excluded.updated_at''',
            (task_id, level, signal, report.get('access_probe_result_id', ''), now()))
    else:
        level = state['level']
    for category, item in (report.get('triage') or {}).items():
        if category not in TRIAGE_FIELDS:
            continue
        db.execute('''INSERT INTO pm_access_triage
            (task_id,level,category,summary,result_id,quote,updated_at)
            VALUES (?,?,?,?,?,?,?) ON CONFLICT(task_id,level,category) DO UPDATE SET
            summary=excluded.summary,result_id=excluded.result_id,
            quote=excluded.quote,updated_at=excluded.updated_at''',
            (task_id, level, category, item['summary'], item['result_id'],
             item['quote'], now()))
    count = db.execute('SELECT COUNT(*) FROM pm_access_triage WHERE task_id=? AND level=?',
                       (task_id, level)).fetchone()[0]
    if count == len(TRIAGE_FIELDS):
        db.execute('UPDATE pm_access_state SET triage_done=1,updated_at=? WHERE task_id=?',
                   (now(), task_id))


def import_legacy_access_hint(db, task_id):
    """Old prose is only a pending claim, never proof of an access level."""
    ensure_schema(db)
    if db.execute('SELECT 1 FROM pm_access_state WHERE task_id=?', (task_id,)).fetchone():
        return False
    try:
        rows = db.execute("SELECT report_json FROM pm_agent_action_reports WHERE task_id=? "
                          "AND role='access'", (task_id,)).fetchall()
    except sqlite3.OperationalError:
        return False
    for (raw,) in rows:
        try:
            report = json.loads(raw)
        except ValueError:
            continue
        text = str(report.get('summary') or '')
        if (re.search(r'\b(?:shell|credentials?|execution|доступ|учётн\w*\s+данн\w*)\b',
                      text, re.I)
                and not re.search(r'\b(?:нет|не|без|failed|no)\s+(?:\w+\s+){0,2}'
                                  r'(?:shell|access|доступ)', text, re.I)):
            db.execute('INSERT OR IGNORE INTO pm_access_state '
                       '(task_id,level,signal,updated_at) VALUES (?,\'none\',\'claimed_unverified\',?)',
                       (task_id, now()))
            return True
    return False


def validate_hypotheses(report, records, prior_ids=()):
    """A closure needs a new captured result and an exact excerpt from it."""
    prior_ids = set(prior_ids)
    checked = []
    for raw in report.get('hypotheses') or []:
        if not isinstance(raw, dict):
            continue
        item = dict(raw)
        claim = str(item.get('claim') or '').strip()[:500]
        if not claim:
            continue
        status = str(item.get('result') or item.get('status') or 'untested').lower()
        if status not in HYPOTHESIS_STATES:
            status = 'untested'
        result_id = str(item.get('probe_result_id') or item.get('result_id') or '')
        quote = str(item.get('quote') or '').strip()[:400]
        reason = str(item.get('reason') or '').strip()[:400]
        if status in ('confirmed', 'refuted'):
            record = records.get(result_id) if result_id not in prior_ids else None
            output = str((record or {}).get('text') or '')
            if (not record or record.get('status') not in ('completed', 'ok')
                    or not quote or quote not in output):
                status = 'untested'
                item['validation_warning'] = 'Закрытие требует нового result_id и точной цитаты вывода'
        elif status == 'dropped' and not reason:
            status = 'untested'
            item['validation_warning'] = 'Снятие гипотезы требует причины'
        item.update(claim=claim, result=status, probe_result_id=result_id if status in
                    ('confirmed', 'refuted') else '', quote=quote if status in
                    ('confirmed', 'refuted') else '', reason=reason if status == 'dropped' else '')
        item['cost'] = bounded_cost(item.get('cost', 2))
        checked.append(item)
    report['hypotheses'] = checked[:40]
    return report


def save_hypotheses(db, task_id, stage, report):
    ensure_schema(db)
    claims = list(report.get('hypotheses') or [])
    # Identity, not dict equality: a finding that is merely equal to a verified
    # one is still unverified, and comparing by value kept that ambiguous.
    verified_findings = report.get('findings') or []
    for finding in list(verified_findings) + (report.get('unverified_findings') or []):
        if not isinstance(finding, dict):
            continue
        probe = finding.get('probe') if isinstance(finding.get('probe'), dict) else {}
        kind = finding.get('kind', 'hypothesis')
        claims.append({'claim': finding.get('claim') or finding.get('title'),
                       'kind': kind,
                       'result': ('confirmed' if kind == 'observation' and
                                  any(finding is item for item in verified_findings)
                                  else 'untested'),
                       'probe_result_id': probe.get('result_id', ''),
                       'quote': finding.get('quote', ''), 'test': finding.get('test', ''),
                       'cost': finding.get('cost', 2),
                       'objective_key': finding.get('objective_key')})
    for item in claims:
        key = claim_key(item.get('claim'))
        if not key:
            continue
        kind = item.get('kind', 'hypothesis')
        if kind not in CLAIM_KINDS:
            kind = 'hypothesis'
        status = item.get('result', 'untested')
        if status not in HYPOTHESIS_STATES:
            status = 'untested'
        previous = db.execute('SELECT status FROM pm_hypotheses WHERE task_id=? AND claim_key=?',
                              (task_id, key)).fetchone()
        # A later unsupported mention cannot reopen or erase a proved closure.
        if previous and previous[0] != 'untested' and status == 'untested':
            continue
        db.execute('''INSERT INTO pm_hypotheses
            (task_id,claim_key,claim,kind,status,probe_result_id,quote,reason,test,cost,stage,updated_at,objective_key)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(task_id,claim_key) DO UPDATE SET
            claim=excluded.claim,kind=excluded.kind,status=excluded.status,
            probe_result_id=excluded.probe_result_id,quote=excluded.quote,
            reason=excluded.reason,test=excluded.test,cost=excluded.cost,
            stage=excluded.stage,updated_at=excluded.updated_at,
            objective_key=COALESCE(excluded.objective_key,pm_hypotheses.objective_key)''',
            (task_id, key, item['claim'], kind, status,
             item.get('probe_result_id', ''), item.get('quote', ''),
             item.get('reason', ''), str(item.get('test') or '')[:300],
             bounded_cost(item.get('cost', 2)), stage, now(), item.get('objective_key')))


def list_hypotheses(db, task_id, status=None, limit=100):
    ensure_schema(db)
    query = ('SELECT claim_key,claim,kind,status,probe_result_id,quote,reason,test,cost,stage,updated_at,objective_key '
             'FROM pm_hypotheses WHERE task_id=?')
    params = [task_id]
    if status:
        query += ' AND status=?'
        params.append(status)
    query += ' ORDER BY updated_at DESC LIMIT ?'
    params.append(limit)
    return [dict(zip(('claim_key','claim','kind','status','probe_result_id','quote',
                      'reason','test','cost','stage','updated_at','objective_key'), row))
            for row in db.execute(query, params)]


def inherit_hypotheses(db, old_id, new_id):
    """Old-address conclusions become open questions on the new address."""
    ensure_schema(db)
    added = 0
    for item in list_hypotheses(db, old_id, limit=1000):
        cursor = db.execute('''INSERT OR IGNORE INTO pm_hypotheses
            (task_id,claim_key,claim,kind,status,reason,test,cost,stage,updated_at,objective_key)
            VALUES (?,?,?,?,'untested',?,?,?,?,?,?)''',
            (new_id, item['claim_key'], item['claim'], item['kind'],
             f'Унаследовано из задачи #{old_id}; не доказано на текущем адресе',
             item.get('test', ''), item.get('cost', 2), f'inherited-{old_id}', now(),
             item.get('objective_key')))
        added += cursor.rowcount
    return added


def import_legacy_reports(db, task_id):
    """Conservatively expose old free-text claims as open hypotheses only."""
    ensure_schema(db)
    try:
        rows = db.execute('SELECT role,iteration,report_json FROM pm_agent_action_reports '
                          'WHERE task_id=? ORDER BY iteration,role', (task_id,)).fetchall()
    except sqlite3.OperationalError:
        return 0
    added = 0
    for role, iteration, raw in rows:
        try:
            report = json.loads(raw)
        except ValueError:
            continue
        if not isinstance(report, dict):
            continue
        candidates = [(str(item.get('claim') or ''), 'hypothesis')
                      for item in report.get('hypotheses') or [] if isinstance(item, dict)]
        candidates += [(str(item.get('claim') or item.get('title') or ''),
                        str(item.get('kind') or 'hypothesis'))
                       for item in (report.get('findings') or []) +
                       (report.get('unverified_findings') or []) if isinstance(item, dict)]
        for claim, kind in candidates:
            key = claim_key(claim)
            if not key:
                continue
            if kind not in CLAIM_KINDS:
                kind = 'hypothesis'
            cursor = db.execute('''INSERT OR IGNORE INTO pm_hypotheses
                (task_id,claim_key,claim,kind,status,stage,updated_at)
                VALUES (?,?,?,?,'untested',?,?)''',
                (task_id, key, claim[:500], kind, f'{role}-{iteration}', now()))
            added += cursor.rowcount
    return added
