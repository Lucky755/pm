"""Pentest Master: evidence-backed flag registry.

A flag is not "found" because an agent says so. This module reads the raw
records the capabilities actually produced (storage/capability_log) and the
agent reports, then classifies every candidate:

  confirmed  the same value appears in at least two independent capability
             sources, or an operator confirmed it explicitly;
  candidate  seen once in raw output, or only claimed by an agent.

That keeps a hallucinated flag from ending an assessment while still letting a
single decisive PoC output through once a second source corroborates it.

Литеральный поиск самогенерации — эвристика против случайной самогенерации, не
замена operator_confirm. Склейка строк, base64 и вычисляемый вывод могут её
обойти; операторское подтверждение хранится отдельно.
"""

import argparse
import difflib
import ipaddress
import json
import re
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DB_PATH = ROOT / 'storage/tasks.db'
CAPABILITY_LOG = ROOT / 'storage/capability_log'
POC_ROOT = ROOT / 'storage/pocs'

# A flag is a short upper-case prefix plus a token-like body. The earlier
# permissive pattern matched minified JavaScript (``else{if(a.isIE10...)``,
# ``events{/number}``) and filled the registry with JavaScript fragments, which
# could be "confirmed" by a second page load and end a run on a fake flag.
# Body characters stay in the flag alphabet: JS control characters are out.
DEFAULT_PATTERNS = (
    r'\b[A-Z][A-Z0-9_]{1,19}\{[A-Za-z0-9_!@#$%^&*+.:-]{3,120}\}',
    r'\b(?:flag|ctf|pwn|secret)\{[A-Za-z0-9_!@#$%^&*+.:-]{3,120}\}',
)
KV_PATTERN = r'''(?i)["']?\b(?:flag|flags|token|secret|answer)\b["']?\s*[:=]\s*["']?([A-Za-z0-9._~+/=-]{4,200})["']?'''
SHAPES = {
    'uuid': r'\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b',
    'uuid_nohyphen': r'(?i:\b[0-9a-f]{32}\b)',
    'hex32': r'\b[0-9a-fA-F]{32}\b',
    'hex40': r'\b[0-9a-fA-F]{40}\b',
    'b64': r'\b[A-Za-z0-9+/]{22,}={0,2}\b',
    'digits': r'\b[0-9]{12,}\b',
}

# A claimed value that is this close to a real capture is almost always a
# transcription error by the agent, not a second flag.
TYPO_SIMILARITY = 0.8

# Captured output frequently carries a Python bytes repr, so a real newline
# arrives as the two characters ``\`` and ``n`` (sometimes doubled). The ``\b``
# in the flag pattern then sees the letter ``n`` - a word character - and
# refuses to match. That silently hid a root flag that had been captured three
# times on task 16, so normalise the escapes before matching.
ESCAPE_SEQUENCES = (
    ('\\\\', '\\'),          # a doubled backslash stands for one
    ('\\r\\n', '\n'),
    ('\\n', '\n'),
    ('\\r', '\n'),
    ('\\t', '\t'),
)


def normalise_captured(text, passes=2):
    """Turn literal escape sequences into the characters they stand for."""
    for _ in range(passes):
        before = text
        for source, target in ESCAPE_SEQUENCES:
            text = text.replace(source, target)
        if text == before:
            break
    return text


def looks_like_flag(value, patterns=None):
    """A claimed value must at least have the shape of a flag.

    Without this, phrases an agent writes in the flags list ("root-флаг не
    получен") enter the registry as candidates and show up in the console as if
    they were findings.
    """
    text = str(value or '')
    return canonical_flag_value(text, patterns) is not None


def canonical_flag_value(value, patterns=None):
    """Extract one exact, case-sensitive value from a capture or claim."""
    text = str(value or '')
    matches = set()
    for pattern in (patterns if patterns is not None else (*DEFAULT_PATTERNS, KV_PATTERN)):
        for match in re.finditer(pattern, text):
            candidate = (match.group(1) if match.re.groups else match.group(0))
            candidate = candidate.strip().strip('"\'').rstrip(
                '.,;:)]}"\'' if match.re.groups else '.,;:)]"\'')
            if valid_flag_value(candidate, pattern):
                matches.add(candidate)
    return next(iter(matches)) if len(matches) == 1 else None


def valid_flag_value(value, pattern, target=None):
    if not value or value == str(target) or (value.isdigit() and (len(value) == 13 or int(value) <= 65535)):
        return False
    try:
        address = ipaddress.ip_address(value)
        if address.is_private or address.is_loopback:
            return False
    except ValueError:
        pass
    pattern_text = pattern.pattern if hasattr(pattern, 'pattern') else str(pattern)
    if pattern_text == KV_PATTERN or pattern_text in SHAPES.values():
        if len(value) < 8:
            return False
    if pattern_text in (SHAPES['uuid'], SHAPES['uuid_nohyphen'], SHAPES['hex32'], SHAPES['hex40']):
        if not re.search('[a-fA-F]', value) or not re.search('[0-9]', value):
            return False
    return True


def now():
    return datetime.now(timezone.utc).isoformat()


def nearest_value(value, values, cutoff=TYPO_SIMILARITY):
    """Return the captured value closest to a claimed one, if it is close."""
    matches = difflib.get_close_matches(str(value), [str(item) for item in values],
                                        n=1, cutoff=cutoff)
    return matches[0] if matches else None


def render(obj):
    print(json.dumps(obj, ensure_ascii=False, indent=2))


def connect():
    if not DB_PATH.exists():
        raise ValueError(f'Task database not found: {DB_PATH}')
    db = sqlite3.connect(DB_PATH, timeout=10)
    db.execute('PRAGMA busy_timeout = 5000')
    ensure_schema(db)
    db.commit()
    return db


def ensure_schema(db):
    """Install only the current registry shape on any supplied connection."""
    db.execute("""
        CREATE TABLE IF NOT EXISTS pm_verified_flags (
            task_id INTEGER NOT NULL,
            value TEXT NOT NULL,
            status TEXT NOT NULL,
            evidence_count INTEGER NOT NULL,
            reported_by TEXT NOT NULL,
            sources_json TEXT NOT NULL,
            operator_confirmed INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            PRIMARY KEY(task_id, value)
        )
    """)
    columns = {row[1] for row in db.execute('PRAGMA table_info(pm_verified_flags)')}
    if 'operator_confirmed' not in columns:
        db.execute('ALTER TABLE pm_verified_flags ADD COLUMN operator_confirmed INTEGER NOT NULL DEFAULT 0')
        db.execute("UPDATE pm_verified_flags SET operator_confirmed=1 WHERE reported_by='operator'")
    if 'objective_key' not in columns:
        db.execute('ALTER TABLE pm_verified_flags ADD COLUMN objective_key TEXT')
    if 'weight' not in columns:
        db.execute('ALTER TABLE pm_verified_flags ADD COLUMN weight INTEGER NOT NULL DEFAULT 0')
    db.execute('''CREATE TABLE IF NOT EXISTS pm_flag_patterns (
        task_id INTEGER NOT NULL, pattern TEXT NOT NULL, source TEXT NOT NULL,
        created_at TEXT NOT NULL, PRIMARY KEY(task_id, pattern))''')


def flag_patterns(db, task_id):
    ensure_schema(db)
    return (*DEFAULT_PATTERNS, KV_PATTERN, *(row[0] for row in db.execute(
        'SELECT pattern FROM pm_flag_patterns WHERE task_id=? ORDER BY created_at,pattern',
        (task_id,))))


def load_patterns(db, task_id):
    return flag_patterns(db, task_id)


def save_patterns(db, task_id, patterns=(), prefixes=(), shapes=(), expects=()):
    ensure_schema(db)
    entries = [(item, 'task_regex') for item in patterns]
    entries += [(r'\b' + re.escape(prefix) + r'\{[^}\n]{1,200}\}', 'task_regex')
                for prefix in prefixes]
    entries += [(SHAPES[name], 'shape:' + name) for name in shapes if name in SHAPES]
    unknown = set(shapes) - set(SHAPES)
    if unknown:
        raise ValueError('Неизвестная форма флага: ' + ', '.join(sorted(unknown)))
    entries += [(re.escape(value), 'exact') for value in expects if value]
    existing = {row[0] for row in db.execute('SELECT pattern FROM pm_flag_patterns WHERE task_id=?',
                                             (task_id,))}
    if len(existing | {item[0] for item in entries}) > 20:
        raise ValueError('Для задачи допускается не более 20 дополнительных шаблонов')
    for pattern, source in entries:
        if len(pattern) > 300:
            raise ValueError('Шаблон флага длиннее 300 символов')
        try:
            re.compile(pattern)
        except re.error as exc:
            raise ValueError('Некорректный шаблон флага: ' + str(exc)) from exc
    with db:
        db.executemany('INSERT OR IGNORE INTO pm_flag_patterns VALUES (?,?,?,?)',
                       [(task_id, pattern, source, now()) for pattern, source in entries])


def capability_records(task_id, limit=400):
    path = CAPABILITY_LOG / f'task_{task_id}.jsonl'
    if not path.is_file():
        return []
    records = []
    for number, line in enumerate(path.read_text(encoding='utf-8', errors='replace').splitlines()):
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except ValueError:
            continue
        payload = record.get('result')
        if not isinstance(payload, dict):
            continue
        text = normalise_captured('\n'.join([
            str(payload.get('stdout', '')),
            str(payload.get('stderr', '')),
            str(payload.get('response', '')),
            str(payload.get('output', '')),
        ]))
        if text:
            argv = [str(item) for item in (record.get('argv') or [])]
            poc_file = ''
            if '--poc-file' in argv:
                index = argv.index('--poc-file') + 1
                if index < len(argv):
                    poc_file = argv[index]
            source_literals = set(record.get('source_flag_literals') or [])
            source_text = ''
            if poc_file:
                try:
                    poc = Path(poc_file).resolve()
                    allowed = (POC_ROOT / f'task_{task_id}').resolve()
                    if poc.is_relative_to(allowed) and poc.is_file() and poc.stat().st_size <= 262144:
                        source_text = poc.read_text(encoding='utf-8', errors='replace')
                        if 'source_flag_literals' not in record:
                            for pattern in DEFAULT_PATTERNS:
                                source_literals.update(re.findall(pattern, source_text))
                except OSError:
                    pass
            normalized_argv = []
            skip = False
            for token in argv:
                if skip:
                    skip = False
                    continue
                if token in ('--timeout', '--wait', '--idle'):
                    skip = True
                    continue
                if token != '--execute':
                    normalized_argv.append(token)
            if poc_file:
                identity = str(Path(poc_file).resolve())
            else:
                identity = json.dumps(normalized_argv, ensure_ascii=False, separators=(',', ':'))
            records.append({
                'ref': f'capability:{number}:{record.get("tool")}',
                'tool': record.get('tool'),
                'provenance': record.get('provenance', 'unknown'),
                'time': record.get('timestamp'),
                'text': text,
                'identity': (str(record.get('tool')), identity),
                'input_text': ' '.join(argv),
                'input_flag_literals': set(record.get('input_flag_literals') or []),
                'source_literals': source_literals,
                'source_text': source_text,
                'source_changed': bool(record.get('poc_changed_during_run') or
                                       payload.get('poc_changed_during_run')),
            })
    return records[-limit:]


def agent_claims(db, task_id):
    try:
        rows = db.execute(
            'SELECT role, iteration, report_json FROM pm_agent_action_reports '
            'WHERE task_id = ?', (task_id,)
        ).fetchall()
    except sqlite3.OperationalError:
        return []
    claims = []
    patterns = flag_patterns(db, task_id)
    sources = dict(db.execute('SELECT pattern,source FROM pm_flag_patterns WHERE task_id=?',
                              (task_id,)))
    for role, iteration, raw in rows:
        try:
            report = json.loads(raw)
        except ValueError:
            continue
        for item in report.get('flags', []):
            raw_value = item.get('value') if isinstance(item, dict) else None
            value = (canonical_flag_value(raw_value, patterns) or
                     canonical_flag_value('flag: ' + str(raw_value or ''), patterns)) if isinstance(item, dict) else None
            if value:
                matched = next((sources.get(pattern, 'kv' if pattern == KV_PATTERN else 'default')
                                for pattern in patterns if re.search(pattern, str(raw_value or ''))),
                               'kv')
                claims.append({'value': value, 'role': role, 'iteration': iteration,
                               'matched_by': matched,
                               'source': str(item.get('source', ''))[:500],
                               'ref': f'agent:{role}:{iteration}'})
    return claims


def scan(task_id, patterns=None, db=None):
    """Classify captured flags; literal self-generation detection is heuristic.

    It catches accidental literals in argv or PoC source, not concatenated or
    encoded output, and does not replace operator_confirm.
    """
    if type(task_id) is not int or task_id <= 0:
        raise ValueError('Expected a positive task id')
    owns_db = db is None
    db = db if db is not None else connect()
    ensure_schema(db)
    patterns = patterns if patterns is not None else flag_patterns(db, task_id)
    pattern_sources = dict(db.execute('SELECT pattern,source FROM pm_flag_patterns WHERE task_id=?', (task_id,)))
    try:
        target_row = db.execute('SELECT target FROM tasks WHERE id=?', (task_id,)).fetchone()
        target = target_row[0] if target_row else None
    except sqlite3.OperationalError:
        target = None
    regexes = []
    for pattern in patterns:
        try:
            regexes.append(re.compile(pattern))
        except re.error as exc:
            raise ValueError(f'Invalid pattern {pattern!r}: {exc}') from exc

    found = {}
    def empty_entry():
        return {'raw': [], 'local_hits': [], 'claims': [], 'tools': set(),
                'independent': set(), 'self_generated': [],
                'source_unverified': [], 'matched_by': set()}
    for record in capability_records(task_id):
        for regex in regexes:
            for match in regex.finditer(record['text']):
                value = match.group(1) if regex.groups else match.group(0)
                value = value.strip().strip('"\'').rstrip(
                    '.,;:)]}"\'' if regex.groups else '.,;:)]"\'')
                if not valid_flag_value(value, regex, target):
                    continue
                entry = found.setdefault(value, empty_entry())
                entry['matched_by'].add(pattern_sources.get(regex.pattern,
                    'kv' if regex.pattern == KV_PATTERN else 'default'))
                if record['source_changed']:
                    entry['source_unverified'].append(record['ref'])
                elif (value in record['input_text'] or value in record['source_text'] or
                        value in record['source_literals']
                        or value in record['input_flag_literals']):
                    entry['self_generated'].append(record['ref'])
                elif record['provenance'] != 'network':
                    if record['ref'] not in entry['local_hits']:
                        entry['local_hits'].append(record['ref'])
                elif record['ref'] not in entry['raw']:
                    entry['raw'].append(record['ref'])
                    entry['tools'].add(str(record.get('tool')))
                    entry['independent'].add(record['identity'])

    try:
        for pattern, source in pattern_sources.items():
            if source == 'exact':
                value = re.sub(r'\\(.)', r'\1', pattern)
                found.setdefault(value, empty_entry())['matched_by'].add('exact')
        for claim in agent_claims(db, task_id):
            if claim['value'] not in found:
                # A claimed value is tracked, but with zero raw evidence.
                found.setdefault(claim['value'], empty_entry())
            found[claim['value']]['claims'].append(claim['ref'])
            found[claim['value']]['matched_by'].add(claim['matched_by'])

        transferred = {}
        for value, sources_json in db.execute(
                "SELECT value, sources_json FROM pm_verified_flags "
                "WHERE task_id = ? AND status = 'candidate' AND reported_by = 'transfer'",
                (task_id,)):
            found.setdefault(value, empty_entry())
            try:
                source_data = json.loads(sources_json)
                transferred[value] = source_data.get('transfer', '')
                found[value]['matched_by'].add(source_data.get('matched_by', 'default'))
            except (ValueError, TypeError):
                transferred[value] = ''

        for (value,) in db.execute(
                'SELECT value FROM pm_verified_flags WHERE task_id = ? AND operator_confirmed = 1',
                (task_id,)):
            found.setdefault(value, empty_entry())

        results = []
        stamp = now()
        for value, entry in found.items():
            roles = sorted({ref.split(':')[1] for ref in entry['claims'] if ref.count(':') >= 2})
            independent_sources = len(entry['independent'])
            status = 'confirmed' if independent_sources >= 2 else 'candidate'

            previous = db.execute(
                'SELECT operator_confirmed, sources_json, objective_key, weight FROM pm_verified_flags '
                'WHERE task_id = ? AND value = ?',
                (task_id, value),
            ).fetchone()
            operator_confirmed = bool(previous and previous[0])
            if operator_confirmed:
                status = 'confirmed'
            evidence_source = ('network' if entry['raw'] else
                               'local' if entry['local_hits'] else 'none')
            matched_by = sorted(entry['matched_by'])[0] if entry['matched_by'] else 'default'

            sources = {
                'raw': entry['raw'][:8],
                'local_hits': entry['local_hits'][:8],
                'local_only': bool(entry['local_hits'] and not entry['raw']),
                'evidence_source': evidence_source,
                'matched_by': matched_by,
                'claims': entry['claims'][:8],
                'tools': sorted(entry['tools']),
                'independent_sources': independent_sources,
                'self_generated': entry['self_generated'][:8],
                'source_unverified': entry['source_unverified'][:8],
            }
            if value in transferred:
                sources['transfer'] = transferred[value]
            if operator_confirmed:
                try:
                    sources['operator'] = json.loads(previous[1]).get('operator', 'operator confirmed')
                except (ValueError, TypeError):
                    sources['operator'] = 'operator confirmed'
            if previous:
                try:
                    marker = json.loads(previous[1]).get('goal_claim_unverified')
                except (ValueError, TypeError):
                    marker = None
                if marker:
                    sources['goal_claim_unverified'] = marker
                    if not operator_confirmed:
                        status = 'candidate'
            reported_by = ','.join(roles + (['transfer'] if value in transferred else []) +
                                   (['operator'] if operator_confirmed else []))
            db.execute(
                'INSERT INTO pm_verified_flags (task_id, value, status, evidence_count, '
                'reported_by, sources_json, created_at, updated_at) '
                'VALUES (?, ?, ?, ?, ?, ?, ?, ?) '
                'ON CONFLICT(task_id, value) DO UPDATE SET '
                'status=excluded.status, evidence_count=excluded.evidence_count, '
                'reported_by=excluded.reported_by, sources_json=excluded.sources_json, '
                'updated_at=excluded.updated_at',
                (task_id, value, status, len(entry['raw']), reported_by,
                 json.dumps(sources, ensure_ascii=False), stamp, stamp),
            )
            results.append({
                'value': value,
                'status': status,
                'raw_hits': len(entry['raw']),
                'local_hits': entry['local_hits'][:8],
                'local_only': bool(entry['local_hits'] and not entry['raw']),
                'evidence_source': evidence_source,
                'matched_by': matched_by,
                'independent_sources': independent_sources,
                'self_generated': bool(entry['self_generated']),
                'operator_confirmed': operator_confirmed,
                'goal_claim_unverified': sources.get('goal_claim_unverified'),
                'objective_key': previous[2] if previous else None,
                'weight': previous[3] if previous else 0,
                'roles': roles,
                'tools': sorted(entry['tools']),
                'claims': sorted(set(entry['claims'])),
            })

        # Drop stale rows: a value that no longer matches any capture (or any
        # report) must not sit in the registry as a candidate forever. Operator
        # and evidence-backed confirmations are never deleted.
        keep = [item['value'] for item in results]
        if keep:
            placeholders = ', '.join('?' for _ in keep)
            db.execute(
                'DELETE FROM pm_verified_flags WHERE task_id = ? AND status != ? '
                f'AND value NOT IN ({placeholders})',
                (task_id, 'confirmed', *keep),
            )
        else:
            db.execute(
                "DELETE FROM pm_verified_flags WHERE task_id = ? AND status != 'confirmed'",
                (task_id,),
            )
        db.commit()
    finally:
        if owns_db:
            db.close()

    confirmed = [item for item in results if item['status'] == 'confirmed']
    candidates = [item for item in results if item['status'] != 'confirmed']
    raw_values = [item['value'] for item in results if item['raw_hits']]
    mismatches = [{
        'value': item['value'],
        'closest': nearest_value(item['value'], raw_values),
    } for item in candidates if item['raw_hits'] == 0 and item['claims']]
    return {
        'status': 'completed',
        'task_id': task_id,
        'count': len(results),
        'confirmed': confirmed,
        'candidates': candidates,
        'mismatches': mismatches,
        'patterns_used': list(patterns),
    }


def listing(task_id):
    db = connect()
    try:
        rows = db.execute(
            'SELECT value, status, evidence_count, reported_by, sources_json, updated_at, '
            'operator_confirmed, objective_key, weight '
            'FROM pm_verified_flags WHERE task_id = ? ORDER BY status, value',
            (task_id,),
        ).fetchall()
    finally:
        db.close()
    return [{
        'value': value,
        'status': status,
        'raw_hits': count,
        'roles': reported_by,
        'sources': json.loads(sources),
        'independent_sources': json.loads(sources).get('independent_sources', 0),
        'operator_confirmed': bool(operator_confirmed),
        'objective_key': objective_key,
        'weight': weight,
        'evidence_source': json.loads(sources).get('evidence_source', 'none'),
        'matched_by': json.loads(sources).get('matched_by', 'default'),
        'local_hits': json.loads(sources).get('local_hits', []),
        'local_only': json.loads(sources).get('local_only', False),
        'goal_claim_unverified': json.loads(sources).get('goal_claim_unverified'),
        'updated_at': updated,
    } for value, status, count, reported_by, sources, updated, operator_confirmed,
          objective_key, weight in rows]


def operator_confirm(task_id, value, note=''):
    db = connect()
    existing = db.execute('SELECT value,sources_json FROM pm_verified_flags WHERE task_id=? AND value=?',
                          (task_id, str(value).strip())).fetchone()
    value = existing[0] if existing else canonical_flag_value(value, flag_patterns(db, task_id))
    if value is None:
        db.close()
        raise ValueError('Expected exactly one flag value')
    try:
        stamp = now()
        try:
            sources = json.loads(existing[1]) if existing else {}
        except (ValueError, TypeError):
            sources = {}
        if not isinstance(sources, dict):
            sources = {}
        sources['operator'] = note[:500] or 'operator confirmed'
        sources.setdefault('evidence_source', 'none')
        sources.setdefault('matched_by', 'default')
        db.execute(
            'INSERT INTO pm_verified_flags (task_id, value, status, evidence_count, '
            'reported_by, sources_json, created_at, updated_at, operator_confirmed) '
            'VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1) '
            'ON CONFLICT(task_id, value) DO UPDATE SET status=excluded.status, '
            'reported_by=excluded.reported_by, sources_json=excluded.sources_json, '
            'operator_confirmed=1, '
            'updated_at=excluded.updated_at',
            (task_id, value, 'confirmed', 0, 'operator',
             json.dumps(sources, ensure_ascii=False), stamp, stamp),
        )
        db.commit()
    finally:
        db.close()
    return {'status': 'completed', 'task_id': task_id, 'value': value,
            'flag_status': 'confirmed'}


def self_test():
    """Offline check in a temporary database and log directory."""
    global CAPABILITY_LOG, DB_PATH
    import tempfile

    saved_log, saved_db = CAPABILITY_LOG, DB_PATH
    with tempfile.TemporaryDirectory(prefix='pm-flags-') as directory:
        try:
            CAPABILITY_LOG = Path(directory)
            DB_PATH = Path(directory) / 'tasks.db'
            noise = ('else{if(d.isIE10||a.isCrossDomain())return a.loadCrossDomain();'
                     'if(!a.isCss()&&d.hasReadyState)a.createLoadElement(function(){a.loaded=!0;'
                     'a.notifyRequests()} try{h.open("GET",b,c),h.send(null)} '
                     'events{/number} blobs{/sha} starred{/owner}{/repo}')
            records = [
                {'tool': 'poc_run', 'timestamp': 't1', 'result': {'stdout': 'root flag HTB{first_one} ok'}},
                {'tool': 'net_exec', 'timestamp': 't2', 'result': {'stdout': 'again HTB{first_one}'}},
                {'tool': 'net_exec', 'timestamp': 't3', 'result': {'stdout': 'single CTF{lonely}'}},
                {'tool': 'net_exec', 'timestamp': 't4', 'result': {'stdout': noise}},
                # A Python bytes repr puts a literal ``\n`` in front of the flag,
                # so the word boundary in the pattern saw the letter ``n`` and the
                # value was invisible. This is how a captured root flag was missed.
                {'tool': 'net_exec', 'timestamp': 't5', 'argv': ['/usr/bin/id'],
                 'result': {'stdout': 'uid=0(root)\\r\\nHTB{repr_capture}\\r\\n'}},
                {'tool': 'net_exec', 'timestamp': 't6', 'argv': ['/usr/bin/cat', '/root/flag'],
                 'result': {'stdout': 'again HTB{repr_capture}'}},
                {'tool': 'poc_run', 'timestamp': 't7',
                 'argv': ['--poc-file', '/work/same.py'],
                 'result': {'stdout': 'DUP{same_poc}'}},
                {'tool': 'poc_run', 'timestamp': 't8',
                 'argv': ['--poc-file', '/work/same.py'],
                 'result': {'stdout': 'DUP{same_poc}'}},
                {'tool': 'poc_run', 'timestamp': 't9',
                 'argv': ['--poc-file', '/work/source.py'],
                 'source_flag_literals': ['FAKE{in_source}'],
                 'result': {'stdout': 'FAKE{in_source}'}},
                {'tool': 'session', 'timestamp': 't10', 'argv': ['--action', 'send'],
                 'result': {'status': 'ok', 'output': 'SESS{only_shell_output}'}},
                {'tool': 'session', 'timestamp': 't11', 'argv': ['--action', 'send'],
                 'result': {'status': 'ok', 'output': 'SESS{corroborated_output}'}},
                {'tool': 'net_exec', 'timestamp': 't12', 'argv': ['/usr/bin/cat'],
                 'result': {'stdout': 'SESS{corroborated_output}'}},
            ]
            for record in records:
                record['provenance'] = ('network' if record['tool'] in ('net_exec', 'session')
                                        else 'local')
            records[0]['provenance'] = 'network'
            (CAPABILITY_LOG / 'task_1.jsonl').write_text(
                '\n'.join(json.dumps(item) for item in records) + '\n', encoding='utf-8')
            DB_PATH.touch()
            db = connect()
            db.execute(
                'CREATE TABLE pm_agent_action_reports (task_id INTEGER, role TEXT, '
                'iteration INTEGER, report_json TEXT)')
            db.execute(
                'INSERT INTO pm_agent_action_reports VALUES (1, ?, 1, ?)',
                ('access', json.dumps({'flags': [{'value': 'HTB{first_one}', 'source': 'x'},
                                                 {'value': 'HTB{hallucinated}', 'source': 'y'},
                                                 {'value': 'HTB{first_0ne}', 'source': 'typo'},
                                                 {'value': 'root-флаг не получен',
                                                  'source': 'not a flag at all'}]})))
            db.execute(
                'INSERT INTO pm_verified_flags (task_id, value, status, evidence_count, '
                'reported_by, sources_json, created_at, updated_at) '
                "VALUES (1, 'STALE{old}', 'candidate', 1, '', '{}', 't', 't')")
            db.commit()
            result = scan(1, db=db)
            db.close()
            listed = {item['value'] for item in listing(1)}
        finally:
            CAPABILITY_LOG, DB_PATH = saved_log, saved_db

    statuses = {item['value']: item['status'] for item in result['confirmed'] + result['candidates']}
    expected = {'HTB{first_one}': 'confirmed', 'CTF{lonely}': 'candidate',
                'HTB{hallucinated}': 'candidate', 'HTB{first_0ne}': 'candidate',
                'HTB{repr_capture}': 'confirmed', 'DUP{same_poc}': 'candidate',
                'FAKE{in_source}': 'candidate',
                'SESS{only_shell_output}': 'candidate',
                'SESS{corroborated_output}': 'confirmed'}
    if statuses != expected:
        raise ValueError(f'Unexpected flag statuses: {statuses}')
    dup = next(item for item in result['candidates'] if item['value'] == 'DUP{same_poc}')
    if dup['independent_sources'] != 0 or len(dup['local_hits']) != 2:
        raise ValueError('Local PoC counted as independent network evidence')
    fake = next(item for item in result['candidates'] if item['value'] == 'FAKE{in_source}')
    if fake['raw_hits'] or not fake['self_generated']:
        raise ValueError('PoC source literal counted as raw evidence')
    if any('isIE10' in value or '/number' in value for value in statuses):
        raise ValueError('JavaScript noise leaked into the flag registry')
    if any('не получен' in value for value in statuses):
        raise ValueError('A prose phrase was accepted as a flag claim')
    if normalise_captured('a\\r\\nb') != 'a\nb':
        raise ValueError('normalise_captured did not unescape a bytes repr')
    if normalise_captured('a\\\\r\\\\nb') != 'a\nb':
        raise ValueError('normalise_captured did not unescape a doubled repr')
    if 'STALE{old}' in listed:
        raise ValueError('A stale candidate survived the scan')
    errors = {item['value']: item['closest'] for item in result['mismatches']}
    if errors.get('HTB{first_0ne}') != 'HTB{first_one}':
        raise ValueError(f'Typo detection failed: {errors}')
    if 'HTB{hallucinated}' in errors and errors['HTB{hallucinated}']:
        raise ValueError('Typo detection invented a neighbour for an unrelated claim')
    return {'status': 'completed', 'test': 'flag_verify', 'flags': statuses,
            'mismatches': errors}


def main(argv=None):
    parser = argparse.ArgumentParser(description='Pentest Master flag verification')
    sub = parser.add_subparsers(dest='command', required=True)

    sc = sub.add_parser('scan', help='scan capability log and reports for flags')
    sc.add_argument('--task-id', type=int, required=True)
    sc.add_argument('--pattern', action='append', default=None)

    li = sub.add_parser('list', help='list registered flags')
    li.add_argument('--task-id', type=int, required=True)

    cf = sub.add_parser('confirm', help='operator confirmation of one value')
    cf.add_argument('--task-id', type=int, required=True)
    cf.add_argument('--value', required=True)
    cf.add_argument('--note', default='')

    sub.add_parser('self-test', help='offline check with a temporary database')

    args = parser.parse_args(argv)

    try:
        if args.command == 'scan':
            render(scan(args.task_id, args.pattern))
        elif args.command == 'list':
            render({'task_id': args.task_id, 'flags': listing(args.task_id)})
        elif args.command == 'confirm':
            render(operator_confirm(args.task_id, args.value, args.note))
        elif args.command == 'self-test':
            render(self_test())
    except (ValueError, OSError, sqlite3.Error) as exc:
        render({'status': 'error', 'error': str(exc)})
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
