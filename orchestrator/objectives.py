"""Task objectives and evidence-backed attribution of captured flags."""

import json
import re

from operator_errors import OperatorError
from orchestrator import flag_verify

MAX_OBJECTIVES = 30
MODES = ('goal-first', 'goal-exclusive', 'all-flags')


def ensure_schema(db):
    db.execute('''CREATE TABLE IF NOT EXISTS pm_objectives (
        task_id INTEGER NOT NULL, key TEXT NOT NULL, title TEXT NOT NULL,
        weight INTEGER NOT NULL DEFAULT 100, role TEXT NOT NULL,
        exclusive INTEGER NOT NULL DEFAULT 0, status TEXT NOT NULL,
        evidence_ref TEXT, evidence_refs_json TEXT NOT NULL DEFAULT '[]',
        created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
        PRIMARY KEY(task_id,key))''')
    columns = {row[1] for row in db.execute('PRAGMA table_info(pm_objectives)')}
    if 'mode' not in columns:
        db.execute("ALTER TABLE pm_objectives ADD COLUMN mode TEXT NOT NULL DEFAULT 'goal-first'")
    if 'expected_flags' not in columns:
        db.execute('ALTER TABLE pm_objectives ADD COLUMN expected_flags INTEGER')
    flag_verify.ensure_schema(db)


def parse_objective_spec(text):
    """Read an optional numeric weight before the first colon."""
    raw = str(text or '').strip()
    match = re.fullmatch(r'(\d+)\s*:(.*)', raw, re.S)
    weight = int(match.group(1)) if match else 100
    title = (match.group(2) if match else raw).strip()
    if not title:
        raise OperatorError('Описание цели не может быть пустым')
    if not 1 <= weight <= 10000:
        raise OperatorError('Вес цели должен быть целым числом от 1 до 10000')
    return weight, title


def split_specs(text):
    """Split semicolon-separated entries while keeping escaped semicolons."""
    parts, current = [], []
    raw = str(text or '')
    index = 0
    while index < len(raw):
        if raw[index:index + 2] == r'\;':
            current.append(';')
            index += 2
        elif raw[index] == ';':
            parts.append(''.join(current).strip())
            current = []
            index += 1
        else:
            current.append(raw[index])
            index += 1
    parts.append(''.join(current).strip())
    if any(not part for part in parts):
        raise OperatorError('Пустая побочная цель между разделителями')
    return parts


def list_objectives(db, task_id):
    ensure_schema(db)
    rows = db.execute('SELECT key,title,weight,role,exclusive,status,evidence_ref,'
                      'evidence_refs_json,created_at,updated_at,mode,expected_flags '
                      'FROM pm_objectives WHERE task_id=? ORDER BY '
                      "CASE WHEN key='goal' THEN 0 ELSE 1 END, CAST(SUBSTR(key,5) AS INTEGER)",
                      (task_id,)).fetchall()
    fields = ('key', 'title', 'weight', 'role', 'exclusive', 'status', 'evidence_ref',
              'evidence_refs_json', 'created_at', 'updated_at', 'mode', 'expected_flags')
    return [{**dict(zip(fields, row)), 'exclusive': bool(row[4]),
             'evidence_refs': json.loads(row[7] or '[]')} for row in rows]


def objective_status(db, task_id):
    rows = list_objectives(db, task_id)
    primary = next((row for row in rows if row['key'] == 'goal'), None)
    return {'primary': primary,
            'confirmed': [row for row in rows if row['status'] == 'confirmed'],
            'open': [row for row in rows if row['status'] != 'confirmed'],
            'exclusive': bool(primary and primary['exclusive']),
            'mode': primary['mode'] if primary else None,
            'expected_flags': primary['expected_flags'] if primary else None,
            'objectives': rows}


def save_objectives(db, task_id, primary_title, primary_weight=100, exclusive=False,
                    specs=(), *, mode='goal-first', expected_flags=None):
    """Upsert stable objective keys without erasing confirmed progress."""
    ensure_schema(db)
    title = str(primary_title or '').strip()
    if not title:
        raise OperatorError('Основная цель не может быть пустой')
    if type(primary_weight) is not int or not 1 <= primary_weight <= 10000:
        raise OperatorError('Вес основной цели должен быть от 1 до 10000')
    if mode not in MODES or (exclusive and mode == 'all-flags'):
        raise OperatorError('Режим целей: goal-first, goal-exclusive или all-flags')
    if exclusive:
        mode = 'goal-exclusive'
    parsed = [parse_objective_spec(item) for item in specs]
    if len(parsed) + 1 > MAX_OBJECTIVES:
        raise OperatorError(f'Можно задать не более {MAX_OBJECTIVES} целей')
    if len({item[1] for item in parsed}) != len(parsed):
        raise OperatorError('Побочные цели не должны повторяться')
    if expected_flags is not None and (type(expected_flags) is not int or
                                       not 1 <= expected_flags <= MAX_OBJECTIVES):
        raise OperatorError(f'Ожидаемое число флагов должно быть от 1 до {MAX_OBJECTIVES}')
    previous = {row['key']: row for row in list_objectives(db, task_id)}
    if previous.get('goal') and previous['goal']['status'] == 'confirmed' and previous['goal']['title'] != title:
        raise OperatorError('Подтверждённую основную цель нельзя заменить в этой задаче')
    stamp = flag_verify.now()
    by_title = {row['title']: row for row in previous.values() if row['role'] == 'secondary'}
    used = {key for key in previous if key.startswith('obj-')}
    wanted = {'goal'}
    with db:
        old = previous.get('goal')
        db.execute('''INSERT INTO pm_objectives
            (task_id,key,title,weight,role,exclusive,status,evidence_ref,evidence_refs_json,
             created_at,updated_at,mode,expected_flags)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(task_id,key) DO UPDATE SET
            title=excluded.title,weight=excluded.weight,exclusive=excluded.exclusive,
            status=CASE WHEN pm_objectives.title=excluded.title THEN pm_objectives.status ELSE 'open' END,
            evidence_ref=CASE WHEN pm_objectives.title=excluded.title THEN pm_objectives.evidence_ref ELSE NULL END,
            evidence_refs_json=CASE WHEN pm_objectives.title=excluded.title THEN pm_objectives.evidence_refs_json ELSE '[]' END,
            updated_at=excluded.updated_at,mode=excluded.mode,expected_flags=excluded.expected_flags''',
            (task_id, 'goal', title, primary_weight, 'primary', int(mode == 'goal-exclusive'),
             'open', None, '[]', old['created_at'] if old else stamp, stamp, mode,
             expected_flags if expected_flags is not None else len(parsed) + 1))
        for weight, side_title in parsed:
            old = by_title.get(side_title)
            if old:
                key = old['key']
            else:
                number = 1
                while f'obj-{number}' in used:
                    number += 1
                key = f'obj-{number}'
                used.add(key)
            wanted.add(key)
            db.execute('''INSERT INTO pm_objectives
                (task_id,key,title,weight,role,exclusive,status,created_at,updated_at)
                VALUES (?,?,?,?,? ,0,'open',?,?) ON CONFLICT(task_id,key) DO UPDATE SET
                weight=excluded.weight,updated_at=excluded.updated_at''',
                (task_id, key, side_title, weight, 'secondary', stamp, stamp))
        for key, row in previous.items():
            if key not in wanted and row['status'] == 'open':
                db.execute('DELETE FROM pm_objectives WHERE task_id=? AND key=?', (task_id, key))
    return list_objectives(db, task_id)


def transfer_objectives(db, old_id, new_id):
    """Carry objective definitions to a new address, without proof status."""
    rows = list_objectives(db, old_id)
    if not rows:
        return 0
    stamp = flag_verify.now()
    for row in rows:
        status = 'attempted' if row['status'] == 'confirmed' else row['status']
        db.execute('''INSERT OR IGNORE INTO pm_objectives
            (task_id,key,title,weight,role,exclusive,status,evidence_ref,evidence_refs_json,
             created_at,updated_at,mode,expected_flags)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)''',
            (new_id, row['key'], row['title'], row['weight'], row['role'],
             int(row['exclusive']), status, None, '[]', stamp, stamp,
             row['mode'], row['expected_flags']))
    return len(rows)


def question_rank(question, objective_key, rows):
    """Use an explicit key or two shared significant title words."""
    active = [row for row in rows if row['status'] != 'confirmed']
    matched = next((row for row in active if row['key'] == objective_key), None)
    if matched is None:
        words = set(re.findall(r'\w{5,}', str(question).casefold()))
        matched = next((row for row in active if len(words & set(
            re.findall(r'\w{5,}', row['title'].casefold()))) >= 2), None)
    return 0 if matched and matched['role'] == 'primary' else 1 if matched else 2


def _record_for(task_id, result_id):
    path = flag_verify.CAPABILITY_LOG / f'task_{task_id}.jsonl'
    try:
        lines = path.read_text(encoding='utf-8', errors='replace').splitlines()
    except OSError:
        return None
    for line in lines:
        try:
            item = json.loads(line)
        except ValueError:
            continue
        if item.get('task_id') == task_id and item.get('id') == result_id:
            return item
    return None


def process_report(db, task_id, report, registry):
    """Accept objective claims only with captured network evidence."""
    state = objective_status(db, task_id)
    if not state['primary']:
        return state
    rows = {item['key']: item for item in state['objectives']}
    values = {item['value']: item for item in registry['confirmed'] + registry['candidates']}
    patterns = flag_verify.flag_patterns(db, task_id)
    for claim in report.get('flags') or []:
        if not isinstance(claim, dict) or claim.get('objective_key') not in rows:
            continue
        raw = str(claim.get('value') or '')
        value = (flag_verify.canonical_flag_value(raw, patterns) or
                 flag_verify.canonical_flag_value('flag: ' + raw, patterns))
        item = values.get(value)
        if not item:
            continue
        key = claim['objective_key']
        result_id = str(claim.get('goal_evidence') or '')
        record = _record_for(task_id, result_id) if result_id else None
        payload = (record or {}).get('result') or {}
        output = '\n'.join(str(payload.get(field) or '') for field in
                           ('stdout', 'stderr', 'response', 'output'))
        valid = bool(record and record.get('provenance') == 'network' and
                     payload.get('status') in ('completed', 'ok') and value in output)
        stored = db.execute('SELECT sources_json FROM pm_verified_flags WHERE task_id=? AND value=?',
                            (task_id, value)).fetchone()
        if not stored:
            continue
        try:
            sources = json.loads(stored[0])
        except (ValueError, TypeError):
            sources = {}
        if not isinstance(sources, dict):
            sources = {}
        if not valid:
            sources['goal_claim_unverified'] = 'заявлено как цель, но result_id не доказывает её'
            item['goal_claim_unverified'] = sources['goal_claim_unverified']
            status = 'confirmed' if item.get('operator_confirmed') else 'candidate'
            db.execute('UPDATE pm_verified_flags SET status=?,sources_json=? WHERE task_id=? AND value=?',
                       (status, json.dumps(sources, ensure_ascii=False), task_id, value))
            if status == 'candidate' and item in registry['confirmed']:
                registry['confirmed'].remove(item)
                registry['candidates'].append(item)
                item['status'] = 'candidate'
            continue
        row = rows[key]
        confirmed = item.get('independent_sources', 0) >= 2
        flag_status = 'confirmed' if confirmed or item.get('operator_confirmed') else 'candidate'
        sources.pop('goal_claim_unverified', None)
        item.pop('goal_claim_unverified', None)
        db.execute('UPDATE pm_verified_flags SET status=?,objective_key=?,weight=?,sources_json=? '
                   'WHERE task_id=? AND value=?',
                   (flag_status, key, row['weight'],
                    json.dumps(sources, ensure_ascii=False), task_id, value))
        item['objective_key'], item['weight'] = key, row['weight']
        if confirmed:
            if item in registry['candidates']:
                registry['candidates'].remove(item)
                registry['confirmed'].append(item)
                item['status'] = 'confirmed'
            refs = row['evidence_refs']
            if result_id not in refs:
                refs.append(result_id)
            db.execute("UPDATE pm_objectives SET status='confirmed',evidence_ref=?,"
                       'evidence_refs_json=?,updated_at=? WHERE task_id=? AND key=?',
                       (result_id, json.dumps(refs), flag_verify.now(), task_id, key))
            row['evidence_refs'] = refs
        elif row['status'] == 'open':
            if item in registry['confirmed'] and flag_status == 'candidate':
                registry['confirmed'].remove(item)
                registry['candidates'].append(item)
                item['status'] = 'candidate'
            db.execute("UPDATE pm_objectives SET status='attempted',updated_at=? "
                       'WHERE task_id=? AND key=?', (flag_verify.now(), task_id, key))
    db.commit()
    return objective_status(db, task_id)
