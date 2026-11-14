"""Task objectives and evidence-backed attribution of captured flags."""

import json
import re

from operator_errors import OperatorError
from orchestrator import flag_verify, diagnostics

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
    from orchestrator import flag_review
    review=flag_review.progress(db,task_id)
    if review is not None:
        waiting={p['objective_key'] for p in review['proposals'] if p['status']=='pending'}
        rows=[{**g,'recorded_status':g['status'],'status':('awaiting_operator' if g['key'] in waiting else 'open') if
            g['status']=='confirmed' and g['key'] not in review['reviewed_goal_keys'] else g['status']} for g in rows]
        primary=next((g for g in rows if g['key']=='goal'),None)
    return {'manual_flag_review':review, 'primary': primary,
            'confirmed': [row for row in rows if row['status'] == 'confirmed'],
            'open': [row for row in rows if row['status'] != 'confirmed'],
            'exclusive': bool(primary and primary['exclusive']),
            'mode': primary['mode'] if primary else None,
            'expected_flags': primary['expected_flags'] if primary else None,
            'objectives': rows}


@diagnostics.committed_changes
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


@diagnostics.committed_changes
def process_report(db, task_id, report, registry):
    """Link proposals to goals. Only an operator decision completes a new goal."""
    from orchestrator import flag_review
    flag_review.activate(db,task_id)
    with db:
        flag_review.ingest_report(db,task_id,report)
    return objective_status(db, task_id)
