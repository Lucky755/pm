"""Shared, local validation and versioned operator intent."""
from datetime import datetime, timezone
import re

from intent_limits import INTENT_MAX
from operator_errors import OperatorError
from orchestrator import task_memory

MAX_HOSTNAMES = 12


def validate_hostnames(raw):
    if raw is None or not raw.strip():
        return []
    names = [x.strip().lower().rstrip('.') for x in raw.split(',')]
    if not 1 <= len(names) <= MAX_HOSTNAMES or len(set(names)) != len(names):
        raise OperatorError('Укажите 1–12 уникальных доменных имён')
    for name in names:
        labels = name.split('.')
        if (len(name) > 253 or name in ('localhost', 'localhost.localdomain') or
            not all(1 <= len(label) <= 63 and
                    re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', label)
                    for label in labels) or name.replace('.', '').isdigit()):
            raise OperatorError('Недопустимое имя хоста: ' + repr(name))
    return names


def validate_intent(text):
    if not text:
        raise OperatorError('Нужно непустое описание задачи')
    if len(text.encode('utf-8')) > INTENT_MAX:
        raise OperatorError(f'Описание превышает явный предел хранения {INTENT_MAX} байт; большие материалы передайте отдельными файлами')


def compose_task_description(objective, constraints, hints=''):
    """Preserve operator constraints and distinguish leads from evidence."""
    objective = str(objective or '').strip()
    constraints = str(constraints or '').strip()
    hints = str(hints or '').strip()
    if not objective:
        raise OperatorError('Нужно описание задачи')
    text = objective
    if constraints:
        text += '\nОграничения: ' + constraints
    if hints:
        text += ('\nПодсказки оператора (зацепки для проверки, не доказанные '
                 'факты; действовать только в рамках текущего scope): ' + hints)
    validate_intent(text)
    return text


def initialize(db):
    db.execute('''CREATE TABLE IF NOT EXISTS pm_task_intents (
        task_id INTEGER PRIMARY KEY,
        intent TEXT NOT NULL,
        created_at TEXT NOT NULL
    )''')


def previous_task_intent(db, task_id):
    if not task_memory.exists(db, 'pm_task_intents'):
        return None
    row = db.execute('SELECT intent FROM pm_task_intents WHERE task_id=?', (task_id,)).fetchone()
    return row[0] if row else None


def restore_task_intent(db, task_id, text, source):
    text, source = str(text).strip(), str(source).strip()
    validate_intent(text)
    if not source or len(source) > 300:
        raise OperatorError('Нужен источник до 300 символов')
    with task_memory.atomic(db):
        if not db.execute('SELECT 1 FROM tasks WHERE id=?', (task_id,)).fetchone():
            raise OperatorError('Задача не найдена')
        previous = previous_task_intent(db, task_id)
        if previous == text:
            return False
        initialize(db)
        db.execute('CREATE TABLE IF NOT EXISTS pm_task_intent_history ('
                   'id INTEGER PRIMARY KEY,task_id INTEGER NOT NULL,previous_intent TEXT,'
                   'intent TEXT NOT NULL,source TEXT NOT NULL,created_at TEXT NOT NULL)')
        stamp = datetime.now(timezone.utc).isoformat()
        db.execute('INSERT INTO pm_task_intent_history '
                   '(task_id,previous_intent,intent,source,created_at) VALUES (?,?,?,?,?)',
                   (task_id, previous, text, source, stamp))
        if 'created_at' in {row[1] for row in db.execute('PRAGMA table_info(pm_task_intents)')}:
            db.execute('INSERT INTO pm_task_intents(task_id,intent,created_at) VALUES (?,?,?) '
                       'ON CONFLICT(task_id) DO UPDATE SET intent=excluded.intent,created_at=excluded.created_at',
                       (task_id, text, stamp))
        else:
            db.execute('INSERT INTO pm_task_intents(task_id,intent) VALUES (?,?) '
                       'ON CONFLICT(task_id) DO UPDATE SET intent=excluded.intent', (task_id, text))
    return True
