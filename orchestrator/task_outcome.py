"""Goal verdict from saved flag decisions. Safe to call on SQLite mode=ro."""
from orchestrator import flag_review, task_memory


def legacy_evidence_count(db, task_id):
    if not task_memory.exists(db, 'pm_verified_flags'):
        return None
    columns = {row[1] for row in db.execute('PRAGMA table_info(pm_verified_flags)')}
    if not {'task_id', 'value', 'status', 'evidence_count'} <= columns:
        return None
    rows = db.execute(
        'SELECT value,status,evidence_count FROM pm_verified_flags WHERE task_id=?', (task_id,))
    return len({value for value, status, count in rows
                if value and status == 'confirmed' and int(count or 0) >= 2})


def saved(db, task_id):
    manual = flag_review.outcome(db, task_id)
    if manual is not None:
        reached = bool(manual['reason'])
        return {**manual, 'source': 'manual', 'reached': reached,
                'label': ('Цель достигнута' if reached else 'Цель ещё не достигнута')
                + f" · {manual['accepted']} из {manual['expected']}"}
    count = legacy_evidence_count(db, task_id)
    reached = count is not None and count >= 2
    return {
        'source': 'legacy', 'reached': True if reached else None,
        'accepted': None, 'expected': None, 'legacy_evidence_count': count,
        'label': 'Цель достигнута · подтверждено по прежнему правилу' if reached else 'Итог цели неизвестен',
    }
