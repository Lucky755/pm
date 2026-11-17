"""Saved launch mode and reconnaissance checkpoint in the existing task DB."""
from datetime import datetime, timezone
import json

from orchestrator import diagnostics


def saved(db, task_id):
    if not db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='pm_task_runtime'").fetchone():
        return None
    row = db.execute('SELECT mode,recon_status,pause_reason FROM pm_task_runtime WHERE task_id=?',(task_id,)).fetchone()
    if not row:return None
    limit=2
    if any(r[1]=='max_specialists' for r in db.execute('PRAGMA table_info(pm_task_runtime)')):
        limit=db.execute('SELECT max_specialists FROM pm_task_runtime WHERE task_id=?',(task_id,)).fetchone()[0]
    return {**dict(zip(('mode','recon_status','pause_reason'),row)),'max_specialists':limit}


def save_mode(db, task_id, mode):
    if mode not in ('legacy','coordinated'):
        raise ValueError('Invalid task mode')
    with db:
        db.execute('''CREATE TABLE IF NOT EXISTS pm_task_runtime (
            task_id INTEGER PRIMARY KEY, mode TEXT NOT NULL CHECK(mode IN ('legacy','coordinated')),
            recon_status TEXT NOT NULL DEFAULT 'pending', pause_reason TEXT NOT NULL DEFAULT '',
            updated_at TEXT NOT NULL)''')
        db.execute('INSERT INTO pm_task_runtime(task_id,mode,updated_at) VALUES(?,?,?) '
                   'ON CONFLICT(task_id) DO UPDATE SET mode=excluded.mode,updated_at=excluded.updated_at',
                   (task_id,mode,datetime.now(timezone.utc).isoformat()))
    diagnostics.emit('state.change',task_id=task_id,table='pm_task_runtime',identifiers={'task_id':task_id},current_state=mode)


def specialist_limit(db,task_id,value=None):
    """Read without migration; an explicit execution setting is saved additively."""
    if value is None:return (saved(db,task_id) or {}).get('max_specialists',2)
    if type(value) is not int or not 1<=value<=10:raise ValueError('Specialist concurrency must be 1..10')
    with db:
        if not saved(db,task_id):save_mode(db,task_id,'coordinated')
        if not any(r[1]=='max_specialists' for r in db.execute('PRAGMA table_info(pm_task_runtime)')):
            db.execute('ALTER TABLE pm_task_runtime ADD COLUMN max_specialists INTEGER NOT NULL DEFAULT 2')
        db.execute('UPDATE pm_task_runtime SET max_specialists=? WHERE task_id=?',(value,task_id))
    return value


def reconnaissance(db, task_id, status, reason=''):
    with db:
        db.execute('UPDATE pm_task_runtime SET recon_status=?,pause_reason=?,updated_at=? WHERE task_id=?',
                   (status,reason,datetime.now(timezone.utc).isoformat(),task_id))
    diagnostics.emit('state.change',task_id=task_id,table='pm_task_runtime',identifiers={'task_id':task_id},
                     current_state=status,reason=reason)


def pause(db, task_id):
    """Read only: do not refresh evidence, instantiate SDKs or change checkpoints."""
    from orchestrator import coordinated_attack as coordinator, operator_questions, target_availability
    from orchestrator import research_budgets,check_series
    work={"research_budgets":research_budgets.listing(db,task_id),"directions":check_series.state(db,task_id),
        'specialist_limit':specialist_limit(db,task_id)}
    availability=target_availability.saved(db,task_id)
    exists=db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='pm_coordinator_runs'").fetchone()
    if exists:
        row=db.execute('SELECT id,status,stop_reason FROM pm_coordinator_runs WHERE task_id=?',(task_id,)).fetchone()
        if row:
            rows=coordinator.steps(db,task_id)
            running=next((r for r in rows if r['status']=='running'),None)
            questions=operator_questions.listing(db,task_id)
            pending=[q for q in questions if q['status']=='pending']
            answered_steps={q['step_id'] for q in questions if q['status']=='answered'}
            waiting=next((r for r in rows if r['status']=='waiting_operator'
                and r['id'] not in answered_steps and not (
                    json.loads(r['decision_json']).get('role')=='access' and r['error'] in ('','role_approval_required','approval_state_changed_use_continue_to_replan','access_requires_operator_approval')
                    and not r['outcome_uncertain'] and not r.get('report_path') and not r.get('report_quality') and not r.get('approved_at')
                    and not r.get('execution_outcome',{}).get('results'))),None)
            damaged=coordinator.report_integrity.unresolved(rows)
            saved_pause=(row[1]=='waiting_operator' and row[2] not in operator_questions.RETIRED_PAUSES
                         and not (row[2]=='operator_questions_pending' and not pending))
            if running or waiting or damaged or pending or saved_pause:
                return {**work,'target_availability':availability,'task_id':task_id,'coordinator_run_id':row[0],'status':'waiting_operator','succeeded':False,
                        'stop_reason':('interrupted_running_step' if running else
                                       'role_report_damaged_requires_review' if damaged else row[2]),
                        'checkpoints':[], 'checkpoint_classifier_blocking':False,
                        'operator_questions':questions,
                        'steps':[coordinator.step_view(r) for r in rows]}
    queued=operator_questions.listing(db,task_id,pending=True)
    if queued:
        return {**work,'target_availability':availability,'task_id':task_id,'coordinator_run_id':None,'status':'waiting_operator','succeeded':False,
                'stop_reason':'operator_questions_pending','steps':[],
                'operator_questions':operator_questions.listing(db,task_id),'checkpoints':[]}
    if db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='pm_tcp_full_scans'").fetchone():
        if db.execute("SELECT 1 FROM pm_tcp_full_scans WHERE task_id=? AND status='running' "
                      'AND target=(SELECT target FROM tasks WHERE id=?)',(task_id,task_id)).fetchone():
            return {**work,'target_availability':availability,'task_id':task_id,'coordinator_run_id':None,'status':'waiting_operator','succeeded':False,'steps':[],
                    'stop_reason':'interrupted_full_tcp_scan'}
    meta=saved(db,task_id)
    if meta and meta['recon_status'] in ('running','waiting_operator') and meta['pause_reason'] not in operator_questions.RETIRED_PAUSES:
        return {**work,'target_availability':availability,'task_id':task_id,'coordinator_run_id':None,'status':'waiting_operator','succeeded':False,'steps':[],
                'stop_reason':meta['pause_reason'] or 'reconnaissance_interrupted_requires_review'}
    return None
