"""Durable operator inbox. Answers are input, never an execution permission."""
import hashlib
import json
from datetime import datetime, timezone
from orchestrator import diagnostics, task_memory

KINDS=frozenset(('pivoting','tool','budget','flag_confirmation'))
RETIRED_PAUSES=frozenset(('role_approval_required','approval_state_changed_use_continue_to_replan',
    'significant_finding','access_state_changed','confirmed_flag_found','objective_state_changed'))


def now():return datetime.now(timezone.utc).isoformat()


def initialize(db):
    db.execute('''CREATE TABLE IF NOT EXISTS pm_operator_questions (
        id INTEGER PRIMARY KEY,task_id INTEGER NOT NULL,target TEXT NOT NULL,
        kind TEXT NOT NULL,branch_id TEXT NOT NULL,question TEXT NOT NULL,reason TEXT NOT NULL,
        boundaries_json TEXT NOT NULL,references_json TEXT NOT NULL,fingerprint TEXT NOT NULL,
        step_id INTEGER,status TEXT NOT NULL CHECK(status IN ('pending','answered','cancelled')),
        answer_json TEXT,created_at TEXT NOT NULL,answered_at TEXT,
        UNIQUE(task_id,target,fingerprint))''')
    db.execute('''CREATE TABLE IF NOT EXISTS pm_operator_question_events (
        id INTEGER PRIMARY KEY,question_id INTEGER NOT NULL,task_id INTEGER NOT NULL,
        event TEXT NOT NULL,payload_json TEXT NOT NULL,created_at TEXT NOT NULL)''')
    db.execute('''CREATE TABLE IF NOT EXISTS pm_operator_policy_events (
        id INTEGER PRIMARY KEY,task_id INTEGER NOT NULL,object_ref TEXT NOT NULL,
        reason TEXT NOT NULL,original_json TEXT NOT NULL,created_at TEXT NOT NULL,
        UNIQUE(task_id,object_ref,reason))''')


def listing(db,task_id,*,pending=False):
    if not task_memory.exists(db,'pm_operator_questions'):return []
    cursor=db.execute('SELECT * FROM pm_operator_questions WHERE task_id=? '
        'AND target=(SELECT target FROM tasks WHERE id=?) '+("AND status='pending' " if pending else '')+
        'ORDER BY id',(task_id,task_id))
    result=[]
    for row in cursor:
        item=dict(zip([col[0] for col in cursor.description],row))
        for field in ('boundaries','references','answer'):
            raw=item.pop(field+'_json');item[field]=json.loads(raw) if raw else None
        result.append(item)
    return result


def branch(decision):return decision.get('branch_id','task')


def available(state):
    pending=[q for q in state.get('operator_questions',[]) if q['status']=='pending']
    if any(q['branch_id']=='task' for q in pending):return []
    blocked={q['branch_id'] for q in pending}
    return [r for r in state['known_resources'] if r.startswith('service:') and r not in blocked]


def blocked(decision,state):
    pending=[q for q in state.get('operator_questions',[]) if q['status']=='pending']
    return bool(pending and (branch(decision)=='task' or any(
        q['branch_id']=='task' or q['branch_id']==branch(decision) for q in pending)))


def request(db,task_id,target,decision,step_id):
    kind=decision['operator_question']['kind']
    if kind not in KINDS:raise ValueError('invalid_operator_question')
    content={'kind':kind,'branch_id':branch(decision),'question':decision['question'],
             'boundaries':decision['boundaries'],'references':decision['references']}
    fingerprint=hashlib.sha256(task_memory.encoded(content).encode()).hexdigest()
    with task_memory.atomic(db):
        initialize(db)
        cursor=db.execute('INSERT OR IGNORE INTO pm_operator_questions '
            '(task_id,target,kind,branch_id,question,reason,boundaries_json,references_json,fingerprint,step_id,status,created_at) '
            "VALUES(?,?,?,?,?,?,?,?,?,?,'pending',?)",(task_id,target,kind,branch(decision),decision['question'],decision['reason'],
                task_memory.encoded(decision['boundaries']),task_memory.encoded(decision['references']),fingerprint,step_id,now()))
        qid=db.execute('SELECT id FROM pm_operator_questions WHERE task_id=? AND target=? AND fingerprint=?',
                       (task_id,target,fingerprint)).fetchone()[0]
        if cursor.rowcount:
            db.execute('INSERT INTO pm_operator_question_events(question_id,task_id,event,payload_json,created_at) '
                "VALUES(?,?,'requested',?,?)",(qid,task_id,task_memory.encoded(content),now()))
    diagnostics.emit('operator.question',task_id=task_id,reason=kind,identifiers={'question_id':qid,'step_id':step_id},
                     parameters={'branch_id':branch(decision)})
    return next(q for q in listing(db,task_id) if q['id']==qid)


def flag_subject(db,task_id,references):
    if not task_memory.exists(db,'pm_verified_flags'):return None
    found=[value for value, in db.execute('SELECT value FROM pm_verified_flags WHERE task_id=?',(task_id,))
           if 'flag:'+task_memory.digest(value) in references]
    return found[0] if len(found)==1 else None


def answer(db,task_id,question_id,decision,text='',*,capability_log=None):
    if decision not in ('approve','decline','information'):raise ValueError('Invalid operator answer')
    if not isinstance(text,str) or len(text)>2000 or diagnostics.clean(text,limit=None)!=text:
        raise ValueError('Invalid operator answer text')
    with task_memory.atomic(db):
        initialize(db)
        item=next((q for q in listing(db,task_id) if q['id']==question_id),None)
        if not item or item['status']!='pending':raise ValueError('No matching pending question')
        payload={'decision':decision,'text':text,'permission_effect':'none; saved scope and budgets remain authoritative'}
        if item['kind']=='flag_confirmation' and decision=='approve':
            value=flag_subject(db,task_id,item['references'])
            if value is None:raise ValueError('Flag question needs one existing flag reference')
            from orchestrator import flag_verify
            flag_verify.operator_confirm(task_id,value,text,db=db)
            payload['flag_status_effect']='operator_confirmed; not new network evidence'
        db.execute("UPDATE pm_operator_questions SET status='answered',answer_json=?,answered_at=? WHERE id=? AND status='pending'",
                   (task_memory.encoded(payload),now(),question_id))
        db.execute('INSERT INTO pm_operator_question_events(question_id,task_id,event,payload_json,created_at) '
            "VALUES(?,?,'answered',?,?)",(question_id,task_id,task_memory.encoded(payload),now()))
        if capability_log is not None:task_memory.sync(db,task_id,capability_log,reason='operator_answer')
    diagnostics.emit('operator.answer',task_id=task_id,reason=decision,identifiers={'question_id':question_id})
    return next(q for q in listing(db,task_id) if q['id']==question_id)


def retire_legacy(db,task_id,steps):
    """Retire only obsolete gates; a possible dispatch remains an unknown outcome."""
    with task_memory.atomic(db):
        initialize(db)
        for row in steps:
            decision=json.loads(row['decision_json'])
            if row['status']!='waiting_operator' or decision.get('action')!='run_role':continue
            if decision.get('role')!='access':continue
            uncertain=bool(row['outcome_uncertain'] or row.get('report_path') or row.get('report_quality') or row.get('approved_at')
                or row.get('execution_outcome',{}).get('results')
                or row['error'] not in ('','role_approval_required','approval_state_changed_use_continue_to_replan','access_requires_operator_approval'))
            db.execute('INSERT OR IGNORE INTO pm_operator_policy_events(task_id,object_ref,reason,original_json,created_at) '
                'VALUES(?,?,?,?,?)',(task_id,'step:'+str(row['id']),'access_gate_retired',task_memory.encoded(row),now()))
            db.execute('UPDATE pm_coordinator_steps SET status=?,error=?,outcome_uncertain=?,updated_at=? WHERE id=?',
                ('running' if uncertain else 'failed','legacy_access_outcome_unknown' if uncertain else
                 'legacy_access_gate_retired_not_started',int(uncertain),now(),row['id']))
        row=db.execute('SELECT id,status,stop_reason,pause_step_id FROM pm_coordinator_runs WHERE task_id=?',(task_id,)).fetchone()
        if row and row[2] in RETIRED_PAUSES:
            db.execute('INSERT OR IGNORE INTO pm_operator_policy_events(task_id,object_ref,reason,original_json,created_at) '
                'VALUES(?,?,?,?,?)',(task_id,'run:'+str(row[0]),'checkpoint_gate_retired',task_memory.encoded(row),now()))
            db.execute("UPDATE pm_coordinator_runs SET status='planned',stop_reason='legacy_gate_retired',pause_step_id=NULL WHERE id=?",(row[0],))
