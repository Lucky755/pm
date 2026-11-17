"""Durable work counters; operator answers grant exactly five, never scope.

Tool dispatch, internal checks and a direction's result are separate units.
Only PM-created typed budget requests carry a grant; model prose grants none.
"""
from contextvars import ContextVar
from functools import wraps
import inspect
import json
import os
import sqlite3
import uuid
from pathlib import Path
from orchestrator import diagnostics,task_memory

BASE={'coordinator':15,'specialist':25,'poc':15,'recon':8}
_depth=ContextVar('pm_budget_tool_depth',default=0)
FREE=frozenset(('pm_capability_read','pm_evidence_index','pm_task_memory','pm_material_read','pm_http_read',
    'pm_browser_read','pm_tool_status','pm_tool_read','pm_port_status','pm_observations','pm_budget_status','pm_checks_status'))
ACTIVE_TOOLS=frozenset(('pm_http_request','pm_http_capture','pm_http_ssrf','pm_poc_run','pm_net_exec',
    'run_network_probe','pm_privileged_scan','pm_port_survey','pm_browser','pm_session','pm_pivot','pm_callback','pm_transfer'))


class Exhausted(ValueError):pass


def initialize(db):
    db.execute('''CREATE TABLE IF NOT EXISTS pm_research_budgets (
        task_id INTEGER NOT NULL,category TEXT NOT NULL,actor TEXT NOT NULL,base_limit INTEGER NOT NULL,
        granted INTEGER NOT NULL DEFAULT 0,used INTEGER NOT NULL DEFAULT 0,history_known INTEGER NOT NULL DEFAULT 1,
        PRIMARY KEY(task_id,category,actor))''')
    db.execute('''CREATE TABLE IF NOT EXISTS pm_budget_events (
        id TEXT PRIMARY KEY,task_id INTEGER NOT NULL,category TEXT NOT NULL,actor TEXT NOT NULL,
        unit TEXT NOT NULL,amount INTEGER NOT NULL,details_json TEXT NOT NULL,created_at TEXT NOT NULL)''')
    db.execute('''CREATE TABLE IF NOT EXISTS pm_budget_requests (
        question_id INTEGER PRIMARY KEY,task_id INTEGER NOT NULL,category TEXT NOT NULL,actor TEXT NOT NULL,
        amount INTEGER NOT NULL,at_limit INTEGER NOT NULL,decision TEXT)''')


def get(db,task_id,category,actor='task'):
    if not task_memory.exists(db,'pm_research_budgets'):return None
    row=db.execute('SELECT base_limit,granted,used,history_known FROM pm_research_budgets WHERE task_id=? AND category=? AND actor=?',
        (task_id,category,actor)).fetchone()
    if not row:return None
    return {'category':category,'actor':actor,'base':row[0],'granted':row[1],'used':row[2],
        'limit':row[0]+row[1],'remaining':max(0,row[0]+row[1]-row[2]),'history_known':bool(row[3])}


def ensure(db,task_id,category,actor='task',base=None,capability_log=None):
    if category not in BASE or not isinstance(actor,str) or not actor:raise ValueError('Invalid budget account')
    base=(4 if category=='recon' and actor=='rounds' else BASE[category]) if base is None else base
    if type(base) is not int or not 1<=base<=BASE[category]:raise ValueError('Initial budget exceeds policy; request an extension')
    if not db.execute('SELECT 1 FROM tasks WHERE id=?',(task_id,)).fetchone():raise ValueError('Unknown task')
    with task_memory.atomic(db):
        initialize(db)
        if get(db,task_id,category,actor):return get(db,task_id,category,actor)
        used=0;known=True
        if category=='coordinator' and task_memory.exists(db,'pm_coordinator_steps'):
            used=db.execute('SELECT COUNT(*) FROM pm_coordinator_steps WHERE task_id=?',(task_id,)).fetchone()[0]
        if category in ('specialist','poc') and task_memory.exists(db,'pm_agent_action_reports'):
            for raw,steps in db.execute('SELECT report_json,steps_used FROM pm_agent_action_reports WHERE task_id=? AND role=?',(task_id,actor)):
                data=json.loads(raw);value=data.get('poc_runs' if category=='poc' else 'tool_calls')
                if value is None:known=False;value=steps if category=='specialist' else 0
                used+=max(0,int(value or 0))
        if category=='poc' and capability_log is not None:
            target=db.execute('SELECT target FROM tasks WHERE id=?',(task_id,)).fetchone()[0]
            captures=[r for r in task_memory.capability_records(task_id,capability_log,target)
                if r.get('tool')=='poc_run' and r.get('actor_role') in (None,actor) and r['result'].get('execution_started') is not False]
            used=max(used,len(captures))
            if any(not r.get('actor_role') for r in captures):known=False
        if category=='recon':
            if actor=='rounds' and task_memory.exists(db,'master_auto_rounds') and task_memory.exists(db,'master_auto_runs'):
                used=db.execute('SELECT COUNT(*) FROM master_auto_rounds r JOIN master_auto_runs a ON a.id=r.run_id WHERE a.task_id=?',(task_id,)).fetchone()[0]
            elif actor=='task':
                if task_memory.exists(db,'network_job_runs') and task_memory.exists(db,'network_phase_plans'):
                    used+=db.execute('SELECT COUNT(*) FROM network_job_runs r JOIN network_phase_plans p ON p.id=r.plan_id WHERE p.task_id=?',(task_id,)).fetchone()[0]
                if task_memory.exists(db,'pm_tcp_full_scan_attempts'):
                    used+=db.execute("SELECT COUNT(*) FROM pm_tcp_full_scan_attempts WHERE task_id=? AND status IN ('running','completed','failed','empty')",(task_id,)).fetchone()[0]
        db.execute('INSERT OR IGNORE INTO pm_research_budgets(task_id,category,actor,base_limit,used,history_known) VALUES(?,?,?,?,?,?)',
            (task_id,category,actor,base,used,int(known)))
    return get(db,task_id,category,actor)


def consume(db,task_id,category,actor='task',*,unit='tool_dispatch',details=None,event_id=None):
    with task_memory.atomic(db):
        ensure(db,task_id,category,actor);event_id=event_id or uuid.uuid4().hex
        if db.execute('SELECT 1 FROM pm_budget_events WHERE id=?',(event_id,)).fetchone():return get(db,task_id,category,actor)
        changed=db.execute('UPDATE pm_research_budgets SET used=used+1 WHERE task_id=? AND category=? AND actor=? AND used<base_limit+granted',
            (task_id,category,actor)).rowcount
        if not changed:raise Exhausted(category+':'+actor)
        db.execute('INSERT INTO pm_budget_events VALUES(?,?,?,?,?,?,?,?)',
            (event_id,task_id,category,actor,unit,1,task_memory.encoded(details or {}),task_memory.now()))
    diagnostics.emit('budget.used',task_id=task_id,reason=unit,parameters={'category':category,'actor':actor})
    return get(db,task_id,category,actor)


def for_question(db,task_id,question_id):
    if not task_memory.exists(db,'pm_budget_requests'):return None
    row=db.execute('SELECT category,actor,amount,at_limit,decision FROM pm_budget_requests WHERE task_id=? AND question_id=?',(task_id,question_id)).fetchone()
    return {'category':row[0],'actor':row[1],'amount':row[2],'previous_limit':row[3],'decision':row[4]} if row else None


def request(db,task_id,category,actor='task',*,reason='Work budget exhausted',step_id=None):
    from orchestrator import operator_questions as questions
    account=ensure(db,task_id,category,actor)
    if category=='poc':raise Exhausted('PoC ceiling is 15; return results to coordinator')
    if account['remaining']:raise ValueError('Budget is not exhausted; an extension is not needed')
    previous=db.execute('SELECT question_id FROM pm_budget_requests WHERE task_id=? AND category=? AND actor=? AND at_limit=?',
        (task_id,category,actor,account['limit'])).fetchone()
    if previous:return next(q for q in questions.listing(db,task_id) if q['id']==previous[0])
    target=db.execute('SELECT target FROM tasks WHERE id=?',(task_id,)).fetchone()[0]
    decision={'operator_question':{'kind':'budget'},'branch_id':'task',
        'question':f"Добавить ровно 5 единиц к {category}/{actor}? Использовано {account['used']} из {account['limit']}.",
        'reason':reason,'references':['intent'],'boundaries':{'task_id':task_id,'target':target,'intent_ref':'intent','resource_refs':['scope:'+target]}}
    with task_memory.atomic(db):
        question=questions.request(db,task_id,target,decision,step_id)
        db.execute('INSERT INTO pm_budget_requests(question_id,task_id,category,actor,amount,at_limit) VALUES(?,?,?,?,5,?)',
            (question['id'],task_id,category,actor,account['limit']))
    return next(q for q in questions.listing(db,task_id) if q['id']==question['id'])


def answered(db,item,decision):
    grant=for_question(db,item['task_id'],item['id'])
    if not grant:return False
    if decision=='information':raise ValueError('Budget extension needs approve or decline')
    if grant['decision'] is not None:raise ValueError('Budget question already applied')
    if decision=='approve':
        db.execute('UPDATE pm_research_budgets SET granted=granted+? WHERE task_id=? AND category=? AND actor=?',
            (grant['amount'],item['task_id'],grant['category'],grant['actor']))
    db.execute('UPDATE pm_budget_requests SET decision=? WHERE question_id=?',(decision,item['id']))
    diagnostics.emit('budget.extension',task_id=item['task_id'],reason=decision,identifiers={'question_id':item['id']},
        parameters={'category':grant['category'],'actor':grant['actor'],'amount':grant['amount']})
    return True


def listing(db,task_id):
    if not task_memory.exists(db,'pm_research_budgets'):return []
    return [get(db,task_id,c,a) for c,a in db.execute('SELECT category,actor FROM pm_research_budgets WHERE task_id=? ORDER BY category,actor',(task_id,))]


def reconnaissance(db,task_id,actor='task',*,unit='network_job'):
    ensure(db,task_id,'recon',actor)
    try:consume(db,task_id,'recon',actor,unit=unit);db.commit()
    except Exhausted:
        request(db,task_id,'recon',actor,reason='Saved reconnaissance queue needs additional bounded work');db.commit();raise


def tool_guard(database):
    def decorate(function):
        signature=inspect.signature(function)
        @wraps(function)
        def execute(*args,**kwargs):
            bound=signature.bind(*args,**kwargs);task=bound.arguments.get('task_id');actor=os.environ.get('PM_BUDGET_ROLE')
            if actor and os.environ.get('PM_TASK_ID') not in (None,'',str(task)):
                return json.dumps({'status':'blocked','execution_started':False,'reason_category':'scope_denied'})
            if not actor or not task or _depth.get() or function.__name__ in FREE:return function(*args,**kwargs)
            try:
                with sqlite3.connect(database(),timeout=10) as db:
                    from orchestrator import check_series
                    action=bound.arguments.get('action')
                    local_action=action in ('read','list','status','release','close')
                    step=int(os.environ.get('PM_COORDINATOR_STEP_ID') or 0)
                    if function.__name__ in ACTIVE_TOOLS and not local_action and any(
                            d['state']=='exhausted' and (d['plan_step'] or 0)==step for d in check_series.state(db,task)):
                        return json.dumps({'status':'replan_required','execution_started':False,'reason_category':'direction_exhausted',
                            'reason':'Five unproductive units: return the saved results to the coordinator before more target actions'})
                    ensure(db,task,'specialist',actor)
                    try:consume(db,task,'specialist',actor,details={'tool':function.__name__})
                    except Exhausted:
                        q=request(db,task,'specialist',actor);db.commit()
                        return json.dumps({'status':'waiting_operator','execution_started':False,'question_id':q['id'],
                            'reason_category':'budget_exhausted','reason':'Specialist dispatch budget exhausted; +5 requires operator'})
                    db.commit()
            except (ValueError,sqlite3.Error) as exc:
                return json.dumps({'status':'blocked','execution_started':False,'reason_category':'budget_state_error','error_type':type(exc).__name__})
            token=_depth.set(1)
            try:return function(*args,**kwargs)
            finally:_depth.reset(token)
        return execute
    return decorate
