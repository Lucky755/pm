"""Task operational state, separate from authorization and historical evidence.

Only an explicit operator assertion can mark a machine deactivated/confirmed
unavailable. TCP refusal/silence and absent ICMP never establish that fact.
"""
from datetime import datetime,timezone
from functools import wraps
import inspect
import json
import sqlite3
from pathlib import Path
from orchestrator import diagnostics

STATES=('active','temporary_error','services_unavailable','confirmed_unavailable','deactivated')
LOCAL_TOOLS=frozenset(('pm_capability_read','pm_evidence_index','pm_task_memory','pm_material_read',
    'pm_http_read','pm_browser_read','pm_observations','pm_worknote','pm_tool_status','pm_tool_read','pm_port_status',
    'pm_material_process','pm_material_import','pm_tool_request','pm_budget_status','pm_checks_status'))

def initialize(db):
    db.execute('''CREATE TABLE IF NOT EXISTS pm_target_availability (
        task_id INTEGER PRIMARY KEY,state TEXT NOT NULL,reason TEXT NOT NULL,source TEXT NOT NULL,
        updated_at TEXT NOT NULL,analysis_sha256 TEXT NOT NULL DEFAULT '')''')
    db.execute('''CREATE TABLE IF NOT EXISTS pm_target_availability_events (
        id INTEGER PRIMARY KEY,task_id INTEGER NOT NULL,state TEXT NOT NULL,reason TEXT NOT NULL,
        source TEXT NOT NULL,created_at TEXT NOT NULL)''')

def saved(db,task_id):
    if not db.execute("SELECT 1 FROM sqlite_master WHERE name='pm_target_availability' AND type='table'").fetchone():
        return {'state':'active','network_allowed':True,'reason':'No offline assertion','source':'default','analysis_sha256':''}
    row=db.execute('SELECT state,reason,source,updated_at,analysis_sha256 FROM pm_target_availability WHERE task_id=?',(task_id,)).fetchone()
    if not row:return {'state':'active','network_allowed':True,'reason':'No offline assertion','source':'default','analysis_sha256':''}
    return {**dict(zip(('state','reason','source','updated_at','analysis_sha256'),row)),
        'network_allowed':row[0]=='active','required_action':'Restore the target/route, then explicitly set target-state active; saved evidence remains usable.'}

def set_state(db,task_id,state,reason,*,source):
    if state not in STATES or not isinstance(reason,str) or not reason.strip():raise ValueError('Availability needs a state and reason')
    if state in ('confirmed_unavailable','deactivated','active') and source!='operator':
        raise ValueError('Only the operator can assert shutdown/restoration')
    old=saved(db,task_id)
    if old['state'] in ('confirmed_unavailable','deactivated') and source!='operator':return old
    with db:
        initialize(db);stamp=datetime.now(timezone.utc).isoformat()
        db.execute('INSERT INTO pm_target_availability(task_id,state,reason,source,updated_at) VALUES(?,?,?,?,?) '
            "ON CONFLICT(task_id) DO UPDATE SET state=excluded.state,reason=excluded.reason,source=excluded.source,updated_at=excluded.updated_at,analysis_sha256=''",
            (task_id,state,reason[:1000],source,stamp))
        db.execute('INSERT INTO pm_target_availability_events(task_id,state,reason,source,created_at) VALUES(?,?,?,?,?)',
            (task_id,state,reason[:1000],source,stamp))
    diagnostics.emit('target.availability',task_id=task_id,previous_state=old['state'],current_state=state,reason=reason)
    return saved(db,task_id)

def require_network(db,task_id):
    value=saved(db,task_id)
    if not value['network_allowed']:raise ValueError('target_offline: '+value['state']+'; '+value['reason'])

def guard(database):
    """Guard active MCP paths; local saved reads do not require a live target."""
    def decorate(fn):
        signature=inspect.signature(fn)
        @wraps(fn)
        def wrapped(*args,**kwargs):
            values=signature.bind(*args,**kwargs);values.apply_defaults();values=values.arguments
            task=values.get('task_id');action=values.get('action')
            local=(fn.__name__ in LOCAL_TOOLS or fn.__name__ in ('pm_session','pm_callback','pm_transfer') and action in ('read','close')
                   or fn.__name__=='pm_browser' and action in ('status','release','close')
                   or fn.__name__=='pm_pivot' and action=='close')
            if task and not local and Path(database()).is_file():
                with sqlite3.connect(f'file:{database()}?mode=ro',uri=True) as db:state=saved(db,task)
                if not state['network_allowed']:
                    return json.dumps({'status':'blocked','execution_started':False,'reason_category':'target_offline',
                        'reason':state['reason'],'availability':state,'required_action':state['required_action']})
            reply=fn(*args,**kwargs)
            # Transport errors do not establish shutdown. Do not treat HTTP 4xx,
            # rejected credentials or a nonzero command as a network outage.
            try:payload=json.loads(reply)
            except (ValueError,TypeError):return reply
            if task and fn.__name__ in ('pm_http_request','pm_http_capture','pm_http_ssrf') and (
                payload.get('reason_category')=='outcome_unknown' or payload.get('error_type') in
                ('TimeoutError','ConnectionError','ConnectionRefusedError','HTTPExecutionError')):
                with sqlite3.connect(database()) as db:
                    set_state(db,task,'temporary_error','HTTP transport failed; use saved data, no automatic retries',source='transport')
            return reply
        return wrapped
    return decorate
