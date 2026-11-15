"""Task-owned connections. Saved metadata is never a liveness test.

The standalone broker is the authority for terminals and their exclusive owner.
SQLite preserves purpose, provenance, dependencies and lifecycle across roles.
"""
from contextlib import contextmanager
import json
import os
import subprocess
import uuid
from orchestrator import diagnostics, task_memory

BROKER='/usr/local/sbin/pm-netguard'
MAX_SESSIONS=10


def initialize(db):
    db.execute('''CREATE TABLE IF NOT EXISTS pm_task_sessions (
        task_id INTEGER NOT NULL,session_id TEXT NOT NULL,resource TEXT NOT NULL,
        username TEXT NOT NULL,purpose TEXT NOT NULL,retain INTEGER NOT NULL DEFAULT 1,
        state TEXT NOT NULL,owner TEXT NOT NULL DEFAULT '',observed_run_id TEXT,
        details_json TEXT NOT NULL,updated_at TEXT NOT NULL,PRIMARY KEY(task_id,session_id))''')
    db.execute('''CREATE TABLE IF NOT EXISTS pm_session_events (
        id INTEGER PRIMARY KEY,task_id INTEGER NOT NULL,session_id TEXT NOT NULL,
        event TEXT NOT NULL,payload_json TEXT NOT NULL,created_at TEXT NOT NULL)''')
    db.execute('''CREATE TABLE IF NOT EXISTS pm_session_dependencies (
        task_id INTEGER NOT NULL,session_id TEXT NOT NULL,dependent_ref TEXT NOT NULL,
        state TEXT NOT NULL,PRIMARY KEY(task_id,session_id,dependent_ref))''')


def now():
    from orchestrator.operator_questions import now as stamp
    return stamp()


def owner():return os.environ.get('PM_SESSION_OWNER') or 'operator:'+str(os.getpid())


def listing(db,task_id):
    if not task_memory.exists(db,'pm_task_sessions'):return []
    cursor=db.execute('SELECT * FROM pm_task_sessions WHERE task_id=? ORDER BY session_id',(task_id,))
    values=[]
    for row in cursor:
        item=dict(zip([c[0] for c in cursor.description],row))
        item['details']=json.loads(item.pop('details_json'))
        item['dependencies']=[{'reference':r[0],'state':r[1]} for r in db.execute(
            'SELECT dependent_ref,state FROM pm_session_dependencies WHERE task_id=? AND session_id=? ORDER BY dependent_ref',
            (task_id,item['session_id']))]
        item['liveness']='unknown'
        if diagnostics.context().get('run_id') and item['observed_run_id']==diagnostics.context()['run_id']:
            item['liveness']=item['state']
        values.append(item)
    return values


def save(db,task_id,sid,payload,*,resource='',username='',purpose='',retain=None):
    with task_memory.atomic(db):
        initialize(db)
        old=next((r for r in listing(db,task_id) if r['session_id']==sid),{})
        observed=payload.get('running',payload.get('status') in ('opened','ok','running'))
        if payload.get('status') in ('unknown','timeout'):observed=None
        if (payload.get('health') or {}).get('ssh',{}).get('status')=='unverified':observed=None
        state=('closed' if payload.get('status')=='closed' else 'unknown' if observed is None else
               'open' if observed else 'disconnected')
        if payload.get('status')=='released' and observed is not False:state=old.get('state','unknown')
        details={**old.get('details',{}),**payload}
        output=payload.get('output')
        if isinstance(output,str) and output:
            details['stream_state_sha256']=task_memory.digest(output)
            details['last_output_characters']=len(output)
        stream_hash=payload.get('stream_state_sha256') or (payload.get('health') or {}).get('stream_state_sha256')
        if stream_hash:details['stream_state_sha256']=stream_hash
        # Original I/O is already in capability/session logs. Current memory
        # and the lifecycle journal keep references, not another stdout copy.
        for field in ('output','stdout','stderr','response','data_b64','preview'):
            details.pop(field,None)
        if isinstance(details.get('argv'),list):
            details['executable']=str(details['argv'][0]) if details['argv'] else ''
            details['argv_sha256']=task_memory.digest(details.pop('argv'))
        event_payload={k:v for k,v in details.items() if k not in ('health','ssh')}
        db.execute('INSERT INTO pm_task_sessions VALUES(?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(task_id,session_id) '
            'DO UPDATE SET resource=excluded.resource,username=excluded.username,purpose=excluded.purpose,retain=excluded.retain,'
            'state=excluded.state,owner=excluded.owner,observed_run_id=excluded.observed_run_id,details_json=excluded.details_json,updated_at=excluded.updated_at',
            (task_id,sid,resource or old.get('resource','unknown'),username or old.get('username','unknown'),
             purpose or old.get('purpose','interactive task work'),int(old.get('retain',1) if retain is None else retain),
             state,payload.get('owner',old.get('owner','')),diagnostics.context().get('run_id'),task_memory.encoded(details),now()))
        db.execute('INSERT INTO pm_session_events(task_id,session_id,event,payload_json,created_at) VALUES(?,?,?,?,?)',
            (task_id,sid,state,task_memory.encoded(event_payload),now()))
        if state in ('closed','disconnected','unknown'):
            dependent_state='source_unknown' if state=='unknown' else 'broken_source'
            db.execute('UPDATE pm_session_dependencies SET state=? WHERE task_id=? AND session_id=?',(dependent_state,task_id,sid))
            if task_memory.exists(db,'pm_pivot_routes'):
                db.execute("UPDATE pm_pivot_routes SET state=? WHERE task_id=? AND source_session=? AND state NOT IN ('pending','declined','closed')",(dependent_state,task_id,sid))
    diagnostics.emit('session.state',task_id=task_id,current_state=state,
        identifiers={'session_id':sid},parameters={'retained':bool(old.get('retain',1) if retain is None else retain)})


def call(task_id,action,session_id='',**fields):
    argv=['sudo','-n',BROKER,'session','--task-id',str(task_id),'--action',action,
          '--owner',owner(),'--owner-pid',str(os.getpid())]
    if session_id:argv+=['--session-id',session_id]
    for key,value in fields.items():argv+=['--'+key.replace('_','-'),str(value)]
    with diagnostics.Action('session.lifecycle',action,task_id=task_id,session_id=session_id) as event:
        try:
            result=subprocess.run(argv,capture_output=True,text=True,timeout=60,env={**os.environ,**diagnostics.child_env()})
            payload=json.loads(result.stdout)
        except (OSError,ValueError,subprocess.TimeoutExpired) as exc:
            payload={'status':'unknown','running':None,'reason_category':'outcome_unknown','error':type(exc).__name__}
        event.status=payload.get('status','unknown');event.fields.update(diagnostics.failure_details(payload))
    return payload


def reconcile(db,task_id,*,execute=None,check_remote=True):
    execute=execute or call
    payload=execute(task_id,'list',check_remote=int(check_remote))
    if payload.get('status') not in ('ok','completed'):
        for item in listing(db,task_id):
            if item['state']!='closed':save(db,task_id,item['session_id'],{'status':'unknown','running':None,'reason':'broker_unavailable'})
        return payload
    actual={item['session_id']:item for item in payload.get('sessions',[]) if item.get('session_id')}
    for sid,item in actual.items():
        save(db,task_id,sid,item,resource=item.get('resource',''),username=item.get('username',''),purpose=item.get('purpose',''))
    for item in listing(db,task_id):
        if item['session_id'] not in actual and item['state']!='closed':
            save(db,task_id,item['session_id'],{'status':'disconnected','running':False,'reason':'worker_missing'})
    return payload


@contextmanager
def role_scope(db,task_id,purpose,*,check_remote=True):
    previous={key:os.environ.get(key) for key in ('PM_SESSION_OWNER','PM_SESSION_PURPOSE')}
    os.environ['PM_SESSION_OWNER']='role:'+uuid.uuid4().hex
    os.environ['PM_SESSION_PURPOSE']=purpose[:1000]
    try:
        if any(s['state']!='closed' for s in listing(db,task_id)):reconcile(db,task_id,check_remote=check_remote)
        yield
    finally:
        try:
            for session in listing(db,task_id):
                if session['owner']!=owner():continue
                active_dependencies=any(d['state'] in ('active','source_unknown') for d in session['dependencies'])
                action='release' if session['retain'] or active_dependencies else 'close'
                result=call(task_id,action,session['session_id'])
                if result.get('status') in ('released','closed'):
                    save(db,task_id,session['session_id'],{'status':result['status'],'running':result.get('running'), 'owner':''})
        except Exception as exc:
            diagnostics.emit('session.cleanup_failed',task_id=task_id,error_type=type(exc).__name__,reason='original_role_outcome_retained')
        for key,value in previous.items():
            if value is None:os.environ.pop(key,None)
            else:os.environ[key]=value


def record_result(db,task_id,action,payload,*,session_id='',resource='',username='',purpose='',retain=None):
    if action=='list':
        actual=payload.get('sessions')
        if isinstance(actual,list):
            for item in actual:
                if item.get('session_id'):save(db,task_id,item['session_id'],item,resource=item.get('resource',''),purpose=item.get('purpose',''))
            ids={s.get('session_id') for s in actual}
            for old in listing(db,task_id):
                if old['session_id'] not in ids and old['state']!='closed':save(db,task_id,old['session_id'],{'status':'disconnected','running':False,'reason':'worker_missing'})
    else:
        sid=payload.get('session_id') or session_id
        if sid and payload.get('status') not in ('blocked','error'):
            save(db,task_id,sid,{**payload,'owner':payload.get('owner',owner())},resource=resource,username=username,purpose=purpose,retain=retain)


def callback_assessment(db,task_id,payload):
    """Correlate a local listener check with existing scoped preflight, no packets."""
    from datetime import datetime,timezone
    from orchestrator.service_inventory import timestamp
    result=dict(payload);result['saved_preflight']={'status':'unknown'}
    if not task_memory.exists(db,'pm_tcp_full_scan_attempts'):return result
    target=db.execute('SELECT target FROM tasks WHERE id=?',(task_id,)).fetchone()[0]
    row=db.execute("SELECT id,status,error,created_at FROM pm_tcp_full_scan_attempts WHERE task_id=? AND target=? "
        "AND status IN ('preflight_ok','preflight_fail','preflight_incomplete') ORDER BY id DESC LIMIT 1",(task_id,target)).fetchone()
    if not row:return result
    stamp=timestamp(row[3])
    if not stamp or not 0<=(datetime.now(timezone.utc)-stamp).total_seconds()<=600:return result
    try:preflight=json.loads(row[2])
    except ValueError:return result
    if not isinstance(preflight,dict):return result
    result['saved_preflight']={'row_id':row[0],'target':target,'status':row[1],
        'reachable':preflight.get('reachable',[]),'unchecked':preflight.get('unchecked',[]),
        'unreachable':preflight.get('unreachable',[]),'created_at':row[3]}
    if str(result.get('diagnosis','')).startswith('waiting'):
        if preflight.get('reachable'):result['diagnosis']='target_preflight_reachable_callback_absent; target_egress_restrictions_possible_not_proven'
        elif preflight.get('unreachable') and not preflight.get('unchecked'):
            result['diagnosis']='checked_target_ports_unreachable; whole_network_outcome_not_proven'
        else:result['diagnosis']='target_preflight_incomplete; callback_absence_has_no_unique_explanation'
    return result
