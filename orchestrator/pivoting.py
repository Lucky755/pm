"""Operator-granted SSH forwards. A route never grants additional task scope."""
import json
import os
import subprocess
from orchestrator import diagnostics,task_memory,task_sessions
from executor.netguard_root import pivot_spec,tool_digest


def initialize(db):
    task_sessions.initialize(db)
    db.execute('''CREATE TABLE IF NOT EXISTS pm_pivot_routes (
        id INTEGER PRIMARY KEY,task_id INTEGER NOT NULL,fingerprint TEXT NOT NULL,
        source_session TEXT NOT NULL,resource_ref TEXT NOT NULL,question_id INTEGER,
        state TEXT NOT NULL,receipt_json TEXT NOT NULL,UNIQUE(task_id,fingerprint))''')


def listing(db,task_id):
    if not task_memory.exists(db,'pm_pivot_routes'):return []
    cursor=db.execute('SELECT * FROM pm_pivot_routes WHERE task_id=? ORDER BY id',(task_id,))
    result=[]
    for row in cursor:
        item=dict(zip([c[0] for c in cursor.description],row));item['receipt']=json.loads(item.pop('receipt_json'))
        item['reachability']='unknown; last probe is historical'
        result.append(item)
    return result


def call(task_id,action,*,spec=None,request_id=None):
    argv=['sudo','-n',task_sessions.BROKER,'pivot','--task-id',str(task_id),'--action',action]
    if spec is not None:argv+=['--spec-json',json.dumps(spec)]
    if request_id:argv+=['--request-id',request_id]
    with diagnostics.Action('pivot',action,task_id=task_id) as event:
        try:
            result=subprocess.run(argv,capture_output=True,text=True,timeout=35,env={**os.environ,**diagnostics.child_env()})
            reply=json.loads(result.stdout)
        except (OSError,ValueError,subprocess.TimeoutExpired) as exc:
            reply={'status':'unknown','reason_category':'outcome_unknown','error':type(exc).__name__}
        event.status=reply.get('status','unknown');event.fields.update(diagnostics.failure_details(reply))
    return reply


def for_question(db,task_id,qid):return next((r for r in listing(db,task_id) if r['question_id']==qid),None)


def request(db,task_id,target,decision,step_id=None,*,execute=None):
    from orchestrator import operator_questions,resources
    execute=execute or call;spec=pivot_spec(decision['operator_question']['request'])
    setting=db.execute('SELECT allow_pivot,allow_port_forward FROM task_scope_settings WHERE task_id=?',(task_id,)).fetchone()
    if not setting or not all(setting):raise ValueError('Pivoting/port forwarding is prohibited by saved task conditions; operator must change scope explicitly')
    graph=resources.graph(db,task_id)
    resource=next((r for r in graph.get('resources',[]) if r['id']==spec['resource_ref']),None)
    if not resource or resource['kind']!='address' or resource['value']!=spec['destination'] or resource['id'] not in graph.get('authorized_resources',[]):
        raise ValueError('Internal resource does not match an authorized saved address')
    source=next((s for s in task_sessions.listing(db,task_id) if s['session_id']==spec['source_session']),None)
    if not source or source['state'] in ('closed','disconnected'):raise ValueError('No usable saved source session')
    fingerprint=tool_digest({k:v for k,v in spec.items() if k!='purpose'})
    previous=next((r for r in listing(db,task_id) if r['fingerprint']==fingerprint),None)
    if previous:return next(q for q in operator_questions.listing(db,task_id) if q['id']==previous['question_id'])
    receipt=execute(task_id,'prepare',spec=spec)
    if receipt.get('status')!='prepared' or receipt.get('request_id')!=tool_digest(receipt.get('manifest')):
        raise ValueError('pivot_prepare_failed:'+str(receipt.get('reason_category','unsupported_source')))
    if receipt['manifest']['spec']!=spec or receipt['manifest']['task_id']!=task_id:raise ValueError('Pivot receipt mismatch')
    plain={**decision,'operator_question':{'kind':'pivoting'},'question':
        f"Разрешить SSH-forward из сессии {spec['source_session']} к {spec['destination']}:{spec['port']}? "+spec['purpose']}
    with task_memory.atomic(db):
        initialize(db)
        question=operator_questions.request(db,task_id,target,plain,step_id)
        db.execute('INSERT INTO pm_pivot_routes(task_id,fingerprint,source_session,resource_ref,question_id,state,receipt_json) '
            "VALUES(?,?,?,?,?,'pending',?)",(task_id,fingerprint,spec['source_session'],spec['resource_ref'],question['id'],task_memory.encoded(receipt)))
    return next(q for q in operator_questions.listing(db,task_id) if q['id']==question['id'])


def answered(db,question,decision):
    item=for_question(db,question['task_id'],question['id'])
    if not item:return False
    if decision=='information':raise ValueError('A pivot route needs approve or decline')
    db.execute('UPDATE pm_pivot_routes SET state=? WHERE id=?',('approved' if decision=='approve' else 'declined',item['id']))
    return True


def apply(db,task_id,route_id,*,authorize=False,execute=None,perform=True):
    execute=execute or call
    item=next((r for r in listing(db,task_id) if r['id']==route_id),None)
    if not item:raise ValueError('Unknown task route')
    if item['state'] in ('pending','declined','closed','broken_source'):return item
    receipt=item['receipt'];rid=receipt['request_id']
    if authorize:
        authorized=execute(task_id,'authorize',request_id=rid)
        if authorized.get('status')=='approved':receipt=authorized
    result=execute(task_id,'apply' if perform and item['state']=='approved' else 'status',request_id=rid)
    merged={**receipt,**result}
    if merged.get('request_id')!=rid or merged.get('manifest')!=receipt['manifest']:
        merged={**receipt,'status':'unknown','reason_category':'outcome_unknown'}
    state=merged.get('route_state',merged.get('status','unknown'))
    if state=='prepared':state='approved'
    with task_memory.atomic(db):
        db.execute('UPDATE pm_pivot_routes SET state=?,receipt_json=? WHERE id=?',(state,task_memory.encoded(merged),route_id))
        if state in ('active','established_unverified'):
            db.execute('INSERT INTO pm_session_dependencies VALUES(?,?,?,?) ON CONFLICT(task_id,session_id,dependent_ref) '
                'DO UPDATE SET state=excluded.state',(task_id,item['source_session'],'pivot:'+str(route_id),'active'))
    return next(r for r in listing(db,task_id) if r['id']==route_id)
