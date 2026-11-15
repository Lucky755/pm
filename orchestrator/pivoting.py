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
        item=dict(zip([c[0] for c in cursor.description],row))
        try:item['receipt']=json.loads(item.pop('receipt_json'))
        except (ValueError,TypeError):item['receipt']=None
        problem=receipt_problem(item)
        if problem:item['diagnostic']=problem
        item['reachability']='unknown; last probe is historical'
        result.append(item)
    return result


def receipt_problem(item):
    """Validate saved identity without reconstructing missing historical data."""
    receipt=item['receipt']
    if not isinstance(receipt,dict) or not isinstance(receipt.get('manifest'),dict) or not isinstance(receipt.get('request_id'),str):
        return {'reason_category':'pivot_receipt_incomplete',
                'reason_summary':'Stored pivot receipt is incomplete; review original broker records. No reconstruction or replay.'}
    manifest=receipt['manifest']
    try:
        spec=pivot_spec(manifest['spec'])
        valid=(receipt['request_id']==tool_digest(manifest) and manifest['task_id']==item['task_id']
            and spec['source_session']==item['source_session'] and spec['resource_ref']==item['resource_ref']
            and isinstance(manifest['listener'],str) and isinstance(manifest['rights'],str)
            and isinstance(manifest['actions'],list) and isinstance(manifest['source_ssh'],dict))
    except (KeyError,ValueError,TypeError):valid=False
    if not valid:
        return {'reason_category':'pivot_receipt_incomplete',
                'reason_summary':'Stored pivot identity cannot be verified; review original broker records. No reconstruction or replay.'}
    return None


def blocked(item):
    return {**item,'status':'blocked',**item['diagnostic'],'execution_started':False}


def merge_reply(item,reply,action):
    """A short error is an outcome, never a replacement route identity."""
    receipt=item['receipt']
    status=reply.get('status') if isinstance(reply,dict) else None
    matching=(isinstance(reply,dict) and reply.get('request_id')==receipt['request_id']
              and reply.get('manifest')==receipt['manifest'])
    state=reply.get('route_state') if status=='completed' else status
    states={'prepared','approved','creating','active','established_unverified','closed','broken_source','unknown','failed'}
    valid=matching and isinstance(state,str) and state in states
    if state=='closed' and (type(reply.get('exit_code')) is not int or reply['exit_code']!=0 or reply.get('error')):valid=False
    merged={**receipt,**reply} if valid else dict(receipt)
    # A previous probe's route_state/exit code cannot complete a new operation.
    for key in ('route_state','probe_performed','reason','reason_category','reason_summary','error','exit_code'):
        merged.pop(key,None)
    if valid:
        merged.update(reply)
        if status!='completed':merged.pop('route_state',None)
    else:
        mismatch=isinstance(reply,dict) and any(key in reply and reply[key]!=receipt[key] for key in ('request_id','manifest'))
        category='pivot_receipt_mismatch' if mismatch else 'outcome_unknown' if status in ('unknown','timeout','error') else 'pivot_reply_incomplete'
        state='unknown'
        merged.update(status='unknown',reason_category=category,
            reason_summary='Pivot '+action+' was not confirmed; original identity retained. Query status; no automatic replay.')
    if state=='unknown' and not merged.get('reason_summary'):
        merged.update(reason_category='outcome_unknown',
            reason_summary='Pivot '+action+' outcome is unknown; retain its source and query status without replay.')
    merged['last_operation']={'action':action,'outcome':state}
    return merged,state


def record_reply(db,item,reply,action,*,capability_log=None):
    receipt,state=merge_reply(item,reply,action)
    dependency='closed' if state=='closed' else 'broken_source' if state=='broken_source' else (
        'active' if state in ('active','established_unverified') else 'unknown')
    if capability_log is None:
        from orchestrator.agent_actions import CAPABILITY_LOG
        capability_log=CAPABILITY_LOG/f"task_{item['task_id']}.jsonl"
    with task_memory.atomic(db):
        db.execute('UPDATE pm_pivot_routes SET state=?,receipt_json=? WHERE task_id=? AND id=?',
            (state,task_memory.encoded(receipt),item['task_id'],item['id']))
        db.execute('INSERT INTO pm_session_dependencies VALUES(?,?,?,?) ON CONFLICT(task_id,session_id,dependent_ref) '
            'DO UPDATE SET state=excluded.state',(item['task_id'],item['source_session'],'pivot:'+str(item['id']),dependency))
        task_memory.sync(db,item['task_id'],capability_log,reason='pivot_'+action+'_result')
    diagnostics.emit('pivot.state',task_id=item['task_id'],current_state=state,
        identifiers={'route_id':item['id'],'request_id':receipt['request_id']},reason=receipt.get('reason_category'))
    return next(r for r in listing(db,item['task_id']) if r['id']==item['id'])


def call(task_id,action,*,spec=None,request_id=None):
    argv=['sudo','-n',task_sessions.BROKER,'pivot','--task-id',str(task_id),'--action',action]
    if spec is not None:argv+=['--spec-json',json.dumps(spec)]
    if request_id:argv+=['--request-id',request_id]
    with diagnostics.Action('pivot',action,task_id=task_id) as event:
        try:
            result=subprocess.run(argv,capture_output=True,text=True,timeout=35,env={**os.environ,**diagnostics.child_env()})
            reply=json.loads(result.stdout)
            if not isinstance(reply,dict):raise ValueError('Broker reply is not an object')
            if result.returncode:
                reply={'status':'unknown','reason_category':'outcome_unknown','error':'BrokerExitNonzero'}
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


def apply(db,task_id,route_id,*,authorize=False,execute=None,perform=True,capability_log=None):
    execute=execute or call
    item=next((r for r in listing(db,task_id) if r['id']==route_id),None)
    if not item:raise ValueError('Unknown task route')
    if item.get('diagnostic'):return blocked(item)
    if item['state'] in ('pending','declined','closed','broken_source'):return item
    receipt=item['receipt'];rid=receipt['request_id']
    if authorize:
        authorized=execute(task_id,'authorize',request_id=rid)
        receipt,state=merge_reply(item,authorized,'authorize')
        if state!='approved':return record_reply(db,item,authorized,'authorize',capability_log=capability_log)
        item={**item,'receipt':receipt,'state':'approved'}
    result=execute(task_id,'apply' if perform and item['state']=='approved' else 'status',request_id=rid)
    if isinstance(result,dict) and result.get('status')=='prepared':
        # The DB approval is durable; applying an unauthorised root receipt did
        # not execute a forward. Explicit operator authorization is still needed.
        result={**result,'status':'approved'}
    return record_reply(db,item,result,'apply' if perform and item['state']=='approved' else 'status',capability_log=capability_log)


def close(db,task_id,route_id,*,capability_log=None):
    item=next((r for r in listing(db,task_id) if r['id']==route_id),None)
    if not item:raise ValueError('Unknown task route')
    if item.get('diagnostic'):return blocked(item)
    if item['state']=='closed':return item
    reply=call(task_id,'close',request_id=item['receipt']['request_id'])
    return record_reply(db,item,reply,'close',capability_log=capability_log)
