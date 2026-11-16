"""Typed managed Chromium sessions; target traffic belongs to PM HTTP, not CDP.

The standalone broker owns process/terminal leases. DOM and screenshots never
establish authentication or research success by themselves.
"""
import base64
import hashlib
import json
import os
import subprocess
from orchestrator import diagnostics,http_artifacts as artifacts,http_client,http_discovery as web,task_memory,task_sessions
from executor.netguard_root import http_spec,http_origin,tool_digest,browser_action_spec


class CaptureImportError(RuntimeError):
    def __init__(self,reply,error,records):
        self.payload={'status':'unknown','reason_category':'capture_import_failed','error_type':type(error).__name__,
            'execution_outcome':reply.get('status','unknown'),'session_id':reply['session_id'],
            'root_http_receipts':[r['receipt_id'] for r in records if r.get('receipt_id')],
            'browser_action_id':reply['browser_action_id'],
            'reason':'Browser returned; material import failed. Inspect saved materials/broker receipts; no automatic replay.'}
        super().__init__(self.payload['reason'])


def initialize(db):
    task_sessions.initialize(db);http_client.initialize(db)
    db.execute('''CREATE TABLE IF NOT EXISTS pm_browser_actions (
        id INTEGER PRIMARY KEY,task_id INTEGER NOT NULL,session_id TEXT NOT NULL,
        operation_id TEXT,action TEXT NOT NULL,status TEXT NOT NULL,
        result_json TEXT NOT NULL,created_at TEXT NOT NULL)''')
    db.execute('''CREATE TABLE IF NOT EXISTS pm_browser_network (
        task_id INTEGER NOT NULL,session_id TEXT NOT NULL,request_sha256 TEXT NOT NULL,
        response_sha256 TEXT NOT NULL,exchange_id INTEGER NOT NULL,result_id TEXT,
        UNIQUE(task_id,session_id,request_sha256,response_sha256))''')


def call(task_id,action,*,session_id='',value=None,max_requests=0):
    command=['sudo','-n',web.BROKER,'browser','--task-id',str(task_id),'--action',action,
        '--owner',task_sessions.owner(),'--owner-pid',str(os.getpid())]
    if session_id:command+=['--session-id',session_id]
    command+=['--max-requests',str(max_requests)]
    with diagnostics.Action('browser',action,task_id=task_id,session_id=session_id) as event:
        try:
            result=subprocess.run(command,input=json.dumps(value or {}),capture_output=True,text=True,timeout=50,
                env={**os.environ,**diagnostics.child_env()})
            reply=json.loads(result.stdout)
            if not isinstance(reply,dict):raise ValueError('Invalid browser response')
        except (OSError,ValueError,subprocess.SubprocessError) as exc:
            reply={'status':'unknown','reason_category':'outcome_unknown','error_type':type(exc).__name__}
        event.status=reply.get('status','unknown');event.fields.update(diagnostics.failure_details(reply))
    return reply


def validate_action(value):
    return browser_action_spec(value)['action']


def import_network(db,task_id,sid,records):
    ids=[]
    for item in records:
        if item.get('task_id')!=task_id or item.get('session_id')!=sid:raise ValueError('Browser receipt task/session mismatch')
        spec=http_spec(item['spec']);response=item['response']
        if response.get('http_protocol')!=1 or response.get('request_sha256')!=tool_digest(spec) or spec['session_id']!=sid:raise ValueError('Browser HTTP identity mismatch')
        http_client.endpoint(db,task_id,http_origin(spec['scheme'],spec['hostname'],spec['port'])+spec['path'],spec['target'])
        request=base64.b64decode(response['request_b64'],validate=True);wire=base64.b64decode(response['wire_b64'],validate=True)
        signature=task_memory.digest([item.get('observed_at'),tool_digest(spec),hashlib.sha256(wire).hexdigest()])
        old=db.execute('SELECT exchange_id FROM pm_browser_network WHERE task_id=? AND session_id=? AND request_sha256=? AND response_sha256=?',
            (task_id,sid,tool_digest(spec),signature)).fetchone()
        if old:ids.append(old[0]);continue
        body=base64.b64decode(response['body_b64'],validate=True);head=base64.b64decode(response['headers_b64'],validate=True)
        request_ref=artifacts.save_material(task_id,request);response_ref=artifacts.save_material(task_id,wire)
        metadata={'request_ref':request_ref,'response_ref':response_ref,'observed_at':item.get('observed_at'),
            'transport_complete':response['transport_complete'],'body_truncated':response['body_truncated'],
            'source':'managed_browser_via_pm_http','session_id':sid,'broker_receipt_id':item.get('receipt_id'),
            'server_outcome':'uninterpreted'}
        metadata.update({k:response.get(k) for k in ('transport_proxy','proxy_instance_id','proxy_request_nonce')})
        aid=None
        if head and response['status_code'] is not None:
            _,headers,_=artifacts.split_response(head+body)
            capture={'body':body,'headers':headers,'status':response['status_code'],'complete':response['transport_complete'],
                'request':{'method':spec['method'],'scheme':spec['scheme'],'hostname':spec['hostname'],'port':spec['port'],
                    'path':spec['path'],'raw_request_ref':request_ref},'metadata':metadata}
            aid=artifacts.save(db,task_id,spec['target'],spec['scheme'],spec['hostname'],spec['port'],spec['path'],capture,web.now())
        with task_memory.atomic(db):
            operation='browser-capture:'+signature
            eid=db.execute("INSERT INTO pm_http_exchanges(task_id,session_id,parent_id,method,url,target,request_sha256,operation_id,phase,artifact_id,metadata_json,created_at) VALUES(?,?,NULL,?,?,?,?,?,?,?,?,?)",
                (task_id,sid,spec['method'],http_origin(spec['scheme'],spec['hostname'],spec['port'])+spec['path'],
                 spec['target'],tool_digest(spec),operation,'finished' if response['transport_complete'] else 'unknown',aid,json.dumps(metadata),web.now())).lastrowid
            db.execute('INSERT INTO pm_browser_network(task_id,session_id,request_sha256,response_sha256,exchange_id) VALUES(?,?,?,?,?)',(task_id,sid,tool_digest(spec),signature,eid))
        ids.append(eid)
    return ids


def execute(db,task_id,session_id,value,*,log=None):
    from orchestrator.agent_actions import CAPABILITY_LOG
    log=log or CAPABILITY_LOG/f'task_{task_id}.jsonl'
    initialize(db);db.commit();kind=validate_action(value)
    session=next((s for s in task_sessions.listing(db,task_id) if s['session_id']==session_id),None)
    if not session or session['details'].get('transport')!='browser':raise ValueError('No managed browser for this task')
    if kind=='open':http_client.endpoint(db,task_id,value['url'])
    prior=db.execute('SELECT result_json FROM pm_browser_actions WHERE task_id=? AND session_id=? ORDER BY id DESC LIMIT 1',(task_id,session_id)).fetchone()
    previous=json.loads(prior[0]) if prior else {}
    identity={'action':value,'resource':previous.get('observed_url',session['resource']),'user':session['username']}
    description={'signature':task_memory.digest(identity),'resource':identity['resource'],'operation':'browser_'+kind,
        'parameters':{'action':kind,'input_sha256':task_memory.digest(value)}}
    with task_memory.atomic(db):
        intent=task_memory.begin_operation(db,task_id,description,conditions={'dom':previous.get('dom_sha256'),'state':previous.get('state_sha256')},
            require_fresh=kind in ('read','wait','open'),reason='explicit browser observation' if kind in ('read','wait','open') else '')
        if not intent['allowed']:return {'status':'blocked','reason_category':intent['reason'],'execution_started':False}
        oid=intent['operation_id'];task_memory.transition(db,task_id,oid,'started',expected_phase='intent')
        row=db.execute("INSERT INTO pm_browser_actions(task_id,session_id,operation_id,action,status,result_json,created_at) VALUES(?,?,?,?,'running','{}',?)",
            (task_id,session_id,oid,kind,web.now())).lastrowid
    reply=call(task_id,'control',session_id=session_id,value=value,max_requests=max(0,web.MAX_TOTAL-web.attempts_used(db,task_id)))
    reply['browser_action_id']=row
    network=reply.pop('network',[]);dom=reply.pop('dom_b64',None)
    try:
        exchanges=import_network(db,task_id,session_id,network)
        if dom is not None:reply['dom_ref']=artifacts.save_material(task_id,base64.b64decode(dom,validate=True))
        safe={k:reply[k] for k in ('status','running','owner','transport','resource','username','purpose','dom_sha256','state_sha256') if k in reply}
        safe['session_id']=session_id
        task_sessions.record_result(db,task_id,'read',safe,session_id=session_id)
        reply['http_exchanges']=exchanges
        with task_memory.atomic(db):
            phase='finished' if reply.get('status')=='completed' else 'cancelled' if reply.get('execution_started') is False else 'unknown'
            task_memory.transition(db,task_id,oid,phase,expected_phase='started',outcome=reply.get('status','unknown'))
            db.execute('UPDATE pm_browser_actions SET status=?,result_json=? WHERE id=?',(reply.get('status','unknown'),json.dumps(reply),row))
            task_memory.sync(db,task_id,log,reason='browser_'+kind)
    except BaseException as exc:
        error=CaptureImportError({**reply,'session_id':session_id},exc,network)
        with task_memory.atomic(db):
            db.execute("UPDATE pm_browser_actions SET status='unknown',result_json=? WHERE id=?",(json.dumps(error.payload),row))
            task_memory.transition(db,task_id,oid,'unknown',expected_phase='started',outcome='capture_import_failed')
        if isinstance(exc,(KeyboardInterrupt,SystemExit)):raise
        raise error from exc
    return reply


def open_session(db,task_id,url,username,purpose,proxy=None):
    initialize(db);http_client.endpoint(db,task_id,url)
    reply=call(task_id,'open',value={'url':url,'username':username,'purpose':purpose,'proxy':proxy})
    task_sessions.record_result(db,task_id,'open',reply,resource=url,username=username,purpose=purpose)
    db.commit()
    return reply


def observations(db,task_id,session_id):
    if not task_memory.exists(db,'pm_browser_actions'):return []
    return [{'id':r[0],'action':r[1],'status':r[2],'result':json.loads(r[3])} for r in db.execute(
        'SELECT id,action,status,result_json FROM pm_browser_actions WHERE task_id=? AND session_id=? ORDER BY id',(task_id,session_id))]
