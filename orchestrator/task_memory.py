"""Versioned task memory over existing sources; no model, network or truth upgrades.

Current structured state, revision history and original materials are separate.
All reads (including context assembly) are read-only. Writers use a SQLite CAS
inside a savepoint; source synchronisation is an explicit execution boundary.
"""
from contextlib import contextmanager
from datetime import datetime, timezone
from functools import wraps
import hashlib
import base64
import json
from pathlib import Path
import re
import sqlite3
import uuid

SCHEMA_VERSION=1
SECTIONS=('goals','constraints','resources','relations','materials','credentials','access',
          'sessions','checks','observations','resolved_claims','refutations','questions','plan','corrections','coverage')
CHUNK_BYTES=4096


class VersionConflict(ValueError):pass


def encoded(value):return json.dumps(value,ensure_ascii=False,sort_keys=True,separators=(',',':'))
def digest(value):return hashlib.sha256(encoded(value).encode()).hexdigest()
def now():return datetime.now(timezone.utc).isoformat()
def exists(db,table):return bool(db.execute('SELECT 1 FROM sqlite_master WHERE type=\'table\' AND name=?',(table,)).fetchone())


@contextmanager
def atomic(db):
    name='memory_'+uuid.uuid4().hex
    db.execute('SAVEPOINT '+name)
    try:
        yield
        db.execute('RELEASE '+name)
    except BaseException:
        db.execute('ROLLBACK TO '+name);db.execute('RELEASE '+name)
        raise


def consistent_read(function):
    @wraps(function)
    def read(db,*args,**kwargs):
        with atomic(db):return function(db,*args,**kwargs)
    return read


def initialize(db):
    """Idempotent additive migration, never touches legacy rows/user_version."""
    with atomic(db):
        db.execute('CREATE TABLE IF NOT EXISTS pm_memory_schema(version INTEGER NOT NULL)')
        row=db.execute('SELECT version FROM pm_memory_schema').fetchone()
        if row and row[0]!=SCHEMA_VERSION:raise ValueError('Unsupported task memory schema')
        if not row:db.execute('INSERT INTO pm_memory_schema VALUES(?)',(SCHEMA_VERSION,))
        db.execute('''CREATE TABLE IF NOT EXISTS pm_memory_heads(
            task_id INTEGER PRIMARY KEY,version INTEGER NOT NULL,state_json TEXT NOT NULL,sha256 TEXT NOT NULL)''')
        db.execute('''CREATE TABLE IF NOT EXISTS pm_memory_revisions(
            task_id INTEGER NOT NULL,version INTEGER NOT NULL,previous_sha256 TEXT NOT NULL,
            state_json TEXT NOT NULL,sha256 TEXT NOT NULL,changes_json TEXT NOT NULL,
            reason TEXT NOT NULL,actor TEXT NOT NULL,created_at TEXT NOT NULL,PRIMARY KEY(task_id,version))''')
        db.execute('''CREATE TABLE IF NOT EXISTS pm_memory_coverage(
            task_id INTEGER NOT NULL,reference TEXT NOT NULL,sha256 TEXT NOT NULL,
            start_byte INTEGER NOT NULL,end_byte INTEGER NOT NULL,kind TEXT NOT NULL,
            report_ref TEXT NOT NULL,created_at TEXT NOT NULL,
            PRIMARY KEY(task_id,reference,sha256,start_byte,end_byte,kind,report_ref))''')
        db.execute('''CREATE TABLE IF NOT EXISTS pm_memory_operations(
            id TEXT PRIMARY KEY,task_id INTEGER NOT NULL,resource TEXT NOT NULL,operation TEXT NOT NULL,
            signature TEXT NOT NULL,parameters_json TEXT NOT NULL,conditions_sha256 TEXT NOT NULL,
            phase TEXT NOT NULL,outcome TEXT NOT NULL DEFAULT '',result_id TEXT,
            started_at TEXT,ended_at TEXT,created_at TEXT NOT NULL)''')
        db.execute('CREATE INDEX IF NOT EXISTS pm_memory_op_key ON pm_memory_operations(task_id,signature)')
        db.execute('''CREATE TABLE IF NOT EXISTS pm_memory_material_versions(
            task_id INTEGER NOT NULL,reference TEXT NOT NULL,sha256 TEXT NOT NULL,body BLOB NOT NULL,
            PRIMARY KEY(task_id,reference,sha256))''')


def current(db,task_id,version=None):
    if exists(db,'pm_memory_schema'):
        schema=db.execute('SELECT version FROM pm_memory_schema').fetchone()
        if not schema or schema[0]!=SCHEMA_VERSION:
            raise ValueError('Unsupported task memory schema')
    if not exists(db,'pm_memory_heads'):return {'version':0,'state':{s:{} for s in SECTIONS},'sha256':None}
    if version is None:
        row=db.execute('SELECT version,state_json,sha256 FROM pm_memory_heads WHERE task_id=?',(task_id,)).fetchone()
    else:
        row=db.execute('SELECT version,state_json,sha256 FROM pm_memory_revisions WHERE task_id=? AND version=?',
                       (task_id,version)).fetchone()
    if not row:
        if version not in (None,0):raise ValueError('Unknown memory version')
        return {'version':0,'state':{s:{} for s in SECTIONS},'sha256':None}
    state=json.loads(row[1])
    if digest(state)!=row[2]:raise ValueError('Memory snapshot checksum mismatch')
    return {'version':row[0],'state':state,'sha256':row[2]}


def apply(db,task_id,expected_version,changes,*,reason,actor='pm'):
    """Atomic compare-and-swap. Corrections require a reason, and retain old data."""
    if type(expected_version) is not int or not reason.strip() or not actor.strip():raise ValueError('Memory update needs version/reason/actor')
    if not exists(db,'tasks') or not db.execute('SELECT 1 FROM tasks WHERE id=?',(task_id,)).fetchone():raise ValueError('Unknown task')
    with atomic(db):
        initialize(db)
        previous=current(db,task_id)
        if previous['version']!=expected_version:raise VersionConflict('Task memory version conflict')
        state=previous['state'];effective=[]
        for change in changes:
            section,key=change['section'],change['key']
            if section not in SECTIONS or not isinstance(key,str) or not key:raise ValueError('Invalid memory key')
            value=change.get('value')
            if value is not None and not isinstance(value,dict):raise ValueError('Memory value must be structured')
            old=state[section].get(key)
            if actor!='source_sync' and ((value or {}).get('source_owned') or (old or {}).get('source_owned')):
                raise ValueError('Only source synchronisation can publish validated source state')
            if old==value:continue
            if section=='corrections' and value is not None and (not value.get('reason') or not value.get('supersedes')):
                raise ValueError('Correction needs reason and original reference')
            if value is None:state[section].pop(key,None)
            else:state[section][key]=value
            effective.append({'section':section,'key':key,'before':old,'after':value})
        if not effective:return previous['version']
        version=expected_version+1;checksum=digest(state);raw=encoded(state)
        db.execute('INSERT OR IGNORE INTO pm_memory_heads VALUES(?,0,?,?)',
                   (task_id,encoded({s:{} for s in SECTIONS}),digest({s:{} for s in SECTIONS})))
        if db.execute('UPDATE pm_memory_heads SET version=?,state_json=?,sha256=? WHERE task_id=? AND version=?',
                      (version,raw,checksum,task_id,expected_version)).rowcount!=1:raise VersionConflict('Task memory version conflict')
        db.execute('INSERT INTO pm_memory_revisions VALUES(?,?,?,?,?,?,?,?,?)',
                   (task_id,version,previous['sha256'] or '',raw,checksum,encoded(effective),reason,actor,now()))
        return version


def rows(db,table,task_id,*,target=None):
    if not exists(db,table):return []
    columns={r[1] for r in db.execute('PRAGMA table_info('+table+')')}
    if 'task_id' not in columns:return []
    query='SELECT * FROM '+table+' WHERE task_id=?';params=[task_id]
    if target is not None and 'target' in columns:query+=' AND target=?';params.append(target)
    cursor=db.execute(query,params)
    return [dict(zip([c[0] for c in cursor.description],row)) for row in cursor]


def capability_records(task_id,path,target):
    if path is None:return
    try:stream=Path(path).open(encoding='utf-8')
    except FileNotFoundError:return
    with stream:
        for line in stream:
            try:item=json.loads(line)
            except ValueError:continue
            result=item.get('result')
            if (item.get('task_id')!=task_id or not isinstance(result,dict)
                    or result.get('task_id',task_id)!=task_id or result.get('target',target)!=target):continue
            if isinstance(item.get('id'),str):
                item['_memory_raw_line']=line.rstrip('\n')
                yield item


def capability_text(record):
    result=record['result']
    return '\n'.join(str(result[k]) for k in ('stdout','stderr','response','output') if result.get(k))


def source_state(db,task_id,capability_log):
    """Complete projection, no LIMIT windows and no interpretation by a model."""
    row=db.execute('SELECT target FROM tasks WHERE id=?',(task_id,)).fetchone()
    if not row:raise ValueError('Unknown task')
    target=row[0];state={s:{} for s in SECTIONS}
    def put(section,key,value):state[section][key]={'source_owned':True,**value}
    for item in rows(db,'pm_target_availability',task_id):
        put('constraints','target_availability',{k:v for k,v in item.items() if k!='analysis_sha256'})
    for item in rows(db,'pm_port_preflight',task_id,target=target):
        put('checks','port_availability:'+str(item['port']),{'port':item['port'],'state':item['state'],
            'observed_at':item['checked_at'],'purpose':'availability','product_identified':False})
    for intent in rows(db,'pm_task_intents',task_id):put('constraints','intent',{'text':intent['intent'],'target':target})
    for settings in rows(db,'task_scope_settings',task_id):put('constraints','scope',settings)
    for network in rows(db,'task_scope_networks',task_id):
        put('constraints','network:'+network['network'],network)
    from orchestrator import resources
    scope=resources.graph(db,task_id)
    if scope['configured']:
        put('constraints','resource_scope',{k:v for k,v in scope.items() if k not in ('resources','relations')})
        for item in scope['resources']:put('resources',item['id'],item)
        for item in scope['relations']:put('relations','relation:'+digest(item),item)
    for approval in rows(db,'pm_operator_approvals',task_id,target=target):
        put('constraints','operator_approval',{k:v for k,v in approval.items() if k not in ('approved_at',)})
    for goal in rows(db,'pm_objectives',task_id):put('goals','objective:'+goal['key'],goal)
    from orchestrator import operator_questions
    from orchestrator import flag_review
    for proposal in flag_review.listing(db,task_id):
        put('goals','flag_proposal:'+str(proposal['id']),proposal)
    for question in operator_questions.listing(db,task_id):
        put('questions','operator_question:'+str(question['id']),question)
    from orchestrator import tool_requests
    for tool in tool_requests.listing(db,task_id):
        put('resources','tool_request:'+str(tool['id']),tool_requests.describe(tool))
    for event in rows(db,'pm_operator_policy_events',task_id):
        put('corrections','retired_policy:'+str(event['id']),{**event,'supersedes':event['object_ref']})
    from orchestrator import service_inventory
    inventory=service_inventory.collect_full(db,task_id)
    for service in inventory['entries']:
        key=f"service:{target}:{service['protocol']}:{service['port']}"
        put('resources',key,service)
        put('relations','target:'+key,{'from':'scope:'+target,'to':key,'kind':'exposes'})
    for asset in rows(db,'pm_assets',task_id):
        key='asset:'+digest([asset['kind'],asset['key']])
        put('credentials' if asset['kind']=='credential' else 'resources',key,
            {**asset,'trust':'candidate' if asset['kind']=='credential' else 'saved_state'})
        if asset.get('last_probe_result_id'):
            put('relations','evidence:'+key,{'from':key,'to':'result:'+asset['last_probe_result_id'],'kind':'cites'})
    for access in rows(db,'pm_access_state',task_id):put('access','access',access)
    for question in rows(db,'pm_credential_acceptance',task_id,target=target):
        put('credentials','accepted:'+str(question['id']),{**question,'trust':'server_accepted','access_implied':False})
    for triage in rows(db,'pm_access_triage',task_id):put('access','triage:'+triage['level']+':'+triage['category'],triage)
    for hypothesis in rows(db,'pm_hypotheses',task_id):
        section=('refutations' if hypothesis['status']=='refuted' else 'questions' if hypothesis['status']=='untested'
                 else 'observations' if hypothesis['status']=='confirmed' and hypothesis['kind']=='observation' else 'resolved_claims')
        put(section,'hypothesis:'+digest(hypothesis['claim_key']),hypothesis)
    for report in rows(db,'pm_agent_action_reports',task_id,target=target):
        ref=f"report:{report['role']}:{report['iteration']}";raw=report['report_json'].encode()
        from orchestrator import report_integrity
        parsed=report_integrity.decode_saved(report['report_json'],task_id,report['role'],report['iteration'])
        if parsed.get('credential_assessment'):
            put('questions','credential_assessment:'+ref,{**parsed['credential_assessment'],'source_ref':ref})
        put('materials',ref,{'kind':'report','role':report['role'],'iteration':report['iteration'],
            'sha256':hashlib.sha256(raw).hexdigest(),'bytes':len(raw),
            'quality':parsed.get('report_quality'),'summary':parsed.get('summary',''),
            'source':{'table':'pm_agent_action_reports','role':report['role'],'iteration':report['iteration']}})
        for session in parsed.get('harness_sessions') or []:
            if isinstance(session,dict) and isinstance(session.get('session_id'),str):
                put('sessions','harness:'+session['session_id'],{**session,'kind':'harness',
                    'liveness':'owned_runtime_closed','resumable':'not_verified','report_ref':ref})
        # These remain claims from the report, not structured confirmed access.
        for index,claim in enumerate(parsed.get('findings') or []):
            if isinstance(claim,dict):put('questions',ref+':finding:'+str(index),
                {'claim':claim,'trust':'report_claim','report_ref':ref})
        for index,question in enumerate(parsed.get('uncertainties') or []):
            put('questions',ref+':uncertainty:'+str(index),{'question':question,'report_ref':ref,'trust':'open'})
    for artifact in rows(db,'pm_http_artifacts',task_id,target=target):
        put('materials','http_artifact:'+str(artifact['id']),{'kind':'http_artifact',
            'sha256':artifact['sha256'],'bytes':artifact['bytes_saved'],'target':target,
            'path':artifact['path'],'port':artifact['port'],'complete':artifact['complete'],
            'source':{'table':'pm_http_artifacts','id':artifact['id']}})
    for item in rows(db,'pm_file_materials',task_id):
        ref='file_material:'+str(item['id']);metadata=json.loads(item['metadata_json'])
        put('materials',ref,{'kind':'file_material','sha256':item['sha256'],'bytes':item['bytes'],
            'name':item['name'],'complete':bool(item['complete']),'metadata':metadata,
            'source_ref':item['source_ref'],'parent_id':item['parent_id'],'fresh_observation':False})
        put('relations','derived:'+ref,{'from':ref,'to':item['source_ref'],'kind':'local_material_derivation','fresh_observation':False})
        for index,candidate in enumerate(metadata.get('credential_candidates',[])):
            put('credentials',ref+':candidate:'+str(index),{**candidate,'material_ref':ref,'trust':'candidate','access_implied':False})
    for item in rows(db,'pm_material_processing',task_id):
        result=json.loads(item['result_json']);ref='material_processing:'+str(item['id'])
        put('checks',ref,{'phase':'finished','outcome':item['status'],'input_ref':item['input_ref'],
            'input_sha256':item['input_sha256'],'complete':result['complete'],'kind':result['kind'],
            'errors':result.get('errors',[]),'fresh_observation':False})
        for index,relation in enumerate(result.get('relations',[])):
            put('relations',ref+':'+str(index),relation)
    for session in rows(db,'pm_http_sessions',task_id):
        put('sessions','web_session:'+session['name'],{'kind':'http','name':session['name'],
            'version':session['version'],'active_exchange_id':session['active_exchange_id'],
            'liveness':'request/response session, not a persistent authenticated socket'})
    for exchange in rows(db,'pm_http_exchanges',task_id):
        put('checks','http_exchange:'+str(exchange['id']),{k:exchange[k] for k in
            ('id','session_id','parent_id','method','url','target','request_sha256','operation_id','phase','artifact_id','created_at')})
    for action in rows(db,'pm_browser_actions',task_id):
        result=json.loads(action['result_json'])
        essential={k:result[k] for k in ('observed_url','title','dom_ref','dom_sha256','state_sha256','http_exchanges','network_result_ids','network_denials','interpretation','error_type','execution_outcome','reason_category','root_http_receipts') if k in result}
        text=result.get('text','');essential.update(text_preview=text[:1000],text_characters=len(text),text_preview_truncated=len(text)>1000)
        put('checks','browser_action:'+str(action['id']),{**{k:action[k] for k in ('id','session_id','operation_id','action','status','created_at')},'result':essential})
        if result.get('dom_ref'):
            put('materials','browser_dom:'+str(action['id']),{**result['dom_ref'],'kind':'browser_dom','action_id':action['id'],
                'session_id':action['session_id'],'source':'observed renderer DOM; not independent target evidence'})
    for message in rows(db,'pm_burp_messages',task_id):
        prefix='burp:'+message['instance_id']+':'+str(message['message_id'])
        meta=json.loads(message['metadata_json'])
        put('checks',prefix,{
            **{k:message[k] for k in ('instance_id','message_id','url','target')},**json.loads(message['metadata_json']),
            'source':'passive_burp_history','fresh_observation':False})
        for part in ('request','response'):
            put('materials',prefix+':'+part,{**meta[part+'_ref'],'kind':'burp_original','source':'passive_burp_history',
                'instance_id':message['instance_id'],'message_id':message['message_id'],'part':part,'fresh_observation':False})
    if exists(db,'network_job_runs') and exists(db,'network_phase_plans'):
        for row in db.execute('SELECT r.id,r.status,r.result_json,p.id,p.profile,p.parameters_json '
                              'FROM network_job_runs r JOIN network_phase_plans p ON p.id=r.plan_id '
                              'WHERE p.task_id=? AND p.target=? ORDER BY r.id',(task_id,target)):
            rid,status,raw,pid,profile,params=row;ref='network_result:'+str(rid)
            put('checks',ref,{'phase':'started' if status=='running' else 'finished','outcome':status,
                             'plan_id':pid,'operation':profile,'parameters':json.loads(params)})
            if raw is not None:put('materials',ref,{'kind':'network_result','sha256':hashlib.sha256(raw.encode()).hexdigest(),
                'bytes':len(raw.encode()),'source':{'table':'network_job_runs','id':rid,'plan_id':pid}})
    for scan in rows(db,'pm_tcp_full_scans',task_id,target=target):
        put('checks','tcp_full:'+str(scan.get('id',target)),{'operation':'tcp_full','phase':'started' if scan['status']=='running' else 'finished',
            'outcome':scan['status'],'open_ports':json.loads(scan['open_ports_json']),
            'followup_status':scan.get('followup_status')})
    for attempt in rows(db,'pm_tcp_full_scan_attempts',task_id,target=target):
        raw=attempt.get('result_json')
        if raw is not None:
            put('materials','tcp_scan_attempt:'+str(attempt['id']),{'kind':'tcp_scan_attempt',
                'sha256':hashlib.sha256(raw.encode()).hexdigest(),'bytes':len(raw.encode()),
                'complete':attempt['status']=='completed','source':{'table':'pm_tcp_full_scan_attempts','id':attempt['id']}})
    for record in capability_records(task_id,capability_log,target):
        result=record['result'];ref='result:'+record['id']
        text=capability_text(record)
        put('materials',ref,{'kind':'capability','tool':record['tool'],'sha256':hashlib.sha256(text.encode()).hexdigest(),
            'bytes':len(text.encode()),'source':{'log':str(capability_log),'result_id':record['id']},
            'provenance':record.get('provenance','unknown')})
        original=record['_memory_raw_line'].encode()
        put('materials','execution:'+record['id'],{'kind':'capability_record','tool':record['tool'],
            'sha256':hashlib.sha256(original).hexdigest(),'bytes':len(original),
            'source':{'log':str(capability_log),'result_id':record['id']}})
        put('checks',ref,{'operation':record['tool'],'phase':'not_started' if result.get('execution_started') is False else 'unknown' if result.get('status')=='timeout' else 'finished',
            'outcome':result.get('status'),'exit_code':result.get('exit_code'),
            'execution_started':result.get('execution_started'),'error_type':result.get('error_type'),
            'reason_category':result.get('kind'),'server_outcome':result.get('server_outcome','unknown'),
            'provenance':record.get('provenance','unknown'),'result_id':record['id'],
            'execution_ref':'execution:'+record['id'],
            'operation_signature':canonical_operation(record['tool'],record['argv'],target,record.get('provenance'))['signature']
                if record.get('argv') and not record.get('argv_truncated') else None,
            'observation_sha256':hashlib.sha256(text.encode()).hexdigest()})
        if record['tool']=='session':
            sid=result.get('session_id')
            if sid:put('sessions','session:'+sid,{'session_id':sid,'last_result_id':record['id'],
                'reported_status':result.get('status'),'liveness':'unknown','action':result.get('action'),
                'observed_at':record.get('timestamp')})
            for session in result.get('sessions') or []:
                if isinstance(session,dict) and session.get('session_id'):
                    put('sessions','session:'+str(session['session_id']),{'session_id':session['session_id'],
                        'last_result_id':record['id'],'liveness':'unknown','observed_alive':session.get('alive'),
                        'observed_at':record.get('timestamp')})
    from orchestrator import task_sessions
    for session in task_sessions.listing(db,task_id):put('sessions','session:'+session['session_id'],session)
    from orchestrator import pivoting
    for route in pivoting.listing(db,task_id):
        put('resources','pivot:'+str(route['id']),route)
        put('relations','pivot_source:'+str(route['id']),{'from':'session:'+route['source_session'],
            'to':route['resource_ref'],'kind':'reached_via_ssh_forward','state':route['state']})
    for step in rows(db,'pm_coordinator_steps',task_id):
        decision=json.loads(step['decision_json'])
        section='plan' if step['status'] in ('planned','running','waiting_operator') else 'checks'
        put(section,'step:'+str(step['id']),{'step_id':step['id'],'phase':step['status'],
            'decision':decision,'error':step['error'],'outcome_uncertain':bool(step['outcome_uncertain']),
            'budget':json.loads(step['budgets_json']),
            'approved_at':step.get('approved_at'),'report_path':step.get('report_path')})
    for operation in rows(db,'pm_memory_operations',task_id):put('checks','operation:'+operation['id'],operation)
    return state


def sync(db,task_id,capability_log,*,reason,expected_version=None):
    """Reconcile validated source rows atomically, preserving annotations/history."""
    with atomic(db):
        initialize(db);head=current(db,task_id)
        if expected_version is not None and expected_version!=head['version']:raise VersionConflict('Task memory version conflict')
        target=db.execute('SELECT target FROM tasks WHERE id=?',(task_id,)).fetchone()[0]
        # Recover only an exact execution/result correlation written by the MCP
        # boundary. Similar output or a claimed model hash can never close it.
        for record in capability_records(task_id,capability_log,target):
            oid=record.get('memory_operation_id')
            if not oid:
                payload=record['result']
                if (record.get('provenance')!='network' or payload.get('cached') or
                        payload.get('status') not in ('completed','ok') or not record.get('argv')):continue
                try:description=canonical_operation(record['tool'],record['argv'],target,record.get('provenance'))
                except (ValueError,IndexError,TypeError):continue
                if description['repeatable_read']:continue
                signature=description['signature']
                if record.get('argv_truncated'):
                    if not re.fullmatch(r'[a-f0-9]{64}',str(record.get('argv_sha256',''))):continue
                    signature='raw:'+record['argv_sha256']
                db.execute('INSERT OR IGNORE INTO pm_memory_operations '
                    '(id,task_id,resource,operation,signature,parameters_json,conditions_sha256,phase,outcome,result_id,created_at) '
                    'VALUES(?,?,?,?,?,?,?,?,?,?,?)',('legacy:'+record['id'],task_id,description['resource'],record['tool'],
                        signature,encoded({'legacy_execution_ref':'execution:'+record['id']}),'legacy_conditions_unknown',
                        'finished','nonzero_exit' if payload.get('exit_code') not in (None,0) else payload['status'],
                        record['id'],record.get('timestamp') or now()))
                continue
            row=db.execute('SELECT phase FROM pm_memory_operations WHERE task_id=? AND id=? AND result_id IS NULL',
                           (task_id,oid)).fetchone()
            outcome=record['result'].get('status')
            if row and row[0] in ('dispatching','started','unknown') and outcome in ('completed','blocked','error','failed'):
                phase='cancelled' if record['result'].get('execution_started') is False else 'finished'
                outcome=record['result'].get('error_type') or outcome
                if outcome=='completed' and record['result'].get('exit_code') not in (None,0):outcome='nonzero_exit'
                db.execute('UPDATE pm_memory_operations SET phase=?,outcome=?,result_id=?,ended_at=? WHERE task_id=? AND id=?',
                           (phase,outcome,record['id'],now(),task_id,oid))
        incoming=source_state(db,task_id,capability_log);changes=[]
        for ref,entry in incoming['materials'].items():
            if entry['kind']=='report':
                body=material(db,task_id,ref,capability_log)
                db.execute('INSERT OR IGNORE INTO pm_memory_material_versions VALUES(?,?,?,?)',
                           (task_id,ref,entry['sha256'],body))
        for section in SECTIONS:
            for key,value in incoming[section].items():changes.append({'section':section,'key':key,'value':value})
            for key,value in head['state'][section].items():
                if value.get('source_owned') and key not in incoming[section]:changes.append({'section':section,'key':key,'value':None})
        return apply(db,task_id,head['version'],changes,reason=reason,actor='source_sync')


def material(db,task_id,reference,capability_log):
    found=db.execute('SELECT target FROM tasks WHERE id=?',(task_id,)).fetchone()
    if not found:raise ValueError('Unknown task')
    target=found[0]
    if re.fullmatch(r'file_material:\d+',reference):
        from orchestrator import material_processing
        return material_processing.load(db,task_id,reference)
    if re.fullmatch(r'result:[\w-]+',reference):
        record=next((r for r in capability_records(task_id,capability_log,target) if 'result:'+r['id']==reference),None)
        if record:return capability_text(record).encode()
    if re.fullmatch(r'execution:[\w-]+',reference):
        record=next((r for r in capability_records(task_id,capability_log,target) if 'execution:'+r['id']==reference),None)
        if record:return record['_memory_raw_line'].encode()
    match=re.fullmatch(r'report:(recon|vuln|access|verify):(\d+)',reference)
    if match:
        row=db.execute('SELECT report_json FROM pm_agent_action_reports WHERE task_id=? AND target=? AND role=? AND iteration=?',
                       (task_id,target,match[1],int(match[2]))).fetchone()
        if row:return row[0].encode()
    if re.fullmatch(r'network_result:\d+',reference):
        row=db.execute('SELECT r.result_json FROM network_job_runs r JOIN network_phase_plans p ON p.id=r.plan_id '
                       'WHERE r.id=? AND p.task_id=? AND p.target=?',(int(reference.split(':')[1]),task_id,target)).fetchone()
        if row and row[0] is not None:return row[0].encode()
    if re.fullmatch(r'tcp_scan_attempt:\d+',reference):
        row=db.execute('SELECT result_json FROM pm_tcp_full_scan_attempts WHERE id=? AND task_id=? AND target=?',
                       (int(reference.split(':')[1]),task_id,target)).fetchone()
        if row and row[0] is not None:return row[0].encode()
    match=re.fullmatch(r'browser_dom:(\d+)',reference)
    if match and exists(db,'pm_browser_actions'):
        row=db.execute('SELECT result_json FROM pm_browser_actions WHERE task_id=? AND id=?',(task_id,int(match[1]))).fetchone()
        if row:
            from orchestrator import http_artifacts
            return http_artifacts.load_material(task_id,json.loads(row[0])['dom_ref'])
    match=re.fullmatch(r'burp:([a-f0-9-]{36}):(\d+):(request|response)',reference)
    if match and exists(db,'pm_burp_messages'):
        row=db.execute('SELECT metadata_json FROM pm_burp_messages WHERE task_id=? AND instance_id=? AND message_id=?',
            (task_id,match[1],int(match[2]))).fetchone()
        if row:
            from orchestrator import http_artifacts
            return http_artifacts.load_material(task_id,json.loads(row[0])[match[3]+'_ref'])
    if re.fullmatch(r'http_artifact:\d+',reference):
        from orchestrator import http_artifacts
        aid=int(reference.split(':')[1])
        row=db.execute('SELECT target FROM pm_http_artifacts WHERE task_id=? AND id=?',(task_id,aid)).fetchone()
        if row and row[0]==target:
            body,_=http_artifacts.load(db,task_id,aid)
            return body
    raise ValueError('Unknown/foreign/missing material reference')


def read_chunk(db,task_id,reference,capability_log,*,offset=0,limit=CHUNK_BYTES,sha256=None):
    if type(offset) is not int or offset<0 or type(limit) is not int or not 1<=limit<=16384:raise ValueError('Invalid material range')
    archived=None
    if sha256 is not None and exists(db,'pm_memory_material_versions'):
        archived=db.execute('SELECT body FROM pm_memory_material_versions WHERE task_id=? AND reference=? AND sha256=?',
                            (task_id,reference,sha256)).fetchone()
    raw=bytes(archived[0]) if archived else material(db,task_id,reference,capability_log)
    checksum=hashlib.sha256(raw).hexdigest()
    if sha256 is not None and sha256!=checksum:raise VersionConflict('Material changed since context snapshot')
    if offset>len(raw):raise ValueError('Material offset past end')
    part=raw[offset:offset+limit]
    result={'reference':reference,'sha256':checksum,'offset':offset,'end':offset+len(part),'total_bytes':len(raw),
            'has_more':offset+len(part)<len(raw)}
    try:result.update(text_untrusted=part.decode('utf-8'),encoding='utf-8')
    except UnicodeDecodeError:
        result.update(text_untrusted=part.decode('utf-8',errors='replace'),encoding='binary or partial UTF-8',
                      data_b64=base64.b64encode(part).decode('ascii'))
    return result


def coverage(db,task_id,reference,sha256):
    if not exists(db,'pm_memory_coverage'):return []
    return [dict(zip(('start','end','kind','report_ref'),r)) for r in db.execute(
        'SELECT start_byte,end_byte,kind,report_ref FROM pm_memory_coverage WHERE task_id=? AND reference=? AND sha256=? '
        'ORDER BY start_byte,end_byte',(task_id,reference,sha256))]


def record_coverage(db,task_id,chunk,*,kind,report_ref='',expected_version=None):
    if kind not in ('delivered','agent_reported_analysis'):raise ValueError('Invalid coverage kind')
    if kind=='agent_reported_analysis' and not report_ref:raise ValueError('Analysis needs saved report reference')
    with atomic(db):
        initialize(db);head=current(db,task_id)
        if expected_version is not None and expected_version!=head['version']:raise VersionConflict('Task memory version conflict')
        inserted=db.execute('INSERT OR IGNORE INTO pm_memory_coverage VALUES(?,?,?,?,?,?,?,?)',
            (task_id,chunk['reference'],chunk['sha256'],chunk['offset'],chunk['end'],kind,report_ref,now())).rowcount
        if inserted:
            apply(db,task_id,head['version'],[{'section':'coverage','key':chunk['reference']+':'+chunk['sha256'],
                'value':{'reference':chunk['reference'],'sha256':chunk['sha256'],
                         'ranges':coverage(db,task_id,chunk['reference'],chunk['sha256'])}}],reason='material_range_'+kind,actor='material_delivery')


@consistent_read
def context(db,task_id,capability_log,*,references=(),question=''):
    """All substantial structured knowledge; only relevant original byte ranges."""
    source=source_state(db,task_id,capability_log);head=current(db,task_id)
    source_counts={key:len(value) for key,value in source.items()}
    for section,items in head['state'].items():
        for key,value in items.items():
            if not value.get('source_owned'):source[section][key]=value
    # Completed action history is navigable separately. Its semantic aggregate
    # retains every original reference without repeating IDs/times/command text.
    check_groups={}
    for key,value in source['checks'].items():
        if value.get('operation_signature'):
            shape={k:value.get(k) for k in ('operation','operation_signature','outcome','exit_code',
                                           'provenance','observation_sha256','execution_started','server_outcome')}
        elif key.startswith('operation:'):
            shape={k:value.get(k) for k in ('operation','resource','signature','conditions_sha256','phase','outcome')}
        else:shape={k:v for k,v in value.items() if k not in ('source_owned',)}
        group=check_groups.setdefault(digest(shape),{**shape,'references':[]})
        group['references'].append(key)
    source['checks']={'groups':list(check_groups.values()),'total_records':len(source['checks']),
                      'history_table':'pm_memory_operations / capability_log / pm_coordinator_steps'}
    # Aggregate identical scan evidence in code. All port identities and sources
    # remain addressable; the context does not repeat the whole scan per port.
    groups={};resources={}
    for key,value in source['resources'].items():
        if key.startswith('service:'):
            shape={k:value.get(k) for k in ('target','protocol','state','identification_uncertain','identification_conflict')}
            shape['identifications']=[{k:v for k,v in item.items() if k!='source'} for item in value['identifications']]
            group=groups.setdefault(digest(shape),{**shape,'ports':[],'references':[]})
            group['ports'].append(value['port']);group['references'].append(key)
            if key in references:
                references=tuple(references)+tuple('result:'+s['result_id'] for s in value['sources'] if s.get('result_id'))
                references+=tuple('network_result:'+str(s['run_id']) for s in value['sources'] if s.get('run_id'))
                references+=tuple('tcp_scan_attempt:'+str(s['attempt_id']) for s in value['sources'] if s.get('attempt_id'))
        else:
            resources[key]=value
            if key in references and value.get('last_probe_result_id'):
                references=tuple(references)+('result:'+value['last_probe_result_id'],)
    materials=source.pop('materials');relevant=[]
    tokens=set(re.findall(r'[\w./:-]{3,}',question.casefold()))
    for ref,item in materials.items():
        rank=0 if ref in references else 1 if tokens & set(re.findall(r'[\w./:-]{3,}',str(item.get('summary',item.get('name',item.get('path','')))).casefold())) else 2
        if rank<2:relevant.append((rank,ref,item))
    chunks=[]
    for _,ref,item in sorted(relevant)[:4]:
        analyzed=coverage(db,task_id,ref,item['sha256']);offset=0
        for record in analyzed:
            if record['kind']=='agent_reported_analysis' and record['start']<=offset:offset=max(offset,record['end'])
        complete=offset>=item['bytes']
        if complete:offset=0
        try:chunks.append({**read_chunk(db,task_id,ref,capability_log,offset=offset,sha256=item['sha256']),
                           'prior_reported_analysis_complete':complete})
        except (OSError,ValueError) as exc:chunks.append({'reference':ref,'error':type(exc).__name__,'available':False})
    # The complete index has every material, not a last-N-report window. Long
    # summaries point to the unchanged original and disclose omitted characters.
    index={}
    for ref,item in materials.items():
        summary=str(item.get('summary',''))
        index[ref]={**{k:item[k] for k in ('kind','sha256','bytes','tool','quality','path','complete') if k in item},
                    'summary':summary[:300],'summary_omitted_characters':max(0,len(summary)-300)}
    source['resources']=resources
    return {'version':head['version'],'source_state_sha256':digest([source,groups,index]),'state':source,
            'service_groups':list(groups.values()),'material_index':index,'relevant_materials':chunks,
            'source_counts':source_counts,
            'relevant_materials_omitted':max(0,len(relevant)-len(chunks)),
            'history':{'table':'pm_memory_revisions','latest_version':head['version']},
            'coverage_note':'Delivered bytes are not analyzed bytes. Agent-reported analysis is not a new observation.'}


def analysis_context(db,task_id):
    """Task memory for metadata-only legacy analysis; no response bodies/secrets."""
    if not exists(db,'tasks') or not db.execute('SELECT 1 FROM tasks WHERE id=?',(task_id,)).fetchone():
        return {'available':False,'reason':'no_persisted_task_in_supplied_database'}
    filename=next((r[2] for r in db.execute('PRAGMA database_list') if r[1]=='main'),None)
    log=Path(filename).parent/'capability_log'/f'task_{task_id}.jsonl' if filename else None
    view=context(db,task_id,log);state=view['state']
    return {'version':view['version'],'mode':'metadata_only','source_state_sha256':view['source_state_sha256'],
        'goals':state['goals'],'constraints':state['constraints'],'service_groups':view['service_groups'],
        'access':{key:{k:v for k,v in item.items() if k not in ('summary','quote')} for key,item in state['access'].items()},
        'credential_candidates':{key:{k:v for k,v in item.items() if k in ('kind','status','last_probe_result_id','trust')}
                                 for key,item in state['credentials'].items()},
        'claim_index':{key:{k:v for k,v in item.items() if k in ('kind','status','probe_result_id','report_ref')}
                      for section in ('observations','resolved_claims','questions','refutations') for key,item in state[section].items()},
        'material_index':{key:{k:v for k,v in item.items() if k!='summary'} for key,item in view['material_index'].items()},
        'sessions':state['sessions'],'plan':state['plan'],'source_counts':view['source_counts']}


def canonical_operation(tool,command,target,provenance='network'):
    """Canonical executable input, never the model's wording/result ID/time."""
    argv=list(map(str,command));params={};inner=None
    transient={'--task-id','--timeout','--wait','--idle','--new-evidence-id','--hypothesis-key',
               '--owner','--owner-pid','--purpose','--username','--resource'}
    i=0
    while i<len(argv):
        token=argv[i]
        if token=='--argv-json' and i+1<len(argv):
            try:inner=json.loads(argv[i+1])
            except ValueError:inner=argv[i+1]
            i+=2;continue
        if token.startswith('--') and token!='--execute':
            value=argv[i+1] if i+1<len(argv) and not argv[i+1].startswith('--') else True
            if token not in transient:params[token]=value
            i+=2 if value is not True else 1;continue
        i+=1
    ports=[];path=params.get('--path');protocol='tcp'
    if isinstance(inner,list) and inner:
        executable=Path(str(inner[0])).name
        cleaned=[executable];j=1
        while j<len(inner):
            item=str(inner[j])
            if executable=='nmap' and item in ('-oN','-oX','-oG','-oA') or executable=='curl' and item in ('-o','--output'):
                j+=2;continue
            if executable=='nmap' and (item=='-p' or item.startswith('-p') and item[2:]):
                raw=str(inner[j+1]) if item=='-p' and j+1<len(inner) else item[2:]
                canonical=','.join(sorted(set(raw.split(','))))
                ports.extend(int(p) for p in canonical.split(',') if p.isdigit())
                cleaned+=['-p',canonical];j+=2 if item=='-p' else 1;continue
            if executable=='curl' and item.startswith(('http://','https://')):
                from urllib.parse import urlsplit
                url=urlsplit(item);protocol=url.scheme;ports.append(url.port or (443 if url.scheme=='https' else 80));path=url.path or '/'
            cleaned.append(item);j+=1
        inner=cleaned
    if str(params.get('--port','')).isdigit():ports.append(int(params['--port']))
    if inner is not None:params['argv']=inner
    elif not params:params['argv']=argv # conservative for unknown helper protocols
    # Scope/port/path identify the resource; significant payload stays in params.
    resource=encoded({'target':params.get('--target',target),'ports':sorted(set(ports)),'protocol':protocol,'path':path,
                      'session_id':params.get('--session-id')})
    # Origin is evidence metadata, not permission to replay arbitrary local code.
    # Only known buffer/index readers bypass execution deduplication.
    safe_session_bootstrap=(tool=='session' and params.get('--action')=='open' and not params.get('--ssh-json')
        and inner in (None,[],['/bin/bash','--noprofile','--norc','-i']))
    repeatable_read=(safe_session_bootstrap or tool in ('capability_read','evidence_index','observations') or
        tool=='session' and params.get('--action') in ('read','list') or
        tool in ('callback','transfer') and params.get('--action') in ('read','diagnose'))
    local=provenance=='local' or repeatable_read or tool=='worknote'
    return {'resource':resource,'operation':tool,'parameters':params,'local':local,
            'repeatable_read':repeatable_read,
            'ports':sorted(set(ports)),
            'raw_signature':'raw:'+hashlib.sha256(json.dumps(argv,ensure_ascii=False,separators=(',',':')).encode()).hexdigest(),
            'signature':digest([resource,tool,params])}


def begin_operation(db,task_id,description,*,conditions=None,require_fresh=False,allow_unknown=False,reason=''):
    """Intent is durable before dispatch. Unknown execution needs explicit review.

    require_fresh is an explicit caller policy, not inferred from model prose.
    allow_unknown is for an operator-controlled continuation, never automatic.
    """
    with atomic(db):
        initialize(db)
        if not exists(db,'tasks') or not db.execute('SELECT 1 FROM tasks WHERE id=?',(task_id,)).fetchone():
            raise ValueError('Unknown task')
        old=db.execute('SELECT id,phase,conditions_sha256,created_at,outcome FROM pm_memory_operations '
                       'WHERE task_id=? AND signature IN (?,?) ORDER BY rowid DESC LIMIT 1',
                       (task_id,description['signature'],description.get('raw_signature',''))).fetchone()
        condition_hash=digest(conditions or {})
        if old and not description.get('repeatable_read',False):
            if old[1] in ('dispatching','started','unknown') and not (allow_unknown and reason.strip()):
                return {'allowed':False,'reason':'previous_outcome_unknown','previous_operation':old[0]}
            if old[1]=='finished' and old[2] in (condition_hash,'legacy_conditions_unknown') and not (require_fresh and reason.strip()):
                return {'allowed':False,'reason':'repeated_operation_without_new_conditions','previous_operation':old[0]}
        oid=uuid.uuid4().hex
        public={key:value if key in ('--target','--port','--ports','--profile','--scheme','--action','--session-id')
                else {'sha256':digest(value),'characters':len(encoded(value))}
                for key,value in description['parameters'].items()}
        if isinstance(description['parameters'].get('argv'),list) and description['parameters']['argv']:
            public['executable']=Path(str(description['parameters']['argv'][0])).name
        db.execute('INSERT INTO pm_memory_operations '
            '(id,task_id,resource,operation,signature,parameters_json,conditions_sha256,phase,created_at) '
            'VALUES(?,?,?,?,?,?,?,?,?)',(oid,task_id,description['resource'],description['operation'],description['signature'],
                                         encoded(public),condition_hash,'intent',now()))
        return {'allowed':True,'operation_id':oid}


def transition(db,task_id,operation_id,phase,*,expected_phase,outcome='',result_id=None):
    allowed={'intent':{'dispatching','started','cancelled'},'dispatching':{'started','unknown','cancelled'},
             'started':{'finished','unknown','cancelled'},'unknown':{'finished'}}
    if phase not in allowed.get(expected_phase,set()):raise ValueError('Invalid operation transition')
    with atomic(db):
        fields='phase=?,outcome=?,result_id=?';values=[phase,outcome,result_id]
        if phase=='started':fields+=',started_at=?';values.append(now())
        if phase in ('finished','cancelled'):fields+=',ended_at=?';values.append(now())
        if phase=='cancelled':fields+=',started_at=NULL'
        cursor=db.execute('UPDATE pm_memory_operations SET '+fields+' WHERE task_id=? AND id=? AND phase=?',
                          (*values,task_id,operation_id,expected_phase))
        if cursor.rowcount!=1:raise VersionConflict('Operation phase conflict')
