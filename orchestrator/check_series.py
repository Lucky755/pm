"""Typed bounded HTTP checks, not an opaque script counted as one iteration.

Authentication: one explicit saved credential pair per check, stop on success
or five rejections. Paths: one predeclared request/time/result-bounded series;
five unproductive series require a new saved coordinator plan with new inputs.
"""
import hashlib
import json
import os
import re
import time
import uuid
from contextvars import ContextVar
from urllib.parse import unquote,urlsplit
from orchestrator import task_memory,diagnostics,http_client,http_artifacts
ACTIVE=ContextVar('pm_check_series_active',default=False)
DEADLINE=ContextVar('pm_check_series_deadline',default=None)


def initialize(db):
    db.execute('''CREATE TABLE IF NOT EXISTS pm_check_directions (
        id TEXT PRIMARY KEY,task_id INTEGER NOT NULL,kind TEXT NOT NULL,resource TEXT NOT NULL,
        state TEXT NOT NULL,failures INTEGER NOT NULL DEFAULT 0,plan_step INTEGER)''')
    db.execute('''CREATE TABLE IF NOT EXISTS pm_check_series (
        id TEXT PRIMARY KEY,task_id INTEGER NOT NULL,direction_id TEXT NOT NULL,plan_json TEXT NOT NULL,
        phase TEXT NOT NULL,elapsed REAL NOT NULL DEFAULT 0,result_json TEXT)''')
    db.execute('''CREATE TABLE IF NOT EXISTS pm_internal_checks (
        id TEXT PRIMARY KEY,task_id INTEGER NOT NULL,direction_id TEXT NOT NULL,series_id TEXT NOT NULL,
        identity TEXT NOT NULL,phase TEXT NOT NULL,outcome TEXT,result_json TEXT,
        UNIQUE(task_id,direction_id,identity))''')


def validate(db,task_id,plan,capability_log):
    fields={'kind','url','hypothesis','max_requests','seconds','criterion','pairs','paths','replan','session_id'}
    if not isinstance(plan,dict) or set(plan)-fields or not {'kind','url','hypothesis','max_requests','seconds','criterion'}<=set(plan):raise ValueError('Incomplete bounded-check plan')
    if plan['kind'] not in ('authentication','paths','traversal'):raise ValueError('Unsupported check kind')
    if not isinstance(plan['hypothesis'],str) or not plan['hypothesis'].strip():raise ValueError('Concrete hypothesis required')
    if type(plan['max_requests']) is not int or not 1<=plan['max_requests']<=50:raise ValueError('Request bound must be 1..50')
    if type(plan['seconds']) is not int or not 1<=plan['seconds']<=600:raise ValueError('Series time must be 1..600 seconds')
    if 'replan' in plan and type(plan['replan']) is not bool:raise ValueError('replan must be a boolean')
    if not re.fullmatch(r'[A-Za-z0-9_.-]{1,64}',str(plan.get('session_id','default'))):raise ValueError('Invalid web session')
    criterion=plan['criterion']
    if not isinstance(criterion,dict) or set(criterion)-{'kind','status','body_contains','sha256'}:raise ValueError('Invalid result criterion')
    if criterion.get('kind') not in ('find_file','inventory','authenticated'):raise ValueError('Explicit result criterion required')
    if (not isinstance(criterion.get('status'),list) or not criterion['status'] or
            any(type(v) is not int or not 100<=v<=599 for v in criterion['status'])):raise ValueError('Explicit response statuses required')
    if criterion['kind']!='inventory' and not (criterion.get('body_contains') or criterion.get('sha256')):raise ValueError('HTTP status alone is not a decisive criterion')
    if 'body_contains' in criterion and (not isinstance(criterion['body_contains'],str) or not 1<=len(criterion['body_contains'])<=4096):raise ValueError('Invalid expected body marker')
    if 'sha256' in criterion and not re.fullmatch(r'[a-f0-9]{64}',str(criterion['sha256'])):raise ValueError('Invalid expected content hash')
    base,target=http_client.endpoint(db,task_id,plan['url'])
    if base['fragment']:raise ValueError('HTTP check URL must not contain a browser fragment')
    items=[]
    if plan['kind']=='authentication':
        if criterion['kind']!='authenticated' or 'paths' in plan:raise ValueError('Authentication criterion/pairs required')
        pairs=plan.get('pairs')
        if not isinstance(pairs,list) or not 1<=len(pairs)<=5 or len(pairs)>plan['max_requests']:raise ValueError('One to five explicit pairs; no Cartesian product or dictionary')
        for item in pairs:
            if not isinstance(item,dict) or set(item)!={'username','password','source_ref'} or any(not isinstance(v,str) or not v for v in item.values()):raise ValueError('Saved credential pair/source required')
            original=task_memory.material(db,task_id,item['source_ref'],capability_log)
            if any(item[k].encode() not in original for k in ('username','password')):raise ValueError('Credential pair is not present in cited material')
            items.append({'url':plan['url'],'auth':{'type':'basic','username':item['username'],'password':item['password']}})
    else:
        if criterion['kind']=='authenticated' or 'pairs' in plan:raise ValueError('Path hypothesis needs path criterion')
        paths=plan.get('paths')
        if not isinstance(paths,list) or not paths or len(paths)>plan['max_requests'] or any(not isinstance(p,str) or not p.startswith('/') or p.startswith('//') for p in paths):raise ValueError('Explicit bounded origin-relative paths required')
        for path in paths:
            url=base['origin']+path;http_client.endpoint(db,task_id,url,target)
            items.append({'url':http_client.endpoint(db,task_id,url,target)[0]['request_url']})
    return base['origin']+(urlsplit(plan['url']).path if plan['kind']=='authentication' else '')+' via '+target,items


def identities_for(db,task_id,plan,items):
    if plan['kind']=='authentication':
        return [task_memory.digest([item,http_client.endpoint(db,task_id,item['url'])[1]]) for item in items]
    state={'auth':{},'cookies':[]}
    if task_memory.exists(db,'pm_http_sessions'):_,state,_=http_client.session_state(db,task_id,plan.get('session_id','default'))
    values=[]
    for item in items:
        url,target=http_client.endpoint(db,task_id,item['url'])
        values.append(task_memory.digest([item,target,state['auth'].get(url['origin']),http_client.cookie_header(state,url)]))
    return values


def state(db,task_id):
    if not task_memory.exists(db,'pm_check_directions'):return []
    return [dict(zip(('id','kind','resource','state','failures','plan_step'),row)) for row in db.execute(
        'SELECT id,kind,resource,state,failures,plan_step FROM pm_check_directions WHERE task_id=? ORDER BY id',(task_id,))]


def matches(criterion,item,body,status,full):
    met=bool(full and status in criterion['status'])
    marker=criterion.get('body_contains')
    if marker:
        contaminated=unquote(item['url'])+' '+json.dumps(item.get('auth',{}),ensure_ascii=False)
        met=met and marker.encode() in body and marker not in contaminated
    if criterion.get('sha256'):met=met and hashlib.sha256(body).hexdigest()==criterion['sha256']
    return bool(met)


def reuse(db,task_id,item,value,criterion):
    try:
        body,audit=http_client.audit_saved_check(db,task_id,item,value)
        return {**value,**audit,'criterion_matched':matches(criterion,item,body,audit['status_code'],audit['source_complete']),
            'reused':True,'requests_sent':0}
    except (ValueError,OSError,KeyError,TypeError) as exc:
        reason=str(exc) if str(exc).startswith('saved_http_') else 'saved_http_integrity_failed'
        return {**value,'criterion_matched':False,'source_complete':False,'reused':True,
            'requests_sent':0,'execution_started':False,'audit_error':reason}


def direct_http(db,task_id,request,session_id,request_limit=6):
    """Explicit Basic trials also obey the five-refusal guard.

    Ordinary use of a saved authenticated session is not another credential
    trial. A generic 200 remains unresolved; the typed series declares its
    positive criterion. No prose/denial blacklist determines authentication.
    """
    auth=request.get('auth') if isinstance(request,dict) else None
    if ACTIVE.get() or not os.environ.get('PM_BUDGET_ROLE') or not isinstance(auth,dict) or auth.get('type')!='basic':
        return http_client.execute(db,task_id,request,session_id,request_limit=request_limit,deadline=DEADLINE.get())
    url,target=http_client.endpoint(db,task_id,request['url']);initialize(db)
    resource=url['origin']+urlsplit(request['url']).path+' via '+target;direction=task_memory.digest([task_id,'authentication',resource])
    row=db.execute('SELECT state,failures FROM pm_check_directions WHERE id=?',(direction,)).fetchone()
    if row and (row[1]>=5 or row[0] in ('unknown','succeeded')):
        return {'status':'replan_required','execution_started':False,'reason_category':'authentication_direction_stopped',
            'reason':'Five refusals, prior success or unknown outcome: use saved results/session and a new justified coordinator plan'}
    identity=task_memory.digest([{'url':request['url'],'auth':auth},target])
    if db.execute('SELECT 1 FROM pm_internal_checks WHERE task_id=? AND direction_id=? AND identity=?',(task_id,direction,identity)).fetchone():
        return {'status':'blocked','execution_started':False,'reason_category':'repeat_guard','reason':'This concrete pair was already checked; reuse its result/session'}
    ident=uuid.uuid4().hex;series='direct-'+ident
    with db:
        db.execute("INSERT OR IGNORE INTO pm_check_directions VALUES(?,?,'authentication',?,'active',0,?)",(direction,task_id,resource,int(os.environ.get('PM_COORDINATOR_STEP_ID') or 0)))
        db.execute("INSERT INTO pm_check_series(id,task_id,direction_id,plan_json,phase) VALUES(?,?,?,?,'running')",(series,task_id,direction,task_memory.encoded({'kind':'one_explicit_pair'})))
        db.execute("INSERT INTO pm_internal_checks VALUES(?,?,?,?,?,'started',NULL,NULL)",(ident,task_id,direction,series,identity))
    diagnostics.emit('check.start',task_id=task_id,identifiers={'check_id':ident,'series_id':series},parameters={'kind':'authentication'})
    def finish(value):
        with db:
            db.execute('UPDATE pm_internal_checks SET phase=?,outcome=?,result_json=? WHERE id=?',(value['phase'],value['outcome'],task_memory.encoded(value),ident))
            db.execute('UPDATE pm_check_series SET phase=?,result_json=? WHERE id=?',(value['phase'],task_memory.encoded(value),series))
            if value['phase']=='unknown':db.execute("UPDATE pm_check_directions SET state='unknown' WHERE id=?",(direction,))
            if value['outcome']=='server_refusal':
                db.execute('UPDATE pm_check_directions SET failures=failures+1 WHERE id=?',(direction,))
                db.execute("UPDATE pm_check_directions SET state='exhausted' WHERE id=? AND failures>=5",(direction,))
        diagnostics.emit('check.end',task_id=task_id,identifiers={'check_id':ident,'series_id':series},status=value['outcome'])
    try:reply=http_client.execute(db,task_id,request,session_id,request_limit=request_limit)
    except BaseException:
        finish({'phase':'unknown','outcome':'unknown'});raise
    full=reply.get('transport_complete')
    refused=reply.get('status_code') in (401,403) and full
    not_started=reply.get('status')=='blocked' and not reply.get('exchange_id')
    value={'phase':'finished' if full or not_started else 'unknown','outcome':'server_refusal' if refused else 'refused_before_execution' if not_started else 'interpretation_required' if full else 'unknown',
        'exchange_id':reply.get('exchange_id'),'artifact_ref':reply.get('artifact_ref'),'status_code':reply.get('status_code'),
        'source_complete':bool(full and not reply.get('body_truncated') and not reply.get('wire_truncated')),
        'session_id':session_id,'request_url':request['url'],'task_id':task_id,'target':target}
    finish(value)
    return {**reply,'internal_check':{'check_id':ident,'direction_id':direction,**value}}


def run(db,task_id,plan,capability_log,request=None):
    from orchestrator import target_availability
    target_availability.require_network(db,task_id)
    resource,items=validate(db,task_id,plan,capability_log);initialize(db)
    family='authentication' if plan['kind']=='authentication' else 'paths'
    direction=task_memory.digest([task_id,family,resource])
    identities=identities_for(db,task_id,plan,items)
    # Neither hypothesis wording, time nor a new ID creates a new check.
    series=task_memory.digest([direction,identities,plan['criterion']])
    row=db.execute('SELECT state,failures,plan_step FROM pm_check_directions WHERE id=?',(direction,)).fetchone()
    if row and row[0]=='unknown':
        return {'status':'outcome_unknown','direction_id':direction,'direction_result':row[0],
                'cached':True,'execution_started':False,'checks':[]}
    saved=db.execute('SELECT phase,result_json FROM pm_check_series WHERE task_id=? AND id=?',(task_id,series)).fetchone()
    if saved:
        if saved[0]=='completed':
            result=json.loads(saved[1])
            checks=[reuse(db,task_id,item,value,plan['criterion']) for item,value in zip(items,result['checks'])]
            invalid=any(c.get('audit_error') for c in checks)
            return {**result,'checks':checks,'cached':True,'checks_started':0,'requests_sent':0,'execution_started':False,
                'criterion_matched':not invalid and any(c['criterion_matched'] for c in checks),
                **({'status':'blocked','direction_result':'saved_evidence_audit_failed'} if invalid else {})}
        return {'status':'outcome_unknown','direction_result':'interrupted_series_no_replay','series_id':series,'execution_started':False}
    if row and row[0]=='succeeded' and family=='authentication':
        return {'status':'completed','direction_id':direction,'direction_result':'prior_criterion_satisfied',
            'criterion_matched':False,'goal_confirmed':False,'cached':True,'execution_started':False,'checks':[]}
    current_step=int(os.environ.get('PM_COORDINATOR_STEP_ID') or 0)
    if row and row[1]>=5:
        decision=None
        if current_step and plan.get('replan') and current_step!=row[2] and task_memory.exists(db,'pm_coordinator_steps'):
            step=db.execute("SELECT decision_json FROM pm_coordinator_steps WHERE task_id=? AND id=? AND status='running'",(task_id,current_step)).fetchone()
            if step:decision=json.loads(step[0])
        if not decision or not decision.get('reason'):
            return {'status':'replan_required','direction_result':'five_unproductive_units','direction_id':direction,'execution_started':False}
        if any(db.execute('SELECT 1 FROM pm_internal_checks WHERE task_id=? AND direction_id=? AND identity=?',(task_id,direction,identity)).fetchone() for identity in identities):
            raise ValueError('New coordinator plan must change substantive checks; old pairs/paths are not replayed')
        db.execute("UPDATE pm_check_directions SET failures=0,state='active',plan_step=? WHERE id=?",(current_step,direction));db.commit()
    with db:
        db.execute("INSERT OR IGNORE INTO pm_check_directions VALUES(?,?,?,?,'active',0,?)",(direction,task_id,plan['kind'],resource,current_step or None))
        db.execute("INSERT INTO pm_check_series(id,task_id,direction_id,plan_json,phase) VALUES(?,?,?,?,'running')",(series,task_id,direction,task_memory.encoded(plan)))
    start=time.monotonic();results=[];matched=False;unknown=False;new_checks=0
    for index,(item,identity) in enumerate(zip(items,identities)):
        if time.monotonic()-start>=plan['seconds']:break
        remaining_requests=plan['max_requests']-sum(r.get('requests_sent',0) for r in results)
        if remaining_requests<=0:break
        old=db.execute('SELECT phase,result_json FROM pm_internal_checks WHERE task_id=? AND direction_id=? AND identity=?',(task_id,direction,identity)).fetchone()
        if old:
            if old[0]!='finished':unknown=True;break
            value=reuse(db,task_id,item,json.loads(old[1]),plan['criterion'])
            # Re-evaluate the current criterion against original saved bytes,
            # never inherit a different series' successful inventory criterion.
            results.append(value)
            if value.get('audit_error'):break
            if value['criterion_matched'] and plan['criterion']['kind']!='inventory':matched=True;break
            continue
        ident=uuid.uuid4().hex
        with db:db.execute("INSERT INTO pm_internal_checks VALUES(?,?,?,?,?,'started',NULL,NULL)",(ident,task_id,direction,series,identity))
        diagnostics.emit('check.start',task_id=task_id,identifiers={'check_id':ident,'series_id':series},parameters={'kind':plan['kind'],'index':index+1})
        try:
            remaining=max(1,int(plan['seconds']-(time.monotonic()-start)))
            session='checks-'+identity[:32] if plan['kind']=='authentication' else plan.get('session_id','default')
            call=request or (lambda value,name,bound:http_client.execute(db,task_id,value,name,request_limit=bound,deadline=start+plan['seconds']))
            token=ACTIVE.set(True)
            deadline_token=DEADLINE.set(start+plan['seconds'])
            try:reply=call({**item,'method':'GET','timeout':min(25,remaining)},session,min(6,remaining_requests))
            finally:DEADLINE.reset(deadline_token);ACTIVE.reset(token)
            body,_=http_artifacts.load(db,task_id,reply['artifact_id']) if reply.get('artifact_id') else (b'',{})
            full=bool(reply.get('transport_complete') and not reply.get('body_truncated'))
            met=matches(plan['criterion'],item,body,reply.get('status_code'),full)
            value={'check_id':ident,'index':index+1,'phase':'finished' if full else 'unknown',
                'outcome':'criterion_matched' if met else 'negative' if full else 'unknown',
                'status_code':reply.get('status_code'),'exchange_id':reply.get('exchange_id'),'artifact_ref':reply.get('artifact_ref'),
                'result_id':reply.get('result_id'),
                'http_stop_reason':reply.get('stop_reason'),'http_status':reply.get('status'),
                'requests_sent':len(reply.get('chain') or []),
                'body_sha256':hashlib.sha256(body).hexdigest(),'session_id':session,'source_complete':full,'criterion_matched':bool(met)}
            if reply.get('execution_started') is False or reply.get('status')=='blocked' and not reply.get('exchange_id'):
                value.update(phase='finished',outcome='refused_before_execution',execution_started=False)
        except (ValueError,OSError,RuntimeError) as exc:
            value={'check_id':ident,'index':index+1,'phase':'unknown','outcome':'unknown','error_type':type(exc).__name__,'criterion_matched':False}
        if value.get('execution_started') is not False:new_checks+=1
        results.append(value)
        with db:
            db.execute('UPDATE pm_internal_checks SET phase=?,outcome=?,result_json=? WHERE id=?',(value['phase'],value['outcome'],task_memory.encoded(value),ident))
            if plan['kind']=='authentication' and value['outcome']=='negative':db.execute('UPDATE pm_check_directions SET failures=failures+1 WHERE id=?',(direction,))
        diagnostics.emit('check.end',task_id=task_id,identifiers={'check_id':ident,'series_id':series},status=value['outcome'])
        if value['phase']=='unknown':unknown=True;break
        if value.get('execution_started') is False:break
        if value['criterion_matched'] and plan['criterion']['kind']!='inventory':matched=True;break
        if plan['kind']=='authentication' and db.execute('SELECT failures FROM pm_check_directions WHERE id=?',(direction,)).fetchone()[0]>=5:break
    not_started=sum(r.get('execution_started') is False for r in results)
    complete=len(results)==len(items) and not not_started or matched
    useful=matched or any(r['criterion_matched'] for r in results)
    with db:
        if unknown:db.execute("UPDATE pm_check_directions SET state='unknown' WHERE id=?",(direction,))
        elif matched:db.execute("UPDATE pm_check_directions SET state='succeeded' WHERE id=?",(direction,))
        elif complete and not useful and plan['kind']!='authentication' and new_checks:
            db.execute('UPDATE pm_check_directions SET failures=failures+1 WHERE id=?',(direction,))
        failures=db.execute('SELECT failures FROM pm_check_directions WHERE id=?',(direction,)).fetchone()[0]
        if failures>=5:db.execute("UPDATE pm_check_directions SET state='exhausted' WHERE id=?",(direction,))
        result={'status':'outcome_unknown' if unknown else 'blocked' if not_started else 'completed' if complete else 'partial',
            'task_id':task_id,'direction_id':direction,'series_id':series,'checks':results,'checks_started':new_checks,
            'checks_recorded':len(results),'unchecked':len(items)-len(results)+not_started,'failures':failures,'criterion_matched':useful,'goal_confirmed':False,
            'requests_sent':sum(r.get('requests_sent',0) for r in results),
            'direction_result':'unknown' if unknown else 'criterion_satisfied' if matched else 'replan_required' if failures>=5 else 'inventory_completed' if complete and useful else 'no_decisive_result',
            'provenance':'network' if new_checks else 'local','cached':not new_checks,
            'credential_acceptance':'criterion_matched_access_not_established' if matched and plan['kind']=='authentication' else None}
        db.execute("UPDATE pm_check_series SET phase=?,elapsed=?,result_json=? WHERE id=?",('unknown' if unknown else 'completed',time.monotonic()-start,task_memory.encoded(result),series))
    return result


def poc_events(payload):
    """Self-reported events from cooperating PoCs, never universal measurement."""
    events=[];invalid=0
    for line in str(payload.get('stdout','')).splitlines():
        if not line.startswith('PM_CHECK '):continue
        try:
            item=json.loads(line[9:])
            if not isinstance(item,dict) or item.get('phase') not in ('start','end') or not isinstance(item.get('check_id'),str):raise ValueError('Invalid event')
            events.append({k:item[k] for k in ('phase','check_id','kind','outcome') if k in item})
        except (ValueError,TypeError):invalid+=1
    return {'source':'poc_self_report' if events else 'unmeasured','universal_measurement':False,
        'started':len({e['check_id'] for e in events if e['phase']=='start'}),
        'finished':len({e['check_id'] for e in events if e['phase']=='end'}),'invalid_events':invalid,
        'output_truncated':bool(payload.get('stdout_truncated') or payload.get('output_truncated'))}


def instrument_python(source):
    """Explicit source transformation; caller preserves the unmodified source."""
    import ast
    tree=ast.parse(source);line=0
    for node in tree.body:
        if (isinstance(node,ast.ImportFrom) and node.module=='__future__' or
                isinstance(node,ast.Expr) and isinstance(node.value,ast.Constant) and isinstance(node.value.value,str)):
            line=node.end_lineno
        else:break
    lines=source.splitlines(keepends=True)
    prelude='''\n# PM cooperating-PoC instrumentation, self-reported, not a permission grant.
def pm_check_start(check_id, kind):
    import json
    print('PM_CHECK '+json.dumps({'phase':'start','check_id':str(check_id),'kind':kind}),flush=True)
def pm_check_end(check_id, outcome):
    import json
    print('PM_CHECK '+json.dumps({'phase':'end','check_id':str(check_id),'outcome':outcome}),flush=True)
'''
    return ''.join(lines[:line])+prelude+''.join(lines[line:])
