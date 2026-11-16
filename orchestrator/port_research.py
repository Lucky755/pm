"""Programmatic discovery/availability aggregation over the existing job queue."""
import json
import re
from orchestrator import network_jobs as jobs,target_availability

STATES=('open','closed','filtered','open|filtered','timeout','unchecked')

def nmap_summary(stdout,protocol='tcp',requested=65535,complete=False):
    from collections import Counter
    found={int(p):state for p,proto,state in re.findall(r'(?m)^(\d+)/(tcp|udp)\s+(open\|filtered|open|closed|filtered)\s+',stdout)
        if proto==protocol and 1<=int(p)<=65535}
    counts=Counter(found.values());grouped={}
    if complete:
        for count,state in re.findall(r'(?i)(\d+)\s+(closed|filtered|open\|filtered)(?:\s+(?:tcp|udp))?\s+ports',stdout):
            grouped[state]=grouped.get(state,0)+int(count)
        if sum(grouped.values())+len(found)>requested:grouped={}
    counts.update(grouped)
    return {'purpose':'discovery','protocol':protocol,'requested_ports':requested,'counts':dict(counts),
        'unchecked_or_unclassified':max(0,requested-sum(counts.values())),
        'transport_completed':complete,'exhaustive_services':False,'product_identified':False}

def initialize(db):
    jobs.initialize(db)
    db.execute('''CREATE TABLE IF NOT EXISTS pm_port_preflight (
        task_id INTEGER NOT NULL,target TEXT NOT NULL,port INTEGER NOT NULL,state TEXT NOT NULL,
        result_json TEXT NOT NULL,checked_at TEXT,PRIMARY KEY(task_id,target,port))''')
    db.commit()

def parse(stdout,protocol,selected,*,complete=True):
    observed={}
    for match in re.finditer(r'(?m)^(\d+)/(tcp|udp)\s+(open\|filtered|open|closed|filtered)\s+(\S+)',stdout):
        port=int(match[1])
        if match[2]==protocol and port in selected:
            observed[port]={'port':port,'protocol':protocol,'state':match[3],
                'service_hint':match[4],'service_verified':False,'purpose':'discovery'}
    missing=set(selected)-set(observed)
    # A single exact Nmap partition identifies the complement; multiple grouped
    # states cannot identify which individual ports had which outcome.
    if complete and 'Nmap done:' in stdout and not re.search(r'(?i)host timeout|skipping host',stdout):
        groups=re.findall(r'(?i)Not shown:\s*(\d+)\s+(closed|filtered|open\|filtered)(?:\s+(?:tcp|udp))?\s+ports',stdout)
        if len(groups)==1 and int(groups[0][0])==len(missing):
            for port in missing:observed[port]={'port':port,'protocol':protocol,'state':groups[0][1].lower(),
                'service_verified':False,'purpose':'discovery','basis':'exact Nmap complement partition'}
    return [observed.get(p,{'port':p,'protocol':protocol,'state':'unchecked',
        'service_verified':False,'purpose':'discovery'}) for p in sorted(selected)]

def queue(db,task_id,target,protocol,selected):
    initialize(db)
    if protocol not in ('tcp','udp'):raise ValueError('Expected tcp or udp')
    selected=sorted(set(selected))
    if not selected or len(selected)>50 or any(type(p) is not int or not 1<=p<=65535 for p in selected):raise ValueError('Expected 1..50 ports')
    from executor.task_scope import check_action
    if check_action(db,task_id,'scan',target)['decision']!='ALLOW':raise ValueError('Discovery outside host scope')
    profile='tcp_ports' if protocol=='tcp' else 'udp_ports';plans=[];covered=set();requested=set(selected)
    for ident,raw in db.execute('SELECT id,parameters_json FROM network_phase_plans WHERE task_id=? AND target=? AND profile=? ORDER BY id',(task_id,target,profile)):
        try:previous={int(p) for p in json.loads(raw)['ports'].split(',')}
        except (ValueError,TypeError,KeyError):continue
        if not previous.intersection(requested):continue
        attempted=db.execute('SELECT 1 FROM network_job_runs WHERE plan_id=?',(ident,)).fetchone()
        if not attempted and not previous.issubset(requested):raise ValueError('Requested subset overlaps pending plan '+str(ident)+'; resume its saved explicit parameters')
        covered.update(previous);plans.append(ident)
    selected=sorted(requested-covered)
    # UDP silence is slow/ambiguous; each operation has its own bounded timeout.
    for offset in range(0,len(selected),50 if protocol=='tcp' else 8):
        params=json.dumps({'ports':','.join(map(str,selected[offset:offset+(50 if protocol=='tcp' else 8)]))},sort_keys=True)
        row=db.execute('SELECT id FROM network_phase_plans WHERE task_id=? AND target=? AND profile=? AND parameters_json=?',
            (task_id,target,profile,params)).fetchone()
        if row:plans.append(row[0]);continue
        plan={'task_id':task_id,'target':target,'profile':profile,'parameters':json.loads(params)}
        command=jobs.validate_plan(db,plan)
        with db:
            ident=db.execute('INSERT INTO network_phase_plans(task_id,goal,profile,target,parameters_json,argv_json,model_summary,status,created_at) '
                "VALUES(?,?,?,?,?,?,?,'planned',?)",(task_id,'Port discovery '+protocol,profile,target,params,json.dumps(command),
                'Discovery only; no product identification or exhaustive-service guarantee',jobs.now())).lastrowid
        plans.append(ident)
    return plans

def run(db,task_id,target,protocol,selected,max_jobs=1):
    target_availability.require_network(db,task_id)
    if type(max_jobs) is not int or not 1<=max_jobs<=8:raise ValueError('Discovery budget must be 1..8')
    plans=queue(db,task_id,target,protocol,selected);used=0
    for ident in plans:
        # Interrupted/timeout/failed attempts are not silently repeated. New
        # unchecked subsets can be explicitly queued after inspecting evidence.
        if db.execute('SELECT 1 FROM network_job_runs WHERE plan_id=?',(ident,)).fetchone():continue
        if used>=max_jobs:break
        jobs.execute_job(db,ident);used+=1
    runs=[]
    for ident in plans:
        row=db.execute('SELECT id,status FROM network_job_runs WHERE plan_id=? ORDER BY attempt DESC LIMIT 1',(ident,)).fetchone()
        if row:runs.append({'plan_id':ident,'run_id':row[0],'status':row[1]})
    pending=len(plans)-len(runs)
    aggregate=summary(db,task_id,target,protocol)
    return {'status':'completed','task_id':task_id,'target':target,'protocol':protocol,'plan_ids':plans,'executed':used,
        'cached':used==0,'runs':runs,'pending':pending,
        'queue_status':'requires_review' if any(r['status']!='completed' for r in runs) or aggregate['counts'].get('unchecked') else 'pending' if pending else 'completed',
        'coverage':'Explicit ports only; TCP + UDP scans never guarantee all services',
        'summary':aggregate}

def records(db,task_id,target):
    """One source filter for inventory and paged reads, including partial runs."""
    rows=db.execute("SELECT o.id,o.data_json,o.observed_at,r.id,p.id,r.status,p.profile,p.parameters_json,r.result_json FROM network_observations o JOIN network_job_runs r ON r.id=o.run_id JOIN network_phase_plans p ON p.id=r.plan_id WHERE o.task_id=? AND p.task_id=? AND o.target=? AND p.target=? AND o.kind='port_state' AND p.profile IN ('tcp_ports','udp_ports') AND r.status IN ('completed','timeout','failed') ORDER BY o.id",(task_id,task_id,target,target))
    for oid,raw,stamp,rid,pid,outcome,profile,parameters,result_raw in rows:
        try:
            data=json.loads(raw);params=json.loads(parameters);result=json.loads(result_raw) if result_raw else None
            expected='tcp' if profile=='tcp_ports' else 'udp'
            if (data.get('state') not in STATES or data.get('protocol')!=expected or type(data.get('port')) is not int
                or not 1<=data['port']<=65535 or str(data['port']) not in params['ports'].split(',')):continue
            if data['state']!='unchecked' and (not isinstance(result,dict) or
                result.get('task_id')!=task_id or result.get('target')!=target or result.get('profile')!=profile):continue
        except (ValueError,TypeError,KeyError):continue
        yield {**data,'observation_id':oid,'observed_at':stamp,'run_id':rid,'plan_id':pid,'job_outcome':outcome}


def summary(db,task_id,target,protocol=None,offset=0,limit=50):
    if protocol not in (None,'tcp','udp') or offset<0 or not 1<=limit<=50:raise ValueError('Invalid summary range')
    from collections import Counter
    latest={}
    for item in records(db,task_id,target):
        if protocol and protocol!=item['protocol']:continue
        latest[(item['protocol'],item['port'])]=item
    all_rows=[latest[k] for k in sorted(latest)]
    return {'purpose':'discovery','counts':dict(Counter(r['state'] for r in all_rows)),
        'total':len(all_rows),'offset':offset,'items':all_rows[offset:offset+limit],
        'has_more':offset+limit<len(all_rows),'exhaustive_services':False}

def preflight_progress(db,task_id,target):
    values=db.execute('SELECT state,COUNT(*) FROM pm_port_preflight WHERE task_id=? AND target=? GROUP BY state',(task_id,target)).fetchall()
    counts=dict(values)
    return {'states':counts,'checked':sum(v for k,v in values if k!='unchecked'),'unchecked':counts.get('unchecked',0)}
