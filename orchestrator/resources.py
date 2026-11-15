"""Task resource graph and explicit grants. Discovery is never authorization."""
import ipaddress
import json
import socket
from urllib.parse import urljoin

from executor.netguard_root import resource_url, validate_resource_policy, authorize_resource, check_target
from orchestrator import task_memory, diagnostics


def parse(value):
    item=resource_url(value)
    if item['kind']=='address':check_target(item['address'],[cidr(item['address'])])
    return item


def cidr(address):
    ip=ipaddress.ip_address(address)
    return str(ip)+('/32' if ip.version==4 else '/128')


def concrete_host(entry):
    try:ipaddress.ip_address(entry['host']);return True
    except ValueError:return False


def web_entry(entry,area,addresses=()):
    return area=='web' or entry['kind']!='address' and not addresses and not (area=='host' and concrete_host(entry))


def grants(policy):return list(dict.fromkeys([cidr(a) for a in policy['addresses']]+policy.get('networks',[])))


def initialize(db):
    with task_memory.atomic(db):
        db.execute('''CREATE TABLE IF NOT EXISTS pm_resource_scope(
            task_id INTEGER PRIMARY KEY,version INTEGER NOT NULL,entry_json TEXT NOT NULL,
            policy_json TEXT NOT NULL,migration_json TEXT,updated_at TEXT NOT NULL)''')
        db.execute('''CREATE TABLE IF NOT EXISTS pm_resources(
            task_id INTEGER NOT NULL,id TEXT NOT NULL,kind TEXT NOT NULL,value TEXT NOT NULL,
            context TEXT NOT NULL,data_json TEXT NOT NULL,PRIMARY KEY(task_id,id))''')
        db.execute('''CREATE TABLE IF NOT EXISTS pm_resource_links(
            task_id INTEGER NOT NULL,source TEXT NOT NULL,relation TEXT NOT NULL,destination TEXT NOT NULL,
            evidence TEXT NOT NULL,data_json TEXT NOT NULL,observed_at TEXT NOT NULL,
            PRIMARY KEY(task_id,source,relation,destination,evidence))''')
        db.execute('''CREATE TABLE IF NOT EXISTS pm_resource_events(
            id INTEGER PRIMARY KEY,task_id INTEGER NOT NULL,version INTEGER NOT NULL,
            event TEXT NOT NULL,payload_json TEXT NOT NULL,created_at TEXT NOT NULL)''')


def saved(db,task_id):
    if not task_memory.exists(db,'pm_resource_scope'):return None
    row=db.execute('SELECT version,entry_json,policy_json,migration_json FROM pm_resource_scope WHERE task_id=?',(task_id,)).fetchone()
    return {'version':row[0],'entry':json.loads(row[1]),'policy':json.loads(row[2]),
            'migration':json.loads(row[3]) if row[3] else None} if row else None


def resolve(raw,*,area=None,addresses=(),aliases=(),networks=(),allow=(),deny=(),ssrf=(),page=(),path_prefix='/',resolver=None):
    """The only DNS boundary; pin all answers, never resolve during authorization."""
    entry=parse(raw)
    area=area or ('web' if entry['kind'] in ('domain','url') else 'host')
    if area not in ('web','host','lab'):raise ValueError('Unknown investigation area')
    if networks and area!='lab':raise ValueError('Network grants require laboratory area')
    if area=='host' and not concrete_host(entry) and not addresses:
        raise ValueError('Host investigation needs an explicit --address; DNS does not prove machine identity')
    lookup=resolver or socket.getaddrinfo
    def ips(host):
        try:values=[str(ipaddress.ip_address(host))]
        except ValueError:
            values=sorted({str(ipaddress.ip_address(r[4][0])) for r in lookup(host,None,socket.AF_UNSPEC,socket.SOCK_STREAM)},
                          key=lambda a:(ipaddress.ip_address(a).version,int(ipaddress.ip_address(a))))
        if not values:raise ValueError('Domain has no usable addresses')
        for value in values:check_target(value,[cidr(value)])
        return values
    if entry['kind']=='url':
        try:literal=str(ipaddress.ip_address(entry['host']))
        except ValueError:literal=None
        if literal is not None:
            check_target(literal,[cidr(literal)])
            if addresses and set(addresses)!={literal}:raise ValueError('An IP URL cannot be pinned to a different address; use a domain or SSRF route')
    primary=[parse(a)['address'] for a in addresses] if addresses else ips(entry['host'])
    if entry['kind']=='address':
        primary=list(dict.fromkeys([entry['address']]+primary))
        if area=='web' and primary!=[entry['address']]:raise ValueError('Multiple web IP origins require explicit --allow-resource URLs')
    values=list(dict.fromkeys(primary))
    host_addresses=list(primary) if area!='web' and (entry['kind']=='address' or addresses or area=='host' and concrete_host(entry)) else []
    bindings={entry['host']:list(values)}
    origins=[]
    urls=[]
    if entry['kind']=='url':urls.append(entry)
    elif entry['kind']=='domain' or area=='web':
        host='['+entry['host']+']' if ':' in entry['host'] else entry['host']
        urls.extend(resource_url(scheme+'://'+host+'/') for scheme in ('http','https'))
    for name in aliases:
        host=resource_url(name)
        if host['kind']!='domain':raise ValueError('Alias must be a domain')
        bindings[host['host']]=list(primary)  # explicit operator alias, not a DNS inference
        endpoints=[(u['scheme'],u['port']) for u in urls if u['host']==entry['host']] or [('http',80),('https',443)]
        for scheme,port in endpoints:urls.append(resource_url(f'{scheme}://{host["host"]}:{port}/'))
    for value in allow:
        item=parse(value)
        if item['kind']=='url':
            current=ips(item['host']);bindings[item['host']]=current;values.extend(current);urls.append(item)
        elif area=='lab' and item['kind']=='address':values.append(item['address']);host_addresses.append(item['address'])
        else:raise ValueError('Additional resources must be URLs or laboratory IPs')
    for url in urls:
        item={'origin':url['origin'],'addresses':bindings[url['host']],'path_prefix':path_prefix}
        if item not in origins:origins.append(item)
    for value in page:
        dependency=parse(value)
        if dependency['kind']!='url':raise ValueError('Page dependency requires an exact URL')
        pinned=ips(dependency['host']);bindings[dependency['host']]=pinned;values.extend(pinned)
        origins.append({'origin':dependency['origin'],'addresses':pinned,'path_prefix':dependency['path'],
                        'purpose':'page_dependency','request_path':dependency['request_path']})
    policy={'version':1,'area':area,'machine':'task-machine','addresses':list(dict.fromkeys(values)),'host_addresses':host_addresses,
            'origins':origins,'networks':[str(ipaddress.ip_network(n,strict=True)) for n in networks],
            'denied':list(deny),'ssrf':[]}
    for value in ssrf:
        if not origins:raise ValueError('SSRF needs an application URL')
        destination=resource_url(value)
        if destination['kind']!='url':raise ValueError('SSRF destination must be an explicit URL')
        policy['ssrf'].append({'application':origins[0]['origin'],'destination':destination['request_url'],'context':policy['machine']})
    grants=list(dict.fromkeys([cidr(a) for a in values]+policy['networks']))
    validate_resource_policy(policy,grants)
    return {'entry':{**entry,'bindings':bindings},'policy':policy,'networks':grants,'target':primary[0]}


def node(db,task_id,kind,value,context='',**data):
    identity='resource:'+task_memory.digest([kind,value,context])
    db.execute('INSERT INTO pm_resources VALUES(?,?,?,?,?,?) ON CONFLICT(task_id,id) DO UPDATE SET data_json=excluded.data_json',
        (task_id,identity,kind,value,context,task_memory.encoded(data)))
    return identity


def link(db,task_id,source,relation,destination,evidence='',**data):
    db.execute('INSERT OR IGNORE INTO pm_resource_links VALUES(?,?,?,?,?,?,?)',
        (task_id,source,relation,destination,evidence,task_memory.encoded(data),task_memory.now()))


def _seed(db,task_id,entry,policy):
    machine=node(db,task_id,'machine',policy['machine'])
    primary=set(entry.get('bindings',{}).get(entry['host'],[policy['addresses'][0]]))
    for address in policy['addresses']:
        context=policy['machine'] if address in primary else policy['machine']+':endpoint:'+address
        owner=machine if address in primary else node(db,task_id,'machine',context,configured=True,identity='separate logical endpoint; physical identity unverified')
        addr=node(db,task_id,'address',address,context)
        link(db,task_id,owner,'address_binding',addr,'operator_configuration',current=True)
        db.execute("UPDATE pm_resource_links SET data_json=? WHERE task_id=? AND source=? AND relation='address_binding' AND destination=?",
                   (task_memory.encoded({'current':True}),task_id,owner,addr))
    for host,addresses in entry.get('bindings',{}).items():
        try:ipaddress.ip_address(host);continue
        except ValueError:pass
        domain=node(db,task_id,'domain',host)
        for address in addresses:
            context=policy['machine'] if address in primary else policy['machine']+':endpoint:'+address
            link(db,task_id,domain,'resolves_or_explicitly_maps_to',node(db,task_id,'address',address,context),
                'operator_configuration',authority='HTTP pin; DNS does not grant host investigation')
    for origin in policy['origins']:
        parsed=resource_url(origin['origin'])
        endpoint=node(db,task_id,'origin',origin['origin'],purpose=origin.get('purpose','research'))
        link(db,task_id,machine,'allowed_page_dependency' if origin.get('purpose')=='page_dependency' else 'authorized_origin',endpoint,'operator_configuration')
        for address in origin['addresses']:
            context=policy['machine'] if address in primary else policy['machine']+':endpoint:'+address
            service=node(db,task_id,'service',f'tcp:{address}:{parsed["port"]}',context,target=address,port=parsed['port'],protocol='tcp',status='configured_endpoint_not_observed_open')
            link(db,task_id,endpoint,'reached_via',service,'operator_configuration',method='direct_namespace',host=parsed['host'],sni=parsed['host'] if parsed['scheme']=='https' else None)
        if origin.get('purpose')=='page_dependency':
            file=node(db,task_id,'path',origin['origin']+origin['request_path'],permission='single_page_dependency')
            link(db,task_id,endpoint,'page_dependency_path',file,'operator_configuration')
    if entry['kind']=='url':
        path=node(db,task_id,'path',entry['request_url'],policy['machine'],query=entry['query'],fragment=entry['fragment'])
        link(db,task_id,node(db,task_id,'origin',entry['origin']),'entrypoint',path,'operator_configuration')
    for grant in policy['ssrf']:
        dest=node(db,task_id,'path',grant['destination'],policy['machine'],route='ssrf',vantage='target_application')
        link(db,task_id,node(db,task_id,'origin',grant['application']),'ssrf_destination',dest,'operator_configuration',method='ssrf',context=policy['machine'])


def save(db,task_id,configuration):
    with task_memory.atomic(db):
        initialize(db)
        if saved(db,task_id):raise ValueError('Resource scope already configured; use explicit change operation')
        policy=dict(configuration['policy']);policy['machine']=f'task:{task_id}:machine'
        for grant in policy['ssrf']:grant['context']=policy['machine']
        db.execute('INSERT INTO pm_resource_scope VALUES(?,1,?,?,NULL,?)',
            (task_id,task_memory.encoded(configuration['entry']),task_memory.encoded(policy),task_memory.now()))
        _seed(db,task_id,configuration['entry'],policy)
        db.execute('INSERT INTO pm_resource_events(task_id,version,event,payload_json,created_at) VALUES(?,1,?,?,?)',
            (task_id,'configured',task_memory.encoded(configuration),task_memory.now()))
    diagnostics.emit('resource.configured',task_id=task_id,reason=policy['area'],
                     parameters={'addresses':len(policy['addresses']),'origins':len(policy['origins']),'networks':len(policy['networks'])})


def authorize(db,task_id,operation,target,**kwargs):
    state=saved(db,task_id)
    if state:authorize_resource(state['policy'],operation,target,**kwargs)


def graph(db,task_id):
    state=saved(db,task_id)
    if state is None:return {'configured':False}
    result={'configured':True,**state,'current_entrypoint':(state['policy']['origins'][0]['origin']+state['entry'].get('request_path','/')) if state['policy']['origins'] else None,
            'access_continuity':{'liveness':'unknown','prior_address':state['migration']['old_address']} if state['migration'] else None,
            'resources':task_memory.rows(db,'pm_resources',task_id),
            'relations':task_memory.rows(db,'pm_resource_links',task_id)}
    for group in ('resources','relations'):
        for item in result[group]:item['data']=json.loads(item.pop('data_json'))
    # Read the established inventory with the same task/scope/provenance filters.
    # Context construction never writes derived facts or executes discovery.
    from orchestrator import service_inventory
    by_id={r['id']:r for r in result['resources']}
    for address in state['policy']['addresses']:
        for service in service_inventory.collect_full(db,task_id,address=address)['entries']:
            value=f'{service["protocol"]}:{address}:{service["port"]}'
            context=state['policy']['machine'] if address in state['entry'].get('bindings',{}).get(state['entry']['host'],[]) else state['policy']['machine']+':endpoint:'+address
            identity='resource:'+task_memory.digest(['service',value,context])
            by_id[identity]={'task_id':task_id,'id':identity,'kind':'service','value':value,'context':context,'data':service}
            address_id='resource:'+task_memory.digest(['address',address,context])
            result['relations'].append({'task_id':task_id,'source':address_id,'relation':'observed_service','destination':identity,
                'evidence':'structured_inventory','data':{'sources':service['sources']}})
    result['resources']=list(by_id.values())
    result['authorized_resources']=[]
    for item in result['resources']:
        allowed=False
        if item['kind']=='machine':allowed=item['value']==state['policy']['machine'] or item['data'].get('configured',False)
        elif item['kind']=='address':allowed=item['value'] in state['policy']['addresses']
        elif item['kind']=='domain':allowed=item['value'] in state['entry'].get('bindings',{})
        elif item['kind']=='origin':allowed=item['value'] in [o['origin'] for o in state['policy']['origins']]
        elif item['kind']=='service':allowed=item['data'].get('target') in state['policy']['addresses']
        elif item['kind']=='path':
            url=resource_url(item['value'])
            allowed=any(url['origin']==o['origin'] for o in state['policy']['origins']) or any(
                url['request_url']==g['destination'] and item['context']==g['context'] for g in state['policy']['ssrf'])
        if allowed:result['authorized_resources'].append(item['id'])
    return result


def machine_targets(db,task_id):
    state=saved(db,task_id)
    if state is None:return []
    return [r[0] for r in db.execute("SELECT value FROM pm_resources WHERE task_id=? AND kind='address' AND context=?",
                                   (task_id,state['policy']['machine']))]


def observe_link(db,task_id,source,url,*,relation='link',evidence=''):
    state=saved(db,task_id)
    if state is None:return None
    item=resource_url(urljoin(source,url))
    if item['kind']!='url':return None
    # Store external URLs and browser fragments without DNS or an implicit grant.
    with task_memory.atomic(db):
        source_id=node(db,task_id,'path',source)
        dest=node(db,task_id,'path',item['request_url'],fragment=item['fragment'],query=item['query'],authority='observed_only')
        link(db,task_id,source_id,relation,dest,evidence,investigation_permission='none',loading='page_dependency' if relation=='page_dependency' else 'link')
    diagnostics.emit('resource.relationship',task_id=task_id,reason=relation,identifiers={'resource_id':dest,'evidence':evidence})
    return dest


def pivot_question(db,task_id,reference,reason,*,step_id=None):
    from orchestrator import operator_questions
    state=saved(db,task_id)
    if not state or reference not in {r['id'] for r in graph(db,task_id)['resources']}:raise ValueError('Unknown pivot resource')
    target=db.execute('SELECT target FROM tasks WHERE id=?',(task_id,)).fetchone()[0]
    decision={'branch_id':reference,'question':'Нужен способ достижения ресурса; уточните pivoting и границы.',
        'reason':reason,'references':[reference],'boundaries':{'task_id':task_id,'target':target,'intent_ref':'intent','resource_refs':[reference]},
        'operator_question':{'kind':'pivoting'}}
    return operator_questions.request(db,task_id,target,decision,step_id)


def rebind(db,task_id,new_address,ports):
    """Same logical machine; original evidence rows/files are never retargeted."""
    initialize(db)
    state=saved(db,task_id)
    old=db.execute('SELECT target FROM tasks WHERE id=?',(task_id,)).fetchone()[0]
    if state is None:
        save(db,task_id,resolve(old));state=saved(db,task_id)
    policy=state['policy'];entry=state['entry']
    from orchestrator import service_inventory
    prior_services=service_inventory.collect_full(db,task_id)['entries']
    check_target(new_address,[cidr(new_address)])
    if old==new_address:raise ValueError('Address unchanged')
    def replace(values):return list(dict.fromkeys(new_address if a==old else a for a in values))
    policy['addresses']=replace(policy['addresses'])
    policy['host_addresses']=replace(policy['host_addresses'])
    for origin in policy['origins']:origin['addresses']=replace(origin['addresses'])
    for host,values in entry.get('bindings',{}).items():entry['bindings'][host]=replace(values)
    # For an IP URL, change its authority explicitly but preserve path/query/fragment.
    for origin in policy['origins']:
        parsed=resource_url(origin['origin'])
        if parsed['host']==old:
            host='['+new_address+']' if ':' in new_address else new_address
            before=origin['origin'];origin['origin']=f'{parsed["scheme"]}://{host}:{parsed["port"]}'
            for grant in policy['ssrf']:
                if grant['application']==before:grant['application']=origin['origin']
    with task_memory.atomic(db):
        version=state['version']+1
        migration={'old_address':old,'new_address':new_address,'ports':sorted(set(ports)),'status':'connections_pending'}
        changed=db.execute('UPDATE pm_resource_scope SET version=?,entry_json=?,policy_json=?,migration_json=?,updated_at=? WHERE task_id=? AND version=?',
            (version,task_memory.encoded(entry),task_memory.encoded(policy),task_memory.encoded(migration),task_memory.now(),task_id,state['version']))
        if changed.rowcount!=1:raise task_memory.VersionConflict('Resource scope version changed')
        for service in prior_services:
            value=f'{service["protocol"]}:{old}:{service["port"]}'
            node(db,task_id,'service',value,policy['machine'],**{**service,'current_address':False,'liveness':'unknown'})
        db.execute('UPDATE tasks SET target=? WHERE id=?',(new_address,task_id))
        db.execute('UPDATE task_scope_settings SET initial_target=? WHERE task_id=?',(new_address,task_id))
        if task_memory.exists(db,'pm_coordinator_runs'):db.execute('UPDATE pm_coordinator_runs SET target=? WHERE task_id=?',(new_address,task_id))
        db.execute("UPDATE pm_resource_links SET data_json=? WHERE task_id=? AND relation='address_binding'",
                   (task_memory.encoded({'current':False}),task_id))
        _seed(db,task_id,entry,policy)
        db.execute('INSERT INTO pm_resource_events(task_id,version,event,payload_json,created_at) VALUES(?,?,?,?,?)',
            (task_id,version,'address_changed',task_memory.encoded({'old_address':old,'new_address':new_address,'previous':state}),task_memory.now()))
    diagnostics.emit('resource.address_changed',task_id=task_id,reason='operator_same_machine',
                     identifiers={'version':version},parameters={'old_address':old,'new_address':new_address,'known_ports':len(ports)})
    return migration
