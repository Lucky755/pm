"""Task HTTP sessions and fresh exchanges. Privileged transport is one hop only.

Originals remain private content-addressed artifacts. No URL response cache,
automatic replay of unknown operations, inferred authentication or goal success.
"""
import base64
import hashlib
import json
from http.cookies import SimpleCookie
import re
import subprocess
import time
from urllib.parse import parse_qsl,urlencode,urljoin,urlsplit

from executor import netguard_root as broker
from orchestrator import diagnostics,http_artifacts as artifacts,http_discovery as web,resources,task_memory


class HTTPExecutionError(RuntimeError):pass


def initialize(db):
    web.init(db);artifacts.initialize(db)
    db.execute('''CREATE TABLE IF NOT EXISTS pm_http_sessions (
        task_id INTEGER NOT NULL,name TEXT NOT NULL,version INTEGER NOT NULL,
        state_ref_json TEXT NOT NULL,active_exchange_id INTEGER,PRIMARY KEY(task_id,name))''')
    db.execute('''CREATE TABLE IF NOT EXISTS pm_http_exchanges (
        id INTEGER PRIMARY KEY,task_id INTEGER NOT NULL,session_id TEXT NOT NULL,
        parent_id INTEGER,method TEXT NOT NULL,url TEXT NOT NULL,target TEXT NOT NULL,
        request_sha256 TEXT NOT NULL,operation_id TEXT NOT NULL,phase TEXT NOT NULL,
        artifact_id INTEGER,metadata_json TEXT NOT NULL,created_at TEXT NOT NULL)''')


def session_state(db,task_id,name):
    row=db.execute('SELECT version,state_ref_json,active_exchange_id FROM pm_http_sessions WHERE task_id=? AND name=?',(task_id,name)).fetchone()
    if not row:return 0,{'auth':{},'cookies':[]},None
    state=json.loads(artifacts.load_material(task_id,json.loads(row[1])) or b'{}')
    return row[0],state,row[2]


def pairs(value):
    if isinstance(value,dict):value=list(value.items())
    if not isinstance(value,list) or any(not isinstance(p,(list,tuple)) or len(p)!=2 or not all(isinstance(s,str) for s in p) for p in value):raise ValueError('Expected string name/value pairs')
    return [list(p) for p in value]


def cookie_header(state,url):
    host=url['host'];path=url['path'];now=time.time();result=[]
    for cookie in state['cookies']:
        domain=cookie['domain']
        match=host==domain or not cookie['host_only'] and host.endswith('.'+domain)
        boundary=cookie['path'];path_match=path==boundary or path.startswith(boundary if boundary.endswith('/') else boundary+'/')
        if match and path_match and (not cookie['secure'] or url['scheme']=='https') and (cookie['expires'] is None or cookie['expires']>now):
            result.append(cookie['name']+'='+cookie['value'])
    return '; '.join(result)


def update_cookies(state,url,headers):
    import email.utils
    for key,value in headers:
        if key.lower()!='set-cookie':continue
        jar=SimpleCookie()
        try:jar.load(value)
        except Exception:continue
        for name,m in jar.items():
            domain=(m['domain'] or url['host']).lower().lstrip('.')
            if domain!=url['host'] and not url['host'].endswith('.'+domain):continue
            if domain!=url['host'] and '.' not in domain:continue
            default_path=url['path'].rsplit('/',1)[0] or '/'
            path=m['path'] if m['path'].startswith('/') else default_path
            expires=None
            if m['max-age']:
                try:expires=time.time()+int(m['max-age'])
                except ValueError:continue
            elif m['expires']:
                try:expires=email.utils.parsedate_to_datetime(m['expires']).timestamp()
                except (ValueError,TypeError,OverflowError):continue
            state['cookies']=[c for c in state['cookies'] if (c['name'],c['domain'],c['path'])!=(name,domain,path)]
            if expires is None or expires>time.time():
                state['cookies'].append({'name':name,'value':m.value,'domain':domain,'path':path,
                    'host_only':not bool(m['domain']),'secure':bool(m['secure']),'expires':expires})
    if len(state['cookies'])>256:raise ValueError('HTTP cookie session budget exhausted')


def endpoint(db,task_id,value,target=None):
    url=resources.parse(value)
    if url['kind']!='url':raise ValueError('HTTP needs an explicit URL')
    saved=resources.saved(db,task_id)
    if saved:
        origin=next((o for o in saved['policy']['origins'] if o['origin']==url['origin']),None)
        target=target or (origin['addresses'][0] if origin else url['host'])
    else:target=target or web.validate_scope(db,task_id)
    # Never resolve a redirect's arbitrary DNS name on Kali or grant its IP.
    try:target=str(broker.ipaddress.ip_address(target))
    except ValueError:raise ValueError('HTTP resource has no saved authorized address pin')
    web.validate_endpoint(db,task_id,target,url['scheme'],url['host'],url['port'],url['request_path'])
    return url,target


def build(db,task_id,request,session_id,state):
    allowed={'url','target','method','headers','cookies','auth','query','body','body_b64','json','form','files','ssrf','timeout','tls_verify'}
    if not isinstance(request,dict) or set(request)-allowed or 'url' not in request:raise ValueError('Unknown or missing HTTP request field')
    url,target=endpoint(db,task_id,request['url'],request.get('target'))
    path=url['request_path'];query=pairs(request.get('query',[]))
    form=pairs(request.get('form',[]));json_body=request.get('json');route=request.get('ssrf')
    if route:
        if not isinstance(route,dict) or set(route)-{'destination','context','parameter','location'}:raise ValueError('Invalid SSRF specification')
        scope=resources.saved(db,task_id)
        if not scope:raise ValueError('SSRF needs explicit task resource scope')
        destination=resources.parse(route['destination'])
        if destination['kind']!='url':raise ValueError('SSRF destination must be a URL')
        parameter=route.get('parameter','url');location=route.get('location','query')
        if not re.fullmatch(r'[A-Za-z][A-Za-z0-9_.-]{0,63}',parameter):raise ValueError('Invalid SSRF parameter')
        route={'destination':destination['request_url'],'context':route.get('context',scope['policy']['machine'])}
        resources.authorize(db,task_id,'ssrf',target,scheme=url['scheme'],hostname=url['host'],port=url['port'],
            path=path,destination=route['destination'],context=route['context'])
        if any(k==parameter for k,v in parse_qsl(url['query'])+query+form) or isinstance(json_body,dict) and parameter in json_body:raise ValueError('Duplicate SSRF destination parameter')
        if location=='query':query.append([parameter,route['destination']])
        elif location=='form':form.append([parameter,route['destination']])
        elif location=='json':json_body={**(json_body or {}),parameter:route['destination']}
        else:raise ValueError('Unsupported SSRF location')
    if query:path+=('&' if '?' in path else '?')+urlencode([(k,v) for k,v in query])
    headers=pairs(request.get('headers',[]));forms=bool(form) or 'form' in request
    if any(k.lower()=='cookie' for k,v in headers):raise ValueError('Use the session cookies field instead of a raw Cookie header')
    json_present='json' in request or json_body is not None
    modes=sum((('body' in request or 'body_b64' in request),json_present,forms or bool(request.get('files'))))
    if modes>1 or 'body' in request and 'body_b64' in request:raise ValueError('Choose one HTTP body representation')
    body=b'';ctype=None
    if 'body' in request:
        if not isinstance(request['body'],str):raise ValueError('Body must be text; use body_b64 for binary')
        body=request['body'].encode()
    elif 'body_b64' in request:body=base64.b64decode(request['body_b64'],validate=True)
    elif json_present:body=json.dumps(json_body,ensure_ascii=False).encode();ctype='application/json'
    elif request.get('files'):
        from orchestrator.agent_actions import TASK_WORK_BASE
        workspace=(TASK_WORK_BASE/str(task_id)).resolve()
        if not isinstance(request['files'],list) or not 1<=len(request['files'])<=16:raise ValueError('Multipart file count budget exceeded')
        identities=[]
        for file in request['files']:
            if not isinstance(file,dict) or not isinstance(file.get('path'),str):raise ValueError('Invalid multipart file')
            candidate=workspace/file['path'].removeprefix('/work/')
            if candidate.is_symlink() or not candidate.resolve().is_relative_to(workspace) or not candidate.is_file() or candidate.stat().st_size>artifacts.MAX_BODY:raise ValueError('Upload must be a bounded task workspace file')
            identities.append(hashlib.sha256(candidate.read_bytes()).hexdigest())
        if sum((workspace/f['path'].removeprefix('/work/')).stat().st_size for f in request['files'])>artifacts.MAX_BODY:raise ValueError('Multipart body budget exceeded')
        boundary='pm-'+task_memory.digest([form,request['files'],identities])[:32]
        chunks=[]
        for name,value in form:
            if re.search(r'[\r\n"\\]',name):raise ValueError('Invalid form field')
            chunks.extend([f'--{boundary}\r\nContent-Disposition: form-data; name="{name}"\r\n\r\n'.encode(),value.encode(),b'\r\n'])
        for file in request['files']:
            if not isinstance(file,dict) or set(file)-{'field','path','filename','content_type'}:raise ValueError('Invalid multipart file')
            local=workspace/file['path'].removeprefix('/work/')
            if local.is_symlink() or not local.resolve().is_relative_to(workspace) or not local.is_file():raise ValueError('Upload must be a task workspace file')
            if local.stat().st_size>artifacts.MAX_BODY:raise ValueError('Upload too large')
            name=file['field'];filename=file.get('filename',local.name);content_type=file.get('content_type','application/octet-stream')
            if any(re.search(r'[\r\n"\\]',v) for v in (name,filename,content_type)):raise ValueError('Invalid multipart metadata')
            chunks.extend([f'--{boundary}\r\nContent-Disposition: form-data; name="{name}"; filename="{filename}"\r\nContent-Type: {content_type}\r\n\r\n'.encode(),local.read_bytes(),b'\r\n'])
        chunks.append(f'--{boundary}--\r\n'.encode());body=b''.join(chunks);ctype='multipart/form-data; boundary='+boundary
    elif forms:body=urlencode([(k,v) for k,v in form]).encode();ctype='application/x-www-form-urlencoded'
    if ctype:
        if any(k.lower()=='content-type' for k,v in headers):raise ValueError('Body representation sets Content-Type')
        headers.append(['Content-Type',ctype])
    auth=request.get('auth')
    authorizations=[v for k,v in headers if k.lower()=='authorization']
    if len(authorizations)>1 or authorizations and auth is not None:raise ValueError('Ambiguous HTTP authentication')
    if authorizations:state['auth'][url['origin']]=authorizations[0]
    if auth is not None:
        if not isinstance(auth,dict):raise ValueError('Invalid HTTP authentication')
        if auth.get('type')=='basic' and set(auth)=={'type','username','password'}:
            value='Basic '+base64.b64encode((auth['username']+':'+auth['password']).encode()).decode()
        elif auth.get('type')=='bearer' and set(auth)=={'type','token'}:value='Bearer '+auth['token']
        else:raise ValueError('Supported auth: basic or bearer')
        state['auth'][url['origin']]=value
    if url['origin'] in state['auth'] and not any(k.lower()=='authorization' for k,v in headers):headers.append(['Authorization',state['auth'][url['origin']]])
    for name,value in pairs(request.get('cookies',{})):
        if not re.fullmatch(r'[A-Za-z0-9_.-]+',name) or re.search(r'[\s;\r\n]',value):raise ValueError('Invalid explicit cookie')
        state['cookies']=[c for c in state['cookies'] if not (c['name']==name and c['domain']==url['host'] and c['path']=='/')]
        state['cookies'].append({'name':name,'value':value,'domain':url['host'],'path':'/','host_only':True,'secure':False,'expires':None})
    cookie=cookie_header(state,url)
    if cookie:
        if any(k.lower()=='cookie' for k,v in headers):raise ValueError('Use cookies/session instead of duplicate Cookie header')
        headers.append(['Cookie',cookie])
    spec=broker.http_spec({'method':request.get('method','GET').upper(),'target':target,'scheme':url['scheme'],
        'hostname':url['host'],'port':url['port'],'path':path,'headers':headers,'body_b64':base64.b64encode(body).decode(),
        'session_id':session_id,'limit_bytes':artifacts.response_limit(db,task_id),'timeout':request.get('timeout',25),
        'tls_verify':request.get('tls_verify',True),'ssrf':route})
    return spec,url


def transport(task_id,spec):
    with diagnostics.Action('http','request',task_id=task_id,parameters={'method':spec['method'],'session_id':spec['session_id']}) as action:
        result=subprocess.run(['sudo','-n',web.BROKER,'http','--task-id',str(task_id)],input=json.dumps(spec),
            capture_output=True,text=True,timeout=spec['timeout']+10,env={**__import__('os').environ,**diagnostics.child_env()})
        payload=json.loads(result.stdout)
        if result.returncode or not isinstance(payload,dict) or payload.get('http_protocol')!=1 or payload.get('request_sha256')!=broker.tool_digest(spec):raise ValueError('HTTP broker protocol mismatch; operation not replayed')
        action.status=payload['status']
    return payload


def execute(db,task_id,request,session_id='default'):
    if not re.fullmatch(r'[A-Za-z0-9_.-]{1,64}',session_id):raise ValueError('Invalid web session name')
    initialize(db);db.commit();root_id=None;chain=[]
    support=subprocess.run([web.BROKER,'capabilities'],capture_output=True,text=True,timeout=5)
    try:capabilities=json.loads(support.stdout)
    except ValueError:capabilities={}
    if support.returncode or not isinstance(capabilities,dict) or capabilities.get('http_protocol')!=1 or capabilities.get('http_header_limit',0)<artifacts.MAX_HEADERS:
        raise ValueError('NetGuard needs http_protocol=1 with 1 MiB headers; update the root-owned broker before HTTP execution')
    # Redirect budget is part of the existing total HTTP request budget.
    for hop in range(6):
        with task_memory.atomic(db):
            version,state,busy=session_state(db,task_id,session_id)
            if busy is not None:raise ValueError('Web session has an unfinished exchange; inspect it before continuing')
            previous_state=task_memory.digest(state)
            spec,url=build(db,task_id,request,session_id,state)
            fresh=spec['method'] in ('GET','HEAD','OPTIONS')
            # A new session label/response limit is not another target operation.
            # Effective authorization/cookies are already in the actual headers.
            signature_spec={k:v for k,v in spec.items() if k not in ('timeout','limit_bytes','session_id','ssrf','body_b64')}
            signature_spec['body_sha256']=hashlib.sha256(base64.b64decode(spec['body_b64'])).hexdigest()
            fingerprint=task_memory.digest(signature_spec)
            description={'signature':fingerprint,'resource':url['origin']+spec['path'],'operation':'http_request',
                'parameters':{'method':spec['method'],'request_sha256':fingerprint,'session_id':session_id}}
            if web.attempts_used(db,task_id)>=web.MAX_TOTAL:raise ValueError('Task HTTP request budget exhausted')
            intent=task_memory.begin_operation(db,task_id,description,conditions={},
                require_fresh=fresh,reason='explicit fresh HTTP read' if fresh else '')
            if not intent['allowed']:raise ValueError(intent['reason'])
            oid=intent['operation_id']
            eid=db.execute("INSERT INTO pm_http_exchanges(task_id,session_id,parent_id,method,url,target,request_sha256,operation_id,phase,metadata_json,created_at) VALUES(?,?,?,?,?,?,?,?,'started','{}',?)",
                (task_id,session_id,root_id,spec['method'],url['origin']+spec['path'],spec['target'],fingerprint,oid,web.now())).lastrowid
            original=artifacts.save_material(task_id,json.dumps(state,sort_keys=True).encode())
            db.execute('INSERT INTO pm_http_sessions VALUES(?,?,?,?,?) ON CONFLICT(task_id,name) DO UPDATE SET active_exchange_id=excluded.active_exchange_id',
                (task_id,session_id,version,json.dumps(original),eid))
            task_memory.transition(db,task_id,oid,'started',expected_phase='intent')
        payload=None;metadata={};aid=None
        try:
            payload=transport(task_id,spec)
            raw_request=base64.b64decode(payload['request_b64'],validate=True)
            head=base64.b64decode(payload['headers_b64'],validate=True);body=base64.b64decode(payload['body_b64'],validate=True)
            wire=base64.b64decode(payload['wire_b64'],validate=True)
            if len(head)>artifacts.MAX_HEADERS or len(body)>spec['limit_bytes'] or len(raw_request)>artifacts.MAX_BODY+artifacts.MAX_HEADERS:raise ValueError('HTTP transport material exceeds budget')
            request_ref=artifacts.save_material(task_id,raw_request);response_ref=artifacts.save_material(task_id,wire)
            metadata={'request_ref':request_ref,'response_ref':response_ref,'elapsed_seconds':payload['elapsed_seconds'],
                'transport_complete':payload['transport_complete'],'body_truncated':payload['body_truncated'],
                'wire_truncated':payload['wire_truncated'],'request_write_completed':payload['request_write_completed'],
                'status_code':payload['status_code'],'error_type':payload.get('error_type'),'session_version':version,
                'server_outcome':'uninterpreted; HTTP status does not establish authentication or goal success'}
            if head and payload['status_code'] is not None:
                from email.parser import BytesParser
                # Original fields, including cookies and redirects, stay in the private original.
                status_lines=list(re.finditer(rb'(?m)^HTTP/1\.[01] [0-9]{3}[^\r\n]*\r?\n',head))
                fields=head[status_lines[-1].end():]
                response_headers=list(BytesParser().parsebytes(fields).items())
                update_cookies(state,url,response_headers)
                safe_headers={k.lower():v for k,v in response_headers if k.lower() in ('content-type','content-length','content-encoding','server')}
                route={'method':'ssrf','application':url['origin'],'destination_contact':'unverified; observed application response',**spec['ssrf']} if spec['ssrf'] else None
                capture={'body':body,'headers':safe_headers,'status':payload['status_code'],'complete':payload['transport_complete'],
                    'request':{'method':spec['method'],'scheme':spec['scheme'],'hostname':spec['hostname'],'port':spec['port'],
                        'path':spec['path'],'raw_request_ref':request_ref},'metadata':{**metadata,'route':route}}
                aid=artifacts.save(db,task_id,spec['target'],spec['scheme'],spec['hostname'],spec['port'],spec['path'],capture,web.now())
                metadata['location']=next((v for k,v in response_headers if k.lower()=='location'),None)
        except BaseException as exc:
            metadata.update(error_type=type(exc).__name__,transport_complete=False,reason='HTTP outcome unknown; no automatic replay')
            with task_memory.atomic(db):
                db.execute("UPDATE pm_http_exchanges SET phase='unknown',metadata_json=? WHERE id=?",(json.dumps(metadata),eid))
                db.execute('UPDATE pm_http_sessions SET active_exchange_id=NULL WHERE task_id=? AND name=?',(task_id,session_id))
                task_memory.transition(db,task_id,oid,'unknown',expected_phase='started',outcome='outcome_unknown')
            if isinstance(exc,Exception):raise HTTPExecutionError(f'HTTP exchange {eid} outcome unknown; inspect saved materials, no automatic replay') from exc
            raise
        with task_memory.atomic(db):
            phase='finished' if payload['transport_complete'] else 'unknown'
            state_ref=artifacts.save_material(task_id,json.dumps(state,sort_keys=True).encode())
            next_version=version+int(task_memory.digest(state)!=previous_state)
            db.execute('UPDATE pm_http_sessions SET version=?,state_ref_json=?,active_exchange_id=NULL WHERE task_id=? AND name=? AND active_exchange_id=?',
                (next_version,json.dumps(state_ref),task_id,session_id,eid))
            db.execute('UPDATE pm_http_exchanges SET phase=?,artifact_id=?,metadata_json=? WHERE id=?',(phase,aid,json.dumps(metadata),eid))
            task_memory.transition(db,task_id,oid,phase,expected_phase='started',outcome='transport_complete' if phase=='finished' else 'outcome_unknown')
            from orchestrator.agent_actions import CAPABILITY_LOG
            task_memory.sync(db,task_id,CAPABILITY_LOG/f'task_{task_id}.jsonl',reason='http_exchange')
        chain.append(eid);root_id=root_id or eid
        text,decoding=artifacts.decode_body(body,safe_headers) if aid else ('',{'text_skipped':'no_complete_headers'})
        reply={'status':'completed' if payload['transport_complete'] else 'incomplete','task_id':task_id,'target':spec['target'],
            'memory_operation_id':oid,
            'exchange_id':eid,'chain':chain,'session_id':session_id,'artifact_id':aid,
            'artifact_ref':'http_artifact:'+str(aid) if aid else None,'status_code':payload['status_code'],
            'transport_complete':payload['transport_complete'],'download_complete':payload['transport_complete'],
            'body_truncated':payload['body_truncated'],'cached':False,'server_outcome':metadata['server_outcome'],
            'wire_truncated':payload['wire_truncated'],
            'stdout_truncated':len(text)>4096,'text_characters':len(text),'decoding':decoding,
            'stdout':artifacts.diagnostic_text(text[:4096])}
        if not payload['transport_complete'] or payload['status_code'] not in (301,302,303,307,308) or not metadata.get('location'):return reply
        redirected=urljoin(url['origin']+spec['path'],metadata['location'])
        try:next_url,_=endpoint(db,task_id,redirected)
        except ValueError:
            return {**reply,'status':'blocked','stop_reason':'redirect_outside_scope','redirect_followed':False,
                    'reason_category':'scope_denied','reason_summary':'Redirect is outside saved task boundaries; destination was not contacted.'}
        if hop==5:return {**reply,'status':'incomplete','stop_reason':'redirect_limit'}
        same_origin=next_url['origin']==url['origin']
        headers=[p for p in spec['headers'] if p[0].lower() not in ('cookie','content-type') and
            (same_origin or p[0].lower() in ('accept','accept-language','user-agent','cache-control'))]
        method=spec['method'];body_arg={'body_b64':spec['body_b64']}
        if payload['status_code']==303 and method!='HEAD' or payload['status_code'] in (301,302) and method=='POST':
            method='GET';body_arg={}
        else:headers.extend(p for p in spec['headers'] if p[0].lower()=='content-type')
        request={'url':next_url['request_url'],'method':method,'headers':headers,**body_arg,
                 'timeout':spec['timeout'],'tls_verify':spec['tls_verify']}


def read(db,task_id,exchange_id,part='body',offset=0,limit=4096):
    if part not in ('request','response','body') or type(offset) is not int or offset<0 or not 1<=limit<=65536:raise ValueError('Invalid HTTP material range')
    row=db.execute('SELECT metadata_json,artifact_id FROM pm_http_exchanges WHERE id=? AND task_id=?',(exchange_id,task_id)).fetchone()
    if not row:raise ValueError('HTTP exchange does not belong to task')
    metadata=json.loads(row[0])
    body=artifacts.load(db,task_id,row[1])[0] if part=='body' else artifacts.load_material(task_id,metadata[part+'_ref'])
    chunk=body[offset:offset+limit]
    return {'status':'completed','provenance':'local','exchange_id':exchange_id,'part':part,'offset':offset,
        'bytes':len(body),'sha256':hashlib.sha256(body).hexdigest(),'data_b64':base64.b64encode(chunk).decode(),
        'has_more':offset+len(chunk)<len(body),'fresh_observation':False}
