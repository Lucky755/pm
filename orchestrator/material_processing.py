"""Task-scoped immutable files and local transformations over memory references.

No target traffic, proof upgrades, specimen execution, checkout or Git fetch.
Outputs and failure receipts are separate from preserved original materials.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import sqlite3
import stat
import subprocess
import sys
import tempfile
from orchestrator import diagnostics,task_memory
from orchestrator.material_worker import MAX_BYTES,VERSION

ROOT=Path(__file__).resolve().parents[1]/'artifacts/materials'
MAX_TASK_BYTES=256*1024*1024


def initialize(db):
    db.execute('''CREATE TABLE IF NOT EXISTS pm_file_materials (
        id INTEGER PRIMARY KEY,task_id INTEGER NOT NULL,sha256 TEXT NOT NULL,bytes INTEGER NOT NULL,
        name TEXT NOT NULL,source_ref TEXT NOT NULL,parent_id INTEGER,complete INTEGER NOT NULL,
        metadata_json TEXT NOT NULL,created_at TEXT NOT NULL,
        UNIQUE(task_id,sha256,name,source_ref))''')
    db.execute('''CREATE TABLE IF NOT EXISTS pm_material_processing (
        id INTEGER PRIMARY KEY,task_id INTEGER NOT NULL,input_ref TEXT NOT NULL,input_sha256 TEXT NOT NULL,
        signature TEXT NOT NULL,status TEXT NOT NULL,result_json TEXT NOT NULL,created_at TEXT NOT NULL)''')


def directory(task_id,create=False):
    if type(task_id) is not int or task_id<1:raise ValueError('Invalid task')
    root=Path(ROOT)
    if root.is_symlink():raise ValueError('Unsafe material root')
    if create:root.mkdir(mode=0o700,parents=True,exist_ok=True)
    path=root/str(task_id)
    if path.is_symlink():raise ValueError('Unsafe task material directory')
    if create:path.mkdir(mode=0o700,exist_ok=True)
    info=path.stat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid!=os.getuid() or info.st_mode&0o077:raise ValueError('Unsafe task material permissions')
    return path


def save(db,task_id,data,*,name,source_ref,parent_id=None,complete=True,metadata=None):
    if not isinstance(data,bytes) or len(data)>MAX_BYTES:raise ValueError('Material exceeds per-file byte limit')
    if not db.execute('SELECT 1 FROM tasks WHERE id=?',(task_id,)).fetchone():raise ValueError('Unknown task')
    if not isinstance(name,str) or not 1<=len(name)<=4096 or not isinstance(source_ref,str) or not source_ref:raise ValueError('Material needs name/source')
    if parent_id is not None and not db.execute('SELECT 1 FROM pm_file_materials WHERE task_id=? AND id=?',(task_id,parent_id)).fetchone():raise ValueError('Foreign parent')
    initialize(db);checksum=hashlib.sha256(data).hexdigest();folder=directory(task_id,True);destination=folder/checksum
    if destination.is_symlink():raise ValueError('Unsafe material file')
    if not destination.exists():
        used=sum(p.stat().st_size for p in folder.iterdir() if p.is_file())
        if used+len(data)>MAX_TASK_BYTES:raise ValueError('Task material byte budget exceeded')
        fd,temporary=tempfile.mkstemp(prefix='.material-',dir=folder)
        try:
            with os.fdopen(fd,'wb') as stream:stream.write(data);stream.flush();os.fsync(stream.fileno())
            os.replace(temporary,destination)
        finally:
            if os.path.exists(temporary):os.unlink(temporary)
    with task_memory.atomic(db):
        db.execute('INSERT OR IGNORE INTO pm_file_materials(task_id,sha256,bytes,name,source_ref,parent_id,complete,metadata_json,created_at) VALUES(?,?,?,?,?,?,?,?,?)',
            (task_id,checksum,len(data),name,source_ref,parent_id,int(bool(complete)),task_memory.encoded(metadata or {}),task_memory.now()))
        row=db.execute('SELECT id FROM pm_file_materials WHERE task_id=? AND sha256=? AND name=? AND source_ref=?',(task_id,checksum,name,source_ref)).fetchone()
    return describe(db,task_id,row[0])


def describe(db,task_id,ident):
    cursor=db.execute('SELECT * FROM pm_file_materials WHERE task_id=? AND id=?',(task_id,ident));row=cursor.fetchone()
    if not row:raise ValueError('Unknown/foreign material')
    data=dict(zip([c[0] for c in cursor.description],row));data['metadata']=json.loads(data.pop('metadata_json'))
    return {**data,'reference':'file_material:'+str(data['id']),'fresh_observation':False}


def load(db,task_id,reference):
    match=re.fullmatch(r'file_material:(\d+)',reference)
    if not match:raise ValueError('Invalid file material reference')
    info=describe(db,task_id,int(match[1]));path=directory(task_id)/info['sha256']
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    with os.fdopen(fd,'rb') as stream:
        details=os.fstat(stream.fileno())
        if not stat.S_ISREG(details.st_mode) or details.st_uid!=os.getuid() or details.st_mode&0o077:raise ValueError('Unsafe file material')
        data=stream.read(MAX_BYTES+1)
    if len(data)!=info['bytes'] or hashlib.sha256(data).hexdigest()!=info['sha256']:raise ValueError('Material integrity mismatch')
    return data


def options_checked(options):
    allowed={'encoding','object_id','ocr','language','page_start','page_end','related'}
    if not isinstance(options,dict) or set(options)-allowed:raise ValueError('Unsupported processing options')
    if 'encoding' in options and (not isinstance(options['encoding'],str) or not re.fullmatch(r'[A-Za-z0-9_.-]{1,40}',options['encoding'])):raise ValueError('Invalid encoding')
    if 'object_id' in options and not re.fullmatch(r'[a-f0-9]{40}',str(options['object_id'])):raise ValueError('Invalid Git object ID')
    if 'language' in options and not re.fullmatch(r'[a-z_+]{1,50}',str(options['language'])):raise ValueError('Invalid OCR language')
    if 'ocr' in options and type(options['ocr']) is not bool:raise ValueError('Invalid OCR option')
    return options


def source_complete(db,task_id,reference):
    if re.fullmatch(r'file_material:\d+',reference):return bool(describe(db,task_id,int(reference.split(':')[1]))['complete'])
    if re.fullmatch(r'http_artifact:\d+',reference):
        row=db.execute('SELECT complete FROM pm_http_artifacts WHERE task_id=? AND id=?',(task_id,int(reference.split(':')[1]))).fetchone()
        return bool(row and row[0])
    return None  # Original record exists; completeness of its acquisition is unknown.


def audit(db,task_id,record,reference,quote,capability_log):
    """Check an exact local citation, never publish a new remote observation."""
    if db is None or not isinstance(record,dict):return None,'material_audit_missing_record'
    if (record.get('task_id')!=task_id or record.get('provenance')!='local' or
            record.get('tool') not in ('material_process','material_import')):return None,'material_audit_wrong_source'
    payload=record.get('result') or {}
    if payload.get('task_id')!=task_id or payload.get('status') not in ('completed','partial'):return None,'material_audit_incomplete_receipt'
    if not isinstance(quote,str) or not quote or len(quote)>8192:return None,'material_audit_exact_quote_required'
    try:
        supplied=payload.get('material_refs') or []
        claimed=next((item for item in supplied if item.get('reference')==reference),None)
        if not claimed:return None,'material_audit_result_reference_mismatch'
        item=describe(db,task_id,int(reference.split(':')[1]));body=load(db,task_id,reference)
        if any(item[k]!=claimed.get(k) for k in ('sha256','bytes')):return None,'material_audit_receipt_integrity_mismatch'
        if record['tool']=='material_process':
            row=db.execute('SELECT result_json FROM pm_material_processing WHERE task_id=? AND id=?',(task_id,payload.get('processing_id'))).fetchone()
            saved=json.loads(row[0]) if row else {}
            if not any(out['reference']==reference and out['sha256']==item['sha256'] for out in saved.get('outputs',[])):
                return None,'material_audit_processing_reference_mismatch'
        current=item;seen=set()
        for _ in range(32):
            if current['reference'] in seen:raise ValueError('Cyclic material lineage')
            seen.add(current['reference']);source=current['source_ref']
            if current['parent_id'] is not None and source!='file_material:'+str(current['parent_id']):raise ValueError('Broken material lineage')
            if source.startswith('file_material:'):
                load(db,task_id,source);current=describe(db,task_id,int(source.split(':')[1]));continue
            if source.startswith(('workspace:','operator:')):break
            # Revalidate acquisition bytes, without repeating that acquisition.
            if source.startswith('http_artifact:'):
                from orchestrator import http_artifacts
                original,_=http_artifacts.load(db,task_id,int(source.split(':')[1]))
            else:original=task_memory.material(db,task_id,source,capability_log)
            if hashlib.sha256(original).hexdigest()!=current['sha256']:raise ValueError('Changed source material')
            break
        else:raise ValueError('Material lineage exceeds audit depth')
        if quote.encode('utf-8') not in body:return None,'material_audit_quote_mismatch'
        return {'kind':'saved_file_material','result_id':record['id'],'artifact_ref':reference,'quote':quote,
            'sha256':item['sha256'],'source_ref':item['source_ref'],'fresh_observation':False},None
    except (ValueError,KeyError,TypeError,OSError,sqlite3.Error):return None,'material_audit_missing_corrupt_or_foreign_source'


def process(db,task_id,reference,capability_log=None,*,operation='auto',options=None):
    if operation not in ('auto','text','archive','pdf','image','executable','git'):raise ValueError('Unknown file handler')
    options=dict(options_checked({} if options is None else options));related=options.pop('related',[])
    if not isinstance(related,list) or len(related)>128:raise ValueError('Git related input limit')
    raw=task_memory.material(db,task_id,reference,capability_log)
    if len(raw)>MAX_BYTES:raise ValueError('Material exceeds processing limit; original retained')
    blobs=[]
    from orchestrator.material_worker import git_member
    for item in related:
        if (not isinstance(item,dict) or set(item)!={'reference','path'} or not isinstance(item['reference'],str)
                or not isinstance(item['path'],str) or not git_member(item['path'])):raise ValueError('Related Git input must be an inert object/pack/index path')
        body=task_memory.material(db,task_id,item['reference'],capability_log)
        if len(body)>MAX_BYTES:raise ValueError('Related material byte limit')
        blobs.append((item,body))
    related_identity=[{**item,'sha256':hashlib.sha256(body).hexdigest()} for item,body in blobs]
    source_state=source_complete(db,task_id,reference)
    if any(source_complete(db,task_id,item['reference']) is False for item,body in blobs):source_state=False
    signature=task_memory.digest({'input':hashlib.sha256(raw).hexdigest(),'operation':operation,'options':options,'related':related_identity,'processor_version':VERSION})
    initialize(db)
    cached=db.execute("SELECT result_json FROM pm_material_processing WHERE task_id=? AND input_ref=? AND signature=? AND status='completed' ORDER BY id DESC LIMIT 1",(task_id,reference,signature)).fetchone()
    if cached:
        result=json.loads(cached[0])
        for output in result['outputs']:load(db,task_id,output['reference'])
        return {**result,'cached':True}
    input_copy=save(db,task_id,raw,name='original',source_ref=reference,complete=source_state is not False,
                    metadata={'role':'preserved_input','source_complete':source_state})
    # Commit the immutable original before starting a parser; failed conversion
    # and failed later publication must not discard the input.
    db.commit()
    with tempfile.TemporaryDirectory(prefix='pm-material-worker-') as tmp:
        folder=Path(tmp);(folder/'input').write_bytes(raw);related_request=[]
        for index,(item,body) in enumerate(blobs):
            filename='related-'+str(index);(folder/filename).write_bytes(body)
            related_request.append({**item,'file':filename})
        (folder/'request.json').write_text(json.dumps({'operation':operation,'options':options,'related':related_request}))
        worker=Path(__file__).with_name('material_worker.py')
        with diagnostics.Action('material','local_material_processing',task_id=task_id,
                                parameters={'reference':reference,'operation':operation}) as event:
            try:
                with subprocess.Popen([sys.executable,str(worker),tmp],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                    start_new_session=True,env={'PATH':'/usr/bin:/bin','LANG':'C.UTF-8',
                        'PYTHONPATH':os.environ.get('PYTHONPATH',str(worker.parents[1])),**diagnostics.child_env()}) as process:
                    try:process.communicate(timeout=90)
                    finally:
                        try:os.killpg(process.pid,signal.SIGKILL)
                        except ProcessLookupError:pass
                        process.wait()
                result=json.loads((folder/'result.json').read_text())
                event.status=result['status']
            except (OSError,ValueError,subprocess.TimeoutExpired) as exc:
                progress=folder/'outputs.json'
                try:outputs=json.loads(progress.read_text()) if progress.is_file() else []
                except (ValueError,OSError):outputs=[]
                result={'status':'partial' if outputs else 'failed','kind':'unknown','complete':False,'outputs':outputs,
                    'errors':[{'category':'worker_failure','reason':type(exc).__name__}]};event.status=result['status']
            outputs=[]
            with task_memory.atomic(db):
                for item in result.get('outputs',[]):
                    try:
                        filename=item['file']
                        if not re.fullmatch(r'output-\d+',filename):raise ValueError('Invalid worker output')
                        body=(folder/filename).read_bytes()
                        if len(body)!=item['bytes'] or hashlib.sha256(body).hexdigest()!=item['sha256']:raise ValueError('Worker output integrity mismatch')
                        outputs.append(save(db,task_id,body,name=item['name'],source_ref=input_copy['reference'],parent_id=input_copy['id'],
                            complete=item.get('kind')!='partial_analyzer_output' and source_state is not False,
                            metadata={k:v for k,v in item.items() if k not in ('file','name','bytes','sha256')}))
                    except (ValueError,OSError) as exc:
                        result.setdefault('errors',[]).append({'category':'publication_error','reason':str(exc)[:200]})
                        result.update(status='partial' if outputs else 'failed',complete=False);break
                result['transformation_complete']=result['complete']
                if source_state is False:
                    result['complete']=False
                    if result['status']=='completed':result['status']='partial'
                    result.setdefault('errors',[]).append({'category':'source_incomplete','reason':'Original acquisition is explicitly incomplete'})
                result={**result,'outputs':outputs,'task_id':task_id,'input_reference':reference,'original_reference':input_copy['reference'],
                    'input_sha256':hashlib.sha256(raw).hexdigest(),'related_inputs':related_identity,'processor_version':VERSION,
                    'source_complete':source_state,'cached':False,'provenance':'local','fresh_observation':False}
                event.status=result['status']
                # Do not place raw secret-bearing content into diagnostic events.
                event.fields.update(output_count=len(outputs),reason_category='material_'+result['status'])
                db.execute('INSERT INTO pm_material_processing(task_id,input_ref,input_sha256,signature,status,result_json,created_at) VALUES(?,?,?,?,?,?,?)',
                    (task_id,reference,result['input_sha256'],signature,result['status'],task_memory.encoded(result),task_memory.now()))
                result['processing_id']=db.execute('SELECT last_insert_rowid()').fetchone()[0]
                db.execute('UPDATE pm_material_processing SET result_json=? WHERE id=?',
                    (task_memory.encoded(result),result['processing_id']))
    db.commit()
    return result
