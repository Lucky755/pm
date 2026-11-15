"""Durable bounded acquisitions. SQLite describes work; root receipts grant it.

Only the operator CLI can authorize a broker receipt. MCP may prepare, inspect
and apply an already authorized receipt, never turn an SQLite approval into root
permission. Failed/unknown transactions are not automatically replayed.
"""
import json
import os
import hashlib
import base64
import stat
import subprocess
from orchestrator import diagnostics, task_memory
from executor.netguard_root import tool_spec, tool_digest

BROKER = '/usr/local/sbin/pm-netguard'


def initialize(db):
    db.execute('''CREATE TABLE IF NOT EXISTS pm_tool_requests (
        id INTEGER PRIMARY KEY, task_id INTEGER NOT NULL, fingerprint TEXT NOT NULL,
        spec_json TEXT NOT NULL, receipt_json TEXT NOT NULL, question_id INTEGER,
        status TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
        UNIQUE(task_id,fingerprint))''')
    db.execute('''CREATE TABLE IF NOT EXISTS pm_tool_events (
        id INTEGER PRIMARY KEY, task_id INTEGER NOT NULL, tool_request_id INTEGER NOT NULL,
        event TEXT NOT NULL, payload_json TEXT NOT NULL, created_at TEXT NOT NULL)''')
    db.execute('''CREATE TABLE IF NOT EXISTS pm_tool_dependencies (
        tool_request_id INTEGER NOT NULL, task_id INTEGER NOT NULL, branch_id TEXT NOT NULL,
        UNIQUE(tool_request_id,task_id,branch_id))''')


def listing(db, task_id):
    if not task_memory.exists(db, 'pm_tool_requests'): return []
    cursor = db.execute('SELECT * FROM pm_tool_requests WHERE task_id=? ORDER BY id', (task_id,))
    values = []
    for row in cursor:
        item = dict(zip([c[0] for c in cursor.description], row))
        item['spec'] = json.loads(item.pop('spec_json'))
        item['receipt'] = json.loads(item.pop('receipt_json'))
        item['dependent_branches'] = ([r[0] for r in db.execute('SELECT branch_id FROM pm_tool_dependencies '
            'WHERE tool_request_id=? AND task_id=? ORDER BY branch_id',(item['id'],task_id))]
            if task_memory.exists(db,'pm_tool_dependencies') else [])
        values.append(item)
    return values


def for_question(db, task_id, question_id):
    return next((item for item in listing(db, task_id) if item['question_id'] == question_id), None)


def broker_call(task_id, action, *, spec=None, request_id=None):
    argv = ['sudo', '-n', BROKER, 'tool', '--task-id', str(task_id), '--action', action]
    if spec is not None: argv += ['--spec-json', json.dumps(spec, ensure_ascii=False)]
    if request_id is not None: argv += ['--request-id', request_id]
    with diagnostics.Action('acquisition', 'tool_'+action, task_id=task_id, tool='tool_'+action,
                            parameters={'action': action, 'request_id': request_id}) as event:
        try:
            process = subprocess.run(argv, capture_output=True, text=True, timeout=240,
                                     env={**os.environ, **diagnostics.child_env()})
            data = json.loads(process.stdout)
        except subprocess.TimeoutExpired:
            data = {'status': 'unknown', 'reason_category': 'outcome_unknown',
                    'error': 'Broker timed out; do not repeat installation without reviewing its receipt'}
        except OSError as exc:
            data = {'status': 'error', 'reason_category': 'permission_denied' if isinstance(exc,PermissionError) else 'executor_unavailable',
                    'error': 'Tool broker is unavailable or has an unsupported protocol; operator must check installation'}
        except ValueError:
            data = {'status':'unknown' if action=='apply' else 'error',
                    'reason_category':'outcome_unknown' if action=='apply' else 'executor_unavailable',
                    'error':'Broker response is unreadable; inspect its receipt before any repeat'}
        event.status = data.get('status', 'error')
        event.fields.update(diagnostics.failure_details(data), result=data.get('result'))
    return data


def record(db, item, status, receipt):
    from orchestrator.operator_questions import now
    # Timeouts/protocol refusals may have no envelope. Never lose the immutable
    # root request reference needed to reconcile a possibly finished operation.
    receipt={**item['receipt'],**receipt}
    if (receipt.get('request_id')!=item['receipt']['request_id']
            or receipt.get('manifest')!=item['receipt']['manifest']):
        receipt={**item['receipt'],'status':'unknown','result':{
            'reason_category':'outcome_unknown','reason':'Broker receipt identity mismatch; do not replay'}}
        status='unknown'
    with task_memory.atomic(db):
        db.execute('UPDATE pm_tool_requests SET status=?,receipt_json=?,updated_at=? WHERE id=?',
                   (status, task_memory.encoded(receipt), now(), item['id']))
        db.execute('INSERT INTO pm_tool_events(task_id,tool_request_id,event,payload_json,created_at) VALUES(?,?,?,?,?)',
                   (item['task_id'], item['id'], status, task_memory.encoded(receipt), now()))
    diagnostics.emit('tool.state', task_id=item['task_id'], status=status,
                     identifiers={'tool_request_id': item['id'], 'question_id': item['question_id']},
                     reason_category=(receipt.get('result') or {}).get('reason_category', receipt.get('reason_category')))
    return next(i for i in listing(db, item['task_id']) if i['id'] == item['id'])


def request(db, task_id, target, decision, step_id=None, *, call=None):
    from orchestrator import operator_questions as questions
    call = call or broker_call
    spec = tool_spec(decision['operator_question']['request'])
    # Purpose/wording/references are explanation, not new installation conditions.
    conditions = {k: v for k, v in spec.items() if k != 'purpose'}
    fingerprint = tool_digest(conditions)
    previous = next((i for i in listing(db, task_id) if i['fingerprint'] == fingerprint), None)
    if previous:
        with task_memory.atomic(db):
            initialize(db)
            db.execute('INSERT OR IGNORE INTO pm_tool_dependencies VALUES(?,?,?)',
                       (previous['id'],task_id,questions.branch(decision)))
        return next(q for q in questions.listing(db, task_id) if q['id'] == previous['question_id'])
    receipt = call(task_id, 'prepare', spec=spec)
    if receipt.get('status') not in ('prepared', 'approved', 'completed', 'failed', 'running', 'unknown') or not receipt.get('request_id'):
        raise ValueError('tool_prepare_failed:' + str(receipt.get('reason_category', 'executor_unavailable')))
    manifest = receipt['manifest']
    if manifest.get('spec') != spec or manifest.get('task_id') != task_id or tool_digest(manifest) != receipt['request_id']:
        raise ValueError('tool_prepare_receipt_mismatch')
    question_decision = {**decision, 'operator_question': {'kind': 'tool'},
        'question': f"Разрешить {spec['kind']} {spec['name']} ({spec['version']})? " + spec['purpose']}
    with task_memory.atomic(db):
        initialize(db)
        question = questions.request(db, task_id, target, question_decision, step_id)
        db.execute('INSERT INTO pm_tool_requests(task_id,fingerprint,spec_json,receipt_json,question_id,status,created_at,updated_at) '
                   "VALUES(?,?,?,?,?,'pending',?,?)", (task_id, fingerprint, task_memory.encoded(spec),
                    task_memory.encoded(receipt), question['id'], questions.now(), questions.now()))
        tool_id=db.execute('SELECT id FROM pm_tool_requests WHERE task_id=? AND fingerprint=?',(task_id,fingerprint)).fetchone()[0]
        db.execute('INSERT OR IGNORE INTO pm_tool_dependencies VALUES(?,?,?)',(tool_id,task_id,questions.branch(decision)))
    return next(q for q in questions.listing(db, task_id) if q['id'] == question['id'])


def answered(db, question, decision):
    item = for_question(db, question['task_id'], question['id'])
    if not item: return False  # Legacy informational tool questions grant nothing.
    if decision == 'information': raise ValueError('Actionable tool request needs approve or decline')
    record(db, item, 'approved' if decision == 'approve' else 'declined', item['receipt'])
    return True


def acquire(db, task_id, request_id, *, authorize=False, call=None):
    call = call or broker_call
    item = next((i for i in listing(db, task_id) if i['id'] == request_id), None)
    if not item: raise ValueError('Unknown task tool request')
    if item['status'] in ('pending', 'declined', 'failed'):
        return {**item, 'reason': 'operator_declined' if item['status'] == 'declined' else 'not_authorized_or_requires_review'}
    root_id = item['receipt']['request_id']
    if item['status'] in ('unknown','running'):
        receipt=call(task_id,'status',request_id=root_id)
        if receipt.get('status') in ('completed','failed'):
            return record(db,item,receipt['status'],receipt)
        if authorize and receipt.get('status') in ('prepared','approved'):
            item=record(db,item,'approved',receipt)
        else:return {**item,'reason':'installation_outcome_unknown_no_replay'}
    if authorize:
        # Called only by the explicit operator command, never by an MCP endpoint.
        receipt = call(task_id, 'authorize', request_id=root_id)
        if receipt.get('status') not in ('approved', 'completed'):
            return record(db, item, receipt.get('status', 'failed'), receipt)
    receipt = call(task_id, 'apply', request_id=root_id)
    status = receipt.get('status', 'failed')
    # A DB answer after a crash does not authorize an unapproved root receipt.
    if status == 'prepared': status = 'approved'
    if status not in ('approved', 'completed', 'failed', 'running', 'unknown'): status = 'failed'
    return record(db, item, status, receipt)


def describe(item):
    manifest = item['receipt'].get('manifest', {})
    return {**{key: item[key] for key in ('id', 'status', 'question_id', 'spec','dependent_branches')},
            'manifest': manifest, 'result': item['receipt'].get('result'),
            'error': item['receipt'].get('error')}


def read_material(db,task_id,request_id,offset=0,limit=4096):
    """Read original workspace bytes locally, including in web-only tasks."""
    from executor.netguard_root import WORK_BASE, TOOL_MAX_BYTES
    if type(offset) is not int or offset<0 or type(limit) is not int or not 1<=limit<=16384:
        raise ValueError('Invalid tool material range')
    item=next((i for i in listing(db,task_id) if i['id']==request_id),None)
    if not item or item['status']!='completed' or item['spec']['kind']=='system_package':
        raise ValueError('No completed user tool/documentation material')
    spec=tool_spec(item['spec']);result=item['receipt']['result']
    relative=('docs' if spec['kind']=='documentation' else 'tools')+'/'+spec['name']+'/'+spec['filename']
    directory=os.open(WORK_BASE/str(task_id),os.O_DIRECTORY|os.O_NOFOLLOW)
    try:
        for component in relative.split('/')[:-1]:
            child=os.open(component,os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=directory)
            os.close(directory);directory=child
        fd=os.open(spec['filename'],os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=directory)
        with os.fdopen(fd,'rb') as stream:
            info=os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.getuid():raise ValueError('Unsafe tool material')
            data=stream.read(TOOL_MAX_BYTES+1)
    finally:os.close(directory)
    if len(data)>TOOL_MAX_BYTES or hashlib.sha256(data).hexdigest()!=result.get('sha256'):
        raise ValueError('Installed material changed; original receipt no longer matches')
    chunk=data[offset:offset+limit]
    return {'status':'completed','reference':'tool_request:'+str(request_id),'provenance':'local_read',
            'sha256':result['sha256'],'total_bytes':len(data),'offset':offset,'bytes':len(chunk),
            'data_b64':base64.b64encode(chunk).decode(),'text_untrusted':chunk.decode('utf-8',errors='replace'),
            'has_more':offset+len(chunk)<len(data)}
