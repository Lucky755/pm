"""Evidence-based operator notifications, separate from research proof statuses."""
import hashlib
import json
import re
from datetime import datetime, timezone
from urllib.parse import unquote

from orchestrator import flag_evidence, diagnostics, objectives


def now():
    return datetime.now(timezone.utc).isoformat()


def initialize(db):
    db.execute('''CREATE TABLE IF NOT EXISTS pm_coordinator_checkpoints (
        id INTEGER PRIMARY KEY, task_id INTEGER NOT NULL, target TEXT NOT NULL,
        fingerprint TEXT NOT NULL, category TEXT NOT NULL, payload_json TEXT NOT NULL,
        step_id INTEGER NOT NULL, status TEXT NOT NULL CHECK(status IN ('pending','reviewed')),
        created_at TEXT NOT NULL, reviewed_at TEXT,
        UNIQUE(task_id,target,fingerprint))''')


def pending(db, task_id, target=None):
    """Read-only, including older tasks with no notification table."""
    if not db.execute("SELECT 1 FROM sqlite_master WHERE name='pm_coordinator_checkpoints' AND type='table'").fetchone():
        return []
    if target is None:
        row=db.execute('SELECT target FROM tasks WHERE id=?',(task_id,)).fetchone()
        if not row:
            return []
        target=row[0]
    rows=db.execute("SELECT id,step_id,payload_json,status FROM pm_coordinator_checkpoints "
                    "WHERE task_id=? AND target=? AND status='pending' ORDER BY id",(task_id,target))
    return [{**json.loads(raw),'id':cid,'step_id':step,'status':status} for cid,step,raw,status in rows]


def review(db, task_id, target, step_id):
    """An explicit continuation acknowledges notifications, not their truth."""
    ids=[item['id'] for item in pending(db,task_id,target) if item['step_id']==step_id]
    with db:
        db.execute("UPDATE pm_coordinator_checkpoints SET status='reviewed',reviewed_at=? "
                   "WHERE task_id=? AND target=? AND step_id=? AND status='pending'",(now(),task_id,target,step_id))
    return ids


def history(db, task_id, target, limit=12):
    """Operator review is metadata, not a change to the research evidence."""
    if not db.execute("SELECT 1 FROM sqlite_master WHERE name='pm_coordinator_checkpoints' AND type='table'").fetchone():
        return {'entries':[],'omitted':0}
    rows=db.execute('SELECT id,status,payload_json FROM pm_coordinator_checkpoints '
                    'WHERE task_id=? AND target=? ORDER BY id DESC LIMIT ?', (task_id,target,limit)).fetchall()
    count=db.execute('SELECT COUNT(*) FROM pm_coordinator_checkpoints WHERE task_id=? AND target=?',
                     (task_id,target)).fetchone()[0]
    return {'entries':[{'id':cid,'status':status,**json.loads(raw)} for cid,status,raw in rows],
            'omitted':max(0,count-len(rows))}


def legacy_report(db, task_id, step_id):
    row=db.execute('SELECT r.report_json FROM pm_coordinator_steps s JOIN pm_agent_action_reports r '
                   'ON r.task_id=s.task_id AND r.iteration=s.report_iteration '
                   'WHERE s.task_id=? AND s.id=?',(task_id,step_id)).fetchone()
    return json.loads(row[0]) if row else {}


def finding_refs(report):
    refs=set()
    for finding in report.get('findings',[]):
        if not isinstance(finding,dict):
            continue
        probe=finding.get('probe') if isinstance(finding.get('probe'),dict) else {}
        for ref in (finding.get('artifact_ref'),finding.get('result_id'),probe.get('result_id')):
            if isinstance(ref,str):
                ref=ref.removeprefix('result:')
                if re.fullmatch(r'http_artifact:[1-9][0-9]*|[a-f0-9]{24,64}',ref):
                    refs.add(ref)
    return refs


def pause_details(db, task_id, target=None):
    points=pending(db,task_id,target)
    if points:
        return points
    # Older saved pauses remain explicit. Display their actual report, without
    # migrating evidence, re-running a role or treating the old heuristic as proof.
    row=db.execute('SELECT pause_step_id,stop_reason FROM pm_coordinator_runs '
                   "WHERE task_id=? AND status='waiting_operator'",(task_id,)).fetchone()
    if not row or row[1] not in ('significant_finding','access_state_changed','confirmed_flag_found','objective_state_changed'):
        return []
    report=legacy_report(db,task_id,row[0])
    return [{'category':'legacy_review','title':diagnostics.clean(f.get('title') or f.get('claim') or 'Сохранённая находка'),
             'evidence_refs':sorted(finding_refs({'findings':[f]})) or [f'report_step:{row[0]}'],
             'reason':'Историческая пауза сохранена по прежнему правилу; confidence и impact не доказывают существенность.',
             'operator_action':CONTINUE} for f in report.get('findings',[]) if isinstance(f,dict)]


def _hash(value):
    return hashlib.sha256(json.dumps(value,sort_keys=True,ensure_ascii=False).encode()).hexdigest()


def _item(category, location, subject, title, refs, reason, action):
    return {'fingerprint':_hash([category,location,subject]),'category':category,'title':diagnostics.clean(title),
            'evidence_refs':refs,'reason':reason,'operator_action':action}


CONTINUE='Изучите сохранённое свидетельство и границы дальнейшей проверки; затем --continue-coordinated.'
SECRET=re.compile(r'''(?im)^\s*["']?(?:[A-Z0-9_]*(?:PASSWORD|PASSWD|API_KEY|CLIENT_SECRET|ACCESS_TOKEN|SECRET_KEY))["']?\s*[:=]\s*["']?([^\s"'<>;]{8,})''')
PLACEHOLDERS={'changeme','change_me','password','your_password','your_api_key','example','placeholder'}


def collect(db, task_id, before, after, *, references=None):
    """Classify original bytes/state, never confidence, impact or model severity.

    Supported source witnesses are integrity-checked Git blobs and exposed
    server-side backup source. Git metadata alone is reconnaissance. More files
    or changed bytes in an already exposed repository are the same disclosure;
    a newly exposed secret is a separate material finding.
    """
    items=[]
    for proof,text in flag_evidence.collect(db,task_id)[0]:
        if references is not None and not any(flag_evidence.reference_matches(
                db,task_id,ref,proof,objectives._record_for(task_id,ref)) for ref in references):
            continue
        location=[proof[k] for k in ('target','scheme','hostname','port')]
        path=unquote(proof['path']).lower()
        source=None
        if proof['kind']=='git_blob':
            source=('git_repository',proof['path'].rsplit('/objects/',1)[0])
        elif path.endswith(('.phps','.php.bak','.php.old','.py.bak','.rb.bak')) and re.search(r'<\?php|(?m:^\s*(?:def |import |from ))',text):
            source=('server_source',proof['path'])
        refs=[proof['capture_ref']]
        if source:
            items.append(_item('source_disclosure',location,source,
                f"Раскрытие исходников: {proof['scheme']}://{proof['hostname']}:{proof['port']}{proof['path']}",refs,
                'Сохранённые байты подтверждают раскрытие исходников; целостность capture и формат/хэш Git-объекта (если применимо) проверены.',CONTINUE))
        config=(proof['kind']=='git_blob' or path.endswith(('.env','.ini','.cfg','.config','.yml','.yaml','.bak')))
        secrets=[]
        if config:
            secrets.extend(match[1] for match in SECRET.finditer(text))
        secrets.extend(match.group() for match in re.finditer(
            r'-----BEGIN (?:RSA |EC |OPENSSH |ENCRYPTED )?PRIVATE KEY-----[\s\S]{32,}?-----END (?:RSA |EC |OPENSSH |ENCRYPTED )?PRIVATE KEY-----',text))
        for value in sorted(set(secrets)):
            if value.lower() in PLACEHOLDERS or value.startswith(('$','<')) or flag_evidence.value_in_request(proof,value):
                continue
            items.append(_item('secret_disclosure',location,_hash(value),
                f"Раскрытие секрета: {proof['scheme']}://{proof['hostname']}:{proof['port']}{proof['path']}",refs,
                'Сохранённый ответ содержит секретоподобное значение в конфигурации или блок приватного ключа; значение скрыто, работоспособность не утверждается.',CONTINUE))
    old=before['essential_state']['access_state'];new=after['essential_state']['access_state']
    if (old['level'],old['signal']) != (new['level'],new['signal']):
        refs=['result:'+new['access_result_id']] if new.get('access_result_id') else [f'pm_access_state:{task_id}']
        items.append(_item('access_change',[after['task']['target']],(new['level'],new['signal']),
            f"Изменение доступа: {old['level']} → {new['level']}; сигнал {new['signal']}",refs,
            'Существенно изменилось сохранённое состояние доступа; требуется проверить свидетельство и границы следующего шага.',
            'Проверьте результат и триаж; --continue-coordinated продолжит планирование. Каждый ACCESS требует отдельного --approve-step ID.'))
    for value in sorted(set(after['confirmed_flags'])-set(before['confirmed_flags'])):
        row=db.execute('SELECT sources_json FROM pm_verified_flags WHERE task_id=? AND value=?',(task_id,value)).fetchone()
        sources=json.loads(row[0]) if row else {}
        proofs=sources.get('verified_evidence',[])
        if proofs and sources.get('matched_by')!='kv':
            items.append(_item('flag_found',[after['task']['target']],_hash(value),
                'Подтверждён флаг, но исследовательская цель ещё не завершена',
                [p['capture_ref'] for p in proofs],
                'Есть проверенное свидетельство флага; требуется оценить оставшиеся обязательные цели.',CONTINUE))
    return items


def register(db, task_id, target, step_id, items):
    with db:
        for item in items:
            db.execute('INSERT OR IGNORE INTO pm_coordinator_checkpoints '
                '(task_id,target,fingerprint,category,payload_json,step_id,status,created_at) '
                "VALUES(?,?,?,?,?,?,'pending',?)",(task_id,target,item['fingerprint'],item['category'],
                                                 json.dumps(item,ensure_ascii=False),step_id,now()))
    return pending(db,task_id,target)
