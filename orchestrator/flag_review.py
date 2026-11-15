"""Task-linked flag proposals and explicit CTF-platform decisions. Local only."""
import json
import re
from pathlib import PurePosixPath, Path
from urllib.parse import unquote
from orchestrator import task_memory, diagnostics


def initialize(db):
    db.execute('''CREATE TABLE IF NOT EXISTS pm_flag_review_policy (
        task_id INTEGER PRIMARY KEY,expected_flags INTEGER,legacy_flags_json TEXT NOT NULL,
        legacy_goals_json TEXT NOT NULL,activated_at TEXT NOT NULL)''')
    db.execute('''CREATE TABLE IF NOT EXISTS pm_flag_proposals (
        id INTEGER PRIMARY KEY,task_id INTEGER NOT NULL,target TEXT NOT NULL,
        objective_key TEXT NOT NULL,objective_title TEXT NOT NULL,value TEXT NOT NULL,value_sha256 TEXT NOT NULL,
        source_json TEXT NOT NULL,materials_json TEXT NOT NULL,status TEXT NOT NULL,
        revision INTEGER NOT NULL DEFAULT 1,question_id INTEGER,created_at TEXT NOT NULL,updated_at TEXT NOT NULL,
        UNIQUE(task_id,target,objective_key,value_sha256))''')
    db.execute('''CREATE TABLE IF NOT EXISTS pm_flag_proposal_events (
        id INTEGER PRIMARY KEY,proposal_id INTEGER NOT NULL,task_id INTEGER NOT NULL,
        event TEXT NOT NULL,payload_json TEXT NOT NULL,created_at TEXT NOT NULL)''')


def activate(db,task_id,expected=None):
    """Snapshot old confirmations once, before any new discovery is classified."""
    with task_memory.atomic(db):
        initialize(db)
        saved=next((g.get('expected_flags') or 0 for g in task_memory.rows(db,'pm_objectives',task_id) if g['key']=='goal'),0)
        expected=max(expected or 0,saved) or None
        if not db.execute('SELECT 1 FROM pm_flag_review_policy WHERE task_id=?',(task_id,)).fetchone():
            flags=task_memory.rows(db,'pm_verified_flags',task_id)
            goals=task_memory.rows(db,'pm_objectives',task_id)
            db.execute('INSERT INTO pm_flag_review_policy VALUES(?,?,?,?,?)',(task_id,expected,
                task_memory.encoded([f for f in flags if f['status']=='confirmed']),
                task_memory.encoded([g for g in goals if g['status']=='confirmed']),task_memory.now()))
        elif expected is not None:
            db.execute('UPDATE pm_flag_review_policy SET expected_flags=MAX(COALESCE(expected_flags,0),?) WHERE task_id=?',
                       (expected,task_id))


def policy(db,task_id):
    if not task_memory.exists(db,'pm_flag_review_policy'):return None
    row=db.execute('SELECT expected_flags,legacy_flags_json,legacy_goals_json FROM pm_flag_review_policy WHERE task_id=?',(task_id,)).fetchone()
    return {'expected_flags':row[0],'legacy_flags':json.loads(row[1]),'legacy_goals':json.loads(row[2])} if row else None


def listing(db,task_id):
    if not task_memory.exists(db,'pm_flag_proposals') or not task_memory.exists(db,'tasks'):return []
    from orchestrator import resources
    targets=resources.machine_targets(db,task_id) or [r[0] for r in db.execute('SELECT target FROM tasks WHERE id=?',(task_id,))]
    cursor=db.execute('SELECT * FROM pm_flag_proposals WHERE task_id=? AND target IN ('+','.join('?' for _ in targets)+') ORDER BY id',(task_id,*targets))
    result=[]
    for row in cursor:
        item=dict(zip([c[0] for c in cursor.description],row))
        item['sources']=json.loads(item.pop('source_json'));item['materials']=json.loads(item.pop('materials_json'))
        result.append(item)
    return result


def registry_status(db,task_id,value):
    old=policy(db,task_id)
    if old and any(item['value']==value for item in old['legacy_flags']):return 'confirmed'
    row=db.execute('SELECT operator_confirmed FROM pm_verified_flags WHERE task_id=? AND value=?',(task_id,value)).fetchone()
    if row and row[0]:return 'confirmed'
    proposals=[p for p in listing(db,task_id) if p['value']==value]
    if any(p['status']=='accepted' for p in proposals):return 'confirmed'
    if proposals and all(p['status']=='rejected' for p in proposals):return 'rejected'
    return 'candidate'


def _goals(db,task_id):return task_memory.rows(db,'pm_objectives',task_id)


def local_log(db,task_id,preferred=None):
    """A temporary/alternate DB must never import a working task's log."""
    filename=next((r[2] for r in db.execute('PRAGMA database_list') if r[1]=='main'),None)
    if not filename:return None
    parent=Path(filename).parent
    if preferred is not None and Path(preferred).parent.parent==parent:return Path(preferred)
    return parent/'capability_log'/f'task_{task_id}.jsonl'


def _flag_task(db,task_id):
    text=' '.join(str(row.get('intent','')) for row in task_memory.rows(db,'pm_task_intents',task_id))
    text+=' '+' '.join(g['title'] for g in _goals(db,task_id))
    return bool(re.search(r'flag|флаг|(?:user|root)\.txt|\bCTF\b',text,re.I))


def _goal(db,task_id,key,path):
    goals=_goals(db,task_id)
    if key:
        found=next((g for g in goals if g['key']==key),None)
        return (found['key'],found['title']) if found else None
    filename=PurePosixPath(unquote(str(path).split('?',1)[0])).name.lower() if path else ''
    matches=[g for g in goals if filename in ('user.txt','root.txt') and filename in g['title'].lower()]
    if len(matches)==1:return matches[0]['key'],matches[0]['title']
    if not _flag_task(db,task_id):return None
    if len(goals)==1:return goals[0]['key'],goals[0]['title']
    if not goals:return ('file:'+filename,filename) if filename in ('user.txt','root.txt') else ('flags','Флаги задания')
    return None


def _event(db,proposal,event,payload):
    db.execute('INSERT INTO pm_flag_proposal_events(proposal_id,task_id,event,payload_json,created_at) VALUES(?,?,?,?,?)',
               (proposal['id'],proposal['task_id'],event,task_memory.encoded(payload),task_memory.now()))


def propose(db,task_id,value,*,objective_key=None,source='',method='',references=(),path=''):
    """A proposal is a claim for platform submission, not technical proof."""
    from orchestrator import flag_verify
    flag_verify.ensure_schema(db)
    activate(db,task_id)
    if not isinstance(value,str) or not value.strip():return None
    if not task_memory.exists(db,'tasks'):return None
    target=db.execute('SELECT target FROM tasks WHERE id=?',(task_id,)).fetchone()
    if not target:return None
    goal=_goal(db,task_id,objective_key,path or source)
    if goal is None:return None  # material remains in its original report/log
    source_data={'source':str(source or 'Saved specialist claim; original acquisition not recorded'),
                 'method':str(method or source or 'specialist report; acquisition unverified'),'path':str(path)}
    with task_memory.atomic(db):
        stamp=task_memory.now()
        legacy=registry_status(db,task_id,value)=='confirmed'
        # A legacy confirmation may be reused only for its already bound goal.
        prior=policy(db,task_id)
        old_operator=[f for f in prior['legacy_flags'] if f.get('operator_confirmed')]
        inherited=legacy and any(f['value']==value for f in old_operator) and (
            not _goals(db,task_id) or any(g['key']==goal[0] for g in prior['legacy_goals']) and any(
                f['value']==value and (f.get('objective_key')==goal[0] or
                    len(prior['legacy_goals'])==1 and len(old_operator)==1) for f in old_operator))
        # Explicit address changes preserve the logical machine and the exact
        # platform decision. Keep the proposal's original evidence address.
        proposal=next((p for p in listing(db,task_id) if p['value']==value and p['objective_key']==goal[0]),None)
        if proposal is None:
            db.execute('INSERT OR IGNORE INTO pm_flag_proposals '
                '(task_id,target,objective_key,objective_title,value,value_sha256,source_json,materials_json,status,created_at,updated_at) '
                'VALUES(?,?,?,?,?,?,?,?,?,?,?)',(task_id,target[0],goal[0],goal[1],value,task_memory.digest(value),
                    task_memory.encoded([source_data]),task_memory.encoded(list(references)),
                    'legacy' if inherited else 'pending',stamp,stamp))
            proposal=next(p for p in listing(db,task_id) if p['value']==value and p['objective_key']==goal[0])
        if not db.execute('SELECT 1 FROM pm_flag_proposal_events WHERE proposal_id=?',(proposal['id'],)).fetchone():
            _event(db,proposal,'proposed',{'value':value,'objective_key':goal[0],'source':source_data,'materials':list(references)})
        sources=proposal['sources'];materials=proposal['materials']
        if source_data not in sources:sources.append(source_data)
        materials=list(dict.fromkeys(materials+list(references)))
        db.execute('UPDATE pm_flag_proposals SET source_json=?,materials_json=? WHERE id=?',
            (task_memory.encoded(sources),task_memory.encoded(materials),proposal['id']))
        # Keep arbitrary exact text addressable in the compatibility registry.
        db.execute('INSERT OR IGNORE INTO pm_verified_flags '
            '(task_id,value,status,evidence_count,reported_by,sources_json,created_at,updated_at) VALUES(?,?,?,0,?,?,?,?)',
            (task_id,value,'candidate','specialist',task_memory.encoded({'proposal_id':proposal['id'],'confirmation_reasons':['operator_confirmation_required']}),stamp,stamp))
    return next(p for p in listing(db,task_id) if p['id']==proposal['id'])


def ingest_report(db,task_id,report,reference=''):
    if report.get('stage_aborted') or report.get('report_incomplete') or (report.get('report_quality') or {}).get('status')=='damaged':return
    for claim in report.get('flags') or []:
        if not isinstance(claim,dict):continue
        refs=[ref for ref in (reference,claim.get('goal_evidence'),claim.get('result_id'),claim.get('artifact_ref')) if isinstance(ref,str) and ref]
        propose(db,task_id,claim.get('value'),objective_key=claim.get('objective_key'),
                source=claim.get('source',''),method=claim.get('method',''),references=refs,path=claim.get('path',''))


def discover_files(db,task_id,log):
    """Aggregate saved single-file cat results; do not execute a command."""
    if not task_memory.exists(db,'tasks'):return
    row=db.execute('SELECT target FROM tasks WHERE id=?',(task_id,)).fetchone()
    if not row:return
    for record in task_memory.capability_records(task_id,log,row[0]):
        result=record['result'];argv=record.get('argv',[])
        if result.get('status') not in ('completed','ok') or result.get('exit_code')!=0:continue
        try:inner=json.loads(argv[argv.index('--argv-json')+1])
        except (ValueError,IndexError,TypeError):continue
        if (not isinstance(inner,list) or len(inner)!=2 or PurePosixPath(str(inner[0])).name!='cat'
                or PurePosixPath(str(inner[1])).name.lower() not in ('user.txt','root.txt')):continue
        propose(db,task_id,result.get('stdout'),source=inner[1],method='Saved single-file cat output',path=inner[1],
                references=['result:'+record['id']])


def enqueue(db,proposal_id,step_id=None):
    from orchestrator import operator_questions
    row=db.execute('SELECT task_id FROM pm_flag_proposals WHERE id=?',(proposal_id,)).fetchone()
    proposal=next(p for p in listing(db,row[0]) if p['id']==proposal_id)
    if proposal['status']!='pending':return None
    if proposal['question_id']:
        return next(q for q in operator_questions.listing(db,proposal['task_id']) if q['id']==proposal['question_id'])
    target=proposal['target']
    decision={'action':'wait_operator','branch_id':'task','question':
        f"Самостоятельно отправьте точное значение кандидата #{proposal_id} для «{proposal['objective_title']}» на CTF-платформе. Принят? Да / Нет. Пересмотр {proposal['revision']}.",
        'reason':'Только оператор сообщает результат проверки на CTF-платформе; доступность машины не требуется.',
        'references':['flag_proposal:'+str(proposal_id),'flag:'+task_memory.digest(proposal['value'])],
        'boundaries':{'task_id':proposal['task_id'],'target':target,'intent_ref':'intent','resource_refs':['scope:'+target]},
        'operator_question':{'kind':'flag_confirmation'}}
    with task_memory.atomic(db):
        question=operator_questions.request(db,proposal['task_id'],target,decision,step_id,_flag_proposal=proposal_id)
        db.execute('UPDATE pm_flag_proposals SET question_id=? WHERE id=?',(question['id'],proposal_id))
    return next(q for q in operator_questions.listing(db,proposal['task_id']) if q['id']==question['id'])


def reconcile(db,task_id,log=None):
    activate(db,task_id)
    if not task_memory.exists(db,'tasks'):return
    target=db.execute('SELECT target FROM tasks WHERE id=?',(task_id,)).fetchone()
    if not target:return
    if log is not None:
        owned_log=local_log(db,task_id,log)
        if owned_log is not None:discover_files(db,task_id,owned_log)
    from orchestrator import report_integrity
    for report in task_memory.rows(db,'pm_agent_action_reports',task_id):
        if report['target']!=target[0]:continue
        parsed=report_integrity.decode_saved(report['report_json'],task_id,report['role'],report['iteration'])
        ingest_report(db,task_id,parsed,f"report:{report['role']}:{report['iteration']}")
    for row in task_memory.rows(db,'pm_verified_flags',task_id):
        if row['status'] not in ('candidate','confirmed'):continue
        if any(p['value'].strip()==row['value'].strip() for p in listing(db,task_id)):continue
        sources=json.loads(row['sources_json'])
        # Generic token/secret/answer key matches are discovery hints, not a
        # task-specific flag link. An explicit report/file/goal can bind them.
        if sources.get('matched_by')=='kv' and not row.get('objective_key'):continue
        discovery=sources.get('discovery_sources') or sources
        propose(db,task_id,row['value'],objective_key=row.get('objective_key'),
            source='Saved candidate registry',method=','.join(discovery.get('tools',[])) or 'saved report/capture',
            references=['result:'+rid for rid in discovery.get('result_ids',[])]+
                       [ref for proof in discovery.get('verified_evidence',[]) for ref in proof.get('capture_refs',[])])
    # Retire obsolete unbound flag questions with an audit event. New questions
    # refer to immutable proposals/goals; no historical answer is rewritten.
    from orchestrator import operator_questions
    old_answers={}
    for question in operator_questions.listing(db,task_id):
        if question['kind']!='flag_confirmation' or question['status']!='answered' or for_question(db,task_id,question):continue
        value=operator_questions.flag_subject(db,task_id,question['references'])
        if value is not None:old_answers.setdefault(value,[]).append(question)
    for value,questions in old_answers.items():
        proposals=[p for p in listing(db,task_id) if p['value']==value and p['status']=='pending']
        if len(questions)!=1 or len(proposals)!=1:continue
        question=questions[0];answer=question.get('answer') or {}
        if answer.get('decision') not in ('approve','decline'):continue
        with task_memory.atomic(db):
            proposal=proposals[0]
            _event(db,proposal,'legacy_answer_linked',{'question_id':question['id'],'original_answer':answer})
            db.execute('UPDATE pm_flag_proposals SET question_id=? WHERE id=?',(question['id'],proposal['id']))
            decide(db,proposal,answer['decision'],answer.get('text',''),question['id'])
    for question in operator_questions.listing(db,task_id,pending=True):
        if question['kind']=='flag_confirmation' and not for_question(db,task_id,question):
            with task_memory.atomic(db):
                db.execute("UPDATE pm_operator_questions SET status='cancelled' WHERE id=?",(question['id'],))
                db.execute('INSERT INTO pm_operator_question_events(question_id,task_id,event,payload_json,created_at) '
                    "VALUES(?,?,'retired_unbound_flag_question',?,?)",(question['id'],task_id,
                        task_memory.encoded({'original_question':question,'reason':'manual_goal_binding_required'}),task_memory.now()))
    for proposal in listing(db,task_id):
        if proposal['status']=='pending':enqueue(db,proposal['id'])


def for_question(db,task_id,question):
    ids=[int(ref.split(':')[1]) for ref in question['references'] if ref.startswith('flag_proposal:') and ref.split(':')[1].isdigit()]
    candidates=[p for p in listing(db,task_id) if p['id'] in ids or p['question_id']==question.get('id')]
    return candidates[0] if len(candidates)==1 else None


def decide(db,proposal,decision,note,question_id):
    from orchestrator import flag_verify
    if proposal['status']!='pending':raise ValueError('Flag proposal is not pending')
    if decision not in ('approve','decline'):raise ValueError('Flag confirmation requires Да/Нет (approve/decline)')
    goal=next((g for g in _goals(db,proposal['task_id']) if g['key']==proposal['objective_key']),None)
    if goal is None and proposal['objective_key'] not in ('flags','file:user.txt','file:root.txt'):
        raise ValueError('The flag question objective no longer exists')
    if goal and goal['title']!=proposal['objective_title']:raise ValueError('Goal changed since this flag question')
    with task_memory.atomic(db):
        status='accepted' if decision=='approve' else 'rejected'
        db.execute('UPDATE pm_flag_proposals SET status=?,updated_at=? WHERE id=? AND status=\'pending\'',
                   (status,task_memory.now(),proposal['id']))
        _event(db,proposal,status,{'question_id':question_id,'answer':decision,'note':note,'revision':proposal['revision']})
        if decision=='approve':
            flag_verify.operator_confirm(proposal['task_id'],proposal['value'],note,db=db)
            if any(g['key']==proposal['objective_key'] for g in _goals(db,proposal['task_id'])):
                goal=next(g for g in _goals(db,proposal['task_id']) if g['key']==proposal['objective_key'])
                ref='operator_flag:'+str(proposal['id'])
                refs=json.loads(goal['evidence_refs_json'])
                if ref not in refs:refs.append(ref)
                db.execute("UPDATE pm_objectives SET status='confirmed',evidence_ref=?,evidence_refs_json=?,updated_at=? WHERE task_id=? AND key=?",
                    (ref,task_memory.encoded(refs),task_memory.now(),proposal['task_id'],proposal['objective_key']))
        elif registry_status(db,proposal['task_id'],proposal['value'])=='rejected':
            db.execute("UPDATE pm_verified_flags SET status='rejected',updated_at=? WHERE task_id=? AND value=?",
                       (task_memory.now(),proposal['task_id'],proposal['value']))


def reconsider(db,task_id,proposal_id,reason):
    if not isinstance(reason,str) or not reason.strip():raise ValueError('Reconsideration requires a reason')
    with task_memory.atomic(db):
        proposal=next((p for p in listing(db,task_id) if p['id']==proposal_id),None)
        if not proposal or proposal['status']!='rejected':raise ValueError('Only a rejected proposal can be reconsidered')
        _event(db,proposal,'operator_reconsidered',{'reason':reason,'previous_question_id':proposal['question_id']})
        db.execute("UPDATE pm_flag_proposals SET status='pending',revision=revision+1,question_id=NULL,updated_at=? WHERE id=?",(task_memory.now(),proposal_id))
        db.execute("UPDATE pm_verified_flags SET status='candidate' WHERE task_id=? AND value=? AND operator_confirmed=0",(task_id,proposal['value']))
        return enqueue(db,proposal_id)


def progress(db,task_id):
    current=policy(db,task_id)
    if current is None:return None
    proposals=listing(db,task_id)
    legacy={f['value'] for f in current['legacy_flags'] if f.get('operator_confirmed')}
    accepted=[p for p in proposals if p['status']=='accepted']
    pairs={(p['objective_key'],p['value']) for p in accepted}
    implied=current['legacy_goals'][0]['key'] if len(current['legacy_goals'])==1 and len(legacy)==1 else None
    pairs.update((f.get('objective_key') or implied,f['value']) for f in current['legacy_flags']
                 if f.get('operator_confirmed') and (f.get('objective_key') or implied))
    count=len(pairs)+len(legacy-{value for _,value in pairs})
    reviewed={p['objective_key'] for p in proposals if p['status'] in ('accepted','legacy')}
    reviewed.update(f['objective_key'] for f in current['legacy_flags'] if f.get('operator_confirmed') and f.get('objective_key'))
    if len(current['legacy_goals'])==1 and len(legacy)==1:reviewed.add(current['legacy_goals'][0]['key'])
    return {'accepted_count':count,'expected_flags':current['expected_flags'],'proposals':proposals,
            'reviewed_goal_keys':sorted(reviewed),'legacy_confirmations':current['legacy_flags']}


def useful_work(db,task_id,expect):
    state=progress(db,task_id)
    if state is None:return True
    waiting=[p for p in state['proposals'] if p['status']=='pending']
    goals=_goals(db,task_id)
    covered={p['objective_key'] for p in waiting}
    if any(g['key'] not in state['reviewed_goal_keys'] and g['key'] not in covered for g in goals):return True
    return state['accepted_count']+len(waiting)<max(expect,state['expected_flags'] or 0)


def completion(db,task_id,expect=None):
    state=progress(db,task_id)
    if state is None:return None
    goals=_goals(db,task_id)
    required=max(expect or 0,state['expected_flags'] or 0,next((g.get('expected_flags') or 0 for g in goals if g['key']=='goal'),0)) or 2
    if state['accepted_count']<required or any(g['key'] not in state['reviewed_goal_keys'] for g in goals):return None
    return ('goal_confirmed' if len(goals)==1 and goals[0].get('exclusive') else 'objectives_done') if goals else 'flag_confirmed'


def completed_result(db,task_id,expect=None):
    """Local completion before preflight, model selection or namespace restore."""
    reason=completion(db,task_id,expect)
    if reason is None:return None
    from orchestrator import coordinated_attack, operator_questions, objectives, attack_loop
    state=progress(db,task_id)
    with task_memory.atomic(db):
        for question in operator_questions.listing(db,task_id,pending=True):
            if question['kind']!='flag_confirmation':continue
            db.execute("UPDATE pm_operator_questions SET status='cancelled' WHERE id=?",(question['id'],))
            db.execute('INSERT INTO pm_operator_question_events(question_id,task_id,event,payload_json,created_at) '
                "VALUES(?,?,'goals_completed',?,?)",(question['id'],task_id,task_memory.encoded({'reason':reason}),task_memory.now()))
            proposal=for_question(db,task_id,question)
            if proposal and proposal['status']=='pending':
                db.execute("UPDATE pm_flag_proposals SET status='superseded',updated_at=? WHERE id=?",(task_memory.now(),proposal['id']))
                _event(db,proposal,'superseded',{'reason':'all_task_goals_completed','question_id':question['id']})
        if task_memory.exists(db,'pm_coordinator_runs'):
            db.execute("UPDATE pm_coordinator_runs SET status='completed',stop_reason=?,updated_at=? WHERE task_id=? AND (status!='completed' OR stop_reason!=?)",
                       (reason,task_memory.now(),task_id,reason))
        if task_memory.exists(db,'tasks') and 'status' in {r[1] for r in db.execute('PRAGMA table_info(tasks)')}:
            db.execute("UPDATE tasks SET status='completed' WHERE id=?",(task_id,))
    rows=coordinated_attack.steps(db,task_id) if task_memory.exists(db,'pm_coordinator_steps') else []
    return {'task_id':task_id,'status':'completed','succeeded':True,'stop_reason':reason,
        'confirmed_flags':list(dict.fromkeys([p['value'] for p in state['proposals'] if p['status']=='accepted']+
                                          [f['value'] for f in state['legacy_confirmations']])),
        'expected_flags':max(expect or 0,state['expected_flags'] or 0) or 2,'operator_confirmations':state['accepted_count'],
        'operator_questions':operator_questions.listing(db,task_id),'steps':[coordinated_attack.step_view(r) for r in rows],
        'objectives_matrix':attack_loop.objective_matrix(objectives.objective_status(db,task_id)['objectives']), 'checkpoints':[]}
