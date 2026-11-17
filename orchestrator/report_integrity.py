"""Canonical report quality is separate from execution and proof outcomes."""
import json
import re


def decode_saved(raw, task_id, role, iteration):
    """A damaged canonical JSON row is data corruption, not an empty success."""
    try:
        report=json.loads(raw)
        if isinstance(report,dict):return report
    except (ValueError,TypeError,UnicodeError):
        pass
    return {'report_quality':{'status':'damaged','reason':'canonical_report_json_invalid',
                             'source_ref':{'table':'pm_agent_action_reports','task_id':task_id,
                                           'role':role,'iteration':iteration}}}


def quality(report):
    if (report.get('report_consistency') or {}).get('blocking'):
        return {'status':'incomplete','reason':'contradictory_assertions'}
    explicit=report.get('report_quality')
    if isinstance(explicit,dict) and explicit.get('status'):
        return explicit
    summary=str(report.get('summary','')).lstrip()
    if ((report.get('raw_report_path') or re.search(r'"(?:summary|findings)"\s*:',summary)) and summary.startswith('{')
            and not report.get('findings') and not report.get('hypotheses')):
        return {'status':'damaged','reason':'legacy_unparsed_response','raw_response_ref':report.get('raw_report_path')}
    if 'Не удалось распаковать JSON внутри summary' in str(report.get('report_warning') or ''):
        return {'status':'damaged','reason':'nested_report_json_invalid'}
    if report.get('stage_aborted') or report.get('report_incomplete'):
        return {'status':'incomplete','reason':'stage_aborted' if report.get('stage_aborted') else 'report_incomplete'}
    return {'status':'locally_repaired' if report.get('report_repaired') else 'valid','reason':None}


def execution(records, prior_ids, calls=None):
    rows=[]
    fresh=[record for rid,record in records.items() if rid not in prior_ids]
    dependency_only=bool(fresh and calls==len(fresh) and all(r['tool'] in ('tool_request','pivot_request') for r in fresh))
    for rid,record in records.items():
        if rid in prior_ids or record['tool'] in ('write_poc','read_file','capability_read','grep','unpack','tool_request','pivot_request'):
            continue
        payload=(record.get('capture_record') or {}).get('result') or {}
        status=record.get('status');code=payload.get('exit_code')
        outcome=('refused' if status in ('blocked','denied','refused') else
                 'executor_error' if status in ('error','failed') and
                 payload.get('error_type') in ('executor_unavailable','executor_error','launch_error') else
                 'executed' if status in ('completed','ok') and type(code) is int and code==0 else
                 'nonzero_exit' if status in ('completed','ok') and type(code) is int else 'unknown')
        responses=[]
        source=(record.get('capture_record') or {}).get('provenance')
        if source=='network' and status in ('completed','ok'):
            codes=[]
            if type(payload.get('status_code')) is int:
                codes.append(('capture',payload['status_code']))
            for field,text in (record.get('outputs') or {}).items():
                codes.extend((field,int(m[1])) for m in re.finditer(r'(?m)^HTTP/\d(?:\.\d)?\s+(\d{3})\b',text))
            for field,code_http in codes:
                responses.append({'source_field':field,'protocol':'http','status_code':code_http,
                                  'outcome':'refused' if code_http in (401,403) else 'not_found' if code_http==404 else
                                  'responded'})
            if code==255 and re.search(r'(?m)^[^\n]*: Permission denied \([^\n]+\)\.?$',
                                      (record.get('outputs') or {}).get('stderr','')):
                responses.append({'source_field':'stderr','protocol':'ssh','outcome':'refused'})
        server=payload.get('server_outcome') if source=='network' and payload.get('server_outcome') in ('refused','accepted','unknown') else 'unknown'
        server_states={item['outcome'] for item in responses}
        if server_states:server=next(iter(server_states)) if len(server_states)==1 else 'mixed'
        rows.append({'result_id':rid,'tool':record['tool'],'status':status,'exit_code':code,'outcome':outcome,
                     'provenance':(record.get('capture_record') or {}).get('provenance'),
                     'server_outcome':server,'server_responses':responses[:20],
                     'omitted_server_responses':max(0,len(responses)-20)})
    statuses={r['outcome'] for r in rows}
    status=('unknown' if 'unknown' in statuses else next(iter(statuses)) if len(statuses)==1 else
            'mixed' if rows else 'not_started' if calls==0 or dependency_only else 'unknown')
    return {'status':status,'results':rows[:30],'omitted':max(0,len(rows)-30)}


def check_consistency(report, assertions):
    """Flag explicit disagreements, never synthesize missing results from prose.

    Exact normalized claim identities and a small set of declarative access
    phrases are supported. This is not a general natural-language truth test.
    Both original assertions and validated results remain available for review.
    """
    from orchestrator.fact_state import claim_key
    claims={};issues=[]
    for field in ('findings','hypotheses'):
        for index,item in enumerate(assertions.get(field) or []):
            if not isinstance(item,dict):continue
            claim=item.get('claim') or item.get('title');key=claim_key(claim)
            state=(('confirmed' if item.get('kind')=='observation' else None) if field=='findings'
                   else item.get('result',item.get('status')))
            if key and state in ('confirmed','refuted'):
                claims.setdefault(key,[]).append({'field':field,'index':index,'outcome':state})
    for key,items in claims.items():
        if len({item['outcome'] for item in items})>1:
            issues.append({'code':'conflicting_claim_outcomes','claim_key':key,'assertions':items})
    clauses=re.split(r'[.;\n]+',str(assertions.get('summary','')))
    positive=any(re.match(r'\s*(?:(?:user|root|ssh) shell (?:obtained|gained|established)\b|'
                         r'(?:we |I )?(?:obtained|gained) (?:a |an )?(?:user |root |ssh )?(?:shell|access)\b|'
                         r'получен\w*\s+(?:пользовательск\w*\s+|root\s+|ssh\s+)?(?:shell|доступ|оболочк\w*))\s*$',
                         clause,re.I) for clause in clauses)
    negative=any(re.match(r'\s*(?:no (?:access|shell) (?:was )?obtained|доступ не получен)\s*$',clause,re.I)
                 for clause in clauses)
    signal=report.get('access_signal','none')
    actual_access=signal in ('execution','shell') and report.get('access_level','none')!='none'
    if (positive and not actual_access) or (negative and actual_access):
        issues.append({'code':'summary_access_disagrees','fields':['summary','access_signal','access_level']})
    if assertions.get('access_signal')=='credential' and signal in ('','none'):
        report['credential_assessment']={'status':'unverified','reason':'server_acceptance_not_supported',
            'result_id':assertions.get('access_probe_result_id'),'quote':assertions.get('access_quote')}
    elif assertions.get('access_signal') not in (None,'','none') and signal in ('','none'):
        issues.append({'code':'access_assertion_not_supported','fields':['access_signal','access_quote','access_probe_result_id']})
    if issues:
        report['report_consistency']={'blocking':True,'issues':issues}
        report['reported_assertions']=assertions
        report['report_incomplete']=True
        report['report_warning']=(report.get('report_warning','')+'; Противоречия или неподтверждённое заявление о доступе: '+
                                  ', '.join(i['code'] for i in issues)).strip('; ')
    return report


def step_execution(row):
    if row.get('execution_outcome'):
        return row['execution_outcome']
    if row.get('outcome_uncertain') or row['status']=='running':
        return {'status':'unknown','results':[]}
    if not row.get('report_path') and row.get('error') in (
            'operator_requested_replan','role_approval_required','planned_transition_no_longer_allowed',
            'assignment_state_changed','legacy_access_gate_retired_not_started','address_changed_not_started',
            'operator_question_answered_no_action','operator_question_pending','operator_question_already_answered','specialist_budget_not_started','operator_cancelled_not_started'):
        return {'status':'not_started','results':[]}
    if row['status'] in ('planned','waiting_operator') and not row.get('report_path'):
        return {'status':'not_started','results':[]}
    return {'status':'unknown','results':[]}


def attach_reports(db, task_id, rows):
    """Read-only annotation; old canonical files and historical statuses stay intact."""
    if not db.execute("SELECT 1 FROM sqlite_master WHERE name='pm_agent_action_reports' AND type='table'").fetchone():
        return rows
    reports={(role,iteration):decode_saved(raw,task_id,role,iteration) for role,iteration,raw in db.execute(
        'SELECT role,iteration,report_json FROM pm_agent_action_reports WHERE task_id=?',(task_id,))}
    for row in rows:
        decision=json.loads(row['decision_json'])
        report=reports.get((decision.get('role'),row.get('report_iteration')))
        if report:
            row['report_quality']=quality(report)
            row['raw_report_path']=report.get('raw_report_path')
            row['execution_outcome']=report.get('execution_outcome')
            row['report_consistency']=report.get('report_consistency')
        row['execution_outcome']=step_execution(row)
    return rows


def unresolved(rows):
    return next((r for r in rows if (r.get('report_quality') or {}).get('status')=='damaged'
                 and not r.get('report_reviewed_at')),None)
