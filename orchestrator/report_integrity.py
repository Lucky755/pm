"""Canonical report quality is separate from execution and proof outcomes."""
import json
import re


def quality(report):
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
    for rid,record in records.items():
        if rid in prior_ids or record['tool'] in ('write_poc','read_file','capability_read','grep','unpack'):
            continue
        payload=(record.get('capture_record') or {}).get('result') or {}
        status=record.get('status');code=payload.get('exit_code')
        outcome=('refused' if status in ('blocked','denied','refused') else
                 'executed' if status in ('completed','ok') and type(code) is int and code==0 else
                 'nonzero_exit' if status in ('completed','ok') and type(code) is int else 'unknown')
        rows.append({'result_id':rid,'tool':record['tool'],'status':status,'exit_code':code,'outcome':outcome,
                     'provenance':(record.get('capture_record') or {}).get('provenance')})
    statuses={r['outcome'] for r in rows}
    status=('unknown' if 'unknown' in statuses else next(iter(statuses)) if len(statuses)==1 else
            'mixed' if rows else 'not_started' if calls==0 else 'unknown')
    return {'status':status,'results':rows[:30],'omitted':max(0,len(rows)-30)}


def step_execution(row):
    if row.get('execution_outcome'):
        return row['execution_outcome']
    if row.get('outcome_uncertain') or row['status']=='running':
        return {'status':'unknown','results':[]}
    if not row.get('report_path') and row.get('error') in (
            'operator_requested_replan','role_approval_required','planned_transition_no_longer_allowed',
            'assignment_state_changed'):
        return {'status':'not_started','results':[]}
    if row['status'] in ('planned','waiting_operator') and not row.get('report_path'):
        return {'status':'not_started','results':[]}
    return {'status':'unknown','results':[]}


def attach_reports(db, task_id, rows):
    """Read-only annotation; old canonical files and historical statuses stay intact."""
    if not db.execute("SELECT 1 FROM sqlite_master WHERE name='pm_agent_action_reports' AND type='table'").fetchone():
        return rows
    reports={(role,iteration):json.loads(raw) for role,iteration,raw in db.execute(
        'SELECT role,iteration,report_json FROM pm_agent_action_reports WHERE task_id=?',(task_id,))}
    for row in rows:
        decision=json.loads(row['decision_json'])
        report=reports.get((decision.get('role'),row.get('report_iteration')))
        if report:
            row['report_quality']=quality(report)
            row['raw_report_path']=report.get('raw_report_path')
            row['execution_outcome']=report.get('execution_outcome')
        row['execution_outcome']=step_execution(row)
    return rows


def unresolved(rows):
    return next((r for r in rows if (r.get('report_quality') or {}).get('status')=='damaged'
                 and not r.get('report_reviewed_at')),None)
