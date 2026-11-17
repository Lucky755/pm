"""Concurrent execution of PM coordinator steps through the single Harness adapter.

No durable workflow mirror: decisions, assignments, questions and lifecycle use
pm_coordinator_steps in the existing task DB. Handles below die with this run.
"""
from concurrent.futures import wait,FIRST_COMPLETED
import json
from orchestrator import model_adapter,task_memory,research_budgets,instructions,operator_questions,diagnostics


def session_started(task_id,step_id,sid,mode):
    from orchestrator import agent_actions as actions
    with actions.connect() as db,task_memory.atomic(db):
        raw=db.execute('SELECT runtime_sessions_json FROM pm_coordinator_steps WHERE task_id=? AND id=?',(task_id,step_id)).fetchone()
        if not raw:raise ValueError('Missing owning coordinator step')
        sessions=json.loads(raw[0] or '[]');sessions.append({'session_id':sid,'mode':mode})
        db.execute('UPDATE pm_coordinator_steps SET runtime_sessions_json=? WHERE id=?',(task_memory.encoded(sessions),step_id))
    diagnostics.emit('specialist.session',task_id=task_id,step_id=step_id,session_id=sid,mode=mode)


def request_cancel(db,task_id,step_id):
    from orchestrator import coordinated_attack as c
    with task_memory.atomic(db):
        row=next((s for s in c.steps(db,task_id) if s['id']==step_id),None)
        if not row or row['status'] not in ('planned','running'):raise ValueError('Specialist is not active/planned')
        if row['status']=='planned':c.update_step(db,step_id,'failed',error='operator_cancelled_not_started',outcome_uncertain=0)
        else:db.execute('UPDATE pm_coordinator_steps SET cancel_requested_at=? WHERE id=?',(c.now(),step_id))
    diagnostics.emit('specialist.cancel_requested',task_id=task_id,step_id=step_id,reason='operator')


def resources(decision):return set(decision['boundaries']['resource_refs'])


def conflicts(decision,active):
    return any(operator_questions.branch(decision)=='task' or operator_questions.branch(item['decision'])=='task' or
        resources(decision)&resources(item['decision']) for item in active.values())


def unresolved_conflict(decision,rows):
    return any((row['outcome_uncertain'] or row['error'] in ('report_damaged','report_incomplete') and not row.get('report_reviewed_at'))
        and json.loads(row['decision_json']).get('action')=='run_role' and
        (operator_questions.branch(json.loads(row['decision_json']))=='task' or operator_questions.branch(decision)=='task' or
         resources(decision)&resources(json.loads(row['decision_json']))) for row in rows if row['status']=='failed')


def drive(db,task_id,run_id,roles,budgets,max_steps,retries,expect,model,key,role_runner,limit):
    from orchestrator import coordinated_attack as c
    active={};decisions=0;suppressed=None;stop=None;pauses=[]
    def snapshot():
        state=c.snapshot(db,task_id,expect)
        state['active_specialists']=[{'step_id':sid,'decision':item['decision']} for sid,item in active.items()]
        state['specialist_limit']=limit
        state['unresolved_specialists']=[c.step_view(s) for s in c.steps(db,task_id) if s['status']=='failed' and
            (s['outcome_uncertain'] or s['error'] in ('report_damaged','report_incomplete') and not s.get('report_reviewed_at'))]
        return state
    def finish(reason,status='completed'):
        return c.result_view(db,run_id,task_id,snapshot(),expect,reason,status)
    def cancel(item,reason):
        sid=item['step_id']
        with db:db.execute('UPDATE pm_coordinator_steps SET cancel_requested_at=? WHERE id=?',(c.now(),sid))
        not_started=item['worker'].cancel()
        c.update_step(db,sid,'failed',error=reason,outcome_uncertain=int(not not_started))
        diagnostics.emit('specialist.cancelled',task_id=task_id,step_id=sid,reason=reason,
            status='not_started' if not_started else 'outcome_requires_review')
        item['cancelled']=True
    with model_adapter.OwnedWorkflow(limit) as workflow:
        try:
            while True:
                model_adapter.check_cancelled()
                for sid,item in list(active.items()):
                    saved=db.execute('SELECT cancel_requested_at FROM pm_coordinator_steps WHERE id=?',(sid,)).fetchone()
                    if saved[0] and not item.get('cancelled'):cancel(item,'operator_cancelled_specialist')
                    if not item['worker'].future.done():continue
                    del active[sid]
                    if item.get('cancelled'):continue
                    try:
                        outcome=item['worker'].future.result()
                        if isinstance(outcome,dict) and outcome.get('status')=='waiting_operator' and outcome.get('execution_started') is False:
                            c.update_step(db,sid,'failed',error='specialist_budget_not_started',outcome_uncertain=0)
                            pauses.append('operator_questions_pending');continue
                        state,reason=c.complete_specialist(db,task_id,run_id,sid,item['decision'],item['iteration'],expect,branch_local=True)
                        if reason:pauses.append(reason)
                        elif not state['target_availability']['network_allowed']:
                            with db:db.execute('UPDATE pm_target_availability SET analysis_sha256=? WHERE task_id=?',(state['knowledge_sha256'],task_id))
                            stop=('target_restoration_required','waiting_operator')
                        diagnostics.emit('specialist.end',task_id=task_id,step_id=sid,
                            status='waiting_operator' if reason else 'report_saved',reason=reason)
                    except Exception as exc:
                        c.update_step(db,sid,'failed',error=type(exc).__name__,outcome_uncertain=1)
                        pauses.append('role_failed_outcome_requires_review')
                        diagnostics.emit('specialist.end',task_id=task_id,step_id=sid,status='failed',error_type=type(exc).__name__)
                state=snapshot()
                if state['success_verified']:
                    for item in active.values():
                        if not item.get('cancelled'):cancel(item,'goals_completed_cancelled_unneeded_work')
                    return finish(state['verified_stop_reason'])
                if not active and state['directions'] and all(direction['state']=='exhausted' for direction in state['directions']):
                    latest=max((r['id'] for r in c.steps(db,task_id) if r['status']=='completed'),default=0)
                    if latest>max(direction['plan_step'] or 0 for direction in state['directions']):return finish('all_directions_exhausted')
                if (not active and not state['target_availability']['network_allowed'] and
                        state['target_availability']['analysis_sha256']==state['knowledge_sha256']):
                    return finish('target_restoration_required','waiting_operator')
                if stop or decisions>=max_steps:
                    if active:
                        wait([i['worker'].future for i in active.values()],timeout=.1,return_when=FIRST_COMPLETED);continue
                    if stop:return finish(*stop)
                    break
                if pauses and not active:return finish(pauses[0],'waiting_operator')
                pending=[q for q in state['operator_questions'] if q['status']=='pending']
                if pending and not operator_questions.available(state):
                    if active:
                        wait([i['worker'].future for i in active.values()],timeout=.1,return_when=FIRST_COMPLETED);continue
                    return finish('operator_questions_pending','waiting_operator')
                if len(active)>=limit:
                    wait([i['worker'].future for i in active.values()],timeout=.1,return_when=FIRST_COMPLETED);continue
                signature=task_memory.digest([state['knowledge_sha256'],sorted(active),[(q['id'],q['status']) for q in state['operator_questions']]])
                if suppressed==signature:
                    if not active:return finish('no_independent_work_available','waiting_operator' if pending or pauses else 'completed')
                    wait([i['worker'].future for i in active.values()],timeout=.1,return_when=FIRST_COMPLETED);continue
                if not research_budgets.get(db,task_id,'coordinator')['remaining']:
                    research_budgets.request(db,task_id,'coordinator');db.commit()
                    stop=('coordinator_budget_exhausted','waiting_operator');continue
                if state['authorization_block']:
                    stop=(state['authorization_block'],'waiting_operator');continue
                available=tuple(r for r in roles if (research_budgets.get(db,task_id,'specialist',r) or {'remaining':1})['remaining'])
                if not available:
                    if active:suppressed=signature;continue
                    return finish('all_directions_exhausted','waiting_operator' if pending else 'completed')
                planned=next((s for s in c.steps(db,task_id) if s['status']=='planned'),None)
                if planned:
                    decision=json.loads(planned['decision_json']);step_id=planned['id']
                    try:c.parse_decision(decision,state,available)
                    except ValueError:
                        c.update_step(db,step_id,'failed',error='planned_transition_no_longer_allowed');continue
                else:
                    research_budgets.consume(db,task_id,'coordinator',unit='coordinator_decision');db.commit();decisions+=1
                    state=snapshot();error=None;response=None
                    for attempt in range(retries+1):
                        try:
                            with diagnostics.scope(role='coordinator'):
                                response=model(c.decision_prompt(state,available,[c.step_view(s) for s in c.steps(db,task_id)],error,response,attempt),key())
                                if snapshot()['success_verified']:
                                    decision=None;break
                                decision=c.parse_decision(response,state,available)
                            if c.repeated(db,task_id,decision,state):raise ValueError('repeated_question_without_new_evidence')
                            if decision['action']=='run_role' and conflicts(decision,active):raise ValueError('specialist_branch_busy')
                            if decision['action']=='run_role' and unresolved_conflict(decision,c.steps(db,task_id)):raise ValueError('specialist_branch_requires_review')
                            break
                        except (ValueError,RuntimeError,OSError) as exc:error=c.reject_decision(db,run_id,task_id,attempt+1,exc,response)
                    else:
                        c.insert_step(db,run_id,task_id,{},state,budgets,'failed',error)
                        stop=('decision_budget_exhausted:'+error,'failed');continue
                    if decision is None:continue
                    step_id=c.insert_step(db,run_id,task_id,decision,state,budgets)
                    planned=next(s for s in c.steps(db,task_id) if s['id']==step_id)
                    diagnostics.emit('coordinator.decision',task_id=task_id,coordinator_run_id=run_id,step_id=step_id,role=decision['role'],
                        reason=decision['reason'],question=decision['question'],expected_result=decision['expected_result'])
                if decision['action']=='await_specialists':
                    c.update_step(db,step_id,'completed');suppressed=signature;continue
                if decision['action']=='stop':
                    c.update_step(db,step_id,'completed')
                    stop=('operator_questions_pending','waiting_operator') if pending else ('model_stopped_incomplete','completed')
                    continue
                if decision['action']=='wait_operator':
                    try:q=operator_questions.request(db,task_id,state['task']['target'],decision,step_id)
                    except (ValueError,RuntimeError,OSError) as exc:
                        c.update_step(db,step_id,'failed',error=type(exc).__name__);continue
                    c.update_step(db,step_id,'waiting_operator' if q['status']=='pending' else 'failed',error='operator_question_pending')
                    if q['branch_id']=='task':stop=('operator_questions_pending','waiting_operator')
                    suppressed=signature;continue
                fresh=snapshot()
                try:
                    c.parse_decision(decision,fresh,available)
                    if any(state['references'][ref]!=fresh['references'][ref] for ref in decision['references']):raise ValueError('assignment_inputs_changed')
                    if conflicts(decision,active):raise ValueError('specialist_branch_busy')
                    if unresolved_conflict(decision,c.steps(db,task_id)):raise ValueError('specialist_branch_requires_review')
                    assignment=c.resolve_assignment(db,decision,fresh)
                    effective=instructions.limits(instructions.profile(decision['role'],decision['profile']),dict(budgets))
                    account=research_budgets.ensure(db,task_id,'specialist',decision['role'],base=min(budgets['step_limit'],25))
                    if not account['remaining']:
                        research_budgets.request(db,task_id,'specialist',decision['role'],step_id=step_id)
                        c.update_step(db,step_id,'failed',error='specialist_budget_not_started',outcome_uncertain=0);continue
                    effective['step_limit']=account['limit']
                except ValueError:
                    c.update_step(db,step_id,'failed',error='assignment_state_changed',outcome_uncertain=0);suppressed=None;continue
                iteration=planned['report_iteration']
                assignment.update(inherited_limits=effective,coordinator_step_id=step_id)
                c.update_step(db,step_id,'running',assignment_json=c.encoded(assignment))
                worker=workflow.submit(step_id,role_runner,task_id,decision['role'],decision['question'],iteration,
                    effective['poc_budget'],effective['step_limit'],api_key=key(),max_tokens=effective['max_tokens'],assignment=assignment,
                    on_session=lambda sid,mode,step=step_id:session_started(task_id,step,sid,mode))
                active[step_id]={'worker':worker,'step_id':step_id,'decision':decision,'iteration':iteration}
        except BaseException as exc:
            for item in active.values():
                if not item.get('cancelled'):cancel(item,'interrupted_unknown_outcome')
            if isinstance(exc,KeyboardInterrupt):
                with task_memory.atomic(db):
                    db.execute("UPDATE pm_coordinator_runs SET status='waiting_operator',stop_reason='interrupted',pause_step_id=?,updated_at=? WHERE id=?",
                        (next(iter(active),None),c.now(),run_id))
                diagnostics.stop('interrupted',unfinished_step_ids=sorted(active))
            raise
    state=snapshot()
    if any(q['status']=='pending' for q in state['operator_questions']):return finish('operator_questions_pending','waiting_operator')
    if not research_budgets.get(db,task_id,'coordinator')['remaining']:
        research_budgets.request(db,task_id,'coordinator');db.commit();return finish('coordinator_budget_exhausted','waiting_operator')
    return finish('coordinator_step_limit')
