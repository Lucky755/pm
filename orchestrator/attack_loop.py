"""Pentest Master: who hands out the work.

The coordinator that the operator actually runs. It keeps the agreed order -
receive the task, hand it to the specialist, let the specialist act, structure
the output, report - and repeats that cycle for a bounded number of iterations:

    recon -> vuln -> access -> verify   (iteration 1)
        recon -> vuln -> access -> verify   (iteration 2)
        ...

Each role runs in its own Harness session with the real tools and its own step
budget (orchestrator/agent_actions.py). Between roles the driver only passes
structured output: the previous report's summary, its proposed actions and the
current flag registry. The run ends when the expected number of flags (two by
default: user and root) is confirmed, or when a whole iteration adds neither a
new capture nor a new claim.

Every stage is stored, so a later iteration (or a human) can audit exactly which
tool output produced which claim.

Console contract: the loop narrates itself. Each stage prints its objective, the
agent prints one line per tool call/result (agent_actions.progress_watcher), and
the stage ends with the decisive findings plus the flag registry state - not with
the raw list of values the model typed in its report. A value the model claims
without raw evidence is called out as a warning instead of looking like a find.
"""

import argparse
import json
import re
import sqlite3
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from orchestrator import diagnostics

from orchestrator import agent_actions
from orchestrator import flag_verify
from orchestrator import fact_state
from orchestrator import objectives as objective_store

ROLE_ORDER = ('recon', 'vuln', 'access', 'verify')
MAX_ITERATIONS = 7
# A lab room normally ships two flags (user.txt and root.txt). Stopping at the
# first confirmed value left the second one unfound on task 16, so the loop now
# keeps working until both are confirmed - and stops on its own when a whole
# iteration brings no new capture and no new claim.
DEFAULT_EXPECTED_FLAGS = 2
MAX_EXPECTED_FLAGS = 30
MAX_POC_BUDGET = 7
# A run has exactly one of these endings, and only the first three mean the
# work itself finished. Anything else is recorded as incomplete.
NORMAL_STOP_REASONS = frozenset({'iterations_done', 'flag_confirmed', 'no_progress',
                                 'goal_confirmed', 'objectives_done'})
KNOWN_STOP_REASONS = NORMAL_STOP_REASONS | frozenset(
    {'stalled', 'state_unavailable', 'recon_failed', 'vuln_failed',
     'target_unreachable', 'flags_without_goal'})
STAGE_STATUSES = frozenset({'completed', 'salvaged', 'error'})


def now():
    return datetime.now(timezone.utc).isoformat()


def render(obj):
    print(json.dumps(obj, ensure_ascii=False, indent=2))


def say(text=''):
    print(diagnostics.clean(text, limit=None), flush=True)


def stage_facts(task_id):
    """Read the derived ledgers; old free text enters only as open questions."""
    db = agent_actions.connect()
    try:
        before = diagnostics.state_snapshot(db, task_id) if diagnostics.active() else {}
        fact_state.import_legacy_reports(db, task_id)
        fact_state.import_legacy_access_hint(db, task_id)
        fact_state.import_capability_assets(
            db, task_id, agent_actions.CAPABILITY_LOG / f'task_{task_id}.jsonl')
        claims = fact_state.list_hypotheses(db, task_id, limit=200)
        assets = fact_state.list_assets(db, task_id, limit=200)
        access = fact_state.access_state(db, task_id)
        db.commit()
        if diagnostics.active():
            diagnostics.state_diff(before, diagnostics.state_snapshot(db, task_id), task_id)
        return claims, assets, access
    finally:
        db.close()


def objective_for(role, previous, confirmed=(), expect=1, candidates=(), map_known=False,
                  claims=(), assets=(), access=None, objectives=None):
    """Choose among open questions; only typed observations are established."""
    previous = previous or {}
    access = access or {'level': 'none', 'signal': 'none', 'pending': False}
    triage_pending = bool(access.get('pending'))
    established = [item for item in claims if item.get('kind') == 'observation'
                   and item.get('status') == 'confirmed' and item.get('probe_result_id')][:5]
    unknown = []
    for item in claims:
        if item.get('status') == 'untested':
            unknown.append((fact_state.bounded_cost(item.get('cost', 2)),
                            str(item.get('claim') or '')[:180], item.get('claim_key'),
                            item.get('objective_key')))
    for item in assets:
        if item.get('status') == 'discovered':
            unknown.append((1, f"Что даёт проверка {item['kind']} {item['key']}?",
                            f"asset:{item['kind']}:{item['key']}", item.get('objective_key')))
    if role == 'access':
        unknown.append((0, 'Если доступ получен, какова его граница и следующий уровень?',
                        'access-boundary', None))
    for value in candidates[:4]:
        unknown.append((1, f'Подтверждается ли кандидат {value} на текущем адресе?',
                        f'candidate:{value}', None))
    # Old proposed actions are suggestions, never established facts.
    for action in (previous.get('proposed_actions') or [])[:3]:
        if isinstance(action, dict) and action.get('role') == role and action.get('goal'):
            unknown.append((3, str(action['goal'])[:180],
                            fact_state.claim_key(action['goal']), action.get('objective_key')))
    seen = set()
    questions = []
    rows = (objectives or {}).get('objectives') or []
    primary = (objectives or {}).get('primary')
    if primary and primary['status'] != 'confirmed':
        unknown.append((1, f"Как подтвердить основную цель: {primary['title'][:130]}?",
                        'objective:goal', 'goal'))
    ranked = sorted(unknown, key=(lambda row: (objective_store.question_rank(row[1], row[3], rows),
                                               row[0], row[1])) if rows else lambda row: row[0])
    for cost, question, key, objective_key in ranked:
        if not question or key in seen:
            continue
        if (rows and objectives.get('exclusive') and objectives['primary']['status'] == 'confirmed'
                and objective_store.question_rank(question, objective_key, rows) > 0):
            continue
        if triage_pending and re.search(r'эскалац|повышен\w*\s+прав|privileg\w*\s+escalat',
                                         question, re.I):
            continue
        seen.add(key)
        questions.append((cost, question))
        if len(questions) >= 5:
            break
    parts = ['УСТАНОВЛЕНО:']
    parts += [f"- {item['claim'][:180]} [result_id={item['probe_result_id']}]"
              for item in established] or ['- Нет типизированных наблюдений на текущем адресе.']
    if rows:
        parts.append('ЦЕЛИ: ' + '; '.join(
            f"[{row['key']}, вес {row['weight']}, {row['status']}] {row['title'][:120]}"
            for row in rows))
    parts.append('НЕИЗВЕСТНО:')
    parts += [f'- стоимость {cost}: {question}' for cost, question in questions] or [
        '- Какой самый дешёвый зонд даст новый факт о текущей цели?']
    if triage_pending:
        parts.append('ТРИАЖ: подтвердить заявленный доступ и заполнить: кто я; '
                     'где я; граница доступа; достижимое в утверждённом scope; '
                     'доступные учётные данные и конфигурация; следующий уровень.')
    parts.append('ЗАДАЧА:')
    if triage_pending:
        parts.append('Сначала заверши триаж подтверждёнными зондами. '
                     'До этого не ставь целью повышение уровня доступа.')
    elif role == 'recon' and not map_known:
        parts.append('Составь первичную карту, затем сократи самое дешёвое неизвестное одним зондом.')
    else:
        parts.append('Сократи самое дешёвое неизвестное одним зондом; если гипотеза '
                     'опровергнута — переходи к следующему. Не ищи подтверждения выбранной идеи.')
    if confirmed:
        parts.append(f'Флаги: подтверждено {len(confirmed)} из {expect}; '
                     'подтверждённые повторно не доказывай.')
    return '\n'.join(parts)


def confirmed_values(task_id):
    try:
        return [item['value'] for item in flag_verify.listing(task_id)
                if item['status'] == 'confirmed']
    except (ValueError, OSError):
        return []


def task_objectives(task_id):
    db = agent_actions.connect()
    try:
        return objective_store.objective_status(db, task_id)
    finally:
        db.close()


def objective_stop_reason(state, confirmed_count, expect):
    """Keep the legacy threshold when no primary objective is configured."""
    primary = state.get('primary')
    if not primary or state.get('mode') == 'all-flags':
        return 'flag_confirmed' if confirmed_count >= expect else None
    if primary['status'] == 'confirmed' and state.get('exclusive'):
        return 'goal_confirmed'
    if state['objectives'] and all(row['status'] == 'confirmed' for row in state['objectives']):
        return 'objectives_done'
    if primary['status'] == 'confirmed' and confirmed_count >= expect:
        return 'objectives_done'
    if confirmed_count >= expect:
        return 'flags_without_goal'
    return None


def transferred_candidates(task_id):
    """Transferred claims remain candidates until evidence from this IP exists."""
    try:
        return [item['value'] for item in flag_verify.listing(task_id)
                if item['status'] == 'candidate'
                and (item.get('sources') or {}).get('transfer')][:8]
    except (ValueError, OSError):
        return []


def has_service_map(task_id, iteration):
    db = agent_actions.connect()
    try:
        current = agent_actions.service_map(db, task_id, iteration)
        return current['scan_mode'] == 'spot_check'
    finally:
        db.close()


def flag_context_lines(confirmed, candidates, expect):
    """Operator-facing status without treating transferred values as proof."""
    if not confirmed and not candidates:
        return []
    lines = [f'      подтверждено {len(confirmed)} из {expect}' +
             (': ' + ', '.join(confirmed[:4]) if confirmed else '')]
    if candidates:
        lines.append('      известны кандидаты (перенесены, требуют переподтверждения): '
                     + ', '.join(candidates[:8]))
    return lines


def registry_fingerprint(task_id):
    """Snapshot of the registry, used to detect an iteration that found nothing.

    Anything that could become progress changes it: a new value, a new raw
    capture on an existing value, or a new confirmation.
    """
    try:
        return tuple(sorted((item['value'], int(item['raw_hits'] or 0), item['status'])
                            for item in flag_verify.listing(task_id)))
    except (ValueError, OSError, sqlite3.Error):
        # None means "unknown", not "no values": an empty tuple would look like
        # a clean registry and could be read as a lack of progress.
        return None


def decisive_state(task_id):
    """State that changes only when the run learned something new.

    Fresh "untested" hypotheses are plans, not knowledge: every stage proposes
    a few, so counting them made each round look productive and the no-progress
    brake never fired. Confirmations, refutations and asset transitions are the
    events that actually move an investigation.
    """
    try:
        db = agent_actions.connect()
        try:
            claims = fact_state.list_hypotheses(db, task_id, limit=500)
            assets = fact_state.list_assets(db, task_id, limit=500)
        finally:
            db.close()
    except (ValueError, OSError, sqlite3.Error):
        # Unknown, not "unchanged": an unreadable database must never look
        # like a lack of progress and stop the run.
        return None
    by_status = {}
    for item in claims:
        by_status[item.get('status')] = by_status.get(item.get('status'), 0) + 1
    asset_state = {}
    for item in assets:
        asset_state[item.get('status')] = asset_state.get(item.get('status'), 0) + 1
    return (by_status.get('confirmed', 0), by_status.get('refuted', 0),
            asset_state.get('discovered', 0), asset_state.get('dead', 0))


def findings_total(stages):
    """Distinct findings produced by stages that actually did work.

    Flag captures alone are the wrong progress signal: an iteration that found
    a login, an upload endpoint and a readable file path learned something even
    though no flag appeared yet. Two corrections keep the signal honest:
    a stage with zero tool calls only re-summarised the previous report (on task
    17 the iteration-2 vuln and access stages reported four findings each with
    steps=0), and the same finding often reappears in several stages, so titles
    are deduplicated instead of counted again.
    """
    seen = set()
    for stage in stages:
        if int(stage.get('steps_used') or 0) <= 0:
            continue
        for key in stage.get('finding_keys') or ():
            seen.add(finding_key(key))
    return len(seen)


def finding_key(title):
    """Normalize surface formatting; semantic paraphrases remain undetected."""
    return agent_actions.title_key(title)


def quality_metrics(stages):
    """Count probe-backed claims and a lower bound of repeated findings."""
    seen = set()
    repeated = backed = unverified = refuted = 0
    for stage in stages:
        keys = [finding_key(key) for key in stage.get('finding_keys') or []]
        backed += len(keys)
        unverified += int(stage.get('unverified_findings') or 0)
        refuted += int(stage.get('refuted_claims') or 0)
        for key in keys:
            if key in seen:
                repeated += 1
            seen.add(key)
    total = backed + unverified
    return {'probe_backed_share': round(backed / total, 3) if total else None,
            'repeated_facts': repeated, 'refuted_claims': refuted,
            'claims_counted': total,
            'method': 'артефакт в выводе зонда; повторы — нижняя граница по нормализованным заголовкам'}


def canonical_flag_claim(raw, patterns=None):
    text = flag_verify.normalise_captured(str(raw or '').strip())
    return (flag_verify.canonical_flag_value(text, patterns) or
            flag_verify.canonical_flag_value('flag: ' + text, patterns))


def report_registry(registry, report, patterns=None):
    """Print the registry state and flag any claim that raw output does not back."""
    confirmed = registry.get('confirmed') or []
    candidates = registry.get('candidates') or []
    say(f'[FLAG] реестр: подтверждено {len(confirmed)} · кандидатов {len(candidates)}')
    for item in confirmed:
        label = ('[ЦЕЛЬ]' if item.get('objective_key') == 'goal' else
                 f'[{item["objective_key"]}]' if item.get('objective_key') else '[—]')
        say(f'[FLAG] подтверждён {label} {item["value"]} '
            f'(сырых источников: {item["raw_hits"]}; evidence_source: '
            f'{item.get("evidence_source", "none")}; matched_by: {item.get("matched_by", "default")}; '
            f'{"операторское подтверждение" if item.get("operator_confirmed") else "сетевая проверка"})')
    for item in candidates:
        label = ('[ЦЕЛЬ]' if item.get('objective_key') == 'goal' else
                 f'[{item["objective_key"]}]' if item.get('objective_key') else '[—]')
        marker = (f'; {item["goal_claim_unverified"]}'
                  if item.get('goal_claim_unverified') else '')
        say(f'[FLAG] кандидат {label} {item["value"]} '
            f'(evidence_source: {item.get("evidence_source", "none")}; '
            f'matched_by: {item.get("matched_by", "default")}; '
            f'local_only: {bool(item.get("local_only"))}{marker})')

    mismatches = {item['value']: item.get('closest')
                  for item in registry.get('mismatches') or []}
    seen = {item['value'] for item in confirmed}
    for claim in report.get('flags') or []:
        if not isinstance(claim, dict):
            continue
        value = canonical_flag_claim(claim.get('value'), patterns)
        if not value or value in seen:
            continue
        seen.add(value)
        state = next((item for item in candidates if item['value'] == value), None)
        if state and state.get('raw_hits'):
            say(f'[FLAG] заявлен {value} · сырых подтверждений: {state["raw_hits"]} '
                f'· evidence_source: {state.get("evidence_source", "none")} '
                f'· matched_by: {state.get("matched_by", "default")}')
            continue
        if state and state.get('local_only'):
            say(f'[FLAG] кандидат {value} · только локальное совпадение '
                f'(local_only; evidence_source: local; matched_by: {state.get("matched_by", "default")})')
            continue
        near = mismatches.get(value)
        hint = f'; в сыром выводе рядом: {near}' if near else ''
        say(f'[FLAG] ВНИМАНИЕ: {value} заявлен агентом, '
            f'но в сыром выводе не найден{hint}')


def objective_matrix(rows):
    """Compact operator view of objective status and evidence references."""
    lines = [f'Цели: {sum(row["status"] == "confirmed" for row in rows)}/{len(rows)} закрыто']
    for row in rows:
        label = 'ЦЕЛЬ' if row['key'] == 'goal' else row['key']
        state = {'confirmed': 'подтверждена', 'open': 'открыта',
                 'attempted': 'проверяется', 'blocked': 'заблокирована'}.get(
                     row['status'], 'неизвестна')
        if row['key'] == 'goal' and row['status'] != 'confirmed':
            state = 'НЕ ПОДТВЕРЖДЕНА'
        evidence = f', result_id={row["evidence_ref"]}' if row.get('evidence_ref') else ''
        lines.append(f'[{label} {row["weight"]}] {row["title"][:80]} — {state}{evidence}')
    return lines


def stage_flags(stage):
    """Human-readable claimed values with their registry status."""
    labels = []
    for value, state in (stage.get('flag_state') or {}).items():
        if state.get('status') == 'confirmed':
            tag = 'подтверждён'
        elif state.get('raw_hits'):
            tag = f'сырых {state["raw_hits"]}'
        else:
            tag = 'только заявка'
        labels.append(f'{value} [{tag}; evidence_source: {state.get("evidence_source", "none")}; '
                      f'matched_by: {state.get("matched_by", "default")}]')
    return ', '.join(labels)


def next_iteration(task_id):
    """Continue the numbering after a resumed run instead of restarting at 1.

    A restarted counter made the "first iteration" guard fire again on a task
    that already had a history, and the new stages looked like they belonged
    to an empty run instead of continuing the investigation.
    """
    try:
        db = agent_actions.connect()
        try:
            row = db.execute('SELECT COALESCE(MAX(iteration), 0) '
                             'FROM pm_agent_action_reports WHERE task_id = ?',
                             (int(task_id),)).fetchone()
        finally:
            db.close()
    except (ValueError, OSError, sqlite3.Error) as exc:
        raise RuntimeError(
            f'Не удалось определить следующую итерацию задачи {task_id}: {exc}'
        ) from exc
    return max(1, int(row[0] or 0) + 1)


def network_unreachable_since(task_id, start):
    """Read structured capability outcomes added after an iteration began."""
    path = agent_actions.CAPABILITY_LOG / f'task_{task_id}.jsonl'
    try:
        lines = path.read_text(encoding='utf-8', errors='replace').splitlines()[start:]
    except OSError:
        return False
    outcomes = []
    for line in lines:
        try:
            record = json.loads(line)
        except ValueError:
            continue
        tool = record.get('tool')
        if tool not in ('net_exec', 'session', 'network_probe', 'http_get',
                        'http_headers', 'http_path', 'http_document', 'http_capture') and not (
                tool == 'poc_run' and record.get('provenance') == 'network'):
            continue
        result = record.get('result') or {}
        outcomes.append(result.get('status') == 'timeout' or
                        result.get('kind') in ('timeout', 'unreachable') or
                        result.get('exit_code') in (7, 28, 110, 111, 124, 137))
    return bool(outcomes) and all(outcomes)


@diagnostics.stage
def run(task_id, iterations=1, roles=ROLE_ORDER, poc_budget=7, step_limit=15,
        api_key=None, max_tokens=None, expect_flags=None):
    iterations = int(iterations)
    if not 1 <= iterations <= MAX_ITERATIONS:
        raise ValueError(f'iterations must be 1..{MAX_ITERATIONS}')
    roles = tuple(role for role in roles if role in ROLE_ORDER)
    if not roles:
        raise ValueError('No valid roles selected')
    limit = int(max_tokens or agent_actions.DEFAULT_MAX_TOKENS)
    # An empty answer at the prompt arrives as 0; downstream validation then
    # aborted the whole run before the first stage (task 25, first attempt).
    poc_budget = min(MAX_POC_BUDGET, max(1, int(poc_budget or MAX_POC_BUDGET)))
    objective_state = task_objectives(task_id)
    if expect_flags is None:
        expect = (objective_state['expected_flags'] or len(objective_state['objectives'])
                  if objective_state['primary'] else DEFAULT_EXPECTED_FLAGS)
    else:
        expect = int(expect_flags)
    if not 1 <= expect <= MAX_EXPECTED_FLAGS:
        raise ValueError(f'expect_flags must be 1..{MAX_EXPECTED_FLAGS}')

    stages = []
    pattern_db = agent_actions.connect()
    try:
        patterns = flag_verify.load_patterns(pattern_db, task_id)
    finally:
        pattern_db.close()
    stop_reason = 'iterations_done'
    previous = None
    first_iteration = next_iteration(task_id)
    unreadable_rounds = 0
    unreachable_rounds = 0

    for iteration in range(first_iteration, first_iteration + iterations):
        map_known = has_service_map(task_id, iteration)
        marker = (registry_fingerprint(task_id), findings_total(stages),
                  decisive_state(task_id))
        capability_start = agent_actions.capability_count(task_id)
        iteration_start = len(stages)
        for role in roles:
            claims, assets, access = stage_facts(task_id)
            already = confirmed_values(task_id)
            candidates = transferred_candidates(task_id)
            for status_line in flag_context_lines(already, candidates, expect):
                say(status_line)
            objective = objective_for(role, previous, already, expect, candidates,
                                      map_known=map_known, claims=claims, assets=assets,
                                      access=access, objectives=objective_state)
            say(f'[STAGE] iteration={iteration}/{iterations} role={role}')
            if objective:
                say(f'      цель: {agent_actions.short_text(objective, 220)}')
            try:
                outcome = agent_actions.run_role(
                    task_id, role, objective, iteration, poc_budget, step_limit,
                    api_key=api_key, max_tokens=limit,
                )
            except (ValueError, RuntimeError, OSError) as exc:
                message = str(exc)
                # The stage may already have produced observations before it
                # died. Record an intermediate report and hand it to the next
                # stage instead of replacing the work with an empty error slot.
                salvaged, salvaged_path = None, ''
                try:
                    db = agent_actions.connect()
                    try:
                        context = agent_actions.task_context(db, task_id)
                        salvaged_path = agent_actions.salvage_intermediate_report(
                            db, context, role, iteration, exc)
                    finally:
                        db.close()
                    with open(salvaged_path, encoding='utf-8') as stream:
                        salvaged = json.load(stream)
                except (ValueError, RuntimeError, OSError) as salvage_error:
                    say(f'      промежуточный отчёт не сохранён: {salvage_error}')
                stage = {'iteration': iteration, 'role': role,
                         'status': 'salvaged' if salvaged else 'error',
                         'error': message, 'at': now()}
                if salvaged:
                    stage.update({
                        'report_path': salvaged_path,
                        'steps_used': 0,
                        'summary': str(salvaged.get('summary') or '')[:1200],
                        'report_warning': salvaged.get('report_warning', ''),
                        'findings': 0, 'finding_keys': [],
                        'verified_observations': len(salvaged.get('verified') or []),
                    })
                stages.append(stage)
                say(f'[STAGE] {role} failed: {message}')
                if 'max-tokens' in message:
                    say('      подсказка: компактный повтор тоже не уложился — '
                        f'поднимите лимит вывода (сейчас {limit} токенов)')
                if salvaged:
                    say('      промежуточный отчёт сохранён: '
                        f"{len(salvaged.get('hypotheses') or [])} гипотез, "
                        f"{len(salvaged.get('verified') or [])} подтверждённых "
                        'наблюдений передано следующей стадии')
                    previous = {'role': role,
                                'summary': str(salvaged.get('summary') or ''),
                                'findings': salvaged.get('findings') or [],
                                'flags': [], 'verified': salvaged.get('verified') or [],
                                'uncertainties': [], 'proposed_actions': []}
                    continue
                # A fresh task whose recon never started has nothing to continue
                # from. On a resumed task the ledgers still carry the history, so
                # one failed role is no reason to kill the run.
                if role in ('recon', 'vuln') and first_iteration == 1:
                    stop_reason = f'{role}_failed'
                    return finish(task_id, stages, stop_reason, previous, expect)
                # Keep the last useful context. Replacing it with an empty error
                # stage left the next agent with "Previous stage (verify):" and
                # nothing else, so iteration 2 had to rediscover the target.
                note = f'Этап {role} завершился без отчёта: {message}'
                if previous and previous.get('summary'):
                    previous = {**previous,
                                'summary': note + '. Предыдущий контекст: '
                                           + str(previous['summary'])[:900]}
                else:
                    previous = {'role': role, 'summary': note, 'findings': [],
                                'flags': [], 'proposed_actions': []}
                continue

            report = outcome['report']
            previous = {'role': role, **report}
            registry = flag_verify.scan(task_id, patterns=patterns)
            objective_db = agent_actions.connect()
            try:
                objective_state = objective_store.process_report(
                    objective_db, task_id, report, registry)
            finally:
                objective_db.close()
            states = {item['value']: item
                      for item in registry['confirmed'] + registry['candidates']}
            claimed = [value for item in report['flags']
                       if (value := canonical_flag_claim(item.get('value'), patterns))]
            stage = {
                'iteration': iteration,
                'role': role,
                'status': 'completed',
                'steps_used': outcome['steps_used'],
                'tool_events': outcome['tool_events'],
                'reads': outcome['reads'],
                'denied': outcome['denied'],
                'session_share': outcome['session_share'],
                'thinking_chars': outcome.get('thinking_chars', 0),
                'tool_calls': outcome.get('tool_calls', outcome['steps_used']),
                'tokens_used': outcome.get('tokens_used', 0),
                'input_tokens': outcome.get('input_tokens', 0),
                'cache_read_tokens': outcome.get('cache_read_tokens', 0),
                'output_tokens': outcome.get('output_tokens', 0),
                'peak_context_tokens': outcome.get('peak_context_tokens', 0),
                'elapsed_seconds': outcome['elapsed_seconds'],
                'report_path': outcome['report_path'],
                'summary': report['summary'][:1200],
                'report_warning': report.get('report_warning', ''),
                'report_repaired': bool(report.get('report_repaired', False)),
                'stats_unknown': outcome.get('stats_unknown', False),
                'report_incomplete': bool(report.get('report_incomplete')),
                'findings': len(report['findings']),
                'unverified_findings': len(report.get('unverified_findings') or []),
                'refuted_claims': sum(1 for item in report.get('hypotheses') or []
                                      if isinstance(item, dict) and item.get('result') == 'refuted')
                                   if role == 'verify' else 0,
                'finding_keys': [agent_actions.short_text((item or {}).get('title', ''), 80).lower()
                                 for item in report['findings']
                                 if (item or {}).get('title')][:60],
                'degraded': outcome.get('degraded', False),
                'recovery': outcome.get('recovery'),
                'no_tools': outcome.get('no_tools', False),
                'flags': claimed,
                'flag_state': {
                    value: {
                        'status': (states.get(value) or {}).get('status', 'candidate'),
                        'raw_hits': (states.get(value) or {}).get('raw_hits', 0),
                        'evidence_source': (states.get(value) or {}).get('evidence_source', 'none'),
                        'matched_by': (states.get(value) or {}).get('matched_by', 'default'),
                    } for value in claimed
                },
                'recovered_from_truncation': outcome.get('recovered_from_truncation', False),
                'at': now(),
            }
            stages.append(stage)
            note = {'max-tokens': ' · отчёт восстановлен после обрезки',
                    'json': ' · отчёт получен повторным запросом',
                    'fallback': ' · сохранён частичный отчёт'}.get(
                        stage.get('recovery'), '')
            if stage['degraded']:
                note += ' · отчёт не распознан, сохранён только текст'
            say(f'[STAGE] {role} ok steps={outcome["steps_used"]} '
                f'findings={len(report["findings"])} '
                f'elapsed={outcome["elapsed_seconds"]}s{note}')
            say(f'      рассуждения: {stage["thinking_chars"]} знаков · '
                f'вызовы: {stage["tool_calls"]} · токены: вход {stage["input_tokens"]}, '
                f'кеш {stage["cache_read_tokens"]}, вывод {stage["output_tokens"]}, '
                f'пик контекста {stage["peak_context_tokens"]}')
            if stage['report_warning']:
                say('      предупреждение отчёта: ' + stage['report_warning'])
            if stage['report_repaired']:
                say('      JSON отчёта автоматически исправлен; проверьте evidence')
            if stage['no_tools']:
                say('      внимание: этап не сделал ни одного вызова инструмента — '
                    'его вывод ничего не доказывает')
            if stage.get('report_incomplete'):
                say('      внимание: verify завершился без решающего зонда — '
                    'этот отчёт не является независимым подтверждением')
            if stage['session_share'] > 0.6:
                say('      внимание: больше 60% вызовов стадии прошли через pm_session')
            for index, item in enumerate(report['findings'][:3], 1):
                title = agent_actions.short_text((item or {}).get('title', ''), 100)
                if title:
                    say(f'      находка {index}: {title}')
            report_registry(registry, report, patterns)

            found = [item['value'] for item in registry['confirmed']]
            if found and len(found) < expect:
                say(f'[FLAG] подтверждено {len(found)} из {expect} — продолжаю поиск '
                    'остальных')
            reason = objective_stop_reason(objective_state, len(found), expect)
            if reason:
                stop_reason = reason
                say(f'[FLAG] остановка: {reason}; подтверждены: {", ".join(found)}')
                # A confirmed flag ends the run, but a claim nobody backed with
                # raw output must not disappear silently: on task 16 the root
                # flag sat unconfirmed and the operator had to ask about it.
                unbacked = [item['value'] for item in registry['candidates']
                            if item.get('claims') and not item.get('raw_hits')]
                if unbacked:
                    say('[FLAG] внимание: заявлены, но сырым выводом не подтверждены: '
                        + ', '.join(unbacked[:5]))
                    say('      цикл останавливается — эти значения проверьте отдельно')
                if reason in ('goal_confirmed', 'objectives_done', 'flags_without_goal'):
                    return finish(task_id, stages, stop_reason, previous, expect)
                if role != 'verify' and 'verify' not in roles:
                    say('      внимание: роль verify не включена — независимое '
                        'подтверждение флагов не выполнялось')
                if role != 'verify' and 'verify' in roles:
                    # Corroborate before closing.
                    try:
                        verify = agent_actions.run_role(
                            task_id, 'verify',
                            f'Подтверди или опровергни флаги {found} по сырому выводу '
                            'инструментов. Перечисли точные источники.',
                            iteration, poc_budget, step_limit,
                            api_key=api_key, max_tokens=limit,
                        )
                        verified = flag_verify.scan(task_id, patterns=patterns)
                        objective_db = agent_actions.connect()
                        try:
                            objective_store.process_report(objective_db, task_id,
                                                           verify['report'], verified)
                        finally:
                            objective_db.close()
                        verified_states = {item['value']: item
                                           for item in verified['confirmed']
                                           + verified['candidates']}
                        stages.append({
                            'iteration': iteration, 'role': 'verify', 'status': 'completed',
                            'steps_used': verify['steps_used'],
                            'tool_events': verify['tool_events'],
                            'reads': verify['reads'],
                            'denied': verify['denied'],
                            'session_share': verify['session_share'],
                            'thinking_chars': verify.get('thinking_chars', 0),
                            'tool_calls': verify.get('tool_calls', verify['steps_used']),
                            'tokens_used': verify.get('tokens_used', 0),
                            'input_tokens': verify.get('input_tokens', 0),
                            'cache_read_tokens': verify.get('cache_read_tokens', 0),
                            'output_tokens': verify.get('output_tokens', 0),
                            'peak_context_tokens': verify.get('peak_context_tokens', 0),
                            'elapsed_seconds': verify['elapsed_seconds'],
                            'report_path': verify['report_path'],
                            'summary': verify['report']['summary'][:1200],
                            'report_warning': verify['report'].get('report_warning', ''),
                            'report_repaired': bool(verify['report'].get('report_repaired', False)),
                            'stats_unknown': verify.get('stats_unknown', False),
                            'report_incomplete': bool(verify['report'].get('report_incomplete')),
                            'findings': len(verify['report']['findings']),
                            'unverified_findings': len(verify['report'].get('unverified_findings') or []),
                            'refuted_claims': sum(1 for item in verify['report'].get('hypotheses') or []
                                                  if isinstance(item, dict) and item.get('result') == 'refuted'),
                            'finding_keys': [agent_actions.short_text((item or {}).get('title', ''), 80).lower()
                                             for item in verify['report']['findings']
                                             if (item or {}).get('title')][:60],
                            'degraded': verify.get('degraded', False),
                            'flags': list(verified_states),
                            'flag_state': {
                                value: {'status': item['status'],
                                        'raw_hits': item['raw_hits'],
                                        'evidence_source': item.get('evidence_source', 'none'),
                                        'matched_by': item.get('matched_by', 'default')}
                                for value, item in verified_states.items()
                            },
                            'at': now(),
                        })
                        if verify['session_share'] > 0.6:
                            say('      внимание: больше 60% вызовов verify прошли через pm_session')
                        if verify['report'].get('report_warning'):
                            say('      предупреждение отчёта: ' + verify['report']['report_warning'])
                        if verify['report'].get('report_repaired'):
                            say('      JSON отчёта автоматически исправлен; проверьте evidence')
                        previous = {'role': 'verify', **verify['report']}
                    except (ValueError, RuntimeError, OSError) as exc:
                        stages.append({'iteration': iteration, 'role': 'verify',
                                       'status': 'error', 'error': str(exc), 'at': now()})
                        say(f'[STAGE] verify failed: {exc}')
                return finish(task_id, stages, stop_reason, previous, expect)

        iteration_stages = stages[iteration_start:]
        if any(item.get('stats_unknown') for item in iteration_stages):
            say('[FLAG] счётчик шагов недоступен — не считаю итерацию бездействующей')
            continue
        iteration_steps = sum(int(item.get('steps_used') or 0)
                              for item in iteration_stages)
        if iteration_stages and not iteration_steps:
            if any(item.get('status') == 'salvaged' for item in iteration_stages):
                # A salvaged stage did work, we simply do not know how many
                # calls it made. Calling that "stalled" would be false.
                continue
            if all(item.get('status') == 'error' for item in iteration_stages):
                # Nothing ran because every stage died, not because the model
                # ran out of output. Blaming the token budget here sent the
                # operator looking in the wrong place.
                stop_reason = 'stalled'
                say('[FLAG] все стадии итерации упали до первого вызова — '
                    'причина в ошибке стадии выше, а не в лимите вывода')
                break
            # Every role talked and none acted: this is an exhausted output
            # budget, not a dead end in the target. Saying so is more useful
            # than another silent iteration (task 18 spent four like this).
            stop_reason = 'stalled'
            say('[FLAG] итерация не сделала ни одного вызова инструмента — '
                'это исчерпанный лимит вывода модели, а не отказ разведки')
            say('      подсказка: поднимите --max-tokens (сейчас '
                f'{limit}) или проверьте провайдера')
            break

        current = (registry_fingerprint(task_id), findings_total(stages),
                   decisive_state(task_id))
        if current[0] is None or current[2] is None:
            # An unreadable state is unknown, not unchanged. Two blind rounds in
            # a row are still a reason to stop - but say so honestly.
            unreadable_rounds += 1
            if unreadable_rounds >= 2:
                stop_reason = 'state_unavailable'
                say('[FLAG] состояние задачи не читается два круга подряд — '
                    'останавливаюсь, не выдавая это за отсутствие прогресса')
                break
            continue
        unreadable_rounds = 0
        if current == marker:
            if network_unreachable_since(task_id, capability_start):
                unreachable_rounds += 1
                if unreachable_rounds >= 2:
                    stop_reason = 'target_unreachable'
                    say('[FLAG] две итерации подряд: все сетевые вызовы завершились '
                        'тайм-аутом или недоступностью цели; останавливаюсь')
                    break
                continue
            stop_reason = 'no_progress'
            say('[FLAG] за итерацию не появилось ни новых захватов, ни новых заявок, '
                'ни новых находок — останавливаюсь')
            break
        unreachable_rounds = 0

    return finish(task_id, stages, stop_reason, previous, expect)


def finish(task_id, stages, stop_reason, previous, expect=DEFAULT_EXPECTED_FLAGS):
    """Write the run summary. Never raises: reporting must survive bad state."""
    diagnostics.stop(stop_reason, task_id=task_id)
    confirmed = confirmed_values(task_id)
    candidates = transferred_candidates(task_id)
    problems = []
    if stop_reason not in KNOWN_STOP_REASONS:
        problems.append(f'неизвестная причина остановки: {stop_reason!r}')
    if not stages:
        problems.append('ни одна стадия не запускалась')
    for item in stages:
        status = item.get('status')
        if status not in STAGE_STATUSES:
            problems.append(f"стадия {item.get('role')} итерации "
                            f"{item.get('iteration')} имеет неизвестный статус "
                            f'{status!r}')
        elif status == 'error':
            problems.append(f"стадия {item.get('role')} итерации "
                            f"{item.get('iteration')} завершилась ошибкой: "
                            f"{str(item.get('error') or '')[:200]}")
        elif status == 'salvaged':
            problems.append(f"стадия {item.get('role')} итерации "
                            f"{item.get('iteration')} прервана; сохранён промежуточный отчёт"
                            + (f": {str(item['error'])[:200]}" if item.get('error') else ''))
        if item.get('report_incomplete'):
            problems.append(f"стадия {item.get('role')} итерации "
                            f"{item.get('iteration')} завершилась без решающего зонда")
        if item.get('report_path') and not Path(item['report_path']).is_file():
            problems.append(f"отсутствует файл отчёта стадии: {item['report_path']}")
    warnings = []
    if len(confirmed) < expect:
        warnings.append(f'подтверждено {len(confirmed)} из {expect} ожидаемых флагов')
    if candidates:
        warnings.append('перенесённые значения без подтверждения на этом хосте: '
                        + ', '.join(candidates[:5]))
    if any(item.get('stats_unknown') for item in stages):
        warnings.append('число вызовов некоторых стадий неизвестно')
    # The structured state is part of the result, not only of the free-text
    # summary: an operator reading the loop JSON must see the access level and
    # the open hypotheses without querying the database by hand.
    try:
        db = agent_actions.connect()
        try:
            access_state = fact_state.access_state(db, task_id)
            hypotheses = fact_state.list_hypotheses(db, task_id, limit=200)
            try:
                objective_data = objective_store.objective_status(db, task_id)
            except (TypeError, AttributeError):
                objective_data = {'primary': None, 'objectives': []}
            try:
                patterns_used = flag_verify.load_patterns(db, task_id)
                flag_details = flag_verify.listing(task_id)
            except (ValueError, sqlite3.Error, TypeError, AttributeError):
                patterns_used, flag_details = flag_verify.DEFAULT_PATTERNS, []
        finally:
            db.close()
    except (ValueError, OSError, sqlite3.Error) as exc:
        access_state, hypotheses, patterns_used, flag_details = {}, [], flag_verify.DEFAULT_PATTERNS, []
        objective_data = {'primary': None, 'objectives': []}
        problems.append(f'не удалось прочитать итоговое состояние: {exc}')
    primary = objective_data.get('primary')
    rows = objective_data.get('objectives') or []
    if rows:
        warnings.append(f'подтверждено {len(confirmed)} из {expect} флагов; '
                        f'целей закрыто {len(objective_data.get("confirmed") or [])} из {len(rows)}')
    if primary and primary['status'] != 'confirmed' and (
            stop_reason == 'flags_without_goal' or stop_reason in NORMAL_STOP_REASONS):
        problems.append('основная цель не подтверждена')
    succeeded = (not problems and stop_reason in NORMAL_STOP_REASONS and
                 (not primary or primary['status'] == 'confirmed'))
    result = {
        'status': 'completed' if succeeded else 'incomplete',
        'succeeded': succeeded,
        'problems': problems,
        'warnings': warnings,
        'task_id': task_id,
        'stop_reason': stop_reason,
        'expected_flags': expect,
        'steps_total': sum(int(item.get('steps_used') or 0) for item in stages),
        'stats_unknown': any(item.get('stats_unknown') for item in stages),
        'empty_stages': sum(1 for item in stages if item.get('no_tools')),
        'quality': quality_metrics(stages),
        'stages': stages,
        'confirmed_flags': confirmed,
        'candidate_flags': candidates,
        'objectives': rows,
        'objectives_matrix': objective_matrix(rows) if rows else [],
        'flag_details': flag_details,
        'patterns_used': list(patterns_used),
        'has_flags': bool(confirmed),
        'access_state': access_state,
        'hypotheses': hypotheses,
        'last_summary': (previous or {}).get('summary', '')[:2000],
    }
    diagnostics.emit('assessment.result', task_id=task_id, status=result['status'],
                     succeeded=succeeded, objective_confirmed=(primary['status'] == 'confirmed') if primary else None)
    directory = agent_actions.REPORT_DIR / f'task_{task_id}'
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    # Two runs started within the same second used to overwrite each other's
    # only audit trail.
    path = directory / f'loop-{stamp}-{uuid.uuid4().hex[:8]}.json'
    path.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding='utf-8')
    path.chmod(0o600)
    result['loop_report'] = str(path)
    quality = result['quality']
    share = (str(quality['probe_backed_share']) if quality['probe_backed_share'] is not None
             else 'нет данных')
    say('[QUALITY] привязаны к выводу зонда: '
        f'{share}; повторов (нижняя граница): {quality["repeated_facts"]}; '
        f'опровергнуто verify: {quality["refuted_claims"]}')
    for problem in problems:
        say('[FLAG] проблема запуска: ' + problem)
    if result['status'] != 'completed':
        say(f'[FLAG] прогон записан как {result["status"]}: '
            'часть работы не завершена, смотрите problems')
    return result


@diagnostics.entrypoint
def main(argv=None):
    parser = argparse.ArgumentParser(description='Pentest Master role loop')
    sub = parser.add_subparsers(dest='command', required=True)

    run_parser = sub.add_parser('run', help='dispatch roles for N iterations')
    run_parser.add_argument('--task-id', type=int, required=True)
    run_parser.add_argument('--iterations', type=int, default=1)
    run_parser.add_argument('--roles', default=','.join(ROLE_ORDER))
    run_parser.add_argument('--poc-budget', type=int, default=7)
    run_parser.add_argument('--step-limit', type=int, default=15)
    run_parser.add_argument('--max-tokens', type=int, default=None)
    run_parser.add_argument('--expect-flags', type=int, default=None)

    args = parser.parse_args(argv)

    try:
        if args.command == 'run':
            roles = tuple(item.strip().lower() for item in args.roles.split(',') if item.strip())
            from orchestrator.coordinated_attack import task_lock
            with task_lock(args.task_id):
                render(run(args.task_id, args.iterations, roles,
                           args.poc_budget, args.step_limit, max_tokens=args.max_tokens,
                           expect_flags=args.expect_flags))
    except (ValueError, RuntimeError, OSError) as exc:
        render({'status': 'error', 'error': str(exc)})
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
