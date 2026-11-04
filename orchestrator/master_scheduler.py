"""Pentest Master: single-command coordinator for existing network, Burp, and evidence modules.

Runs only when invoked manually. Dry-run by default. Does not modify existing modules.

Examples:
  python orchestrator/master_scheduler.py status --task-id 9
  python orchestrator/master_scheduler.py run --task-id 9
  python orchestrator/master_scheduler.py run --task-id 10 --execute --sync-burp

--execute explicitly authorizes bounded, in-scope network jobs. It does not bypass
Task Scope or existing executor restrictions. Workstation-level egress isolation
is not provided by Bubblewrap --share-net.
"""

import argparse
import ipaddress
import json
import fcntl
import sqlite3
import subprocess
from datetime import datetime, timezone
from contextlib import contextmanager, nullcontext
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from orchestrator import diagnostics

from orchestrator import evidence_pipeline as evidence
from orchestrator import network_workflow as workflow
from orchestrator import network_enrichment as enrichment
from orchestrator import network_jobs as jobs
from orchestrator import decision_agent as decisions

BASE_PROFILES = ("tcp_ports", "http_headers")
ENRICHMENT_PROFILES = ("service_versions", "http_get")
MAX_JOBS = 12
DOCUMENTATION = tuple(ipaddress.ip_network(x) for x in (
    "192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24",
))


def emit(obj):
    print(json.dumps(obj, indent=2, ensure_ascii=False), flush=True)


def validate_task(db, task_id):
    """Check task scope before taking ANY action; source modules recheck."""
    target = workflow.load_task_target(db, task_id)
    enrichment.verify_scope(db, task_id, target)
    return target


def pending(db, task_id, profiles):
    """Only never-attempted plans are eligible; failures are not retried automatically."""
    marks = ",".join("?" for _ in profiles)
    rows = db.execute(f"""
        SELECT p.id, p.profile FROM network_phase_plans AS p
        WHERE p.task_id = ? AND p.status = 'planned'
          AND p.profile IN ({marks})
          AND NOT EXISTS (
              SELECT 1 FROM network_job_runs AS r WHERE r.plan_id = p.id
          )
        ORDER BY p.id
    """, (task_id, *profiles)).fetchall()
    return [{"plan_id": row[0], "profile": row[1]} for row in rows]


def execute_pending(db, task_id, profiles, remaining):
    outcomes = []
    for item in pending(db, task_id, profiles)[:remaining]:
        plan_id = item["plan_id"]
        try:
            if item["profile"] in BASE_PROFILES:
                result = jobs.execute_job(db, plan_id)
            else:
                result = enrichment.run_plan(db, plan_id)
        except (ValueError, OSError, sqlite3.Error) as exc:
            result = {"plan_id": plan_id, "status": "blocked", "error": str(exc)}
        outcomes.append(result)
        print(f"[JOB] #{plan_id}: {result['status']}", flush=True)
    return outcomes


def compact_status(db, task_id):
    digest, bundle = evidence.make_snapshot(db, task_id)
    completed = evidence.saved_reports(db, task_id, digest)
    return {
        "task_id": task_id,
        "target": bundle["authorized_target"],
        "evidence_sha256": digest,
        "network_observations": len(bundle["network_observations"]),
        "burp_observations": len(bundle["burp_http_metadata"]),
        "agents_completed": [name for name in evidence.STAGES if name in completed],
        "agents_pending": [name for name in evidence.STAGES if name not in completed],
        "pending_baseline": pending(db, task_id, BASE_PROFILES),
        "pending_enrichment": pending(db, task_id, ENRICHMENT_PROFILES),
    }


@diagnostics.stage
def run(db, task_id, execute, sync_burp, skip_agents, max_jobs, decide=False):
    target = validate_task(db, task_id)
    if execute and any(ipaddress.ip_address(target) in net for net in DOCUMENTATION):
        raise ValueError("Live network execution disabled for documentation targets")
    print(f"[TASK] {task_id} | {target} | mode={'LIVE' if execute else 'PLAN ONLY'}", flush=True)

    # Optionally import currently observed Burp history. Burp need not be open
    # unless --sync-burp is explicitly requested.
    if sync_burp:
        print("[BURP] Importing metadata", flush=True)
        result = evidence.load_burp().import_history(task_id, limit=50)
        emit({"burp_sync": result})

    outcomes = []
    if execute:
        print("[NETWORK] Baseline jobs", flush=True)
        outcomes.extend(execute_pending(db, task_id, BASE_PROFILES, max_jobs))

    # Existing Network Workflow proposes HTTP HEAD only from completed port scans.
    added_http = workflow.create_followups(db, task_id)
    print(f"[PLAN] HTTP follow-ups added: {len(added_http)}", flush=True)
    if execute and len(outcomes) < max_jobs:
        outcomes.extend(execute_pending(db, task_id, BASE_PROFILES,
                                        max_jobs - len(outcomes)))

    # Existing Network Enrichment proposes service detection and HTTP GET only
    # when verified observations justify these checks.
    added_v2 = enrichment.plan_followups(db, task_id)
    print(f"[PLAN] v2 enrichment added: {len(added_v2)}", flush=True)
    if execute and len(outcomes) < max_jobs:
        outcomes.extend(execute_pending(db, task_id, ENRICHMENT_PROFILES,
                                        max_jobs - len(outcomes)))

    # Optional model-guided decision, strictly limited to validated candidates.
    # This is planning only unless --execute is also explicitly provided.
    decision_result = None
    if decide:
        print('[DECIDE] Selecting from evidence-grounded candidates', flush=True)
        decision_result = decisions.plan(db, task_id)
        print(f"[DECIDE] {decision_result['status']}; new plans: "
              f"{len(decision_result['new_plans'])}", flush=True)
        if execute and len(outcomes) < max_jobs:
            remain = max_jobs - len(outcomes)
            outcomes.extend(execute_pending(db, task_id, BASE_PROFILES, remain))
            if len(outcomes) < max_jobs:
                outcomes.extend(execute_pending(db, task_id, ENRICHMENT_PROFILES,
                                                max_jobs - len(outcomes)))

    digest, bundle = evidence.make_snapshot(db, task_id)
    print(f"[EVIDENCE] {digest[:12]} | network={len(bundle['network_observations'])} "
          f"burp={len(bundle['burp_http_metadata'])}", flush=True)

    if not skip_agents and (bundle["network_observations"] or bundle["burp_http_metadata"]):
        evidence.run_agents(db, task_id, digest, bundle)
    elif not skip_agents:
        print("[AGENTS] No observations yet; skipping analysis", flush=True)

    result = compact_status(db, task_id)
    result["job_outcomes"] = outcomes
    if decision_result is not None:
        result["decision"] = {"status": decision_result["status"], "new_plans": decision_result["new_plans"]}
    emit(result)
    return result


def _now():
    return datetime.now(timezone.utc).isoformat()


def _agent_work(task_id):
    """Number of capability calls recorded for a task so far.

    Agent exploitation rarely changes network observations: an RCE that returns
    a flag is invisible to the scans that feed the evidence digest. Counting the
    capability log keeps such a round from being classified as "no new
    evidence" and stopping the chain right after the breakthrough.
    """
    path = ROOT / 'storage/capability_log' / f'task_{task_id}.jsonl'
    if not path.is_file():
        return 0
    try:
        with path.open('r', encoding='utf-8', errors='replace') as handle:
            return sum(1 for line in handle if line.strip())
    except OSError:
        return 0


def _init_auto_history(db):
    """Persist each manually started session and the rounds it completed."""
    with db:
        db.execute("""CREATE TABLE IF NOT EXISTS master_auto_runs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            task_id INTEGER NOT NULL,
            live INTEGER NOT NULL,
            model_decisions INTEGER NOT NULL,
            status TEXT NOT NULL,
            stop_reason TEXT,
            started_at TEXT NOT NULL,
            finished_at TEXT
        )""")
        db.execute("""CREATE TABLE IF NOT EXISTS master_auto_rounds (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            run_id INTEGER NOT NULL,
            round_number INTEGER NOT NULL,
            evidence_before TEXT NOT NULL,
            evidence_after TEXT,
            jobs_json TEXT,
            decision_json TEXT,
            status TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY(run_id) REFERENCES master_auto_runs(id),
            UNIQUE(run_id, round_number)
        )""")


def auto_history(db, task_id, limit=5):
    _init_auto_history(db)
    rows = db.execute("""SELECT id, live, model_decisions, status,
                                stop_reason, started_at, finished_at
                         FROM master_auto_runs WHERE task_id=?
                         ORDER BY id DESC LIMIT ?""", (task_id, limit)).fetchall()
    return [dict(zip(('run_id', 'live', 'model_decisions', 'status',
                      'stop_reason', 'started_at', 'finished_at'), row)) for row in rows]


@diagnostics.stage
def auto(db, task_id, execute, sync_burp, skip_agents, max_jobs,
         decide=False, max_rounds=4, bootstrap=False, web_enabled=False):
    """Manual, bounded evidence -> plans -> execution -> analysis loop.

    --execute is mandatory for any target network traffic; default dry-run.
    The global job budget is shared across ALL rounds.
    A failed job is never retried automatically because pending() excludes it.
    Already completed agent reports and model decisions are cached per evidence hash.
    """
    target = validate_task(db, task_id)
    if execute and any(ipaddress.ip_address(target) in net for net in DOCUMENTATION):
        raise ValueError('Live network execution disabled for documentation targets')
    discovery = None
    if bootstrap:
        if not execute:
            raise ValueError('--bootstrap requires --execute')
        from orchestrator import bootstrap_discovery as discovery
        discovery.safe_task_target(db, task_id)
    web_discovery = None
    if web_enabled:
        if not execute:
            raise ValueError('Web discovery requires approved live execution')
        from orchestrator import http_discovery as web_discovery
        web_discovery.require_capture_support()
        web_discovery.init(db)
        web_discovery.validate_scope(db, task_id)
    active_enrichment = tuple(p for p in ENRICHMENT_PROFILES if web_discovery is None or p != 'http_get')
    _init_auto_history(db)
    with db:
        run_id = db.execute("""INSERT INTO master_auto_runs
            (task_id,live,model_decisions,status,started_at)
            VALUES (?,?,?,'running',?)""", (task_id, int(execute), int(decide), _now())).lastrowid

    diagnostics.emit('state.change', task_id=task_id, table='master_auto_runs',
                     identifiers={'id': run_id}, status='running')
    all_jobs = []
    round_reports = []
    stop_reason = 'round_limit'
    print(f'[AUTO] session #{run_id} | task={task_id} | target={target} | '
          f'mode={"LIVE" if execute else "PLAN ONLY"} | rounds<={max_rounds} | jobs<={max_jobs}',
          flush=True)

    try:
        if sync_burp:
            print('[BURP] Importing current metadata (once)', flush=True)
            emit({'burp_sync': evidence.load_burp().import_history(task_id, limit=50)})

        for number in range(1, max_rounds + 1):
            digest_before, bundle_before = evidence.make_snapshot(db, task_id)
            agent_work_before = _agent_work(task_id)
            with db:
                db.execute("""INSERT INTO master_auto_rounds
                    (run_id,round_number,evidence_before,status,created_at)
                    VALUES (?,?,?,'running',?)""", (run_id, number, digest_before, _now()))

            round_action = diagnostics.Action('round', 'scheduler', task_id=task_id, iteration=number,
                                              identifiers={'auto_run_id': run_id, 'round': number})
            round_action.__enter__()
            round_jobs = []
            decision_result = None
            try:
                # Empty-evidence startup must NOT be treated as completion.
                # The first batches are ordered using the local Nmap services
                # popularity table, not guessed by the LLM.
                new_discovery = discovery.queue_next(db, task_id) if discovery else []
                if new_discovery:
                    print(f'[BOOTSTRAP] queued={len(new_discovery)} '
                          f'ports={sum(x["ports"] for x in new_discovery)}', flush=True)
                # Deterministic plans never need model tokens, and dedupe in DB.
                new_head = workflow.create_followups(db, task_id)
                new_v2 = (enrichment.plan_followups(db, task_id, include_http_get=False)
                          if web_discovery is not None else enrichment.plan_followups(db, task_id))
                print(f'[ROUND {number}] +HEAD={len(new_head)} +v2={len(new_v2)}', flush=True)

                slots = max_jobs - len(all_jobs)
                if execute and slots > 0:
                    round_jobs.extend(execute_pending(db, task_id, BASE_PROFILES, slots))
                    slots = max_jobs - len(all_jobs) - len(round_jobs)
                    if slots > 0:
                        round_jobs.extend(execute_pending(db, task_id, active_enrichment, slots))

                # Bounded HTML discovery from observed HTTP redirects and local hrefs.
                # Uses NetGuard's binary http_capture profile and shares the
                # same global job budget. No form submission or redirect follow.
                web_jobs = []
                slots = max_jobs - len(all_jobs) - len(round_jobs)
                if web_discovery is not None and execute and slots > 0:
                    web_jobs = web_discovery.execute_round(db, task_id, max_requests=min(2, slots),capture=True)
                    round_jobs.extend([{'profile': 'http_path', **item} for item in web_jobs])

                # Analyze the evidence AFTER the jobs that were just completed.
                digest_mid, bundle_mid = evidence.make_snapshot(db, task_id)
                if not skip_agents:
                    if bundle_mid['network_observations'] or bundle_mid['burp_http_metadata'] or bundle_mid.get('web_observations'):
                        evidence.run_agents(db, task_id, digest_mid, bundle_mid)
                    else:
                        print(f'[ROUND {number}] No observations; skipping agents', flush=True)

                remaining = max_jobs - len(all_jobs) - len(round_jobs)
                queue_before_decision = (pending(db, task_id, BASE_PROFILES)
                                         + pending(db, task_id, active_enrichment))
                # Don't pay for a new decision while already selected work is queued,
                # or when there is no execution capacity in a LIVE run.
                may_decide = (decide and not queue_before_decision
                              and (not execute or remaining > 0))
                if may_decide and web_discovery is not None:
                    may_decide = (not any(j.get('status') != 'completed' for j in web_jobs)
                                  and not web_discovery.has_more(db,task_id,capture=True))
                if may_decide:
                    print(f'[ROUND {number}] Decision from evidence {digest_mid[:12]}', flush=True)
                    decision_result = decisions.plan(db, task_id)
                    print(f'[DECIDE] {decision_result["status"]}; '
                          f'new plans={len(decision_result["new_plans"])}', flush=True)
                    if execute and decision_result['new_plans']:
                        round_jobs.extend(execute_pending(db, task_id, BASE_PROFILES, remaining))
                        remaining = max_jobs - len(all_jobs) - len(round_jobs)
                        if remaining > 0:
                            round_jobs.extend(execute_pending(db, task_id, active_enrichment, remaining))

                all_jobs.extend(round_jobs)
                digest_after, bundle_after = evidence.make_snapshot(db, task_id)
                # A decision can execute a job after the first agent pass.
                # Analyze THAT resulting snapshot before stopping on budget.
                if (not skip_agents and digest_after != digest_mid
                        and (bundle_after['network_observations']
                             or bundle_after['burp_http_metadata'] or bundle_after.get('web_observations'))):
                    evidence.run_agents(db, task_id, digest_after, bundle_after)
                outstanding = (pending(db, task_id, BASE_PROFILES)
                               + pending(db, task_id, active_enrichment))
                changed = digest_before != digest_after
                agent_work = max(0, _agent_work(task_id) - agent_work_before)

                report = {
                    'round': number,
                    'evidence_before': digest_before[:12],
                    'evidence_after': digest_after[:12],
                    'new_observations': (len(bundle_after['network_observations'])
                                         + len(bundle_after['burp_http_metadata'])
                                         + len(bundle_after.get('web_observations', []))
                                         - len(bundle_before['network_observations'])
                                         - len(bundle_before['burp_http_metadata'])
                                         - len(bundle_before.get('web_observations', []))),
                    'evidence_changed': changed,
                    'agent_capability_calls': agent_work,
                    'jobs': round_jobs,
                    'new_decision_plans': (decision_result or {}).get('new_plans', []),
                    'bootstrap_plans': new_discovery,
                    'web_paths': [j.get('path') for j in web_jobs],
                    'pending_jobs': len(outstanding),
                }
                round_reports.append(report)
                with db:
                    db.execute("""UPDATE master_auto_rounds
                        SET evidence_after=?,jobs_json=?,decision_json=?,status='completed'
                        WHERE run_id=? AND round_number=?""",
                        (digest_after, json.dumps(round_jobs, ensure_ascii=False),
                         json.dumps(decision_result, ensure_ascii=False) if decision_result else None,
                         run_id, number))
                print(f'[ROUND {number}] observations={len(bundle_after["network_observations"])}'
                      f'+{len(bundle_after["burp_http_metadata"])} web={len(bundle_after.get("web_observations", []))} '
                      f'pending={len(outstanding)} jobs={len(round_jobs)} '
                      f'changed={changed}', flush=True)

                if not execute:
                    stop_reason = 'plan_only'
                    break
                if web_discovery and any(j.get('status') != 'completed' for j in web_jobs):
                    stop_reason = 'http_job_failed'
                    break
                if discovery and any(j.get('status') not in ('completed', 'already_completed')
                                     for j in round_jobs):
                    # A broken namespace or executor must not trigger more batches.
                    stop_reason = 'bootstrap_job_failed'
                    break
                if len(all_jobs) >= max_jobs:
                    stop_reason = 'job_budget'
                    break
                # Work done with no new factual evidence must not cause an
                # indefinite chain of repeated model calls and empty probes.
                # A negative 32-port batch is scan coverage, not proof
                # that the host has no services. Continue discovery only
                # when there are more ranked ports and budget/rounds remain.
                discovery_more = discovery.has_more(db, task_id) if discovery else False
                if web_discovery is not None:
                    discovery_more = discovery_more or web_discovery.has_more(db, task_id,capture=True)
                if (round_jobs and not changed and not agent_work
                        and not discovery_more and not outstanding):
                    stop_reason = 'no_new_evidence'
                    break
                if not outstanding and not changed and not agent_work and not discovery_more:
                    stop_reason = 'no_progress'
                    break
                if not outstanding and not round_jobs and not discovery_more:
                    stop_reason = 'queue_empty'
                    break
                # Changed evidence or pending jobs => next bounded round.
            except BaseException as exc:
                state = 'interrupted' if isinstance(exc, KeyboardInterrupt) else 'failed'
                with db:
                    db.execute("""UPDATE master_auto_rounds SET status=?
                        WHERE run_id=? AND round_number=?""", (state, run_id, number))
                raise
            finally:
                round_action.__exit__(*sys.exc_info())

        with db:
            db.execute("""UPDATE master_auto_runs
                SET status='completed',stop_reason=?,finished_at=? WHERE id=?""",
                (stop_reason, _now(), run_id))
    except BaseException as exc:
        # Ctrl+C is also recorded, while the signal still reaches the caller.
        state = 'interrupted' if isinstance(exc, KeyboardInterrupt) else 'failed'
        with db:
            db.execute("""UPDATE master_auto_runs
                SET status=?,stop_reason=?,finished_at=? WHERE id=?""",
                (state, 'interrupted' if state == 'interrupted' else 'error',
                 _now(), run_id))
        raise

    diagnostics.emit('state.change', task_id=task_id, table='master_auto_runs',
                     identifiers={'id': run_id}, status='completed', reason=stop_reason)
    result = compact_status(db, task_id)
    if discovery:
        result['bootstrap_progress'] = discovery.progress(db, task_id)
    if web_discovery:
        result['deferred_legacy_http_get'] = [item for item in result.get('pending_enrichment',[])
                                             if item['profile'] == 'http_get']
        result['pending_enrichment'] = pending(db,task_id,active_enrichment)
        result['web_observations'] = len(web_discovery.evidence_rows(db, task_id))
        result['web_progress'] = web_discovery.queue_status(db, task_id,capture=True)
    result.update({'auto_run_id': run_id, 'auto_status': 'completed',
                   'stop_reason': stop_reason, 'rounds': round_reports,
                   'total_jobs': len(all_jobs)})
    emit(result)
    return result


@contextmanager
def exclusive_run_lock():
    """Prevent two manually started coordinators from executing the same plans."""
    lockpath = ROOT / "runtime/master_scheduler.lock"
    lockpath.parent.mkdir(parents=True, exist_ok=True)
    with lockpath.open("a+") as lockfile:
        try:
            fcntl.flock(lockfile.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise ValueError("Another master_scheduler run is active") from exc
        try:
            yield
        finally:
            fcntl.flock(lockfile.fileno(), fcntl.LOCK_UN)


@diagnostics.entrypoint
def main():
    parser = argparse.ArgumentParser(description="Pentest Master unified coordinator")
    parser.add_argument("command", choices=("status", "run", "auto", "auto-history"))
    parser.add_argument("--task-id", type=int, required=True)
    parser.add_argument("--bootstrap", action="store_true",
                        help="For auto --execute: queue bounded 32-port Nmap discovery batches when no open ports are known")
    parser.add_argument("--decide", action="store_true",
                        help="Ask model to select bounded follow-up plans; consumes API tokens once per evidence version")
    parser.add_argument("--execute", action="store_true",
                        help="Explicitly run in-scope network probes; otherwise plan only")
    parser.add_argument("--sync-burp", action="store_true",
                        help="Import current Burp Bridge HTTP metadata")
    parser.add_argument("--no-agents", action="store_true",
                        help="Skip model calls; useful when building the queue")
    parser.add_argument("--max-jobs", type=int, default=8,
                        help="Maximum live network jobs per invocation (1..12)")
    parser.add_argument("--max-rounds", type=int, default=4,
                        help="For auto: maximum rounds per invocation (1..8)")
    args = parser.parse_args()
    if not 1 <= args.max_jobs <= MAX_JOBS:
        parser.error("--max-jobs must be between 1 and 12")
    if not 1 <= args.max_rounds <= 8:
        parser.error("--max-rounds must be between 1 and 8")
    if args.bootstrap and args.command != 'auto':
        parser.error('--bootstrap is only available with auto')
    if args.bootstrap and not args.execute:
        parser.error('--bootstrap requires --execute')
    if args.command in ("status", "auto-history") and (args.execute or args.sync_burp or args.no_agents or args.decide):
        parser.error("status/auto-history do not accept run-only flags")
    try:
        from orchestrator.coordinated_attack import task_lock
        execution_lock=task_lock(args.task_id) if args.command in ('run','auto') else nullcontext()
        with execution_lock, exclusive_run_lock():
            with evidence.connect() as db:
                jobs.initialize(db)
                validate_task(db, args.task_id)
                if args.command == "status":
                    emit(compact_status(db, args.task_id))
                elif args.command == "auto-history":
                    emit(auto_history(db, args.task_id))
                elif args.command == "auto":
                    auto(db, args.task_id, args.execute, args.sync_burp,
                         args.no_agents, args.max_jobs, args.decide, args.max_rounds, args.bootstrap)
                else:
                    run(db, args.task_id, args.execute, args.sync_burp,
                        args.no_agents, args.max_jobs, args.decide)
    except (ValueError, RuntimeError, OSError, sqlite3.Error,
            ImportError, subprocess.SubprocessError) as exc:
        emit({"status": "blocked", "error": str(exc)})
        raise SystemExit(1)



if __name__ == "__main__":
    main()
