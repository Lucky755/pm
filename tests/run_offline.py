"""Explicit offline inventory. Each suite gets a fresh interpreter: legacy import
stubs cannot leak. Manual API/host integration experiments are never imported.
"""
import argparse
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
OFFLINE = frozenset(('test_manual_flags', 'test_autonomous_workflow', 'test_operation_repeat_policy', 'test_task_memory', 'test_instruction_system', 'test_model_adapter', 'test_agent_prompt_context', 'test_agent_provider_recovery', 'test_application_discovery', 'test_auto_scheduler', 'test_bootstrap_discovery', 'test_console_model_progress', 'test_console_theme_v4', 'test_console_v2', 'test_console_v5', 'test_context_continuation', 'test_coordinated_attack', 'test_coordinator_checkpoints', 'test_decision_diagnostics_v2', 'test_diagnostic_integration', 'test_flag_evidence', 'test_flag_extensions', 'test_full_scan_recovery', 'test_http_artifacts', 'test_http_assets_v3', 'test_http_capture_mcp', 'test_http_discovery_v2', 'test_http_document', 'test_http_evidence_v2', 'test_http_scheduler_v2', 'test_netguard_docker', 'test_netguard_policy', 'test_objectives', 'test_offline_runner', 'test_operator_extensions', 'test_pm_console', 'test_report_integrity', 'test_report_semantics', 'test_run_diagnostics', 'test_scheduler_first_run', 'test_service_inventory', 'test_task_launch', 'test_verify_saved_capture'))
OFFLINE = OFFLINE | {'test_resource_scope', 'test_tool_requests'}
SCRIPTS = frozenset(('test_burp_import', 'test_decision_agent', 'test_evidence_pipeline', 'test_evidence_recovery', 'test_master_scheduler', 'test_policy'))
RUNTIME = frozenset(('test_model_adapter_runtime', 'test_coordinated_runtime', 'test_evidence_readonly_runtime', 'test_tool_download_runtime'))
MANUAL = frozenset(('test_agent_tool_selection', 'test_agent_v3_selection', 'test_approval_mcp', 'test_harness_mcp', 'test_local_tool_mcp', 'test_mcp_connection', 'test_network_mcp', 'test_pi_provider', 'test_shell_disabled', 'test_tool_v3_mcp'))


def validate_inventory():
    groups=(OFFLINE,SCRIPTS,RUNTIME,MANUAL)
    discovered={p.stem for p in (ROOT/'tests').glob('test_*.py')}
    classified=set().union(*groups)
    if discovered!=classified or sum(map(len,groups))!=len(classified):
        raise ValueError(f'Test inventory mismatch: unclassified={sorted(discovered-classified)}, '
                         f'missing={sorted(classified-discovered)}; categories must not overlap')


def command(name):
    if name in SCRIPTS:
        return [sys.executable,str(ROOT/'tests'/f'{name}.py')]
    if name not in OFFLINE|RUNTIME:
        raise ValueError('Manual/infrastructure tests require separate authorization: '+name)
    return [sys.executable,'-m','unittest','tests.'+name,'-v']


def run_suite(name, timeout=180):
    env=os.environ.copy()
    env['PYTHONPATH']=str(ROOT) # actual checkout; never the historical hardcoded root
    env.pop('PYTHONOPTIMIZE',None) # legacy assert scripts must actually execute assertions
    with tempfile.TemporaryDirectory(prefix='pm-suite-model-audit-') as directory:
        env['PM_MODEL_AUDIT_DIR']=directory
        return subprocess.run(command(name),cwd=ROOT,env=env,stdin=subprocess.DEVNULL,
                              stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,timeout=timeout)


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--runtime',action='store_true',help='Also run installed SDK/MCP with loopback fake API')
    parser.add_argument('--only',nargs='+',help='Selected classified offline suites (module names)')
    parser.add_argument('--list',action='store_true')
    parser.add_argument('--verbose',action='store_true',help='Print complete captured output, including warnings')
    args=parser.parse_args(argv)
    validate_inventory()
    if args.list:
        for label,group in (('OFFLINE',OFFLINE),('OFFLINE SCRIPT',SCRIPTS),('LOOPBACK SDK/MCP',RUNTIME),
                            ('MANUAL: API key and/or working infrastructure; not run',MANUAL)):
            print(label+': '+', '.join(sorted(group)))
        return 0
    selected=args.only or sorted(OFFLINE|SCRIPTS|(RUNTIME if args.runtime else set()))
    if set(selected)-(OFFLINE|SCRIPTS|(RUNTIME if args.runtime else set())):
        parser.error('Only classified offline suites are allowed; --runtime enables local SDK smoke tests')
    failures=[];tests=0;scripts=0;skips=0
    for name in selected:
        try:
            result=run_suite(name)
        except subprocess.TimeoutExpired:
            print('FAIL '+name+': timeout',flush=True);failures.append(name);continue
        counts=re.search(r'Ran (\d+) tests? in ',result.stdout)
        skipped=re.search(r'OK \(skipped=(\d+)\)',result.stdout)
        if skipped:skips+=int(skipped[1])
        if counts:tests+=int(counts[1])
        if (result.returncode or (name not in SCRIPTS and (not counts or int(counts[1])==0))
                or name in SCRIPTS and '[PASS]' not in result.stdout):
            failures.append(name)
            print('FAIL '+name+'\n'+result.stdout,flush=True)
        else:
            if not counts:scripts+=1
            print(('SKIP/PASS ' if skipped else 'PASS ')+name+
                  (': '+counts[1]+' unittest cases' if counts else ': legacy assertions, isolated process'),flush=True)
            if args.verbose:print(result.stdout,flush=True)
    print(f'Tests executed: {tests-skips}; skipped: {skips}; legacy scripts passed: {scripts}; failed suites: {len(failures)}')
    if not args.runtime:print('NOT RUN: loopback SDK/MCP smoke tests (use --runtime).')
    print('NOT RUN: manual API/infrastructure experiments: '+', '.join(sorted(MANUAL)))
    return 1 if failures or skips else 0


if __name__=='__main__':
    raise SystemExit(main())
