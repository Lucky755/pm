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
OFFLINE = OFFLINE | {'test_resource_scope', 'test_tool_requests', 'test_pivot_close','test_burp_adapter'}
OFFLINE = OFFLINE | {'test_material_processing'}
OFFLINE = OFFLINE | {'test_research_budgets'}
OFFLINE = OFFLINE | {'test_specialist_workflow'}
OFFLINE = OFFLINE | {'test_method_library'}
OFFLINE = OFFLINE | {'test_operator_console'}
OFFLINE = OFFLINE | {'test_final_audit'}
OFFLINE = OFFLINE | {'test_result_ownership'}
SCRIPTS = frozenset(('test_burp_import', 'test_decision_agent', 'test_evidence_pipeline', 'test_evidence_recovery', 'test_master_scheduler', 'test_policy'))
RUNTIME = frozenset(('test_model_adapter_runtime', 'test_coordinated_runtime', 'test_evidence_readonly_runtime', 'test_tool_download_runtime', 'test_task_sessions', 'test_session_runtime', 'test_http_client_runtime','test_browser_runtime'))
RUNTIME = RUNTIME | {'test_burp_proxy_runtime'}
RUNTIME = RUNTIME | {'test_port_research'}
RUNTIME = RUNTIME | {'test_work_series_runtime'}
RUNTIME = RUNTIME | {'test_specialist_workflow_runtime'}
RUNTIME = RUNTIME | {'test_method_library_runtime'}
RUNTIME = RUNTIME | {'test_operator_console_runtime'}
RUNTIME = RUNTIME | {'test_final_audit_runtime'}
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


def storage_guard(directory,workspace=ROOT):
    """Fail before accidental production SQLite/files access, not a test skip."""
    directory=Path(directory)
    source='''import os,sys
from pathlib import Path
from urllib.parse import unquote,urlsplit
from contextvars import ContextVar
protected=Path(PROTECTED).resolve()
violation=Path(VIOLATION)
current_open=ContextVar('pm_guard_open',default=None)
original_open=os.open
def checked_open(path,flags,mode=0o777,*,dir_fd=None):
 name=os.fsdecode(path);actual=Path(name)
 if dir_fd is not None and not actual.is_absolute():actual=Path('/proc/self/fd/'+str(dir_fd)).resolve()/actual
 token=current_open.set((name,str(actual)))
 try:return original_open(path,flags,mode,dir_fd=dir_fd)
 finally:current_open.reset(token)
os.open=checked_open
def guard(event,args):
 if event not in ('open','sqlite3.connect') or not args:return
 name=args[0]
 if not isinstance(name,(str,bytes,os.PathLike)):return
 name=os.fsdecode(name)
 override=current_open.get()
 if event=='open' and override and name==override[0]:name=override[1]
 if name.startswith('file:'):name=unquote(urlsplit(name).path)
 if Path(name).resolve().is_relative_to(protected):
  violation.write_text(name)
  raise PermissionError('Offline test attempted working storage access: '+name)
sys.addaudithook(guard)
'''.replace('PROTECTED',repr(str(Path(workspace)/'storage'))).replace('VIOLATION',repr(str(directory/'storage-violation')))
    (directory/'sitecustomize.py').write_text(source)
    return str(directory)+os.pathsep+str(ROOT)


def run_suite(name, timeout=180):
    env=os.environ.copy()
    env['PYTHONPATH']=str(ROOT) # actual checkout; never the historical hardcoded root
    env.pop('PYTHONOPTIMIZE',None) # legacy assert scripts must actually execute assertions
    with tempfile.TemporaryDirectory(prefix='pm-suite-model-audit-') as directory:
        env['PM_MODEL_AUDIT_DIR']=directory
        env['PM_METHOD_LIBRARY_DIR']=str(Path(directory)/'methods')
        env['PYTHONPATH']=storage_guard(directory)
        result=subprocess.run(command(name),cwd=ROOT,env=env,stdin=subprocess.DEVNULL,
                              stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,timeout=timeout)
        if (Path(directory)/'storage-violation').exists():
            result.returncode=1
            result.stdout+='\nFAIL: attempted working storage access; exception handling cannot suppress this failure: '+(Path(directory)/'storage-violation').read_text()+'\n'
        return result


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--runtime',action='store_true',help='Also run local SDK/MCP, PTY and socket tests; model API is loopback fake API')
    parser.add_argument('--only',nargs='+',help='Selected classified offline suites (module names)')
    parser.add_argument('--list',action='store_true')
    parser.add_argument('--verbose',action='store_true',help='Print complete captured output, including warnings')
    args=parser.parse_args(argv)
    validate_inventory()
    if args.list:
        for label,group in (('OFFLINE',OFFLINE),('OFFLINE SCRIPT',SCRIPTS),('LOCAL RUNTIME: SDK/MCP/PTY/sockets',RUNTIME),
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
