"""Read-only compatibility check; no model, runtime startup, DB or key lookup."""
from importlib.metadata import version, PackageNotFoundError
import inspect
import json
import os
from pathlib import Path

EXPECTED={'deepseek-harness-sdk':'0.2.1rc2','deepseek-harness-runtime-bin':'0.2.1rc2',
          'mcp':'1.26.0','pydantic':'2.14.2'}


def check():
    versions={};errors=[]
    for package,expected in EXPECTED.items():
        try:installed=version(package)
        except PackageNotFoundError:installed=None
        versions[package]={'installed':installed,'tested':expected}
        if installed!=expected:errors.append('untested_version:'+package)
    try:
        from deepseek_harness import DeepSeekHarness
        from deepseek_harness.api import Session
        from deepseek_harness_runtime import resolve_bundled_launch_args
        runtime=Path(resolve_bundled_launch_args()[0])
        if not runtime.is_file() or not os.access(runtime,os.X_OK):errors.append('runtime_not_executable')
        for name in ('start_session','resume_session','run','close'):
            if not callable(getattr(DeepSeekHarness,name,None)):errors.append('missing_api:'+name)
        if 'on_notification' not in inspect.signature(Session.run).parameters:errors.append('missing_notifications')
    except (ImportError,OSError,ValueError,TypeError):errors.append('sdk_inspection_failed')
    root=Path(__file__).resolve().parents[1]
    for file in ('orchestrator/evidence_readonly.mjs','orchestrator/agent_actions.mjs',
                 'runtime/harness-home/profiles/sdk-minimal/package.json'):
        if not (root/file).is_file():errors.append('missing_file:'+file)
    return {'compatible':not errors,'versions':versions,'errors':errors,
            'session_cancel_api':False,'native_workflow_python_api':False}


if __name__=='__main__':
    result=check();print(json.dumps(result,indent=2));raise SystemExit(0 if result['compatible'] else 1)
