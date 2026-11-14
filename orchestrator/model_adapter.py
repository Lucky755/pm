"""The single model transport: owned Harness runtimes, no automatic replay.

Analysis hides tools and denies dispatch. Execution requires an explicit policy.
Cancellation closes the owned runtime (SDK rc2 has no session-cancel API).
Raw final responses are private artifacts; diagnostics contain identifiers only.
"""
from contextlib import ExitStack, contextmanager
from dataclasses import dataclass
from contextvars import ContextVar
from pathlib import Path
import hashlib
import json
import os
import threading
import time
import uuid

from orchestrator import diagnostics
from orchestrator.harness_env import harness_env

ROOT=Path(__file__).resolve().parents[1]
DEFAULT_HOME=ROOT/'runtime/harness-home'
DEFAULT_CWD=ROOT/'runtime/workspace'
_configuration=ContextVar('pm_model_configuration',default={})


@contextmanager
def configuration(**options):
    """Explicit operator/test configuration, never a fallback provider chain."""
    token=_configuration.set({**_configuration.get(),**options})
    try:yield
    finally:_configuration.reset(token)


class HarnessCallError(RuntimeError):
    def __init__(self,code,request_id,original=None):
        super().__init__(f'Harness {code}; request_id={request_id}')
        self.code,self.request_id,self.original=code,request_id,original


def audit_directory():
    if os.environ.get('PM_MODEL_AUDIT_DIR'):return Path(os.environ['PM_MODEL_AUDIT_DIR'])
    context=diagnostics.context() or {}
    if context.get('directory'):return Path(context['directory'])/'model_requests'
    if diagnostics.EVENT_DIR!=ROOT/'storage/run_events':return diagnostics.EVENT_DIR.parent/'model_requests'
    return ROOT/'storage/model_requests'


def write_private(path,text):
    path.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
    temporary=path.with_name(path.name+'.'+uuid.uuid4().hex+'.tmp')
    fd=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    try:
        with os.fdopen(fd,'w',encoding='utf-8') as stream:stream.write(text)
        os.replace(temporary,path)
    finally:temporary.unlink(missing_ok=True)


def save_record(record,raw=None,key=None):
    path=audit_directory()/f"{record['request_id']}.json"
    try:
        if raw is not None:
            raw=raw.replace(key,'[REDACTED]') if key else raw
            raw_path=path.with_suffix('.raw.txt')
            write_private(raw_path,raw)
            record.update(raw_response_ref=str(raw_path),raw_response_sha256=hashlib.sha256(raw.encode()).hexdigest())
        write_private(path,json.dumps(record,ensure_ascii=True,indent=2))
    except OSError as exc:
        diagnostics.warning(exc)
        raise
    return record


def reject_response(value,reason,attempt,**context):
    record=dict(getattr(value,'metadata',{}) or {'request_id':uuid.uuid4().hex,'mode':'analysis'})
    raw=getattr(value,'final_response',value)
    raw=raw if isinstance(raw,str) else json.dumps(raw,ensure_ascii=True)
    record.update(context,status='rejected',rejection_reason=reason,recovery_attempt=attempt)
    # The adapter already saved a key-redacted original (also for policy
    # violations, whose public response is empty). Never overwrite it here.
    save_record(record,None if record.get('raw_response_ref') else raw)
    diagnostics.emit('model.response_rejected',request_id=record['request_id'],reason=reason,
                     attempt=attempt,raw_response_ref=record['raw_response_ref'])
    return record


@dataclass
class ModelResult:
    session_id:str
    final_response:str
    finish_reason:str|None
    events:list
    notifications:list
    metadata:dict


def statistics(events):
    usages=[(event.get('data') or {}).get('usage') or {} for event in events if event.get('type')=='assistant/message']
    stats={}
    for source,destination in (('inputTokens','input_tokens'),('outputTokens','output_tokens'),
                               ('cacheReadTokens','cache_read_tokens'),('totalTokens','peak_context_tokens')):
        values=[u.get(source) for u in usages]
        valid=bool(values) and all(type(v) in (int,float) and v>=0 for v in values)
        stats[destination]=(max(values) if source=='totalTokens' else sum(values)) if valid else None
    return stats


def combine_statistics(turns):
    keys=('input_tokens','output_tokens','cache_read_tokens','peak_context_tokens')
    return {k:(max(t[k] for t in turns) if k=='peak_context_tokens' else sum(t[k] for t in turns))
            if turns and all(t.get(k) is not None for t in turns) else None for k in keys}


class HarnessAdapter:
    def __init__(self,*,mode,**options):
        if mode not in ('analysis','execute'):raise ValueError('Unknown Harness mode')
        self.mode=mode
        self.options={'profile':'sdk-minimal','provider':'experiential','model':'glm-5.3-uncensored',
                      'dsh_home':str(DEFAULT_HOME),'cwd':str(DEFAULT_CWD),
                      'request_timeout_seconds':120,**options,**_configuration.get()}
        if mode=='execute' and not self.options.get('patches'):
            raise ValueError('Execution requires an explicit tool policy')
        self.options['env']=harness_env(self.options.get('env'))
        self.timeout=float(self.options['request_timeout_seconds'])
        if self.timeout<=0:raise ValueError('Harness timeout must be positive')
        self.key=self.options.get('api_key')
        if self.key:diagnostics.register_secret(self.key)
        self.stack=ExitStack();self.native=None;self.cancelled=False;self.timed_out=False
        self.close_lock=threading.Lock()

    def __enter__(self):
        from deepseek_harness import DeepSeekHarness
        if self.mode=='analysis':
            from orchestrator.evidence_pipeline import read_only_analysis_patch
            # The final overlay is always our monotonic runtime restriction.
            patches=tuple(self.options.get('patches') or ())
            trusted=False
            if patches:
                try:
                    layers=json.loads(Path(patches[-1]).read_text())
                    plugin=layers[-1]['insert'][0]
                    trusted=(plugin['id']=='pm-evidence-readonly' and
                             Path(plugin['name']).read_bytes()==(ROOT/'orchestrator/evidence_readonly.mjs').read_bytes())
                except (OSError,ValueError,KeyError,IndexError,TypeError):pass
            if not trusted:patches+= (self.stack.enter_context(read_only_analysis_patch()),)
            self.options['patches']=patches
        try:
            self.native=DeepSeekHarness(**self.options)
            self.native.__enter__()
        except Exception as exc:
            self.stack.close()
            request_id=uuid.uuid4().hex
            try:save_record({'request_id':request_id,'mode':self.mode,'status':'configuration_or_start_failure',
                             'error_type':type(exc).__name__,'run_id':(diagnostics.context() or {}).get('run_id')})
            except OSError:pass
            raise HarnessCallError('configuration_or_start_failure',request_id,exc) from None
        return self

    def __exit__(self,kind,value,tb):
        try:
            try:self.close()
            except Exception as exc:
                diagnostics.warning(exc)
                if kind is None:raise HarnessCallError('shutdown_error',uuid.uuid4().hex,exc) from None
        finally:self.stack.close()

    def close(self):
        with self.close_lock:
            if self.native is not None:
                native,self.native=self.native,None
                # Keep fake SDK boundaries compatible with the SDK context API.
                native.__exit__(None,None,None)

    def cancel(self,*,timeout=False):
        self.cancelled=True;self.timed_out=timeout
        self.close()

    def start_session(self,session_id=None):
        if self.native is None:raise HarnessCallError('cancelled' if self.cancelled else 'closed',uuid.uuid4().hex)
        sid=session_id or 'pm-'+uuid.uuid4().hex
        return AdapterSession(self,self.native.start_session(sid),sid)

    def resume_session(self,session_id):
        return AdapterSession(self,self.native.resume_session(session_id),session_id)

    def run(self,prompt,*,session_id=None,**kwargs):
        return self.start_session(session_id).run(prompt,**kwargs)

    @contextmanager
    def analysis_session(self,prefix='format'):
        options={**self.options,'patches':()}
        options['env']={key:value for key,value in options['env'].items() if not key.startswith('PM_AGENT_')}
        with HarnessAdapter(mode='analysis',**options) as child:
            yield child.start_session(prefix+'-'+uuid.uuid4().hex)


class AdapterSession:
    def __init__(self,owner,native,sid):self.owner,self.native,self.id=owner,native,sid

    def run(self,prompt,*,diagnostic_reason=None,on_notification=None,recovery_attempt=0):
        if recovery_attempt and self.owner.mode!='analysis':
            raise ValueError('Format recovery requires analysis mode')
        request_id=uuid.uuid4().hex;started=time.monotonic()
        record={'request_id':request_id,'session_id':self.id,'mode':self.owner.mode,
                'provider':self.owner.options['provider'],'model':self.owner.options['model'],
                'status':'running','recovery_attempt':recovery_attempt,
                'statistics':statistics([]),'prefix_cache':'unknown',
                'prompt_sha256':hashlib.sha256(str(prompt).encode()).hexdigest(),
                'run_id':(diagnostics.context() or {}).get('run_id')}
        record.update({key:(diagnostics.context() or {}).get(key) for key in ('task_id','role','iteration')})
        stable=str(prompt).split('<pm_dynamic_context>',1)[0]
        record.update(prompt_bytes=len(str(prompt).encode()),stable_prefix_sha256=hashlib.sha256(stable.encode()).hexdigest(),
                      stable_prefix_bytes=len(stable.encode()),usage_source='SDK reported values; missing fields unknown',
                      cache_attribution='unknown; a provider/SDK cache counter does not identify the cached PM prefix')
        try:save_record(record)
        except OSError as exc:raise HarnessCallError('audit_error',request_id,exc) from None
        diagnostics.emit('model.request_start',request_id=request_id,session_id=self.id,mode=self.owner.mode)
        timer=threading.Timer(self.owner.timeout,lambda:self.owner.cancel(timeout=True));timer.daemon=True
        timer.start()
        received=False
        try:
            kwargs={'on_notification':on_notification} if on_notification is not None else {}
            raw=diagnostics.model_call(self.native,prompt,diagnostic_reason=diagnostic_reason,**kwargs)
            received=True
            if self.owner.cancelled:
                raise TimeoutError() if self.owner.timed_out else RuntimeError('Owned runtime cancelled')
            events=list(getattr(raw,'events',[]) or [])
            notifications=list(getattr(raw,'notifications',[]) or [])
            message_id=None
            for notification in notifications:
                event=getattr(notification,'payload',{}).get('event',{})
                if event.get('type')=='agent/inbox/spliced':
                    inserted=(event.get('data') or {}).get('inserted') or []
                    message_id=message_id or next((m.get('id') for m in inserted if isinstance(m,dict)),None)
            reason=getattr(raw,'finish_reason',None)
            text=str(getattr(raw,'final_response','') or '')
            if self.owner.key:text=text.replace(self.owner.key,'[REDACTED]')
            violation=self.owner.mode=='analysis' and any(e.get('type')=='tool/call' for e in events)
            record.update(status='policy_violation' if violation else str(reason or 'unknown'),
                          finish_reason=reason,runtime_message_id=message_id,statistics=statistics(events),
                          duration_seconds=round(time.monotonic()-started,3))
            cached=record['statistics']['cache_read_tokens']
            record['prefix_cache']='hit_observed' if cached is not None and cached>0 else 'not_observed' if cached==0 else 'unknown'
            save_record(record,text,self.owner.key)
            return ModelResult(getattr(raw,'session_id',self.id),'' if violation else text,
                               'policy_violation' if violation else reason,events,notifications,record)
        except BaseException as exc:
            code=('timeout' if self.owner.timed_out else 'cancelled' if self.owner.cancelled or isinstance(exc,KeyboardInterrupt)
                  else 'timeout' if isinstance(exc,TimeoutError) else 'audit_error' if received and isinstance(exc,OSError)
                  else 'transport_error')
            record.update(status=code,error_type=type(exc).__name__,duration_seconds=round(time.monotonic()-started,3))
            try:save_record(record)
            except OSError:pass # do not replace the original operation/model failure
            if isinstance(exc,KeyboardInterrupt):
                self.owner.cancel();raise
            if not isinstance(exc,Exception):raise
            raise HarnessCallError(code,request_id,exc) from None
        finally:
            timer.cancel()
            diagnostics.emit('model.request_end',request_id=request_id,session_id=self.id,
                             status=record['status'],statistics=record.get('statistics'),
                             duration_seconds=round(time.monotonic()-started,3))


def model_call(session,prompt,*,diagnostic_reason=None,**kwargs):
    """Call sites use this seam; only AdapterSession may reach model transport."""
    if not isinstance(session,AdapterSession):
        raise TypeError('Model calls require an adapter-owned session')
    if diagnostic_reason in ('saved_report_format','report_format','json_repair'):
        kwargs.setdefault('recovery_attempt',1)
    return session.run(prompt,diagnostic_reason=diagnostic_reason,**kwargs)
