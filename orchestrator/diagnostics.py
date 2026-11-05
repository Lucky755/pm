"""Run-scoped diagnostics. Evidence and execution policy belong to their owners.

Only metadata is recorded. Append locking works across SDK/MCP processes; a
start without an end is intentionally recognizable after SIGKILL or power loss.
"""
from contextlib import contextmanager
from contextvars import ContextVar
from functools import wraps
from pathlib import Path
import fcntl
import inspect
import json
import os
import re
import sqlite3
import subprocess
import sys
import threading
import time
import uuid

EVENT_DIR = Path(__file__).resolve().parents[1] / 'storage/run_events'
_context = ContextVar('pm_diagnostics', default=None)
_action = ContextVar('pm_diagnostic_action', default=None)
_secrets = set()
_relay_runs = set()
ENV_KEYS = ('PM_RUN_ID', 'PM_EVENT_DIR', 'PM_ACTION_ID', 'PM_TASK_ID',
            'PM_ROLE', 'PM_ITERATION', 'PM_EVENT_CONTEXT_FILE')


def register_secret(value):
    if isinstance(value, str) and value:
        _secrets.add(value)


def clean(value, limit=500):
    text = str(value)
    for secret in sorted(_secrets, key=len, reverse=True):
        text = text.replace(secret, '[REDACTED]')
    text = re.sub(r'\x1b\][^\x07]*(?:\x07|\x1b\\)', '', text)
    text = re.sub(r'\x1b\[[0-?]*[ -/]*[@-~]', '', text)
    text = re.sub(r'[\x00-\x1f\x7f-\x9f]', ' ', text)
    text = re.sub(r'(?i)(authorization|cookie|set-cookie)\s*[:=].*', r'\1=[REDACTED]', text)
    text = re.sub(r'(?i)((?:api[_-]?key|password|passwd|secret|token)\s*[=:]\s*)[^\s,;]+',
                  r'\1[REDACTED]', text)
    text = re.sub(r'(https?://)[^/@\s]+:[^/@\s]+@', r'\1[REDACTED]@', text)
    text = re.sub(r'(?i)(--(?:api[-_]?key|password|passwd|secret|token|cookie)(?:=|\s+))[^\s]+',
                  r'\1[REDACTED]', text)
    return text[:limit] if limit is not None else text


def parameters(arguments):
    """Positive allowlist: never print arbitrary command, script, header or body."""
    if isinstance(arguments, str):
        try:
            arguments = json.loads(arguments)
        except ValueError:
            return {}
    if not isinstance(arguments, dict):
        return {}
    result = {}
    for key in ('task_id', 'target', 'port', 'ports', 'profile', 'action', 'timeout',
                'offset', 'limit', 'limit_bytes', 'scheme', 'role', 'iteration', 'plan_id',
                'host', 'hostname', 'path', 'filename', 'poc_file'):
        value = arguments.get(key)
        if isinstance(value, (int, float, bool)) or value is None:
            if key in arguments:
                result[key] = value
        elif isinstance(value, str) and re.fullmatch(r'[\w./,: -]{1,120}', value):
            result[key] = clean(value)
    raw = arguments.get('argv', arguments.get('argv_json'))
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except ValueError:
            raw = None
    if isinstance(raw, (tuple, list)) and raw:
        result['executable'] = clean(Path(str(raw[0])).name)
        result['argc'] = len(raw)
    return result


def context():
    current = _context.get()
    if current is not None:
        return current.copy()
    run_id = os.environ.get('PM_RUN_ID', '')
    if not re.fullmatch(r'[a-f0-9]{32}', run_id):
        return {}
    result = {'run_id': run_id, 'directory': os.environ.get('PM_EVENT_DIR', str(EVENT_DIR)),
              'action_id': os.environ.get('PM_ACTION_ID') or None,
              'task_id': os.environ.get('PM_TASK_ID') or None,
              'role': os.environ.get('PM_ROLE') or None,
              'iteration': os.environ.get('PM_ITERATION') or None}
    for key in ('task_id', 'iteration'):
        if str(result[key]).isdigit():
            result[key] = int(result[key])
    return result


def active():
    return bool(context().get('run_id'))


def child_env():
    ctx = context()
    if not ctx.get('run_id'):
        return {}
    result = {'PM_RUN_ID': ctx['run_id'], 'PM_EVENT_DIR': str(ctx['directory'])}
    for key, field in (('PM_ACTION_ID', 'action_id'), ('PM_TASK_ID', 'task_id'),
                       ('PM_ROLE', 'role'), ('PM_ITERATION', 'iteration')):
        if ctx.get(field) is not None:
            result[key] = str(ctx[field])
    result['PM_EVENT_CONTEXT_FILE'] = str(Path(ctx['directory']) / (ctx['run_id'] + '.context.json'))
    return result


def journal(ctx=None):
    ctx = ctx or context()
    return Path(ctx['directory']) / (ctx['run_id'] + '.jsonl')


def display(event, stream=None):
    fields = ' '.join(f'{key}={clean(event[key])}' for key in
                      ('run_id', 'task_id', 'role', 'iteration', 'status', 'duration_seconds',
                       'exit_code', 'executor_exit_code', 'result_id', 'reason', 'reason_category', 'reason_summary', 'error_type', 'parameters', 'table', 'identifiers',
                       'previous_state', 'current_state', 'input_tokens', 'cache_read_tokens',
                       'output_tokens', 'coordinator_run_id', 'step_id', 'question', 'expected_result',
                       'known_ports','checked_ports','unchecked_ports','reachable_ports',
                       'changed', 'unfinished', 'journal')
                      if event.get(key) is not None)
    try:
        print(f"[EVENT] {event['kind']} {event.get('name', '')} "
              f"action={event.get('action_id', '-')} {fields}".rstrip(),
              file=stream or sys.stderr, flush=True)
    except (OSError, ValueError):
        pass


def warning(exc):
    try:
        print(f'[DIAG-ERROR] event journal unavailable: {type(exc).__name__}', file=sys.stderr, flush=True)
    except (OSError, ValueError):
        pass


def emit(kind, *, console=True, **fields):
    ctx = context()
    if not ctx.get('run_id'):
        return None
    event = {key: ctx.get(key) for key in ('run_id', 'task_id', 'role', 'iteration')}
    event.update(timestamp=time.time(), pid=os.getpid(), event_id=uuid.uuid4().hex,
                 kind=kind, action_id=ctx.get('action_id'))
    event.update(fields)
    # No arbitrary nested data except allowlisted parameters and identifiers.
    def scrub(value):
        if isinstance(value, dict):
            return {clean(k): scrub(v) for k, v in value.items()}
        if isinstance(value, (tuple, list)):
            return [scrub(v) for v in value]
        return clean(value) if isinstance(value, str) else value
    event = scrub(event)
    event['visible'] = console or (event.get('source') == 'mcp' and kind in ('tool.start', 'tool.end'))
    written = False
    try:
        path = journal(ctx)
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            if os.lseek(fd, 0, os.SEEK_END):
                os.lseek(fd, -1, os.SEEK_END)
                if os.read(fd, 1) != b'\n':
                    os.write(fd, b'\n')
            data = (json.dumps(event, ensure_ascii=False) + '\n').encode()
            while data:
                written = os.write(fd, data)
                if written <= 0:
                    raise OSError('short event write')
                data = data[written:]
            written = True
        finally:
            os.close(fd)
    except (OSError, ValueError, TypeError) as exc:
        written = False
        warning(exc)
    if console and (not written or ctx['run_id'] not in _relay_runs):
        display(event)
    return event


def read_events(ctx=None):
    ctx = ctx or context()
    if not ctx.get('run_id'):
        return []
    try:
        lines = journal(ctx).read_text().splitlines()
    except FileNotFoundError:
        return []
    except OSError as exc:
        warning(exc)
        return []
    events = []
    for line in lines:
        try:
            events.append(json.loads(line))
        except ValueError:
            # A torn final append is not an end event.
            continue
    return events


def unfinished(events):
    starts = {e['action_id']: e for e in events if e['kind'].endswith('.start')}
    for event in events:
        if event['kind'].endswith('.end'):
            starts.pop(event['action_id'], None)
    return list(starts.values())


@contextmanager
def scope(**values):
    ctx = context()
    ctx.update(values)
    token = _context.set(ctx)
    try:
        yield ctx
    finally:
        _context.reset(token)


def exception_status(exc):
    if isinstance(exc, SystemExit) and exc.code in (None, 0):
        return 'completed'
    if isinstance(exc, KeyboardInterrupt) or isinstance(exc, SystemExit) and exc.code == 130:
        return 'interrupted'
    if isinstance(exc, (TimeoutError, subprocess.TimeoutExpired)):
        return 'timeout'
    return 'error'


def failure_details(payload=None, exc=None):
    """Classify failure without copying stdout, stderr, commands or environments."""
    payload = payload if isinstance(payload, dict) else {}
    if payload.get('failure_domain') == 'coordinator_decision' and exc is None:
        return {'reason_category':'coordinator_decision',
                'reason_summary':'Coordinator decision validation failed; inspect coordinator.decision_rejected events.'}
    status = payload.get('status')
    text = str(payload.get('error') or payload.get('reason') or payload.get('stderr') or '') if exc is None else str(exc)
    lowered = text.casefold()
    if isinstance(exc, (TimeoutError, subprocess.TimeoutExpired)) or status == 'timeout' or payload.get('kind') == 'timeout':
        category, summary = 'timeout', 'Executor exceeded the configured time limit.'
    elif payload.get('kind') in ('scope', 'scope_denied') or any(token in lowered for token in ('outside authorized scope', 'outside the task scope', 'outside task scope', 'outside scope', 'scope mismatch', 'outside the authorized', 'scope denied', 'за пределами scope')):
        category, summary = 'scope_denied', 'Target is outside the authorized task scope.'
    elif isinstance(exc, FileNotFoundError) or any(token in lowered for token in ('executor unavailable', 'executor not found', 'broker unavailable', 'netguard недоступен', 'no such file', 'исполнитель недоступен')):
        category, summary = 'executor_unavailable', 'Executor is unavailable; check its installation and path.'
    elif isinstance(exc, PermissionError) or '[errno 13]' in lowered:
        category, summary = 'permission_denied', 'Permission to invoke the executor was denied.'
    elif exc is not None and isinstance(exc.__cause__, json.JSONDecodeError):
        category, summary = 'protocol_error', 'Executor returned an invalid JSON response.'
    elif isinstance(exc, KeyboardInterrupt) or isinstance(exc, SystemExit) and exc.code == 130:
        category, summary = 'interrupted', 'Operation interrupted by the operator.'
    elif exc is not None:
        category = 'exception'
        # Timeout/CalledProcessError can embed command arguments. Structured
        # dumps can embed outputs. Preserve the original exception for callers.
        if isinstance(exc, subprocess.SubprocessError) or re.search(r"['\"]?(?:stdout|stderr|argv|env|response_b64)['\"]?\s*[:=]", text, re.I):
            summary = type(exc).__name__ + ': operation failed; diagnostic dump withheld.'
        else:
            summary = type(exc).__name__ + ': ' + clean(text, limit=200)
    elif status == 'blocked':
        category, summary = 'policy_refusal', 'Executor refused the request before execution.'
    elif status == 'nonzero_exit' or payload.get('exit_code') not in (None, 0):
        category, summary = 'nonzero_exit', 'Command returned a nonzero exit code; the check is not confirmed.'
    elif status in ('error', 'failed'):
        category, summary = 'executor_error', 'Executor reported failure; inspect the linked evidence or original operation error.'
    else:
        return {}
    return {'reason_category': category, 'reason_summary': clean(summary, limit=240)}


class Action:
    def __init__(self, kind, name, *, console=True, **fields):
        self.kind, self.name, self.console, self.fields = kind, name, console, fields
        self.id = uuid.uuid4().hex
        self.status = 'completed'

    def __enter__(self):
        self.started = time.monotonic()
        self.parent = context().get('action_id')
        self.manager = scope(action_id=self.id, **{key: self.fields[key] for key in
                             ('task_id', 'role', 'iteration') if key in self.fields})
        self.manager.__enter__()
        self.token = _action.set(self)
        emit(self.kind + '.start', name=self.name, parent_action_id=self.parent,
             console=self.console, **self.fields)
        return self

    def __exit__(self, typ, exc, tb):
        if exc is not None:
            status = exception_status(exc)
            if status == 'interrupted' or self.status not in ('blocked', 'error', 'failed', 'timeout', 'nonzero_exit'):
                self.status = status
            if status != 'completed':
                self.fields['error_type'] = type(exc).__name__
                if status == 'interrupted' or not self.fields.get('reason_category'):
                    self.fields.update(failure_details(exc=exc))
        emit(self.kind + '.end', name=self.name, parent_action_id=self.parent,
             status=self.status, duration_seconds=round(time.monotonic() - self.started, 3),
             console=self.console, **self.fields)
        _action.reset(self.token)
        self.manager.__exit__(typ, exc, tb)


@contextmanager
def run(name, task_id=None, *, fresh=False):
    if active() and not fresh:
        yield None
        return
    run_id = uuid.uuid4().hex
    with scope(run_id=run_id, directory=str(EVENT_DIR), task_id=task_id, action_id=None,role=None,iteration=None):
        outcome = 'completed'
        try:
            with Action('run', name) as action:
                yield action
                outcome = action.status
        except BaseException as exc:
            outcome = exception_status(exc)
            raise
        finally:
            events = read_events()
            pending = unfinished(events)
            for event in pending:
                emit(event['kind'].replace('.start', '.end'), action_id=event['action_id'],
                     name=event.get('name'), status='abandoned', reason=outcome,
                     parent_action_id=event.get('parent_action_id'))
            stops = [e for e in events if e['kind'] == 'run.stop']
            task_ids = sorted({e['task_id'] for e in events if isinstance(e.get('task_id'), int)})
            reason = outcome if outcome != 'completed' else stops[-1]['reason'] if stops else outcome
            if pending and outcome == 'completed':
                outcome, reason = 'incomplete', 'unfinished_actions'
            emit('run.summary', name=name, status=outcome,
                 reason=reason, task_id=task_ids[0] if len(task_ids) == 1 else task_id, task_ids=task_ids,
                 unfinished=[e['action_id'] for e in pending], journal=str(journal()))


@contextmanager
def process_environment():
    """Keep ordinary subprocesses on the current manual operation's run."""
    previous = {key:os.environ.get(key) for key in ENV_KEYS}
    os.environ.update(child_env())
    try:
        yield
    finally:
        for key,value in previous.items():
            if value is None:
                os.environ.pop(key,None)
            else:
                os.environ[key]=value


def entrypoint(function):
    @wraps(function)
    def wrapped(*args, **kwargs):
        name = Path(function.__code__.co_filename).stem
        task_id = None
        argv = sys.argv[1:]
        if name=='pm' and not argv:
            # The menu owns one run per selected operation, not per open UI.
            return function(*args,**kwargs)
        if '--task-id' in argv:
            index = argv.index('--task-id') + 1
            if index < len(argv) and argv[index].isdigit():
                task_id = int(argv[index])
        elif len(argv) > 1 and argv[0] in ('resume', 'attack', 'status', 'change-ip') and argv[1].isdigit():
            task_id = int(argv[1])
        with run(name, task_id) as action:
            # Propagate to ordinary subprocesses, including the planner PTY.
            with process_environment():
                result = function(*args, **kwargs)
                if action and isinstance(result, int) and result != 0:
                    action.status = 'error'
                return result
    return wrapped


def stage(function):
    signature = inspect.signature(function)
    @wraps(function)
    def wrapped(*args, **kwargs):
        if not active():
            return function(*args, **kwargs)
        bound = signature.bind(*args, **kwargs)
        bound.apply_defaults()
        if function.__name__ in ('execute_job', 'run_plan') and isinstance(bound.arguments.get('db'), sqlite3.Connection):
            try:
                row = bound.arguments['db'].execute('SELECT task_id FROM network_phase_plans WHERE id=?',
                                                     (bound.arguments['plan_id'],)).fetchone()
                if row:
                    bound.arguments['task_id'] = row[0]
            except sqlite3.Error:
                pass
        namespace = bound.arguments.get('args')
        if namespace is not None and hasattr(namespace, 'task_id'):
            bound.arguments['task_id'] = namespace.task_id
        with scope(**{key: bound.arguments[key] for key in ('task_id', 'role', 'iteration')
                      if key in bound.arguments}):
            kind = 'tool' if function.__name__ == 'execute_job' else 'stage'
            with Action(kind, function.__name__, parameters=parameters(bound.arguments)) as action:
                result = function(*args, **kwargs)
                if isinstance(result, dict):
                    if result.get('stop_reason'):
                        stop(result['stop_reason'])
                    if result.get('status'):
                        record_result(result)
                    action.status = outcome({'status': result.get('status', 'completed'),
                                             'exit_code': action.fields.get('exit_code')})
                return result
    return wrapped


def tool(function):
    signature = inspect.signature(function)
    @wraps(function)
    def wrapped(*args, **kwargs):
        if not active():
            return function(*args, **kwargs)
        ctx = context()
        # SDK launches MCP once per stage. Read the currently active request
        # parent at dispatch, rather than keeping the first request forever.
        path = os.environ.get('PM_EVENT_CONTEXT_FILE')
        if path:
            try:
                live = json.loads(Path(path).read_text())
                if live.get('run_id') == ctx['run_id']:
                    ctx.update({k: live[k] for k in ('action_id', 'task_id', 'role', 'iteration') if k in live})
            except FileNotFoundError:
                pass
            except (OSError, ValueError) as exc:
                warning(exc)
        bound = signature.bind(*args, **kwargs)
        if 'task_id' in bound.arguments:
            ctx['task_id'] = bound.arguments['task_id']
        with scope(**ctx), Action('tool', function.__name__, console=False,
                                 source='mcp', parameters=parameters(bound.arguments)) as action:
            value = function(*args, **kwargs)
            try:
                payload = json.loads(value) if isinstance(value, str) else value
            except ValueError:
                payload = {}
            if isinstance(payload, dict):
                record_result(payload)
            return value
    return wrapped


def outcome(payload):
    status = str(payload.get('status', 'unknown'))
    if status in ('completed', 'ok', 'success') and payload.get('exit_code') not in (None, 0):
        return 'nonzero_exit'
    return status


def capability_result(record_id, payload, exit_code=None):
    """Attach the evidence reference to the enclosing MCP tool, never its output."""
    action = _action.get()
    if action and action.kind == 'tool':
        action.fields['result_id'] = record_id
        if payload.get('exit_code', exit_code) is not None:
            action.fields['exit_code'] = payload.get('exit_code', exit_code)
    emit('capability.result', console=False, result_id=record_id,
         status=outcome(payload), exit_code=payload.get('exit_code', exit_code), source='mcp')


class Observer:
    def __init__(self):
        self.pending = []
        self.seen = False
        self.request_id = None

    def event(self, notification):
        if getattr(notification, 'method', '') != 'session.event':
            return
        self.seen = True
        event = (getattr(notification, 'payload', None) or {}).get('event') or {}
        self.process(event)

    def process(self, event):
        kind, data = event.get('type'), event.get('data') or {}
        if kind in ('step/start', 'llm/retry-started'):
            if self.request_id:
                emit('model.request.end', action_id=self.request_id, parent_action_id=context().get('action_id'),
                     status='retrying', duration_seconds=round(time.monotonic() - self.request_started, 3))
            if kind == 'llm/retry-started':
                emit('model.retry', reason='sdk_retry_started')
            self.request_id = uuid.uuid4().hex
            self.request_started = time.monotonic()
            emit('model.request.start', action_id=self.request_id, parent_action_id=context().get('action_id'))
        elif kind == 'llm/retry':
            emit('model.retry_scheduled', reason=str((data.get('failure') or {}).get('code') or 'sdk_retry'))
        elif kind in ('assistant/message', 'assistant/attempt'):
            if self.request_id:
                emit('model.request.end', action_id=self.request_id, parent_action_id=context().get('action_id'),
                     status='response_received' if kind == 'assistant/message' else 'attempt_failed',
                     duration_seconds=round(time.monotonic() - self.request_started, 3))
                self.request_id = None
            usage = data.get('usage') or {}
            emit('model.usage', input_tokens=usage.get('inputTokens', 0),
                 cache_read_tokens=usage.get('cacheReadTokens', 0), output_tokens=usage.get('outputTokens', 0))
        elif kind == 'tool/call':
            name = data.get('name', 'tool').split('__')[-1]
            dispatch_id = uuid.uuid4().hex
            emit('dispatch.start', console=False, name=name, action_id=dispatch_id,
                 parent_action_id=context().get('action_id'))
            self.pending.append((name, parameters(data.get('arguments')), time.monotonic(), dispatch_id))
        elif kind == 'tool/result' and self.pending:
            name, params, started, dispatch_id = self.pending.pop(0)
            emit('dispatch.end', console=False, name=name, action_id=dispatch_id,
                 parent_action_id=context().get('action_id'), status='returned',
                 duration_seconds=round(time.monotonic() - started, 3))
            # MCP owns dispatched tools; SDK only owns pre-dispatch refusals.
            matches = [e for e in read_events() if e['kind'] == 'tool.start'
                       and e.get('parent_action_id') == context().get('action_id')
                       and e.get('name') == name and e['action_id'] not in getattr(self, 'consumed', set())]
            if matches:
                self.consumed = getattr(self, 'consumed', set()) | {matches[0]['action_id']}
                return
            message = data.get('message') or {}
            payload = {}
            try:
                payload = json.loads(''.join(b.get('text', '') for b in message.get('content', []) if isinstance(b, dict)))
            except (ValueError, TypeError):
                pass
            with Action('tool', name, source='sdk', parameters=params) as action:
                action.started = started
                action.status = outcome(payload) if isinstance(payload, dict) and payload.get('status') else 'dispatch_error'
                if isinstance(payload, dict):
                    record_result(payload)


@contextmanager
def relay():
    """Render MCP events while a synchronous SDK request is in progress."""
    ctx = context()
    if ctx['run_id'] in _relay_runs:
        yield
        return
    _relay_runs.add(ctx['run_id'])
    seen = {e['event_id'] for e in read_events(ctx)}
    stop = threading.Event()
    def poll():
        while True:
            for event in read_events(ctx):
                if event['event_id'] not in seen:
                    seen.add(event['event_id'])
                    if event.get('visible'):
                        display(event)
            if stop.wait(0.1):
                break
    thread = threading.Thread(target=poll, daemon=True)
    try:
        thread.start()
    except RuntimeError as exc:
        _relay_runs.discard(ctx['run_id'])
        warning(exc)
        yield
        return
    try:
        yield
    finally:
        stop.set()
        thread.join()
        for event in read_events(ctx):
            if event['event_id'] not in seen and event.get('visible'):
                display(event)
        _relay_runs.discard(ctx['run_id'])


def model_call(session, prompt, *, diagnostic_reason=None, **kwargs):
    if not active():
        return session.run(prompt, **kwargs)
    if diagnostic_reason == 'json_repair':
        emit('model.retry', reason=diagnostic_reason)
    with Action('model', 'turn', reason=diagnostic_reason) as action:
        if '\nCompact history (full outputs stay stored by result_id):' in prompt:
            emit('context.switch', reason='request_uses_compact_history', representation='compact')
        # The environment handed to an already running MCP process is immutable.
        path = os.environ.get('PM_EVENT_CONTEXT_FILE') or child_env()['PM_EVENT_CONTEXT_FILE']
        try:
            Path(path).parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            temp = Path(path + '.tmp')
            temp.write_text(json.dumps(context()))
            temp.chmod(0o600)
            os.replace(temp, path)
        except OSError as exc:
            warning(exc)
        observer = Observer()
        callback = kwargs.pop('on_notification', None)
        def notify(event):
            try:
                observer.event(event)
            except Exception as exc:
                warning(exc)
            if callback:
                callback(event)
        with relay():
            result = session.run(prompt, on_notification=notify, **kwargs)
        if not observer.seen:
            for event in getattr(result, 'events', None) or []:
                if isinstance(event, dict):
                    try:
                        observer.process(event)
                    except Exception as exc:
                        warning(exc)
        if observer.request_id:
            emit('model.request.end', action_id=observer.request_id, parent_action_id=action.id,
                 status=str(getattr(result, 'finish_reason', 'unknown')),
                 duration_seconds=round(time.monotonic() - observer.request_started, 3))
        action.status = str(getattr(result, 'finish_reason', 'unknown'))
        return result


def stop(reason, **fields):
    emit('run.stop', reason=reason, **fields)


def state_snapshot(db, task_id):
    result = {}
    for table in ('pm_hypotheses', 'pm_access_state', 'pm_access_triage', 'pm_assets', 'pm_objectives', 'pm_verified_flags'):
        try:
            cursor = db.execute(f'SELECT * FROM {table} WHERE task_id=?', (task_id,))
            columns = [item[0] for item in cursor.description]
            info = list(db.execute(f'PRAGMA table_info({table})'))
            keys = [row[1] for row in info if row[5]]
            result[table] = (keys, [dict(zip(columns, row)) for row in cursor])
        except sqlite3.Error:
            pass
        except (AttributeError, TypeError) as exc:
            warning(exc)
    return result


def state_diff(before, after, task_id):
    import hashlib
    for table, (keys, rows) in after.items():
        sensitive = ('claim_key', 'value') + (('key',) if table == 'pm_assets' else ())
        previous = {tuple(row.get(key) for key in keys): row for row in before.get(table, ([], []))[1]}
        for row in rows:
            pk = tuple(row.get(key) for key in keys)
            old = previous.get(pk)
            if row == old:
                continue
            identifiers = {key: row[key] for key in keys if key not in sensitive}
            for key in sensitive:
                if key in keys:
                    identifiers[key + '_sha256'] = hashlib.sha256(str(row[key]).encode()).hexdigest()
            emit('state.change', task_id=task_id, table=table, identifiers=identifiers,
                 result_id=(row.get('probe_result_id') or row.get('access_result_id') or row.get('result_id')
                            or row.get('last_probe_result_id') or row.get('evidence_ref')),
                 change='insert' if old is None else 'update',
                 changed_fields=[key for key in row if old is None or old.get(key) != row[key]],
                 previous_state={key: old[key] for key in ('status', 'level', 'signal', 'triage_done') if old and key in old},
                 current_state={key: row[key] for key in ('status', 'level', 'signal', 'triage_done') if key in row})
        retained = {tuple(row.get(key) for key in keys) for row in rows}
        for pk, row in previous.items():
            if pk not in retained:
                emit('state.change', task_id=task_id, table=table, change='delete',
                     identifiers={key: (hashlib.sha256(str(row[key]).encode()).hexdigest()
                                        if key in sensitive else row[key]) for key in keys})


def execution_exit(code):
    action = _action.get()
    if action and action.kind == 'tool':
        action.fields['exit_code'] = code



def committed_changes(function):
    signature = inspect.signature(function)
    @wraps(function)
    def wrapped(*args, **kwargs):
        if not active():
            return function(*args, **kwargs)
        arguments = signature.bind(*args, **kwargs).arguments
        db, task_id = arguments['db'], arguments['task_id']
        before = state_snapshot(db, task_id)
        result = function(*args, **kwargs)
        if not db.in_transaction:
            state_diff(before, state_snapshot(db, task_id), task_id)
        return result
    return wrapped


def record_result(payload, returncode=None):
    """Attach metadata to the current action, preserving the actual return value."""
    action = _action.get()
    if not action or not isinstance(payload, dict):
        return
    for key in ('exit_code', 'result_id'):
        if key in payload:
            action.fields[key] = payload[key]
    if returncode is not None:
        action.fields['executor_exit_code'] = returncode
        action.fields.setdefault('exit_code', returncode)
    effective = {**payload, 'exit_code': action.fields.get('exit_code')}
    action.status = outcome(effective)
    if returncode not in (None, 0) and action.status in ('completed', 'ok', 'success', 'planned', 'already_completed'):
        action.status = 'nonzero_exit'
    action.fields.update(failure_details({**effective, 'status': action.status}))


def command_parameters(command):
    values = {}
    for index, item in enumerate(command[:-1]):
        if item in ('--task-id', '--target', '--profile', '--port', '--ports', '--scheme'):
            key = item[2:].replace('-', '_')
            values[key] = command[index + 1]
    if str(values.get('task_id', '')).isdigit():
        values['task_id'] = int(values['task_id'])
    return parameters(values)


def _record_return(value):
    if isinstance(value, dict):
        record_result(value)
    elif isinstance(value, tuple) and len(value) == 2:
        if isinstance(value[0], dict):
            record_result(value[0], value[1])
        elif isinstance(value[1], dict):
            record_result(value[1], value[0])


def call(name, function, *args, task_id=None, parameters=None, **kwargs):
    if not active():
        return function(*args, **kwargs)
    with Action('tool', name, task_id=task_id, parameters=parameters or {}):
        value = function(*args, **kwargs)
        _record_return(value)
        return value


def operation(function):
    """One action around one executor request, including parsing/validation."""
    signature = inspect.signature(function)
    @wraps(function)
    def wrapped(*args, **kwargs):
        if not active():
            return function(*args, **kwargs)
        bound = signature.bind(*args, **kwargs)
        bound.apply_defaults()
        values = parameters(bound.arguments)
        if isinstance(bound.arguments.get('command'), (list, tuple)):
            values.update(command_parameters(bound.arguments['command']))
        with Action('tool', function.__name__, task_id=values.get('task_id', context().get('task_id')),
                    parameters=values):
            value = function(*args, **kwargs)
            _record_return(value)
            return value
    return wrapped
