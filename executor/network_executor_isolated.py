"""Drop-in Network Executor backend for scheduler and MCP.

Planning: calls existing v2 validator only (no network traffic).
Execution: calls root-owned network namespace broker; never falls back to --share-net.

Besides the bounded discovery profiles this wrapper exposes the broker's
capability profiles used by the agents:
  exec      - free argv inside the isolated task namespace
  poc_run   - run an agent-written PoC file (bash/sh/python3/perl)
  research  - fetch CVE/exploit data from the fixed research allowlist
  callback  - open/read/close the scoped callback listener (blind RCE results)
  session   - long-lived interactive process that survives between calls
"""
import argparse
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'executor'))
import network_executor_v2 as existing

BROKER = '/usr/local/sbin/pm-netguard'

# Profiles handled by the broker's capability layer rather than build_command().
CAPABILITY_PROFILES = ('exec', 'poc_run', 'research')
ALL_PROFILES = tuple(sorted(set(existing.PROFILES) | set(CAPABILITY_PROFILES)))
INTERPRETERS = ('bash', 'sh', 'python3', 'perl')
CALLBACK_ACTIONS = ('open', 'read', 'close')
SESSION_ACTIONS = ('open', 'send', 'read', 'interrupt', 'close', 'list')


class BrokerError(RuntimeError):
    pass


def emit(value, failed=False):
    print(json.dumps(value, indent=2, ensure_ascii=False), flush=True)
    if failed:
        raise SystemExit(1)


def parse_argv(raw):
    try:
        value = json.loads(raw)
    except ValueError:
        raise ValueError('--argv-json must be a JSON array of strings')
    if (not isinstance(value, list) or not value
            or not all(isinstance(item, str) for item in value)):
        raise ValueError('--argv-json must be a non-empty JSON array of strings')
    if len(value) > 64 or any(len(item) > 4096 for item in value):
        raise ValueError('argv is too large for the broker')
    if sum(len(item) + 1 for item in value) > 16384:
        raise ValueError('argv is too large for the broker')
    if not value[0].startswith('/'):
        raise ValueError('argv[0] must be an absolute binary path')
    return value


def broker_command(args, target):
    command = ['sudo', '-n', BROKER, 'run', '--task-id', str(args.task_id),
               '--profile', args.profile, '--target', target]
    planned = [args.profile]
    if args.profile == 'exec':
        argv = parse_argv(args.argv_json or '[]')
        for token in argv:
            command.append('--argv=' + token)
        planned = argv
        if args.timeout:
            command += ['--timeout', str(args.timeout)]
    elif args.profile == 'poc_run':
        if not args.poc_file:
            raise ValueError('--poc-file is required for poc_run')
        if args.poc_interp not in INTERPRETERS:
            raise ValueError('Unsupported PoC interpreter')
        allowed = (ROOT / 'storage/pocs' / f'task_{args.task_id}').resolve()
        requested = Path(args.poc_file)
        if not requested.is_absolute():
            requested = (ROOT / requested if requested.parts and requested.parts[0] == 'storage'
                         else allowed / requested)
        poc = requested.resolve()
        if not poc.is_relative_to(allowed):
            raise ValueError('PoC file must belong to this task')
        if not poc.is_file():
            raise ValueError('PoC file does not exist')
        command += ['--poc-file', str(poc), '--poc-interp', args.poc_interp]
        planned = [args.poc_interp, str(poc)]
        if args.timeout:
            command += ['--timeout', str(args.timeout)]
    elif args.profile == 'research':
        if not args.research_host:
            raise ValueError('--research-host is required for research')
        command += ['--research-host', args.research_host, '--path', args.path]
        planned = ['curl', f'https://{args.research_host}{args.path}']
    return command, planned


def parse_session_argv(raw):
    """Interactive session argv; empty means the default shell."""
    if not raw:
        return []
    try:
        value = json.loads(raw)
    except ValueError:
        raise ValueError('--argv-json must be a JSON array of strings')
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ValueError('--argv-json must be a JSON array of strings')
    if len(value) > 64 or any(len(item) > 4096 for item in value):
        raise ValueError('session argv is too large')
    if value and not value[0].startswith('/'):
        raise ValueError('argv[0] must be an absolute binary path')
    return value


def session_command(args):
    if args.action not in SESSION_ACTIONS:
        raise ValueError('Unsupported session action')
    command = ['sudo', '-n', BROKER, 'session', '--action', args.action,
               '--task-id', str(args.task_id)]
    if args.action == 'open':
        for token in parse_session_argv(args.argv_json or '[]'):
            command.append('--argv=' + token)
        if args.idle:
            command += ['--idle', str(args.idle)]
    if args.action in ('send', 'read', 'interrupt', 'close'):
        if not args.session_id:
            raise ValueError('--session-id is required for this action')
        command += ['--session-id', args.session_id]
    if args.action == 'send':
        command += ['--data', args.data or '']
    if args.action in ('send', 'read', 'interrupt') and args.wait is not None:
        command += ['--wait', str(args.wait)]
    return command


def callback_command(args):
    if args.action not in CALLBACK_ACTIONS:
        raise ValueError('Unsupported callback action')
    command = ['sudo', '-n', BROKER, 'callback', '--action', args.action,
               '--task-id', str(args.task_id)]
    if args.port:
        command += ['--port', str(args.port)]
    if args.bind and args.action == 'open':
        command += ['--bind', args.bind]
    if args.timeout and args.action == 'open':
        command += ['--timeout', str(args.timeout)]
    return command


def run_broker(command):
    result = subprocess.run(command, cwd=str(ROOT), stdin=subprocess.DEVNULL,
                            capture_output=True, text=True, errors='replace',
                            timeout=360 if '--profile' in command and
                            command[command.index('--profile') + 1] == 'poc_run' else 260,
                            check=False)
    try:
        payload = json.loads(result.stdout)
    except ValueError:
        raise BrokerError('Privileged broker unavailable: ' +
                          (result.stderr or result.stdout)[-1000:])
    if not isinstance(payload, dict):
        raise BrokerError('Privileged broker returned malformed data')
    return payload, result.returncode


def main():
    p = argparse.ArgumentParser()
    sub = p.add_subparsers(dest='cmd', required=True)
    run = sub.add_parser('run')
    run.add_argument('--task-id', type=int, required=True)
    run.add_argument('--profile', choices=ALL_PROFILES, required=True)
    run.add_argument('--target', required=True)
    run.add_argument('--port', type=int, default=80)
    run.add_argument('--ports', default='80,443')
    run.add_argument('--scheme', choices=('http', 'https'), default='http')
    run.add_argument('--insecure', action='store_true')
    run.add_argument('--path', default='/')
    run.add_argument('--argv-json', default='')
    run.add_argument('--poc-file', default='')
    run.add_argument('--poc-interp', default='bash')
    run.add_argument('--research-host', default='')
    run.add_argument('--timeout', type=int, default=0)
    run.add_argument('--execute', action='store_true')
    cb = sub.add_parser('callback')
    cb.add_argument('--task-id', type=int, required=True)
    cb.add_argument('--action', choices=CALLBACK_ACTIONS, required=True)
    cb.add_argument('--port', type=int, default=0)
    cb.add_argument('--bind', default='')
    cb.add_argument('--timeout', type=int, default=0)
    # Same plan/execute split as `run`: without it the broker is not invoked.
    cb.add_argument('--execute', action='store_true')
    ses = sub.add_parser('session')
    ses.add_argument('--task-id', type=int, required=True)
    ses.add_argument('--action', choices=SESSION_ACTIONS, required=True)
    ses.add_argument('--session-id', default='')
    ses.add_argument('--argv-json', default='')
    ses.add_argument('--data', default='')
    ses.add_argument('--wait', type=float, default=0.8)
    ses.add_argument('--idle', type=int, default=0)
    ses.add_argument('--execute', action='store_true')
    args = p.parse_args()

    try:
        if args.cmd == 'session':
            command = session_command(args)
            if not args.execute:
                emit({'status': 'planned', 'operation': 'network_session',
                      'task_id': args.task_id, 'action': args.action,
                      'argv': command[3:]})
                return
            payload, code = run_broker(command)
            emit(payload, failed=(code != 0))
            return

        if args.cmd == 'callback':
            if not args.execute:
                emit({'status': 'planned', 'operation': 'network_callback',
                      'task_id': args.task_id, 'argv': callback_command(args)})
                return
            payload, code = run_broker(callback_command(args))
            emit(payload, failed=(code != 0))
            return

        # The existing Task Scope still applies and must authorize the target.
        target = existing.legacy.validate_target(args.target)
        existing.validate_execution(target, args.task_id, False)

        if args.profile in CAPABILITY_PROFILES:
            if args.insecure:
                raise ValueError('TLS verification bypass is disabled')
            command, planned = broker_command(args, target)
            if not args.execute:
                emit({'status': 'planned', 'operation': 'network_probe_isolated',
                      'profile': args.profile, 'target': target,
                      'task_id': args.task_id, 'exit_code': None, 'argv': planned})
                return
            payload, code = run_broker(command)
            emit(payload, failed=(code != 0))
            return

        planned_argv = existing.build_command(args.profile, target, args.port,
                                              args.ports, args.scheme, args.insecure)
        if args.insecure:
            raise ValueError('TLS verification bypass is disabled for isolated execution')
        if not args.execute:
            emit({'status': 'planned', 'operation': 'network_probe_isolated',
                  'profile': args.profile, 'target': target,
                  'task_id': args.task_id, 'exit_code': None, 'argv': planned_argv})
            return
        command = ['sudo', '-n', BROKER, 'run', '--task-id', str(args.task_id),
                   '--profile', args.profile, '--target', target, '--port', str(args.port),
                   '--ports', args.ports, '--scheme', args.scheme]
        payload, code = run_broker(command)
        emit(payload, failed=(code != 0 or payload.get('status') != 'completed'))
    except subprocess.TimeoutExpired as exc:
        emit({'status': 'timeout', 'kind': 'timeout',
              'operation': 'network_probe_isolated', 'error': str(exc)}, failed=True)
    except (BrokerError, OSError, subprocess.SubprocessError) as exc:
        emit({'status': 'blocked', 'kind': 'broker',
              'operation': 'network_probe_isolated', 'error': str(exc)}, failed=True)
    except ValueError as exc:
        emit({'status': 'blocked', 'operation': 'network_probe_isolated',
              'task_id': getattr(args, 'task_id', None),
              'profile': getattr(args, 'profile', None),
              'target': getattr(args, 'target', None), 'error': str(exc)}, failed=True)


if __name__ == '__main__':
    main()
