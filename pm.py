#!/usr/bin/env python3
"""Pentest Master operator CLI: one manual command, per-task NetGuard, human output.

No privileged code is imported from this file into the root-owned broker.
No automatic background execution. Never bypasses approval or isolated executor.
"""
from __future__ import annotations

import argparse
import base64
import binascii
import fcntl
import getpass
import hashlib
import ipaddress
import json
import os
import pty
import re
import shutil
import stat
import select
import sqlite3
import subprocess
import sys
import tempfile
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
PYTHON = ROOT / '.venv/bin/python'
BROKER = '/usr/local/sbin/pm-netguard'
DB = ROOT / 'storage/tasks.db'
DOC_NETS = [ipaddress.ip_network(x) for x in (
    '192.0.2.0/24', '198.51.100.0/24', '203.0.113.0/24')]
PORTS_MAX = 32
MAX_HOSTNAMES = 12
TRANSITION_MAX_BYTES = 256 * 1024
from intent_limits import INTENT_MAX, HINTS_MAX
from orchestrator import diagnostics, planner_protocol

from operator_errors import OperatorError


class PlannerValidationError(OperatorError):
    """The planner returned a parsed plan that failed local validation."""


# One terminal-native color scheme: phosphor green / emergency red / graphite.
# No HTML, no emoji, no terminal font dependencies, and NO_COLOR support.
PALETTE = {
    'brand': '1;38;5;118',    # phosphor lime (logo/primary controls)
    'accent': '1;38;5;255',   # high-contrast terminal white
    'success': '1;38;5;82',  # terminal green (verified events)
    'warning': '1;38;5;214', # amber (incomplete/warnings)
    'danger': '1;38;5;196',  # red only for errors
    'muted': '38;5;244',     # subdued slate
    'bright': '1;38;5;255', # white headings
}


def color_enabled(stream=None):
    stream = sys.stdout if stream is None else stream
    return (os.environ.get('NO_COLOR') is None and
            os.environ.get('TERM', '') != 'dumb' and
            bool(getattr(stream, 'isatty', lambda: False)()))


def tint(value, tone='brand', *, stream=None):
    value = str(value)
    if not color_enabled(stream) or tone not in PALETTE:
        return value
    return f"\033[{PALETTE[tone]}m{value}\033[0m"


def safe_display(value):
    """Strip ANSI and C0/C1 controls from untrusted remote/model output."""
    clean = re.sub(r'\x1b\[[0-?]*[ -/]*[@-~]', '', diagnostics.clean(value, limit=None))
    return re.sub(r'[\x00-\x1f\x7f-\x9f]', ' ', clean)


LOGO = (
    r'  ____  _____ _   _ _____ _____ ____ _____',
    r' |  _ \| ____| \ | |_   _| ____/ ___|_   _|',
    r' | |_) |  _| |  \| | | | |  _| \___ \ | |',
    r' |  __/| |___| |\  | | | | |___ ___) || |',
    r' |_|   |_____|_| \_| |_| |_____|____/ |_|',
)


def banner():
    """CLI logo, not a graphic card. Works without colors or a special font."""
    cols = shutil.get_terminal_size(fallback=(80, 24)).columns
    line('')
    if cols >= 51:
        for segment in LOGO:
            line(tint(segment, 'brand'))
        line(' ' * 14 + tint('M A S T E R', 'bright') +
             tint('   //  PENTEST MASTER' , 'muted'))
    else:
        line(tint(' [ PENTEST // MASTER ]', 'brand'))
    line(' ' + tint('─' * min(max(cols - 2, 20), 68), 'muted'))
    line('  ' + tint('[+]', 'success') + ' Ручной запуск' +
         '    ' + tint('[#]', 'brand') + ' Scope: изолирован' +
         '    ' + tint('[*]', 'accent') + ' NetGuard')
    line('  ' + tint('SESSION', 'muted') + '  Работа только по команде оператора')


def line(text='', *, stream=None):
    print(text, file=stream if stream is not None else sys.stdout, flush=True)


def heading(name):
    line('')
    line(' ' + tint('[::]', 'brand') + ' ' + tint(safe_display(name).upper(), 'bright'))
    line(' ' + tint('─' * min(max(22, len(name) + 12), 68), 'muted'))


def validate_target(raw):
    try:
        ip = ipaddress.IPv4Address(raw)
    except ipaddress.AddressValueError as exc:
        raise OperatorError('Нужен один IPv4-адрес цели, не домен и не подсеть') from exc
    if (ip.is_loopback or ip.is_multicast or ip.is_unspecified or
            any(ip in net for net in DOC_NETS)):
        raise OperatorError('Этот адрес нельзя использовать как живую цель')
    return str(ip)


def connect():
    if not DB.is_file():
        raise OperatorError(f'Не найдена база задач: {DB}')
    db = sqlite3.connect(DB, timeout=10)
    db.execute('PRAGMA busy_timeout=5000')
    db.execute('''CREATE TABLE IF NOT EXISTS pm_task_hostnames (
        task_id INTEGER PRIMARY KEY,
        hostnames_json TEXT NOT NULL
    )''')
    db.execute('''CREATE TABLE IF NOT EXISTS pm_operator_approvals (
        task_id INTEGER PRIMARY KEY,
        target TEXT NOT NULL,
        allowed TEXT NOT NULL,
        egress TEXT NOT NULL,
        approved_at TEXT NOT NULL,
        closed_at TEXT
    )''')
    db.execute('''CREATE TABLE IF NOT EXISTS pm_task_intents (
        task_id INTEGER PRIMARY KEY,
        intent TEXT NOT NULL,
        created_at TEXT NOT NULL
    )''')
    db.execute('''CREATE TABLE IF NOT EXISTS pm_task_lineage (
        previous_task_id INTEGER NOT NULL UNIQUE,
        successor_task_id INTEGER NOT NULL UNIQUE,
        previous_target TEXT NOT NULL,
        successor_target TEXT NOT NULL,
        changed_at TEXT NOT NULL,
        transfer_enabled INTEGER NOT NULL DEFAULT 0,
        transfer_state TEXT NOT NULL DEFAULT 'pending'
    )''')
    lineage_columns = {row[1] for row in db.execute('PRAGMA table_info(pm_task_lineage)')}
    if 'transfer_enabled' not in lineage_columns:
        db.execute('ALTER TABLE pm_task_lineage ADD COLUMN transfer_enabled INTEGER NOT NULL DEFAULT 0')
    if 'transfer_state' not in lineage_columns:
        db.execute("ALTER TABLE pm_task_lineage ADD COLUMN transfer_state TEXT NOT NULL DEFAULT 'pending'")
        # Rows created before durable transitions have already finished.
        db.execute("UPDATE pm_task_lineage SET transfer_state='done'")
    db.execute('''CREATE TABLE IF NOT EXISTS pm_tcp_full_scans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        task_id INTEGER NOT NULL,
        target TEXT NOT NULL,
        status TEXT NOT NULL,
        open_ports_json TEXT NOT NULL DEFAULT '[]',
        error TEXT,
        created_at TEXT NOT NULL,
        UNIQUE(task_id,target)
    )''')
    scan_columns = {row[1] for row in db.execute('PRAGMA table_info(pm_tcp_full_scans)')}
    if 'last_seen_at' not in scan_columns:
        db.execute('ALTER TABLE pm_tcp_full_scans ADD COLUMN last_seen_at TEXT')
    db.execute('''CREATE TABLE IF NOT EXISTS pm_tcp_full_scan_attempts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        task_id INTEGER NOT NULL,
        target TEXT NOT NULL,
        status TEXT NOT NULL,
        error TEXT,
        created_at TEXT NOT NULL
    )''')
    db.commit()
    return db


def task_target(db, task_id):
    row = db.execute('SELECT target FROM tasks WHERE id=?', (task_id,)).fetchone()
    if not row:
        raise OperatorError(f'Задача #{task_id} не найдена')
    return validate_target(row[0])


def ensure_task_scope(db, task_id, target, *, create=False):
    try:
        row = db.execute('SELECT initial_target FROM task_scope_settings WHERE task_id=?',
                         (task_id,)).fetchone()
    except sqlite3.OperationalError:
        row = None
    if row is None and create:
        command = [str(PYTHON), str(ROOT / 'executor/task_scope.py'),
                   'init', '--task-id', str(task_id)]
        proc = subprocess.run(command, cwd=ROOT, capture_output=True, text=True,
                              stdin=subprocess.DEVNULL, timeout=30)
        if proc.returncode:
            raise OperatorError('Ошибка инициализации Task Scope: ' + (proc.stderr or proc.stdout)[-700:])
        row = db.execute('SELECT initial_target FROM task_scope_settings WHERE task_id=?',
                         (task_id,)).fetchone()
    if not row or row[0] != target:
        raise OperatorError('Task Scope отсутствует или не совпадает с IP задачи. Выполнение запрещено.')
    # Independent application-level permission validation, before any root operation.
    from executor.task_scope import check_action
    check = check_action(db, task_id, 'connect', target)
    if check.get('decision') != 'ALLOW':
        raise OperatorError('Task Scope запретил подключение к этой цели')


def get_egress(target):
    proc = subprocess.run(['/usr/sbin/ip', '-4', 'route', 'get', target],
                          capture_output=True, text=True, timeout=8)
    if proc.returncode:
        raise OperatorError('Нет маршрута к цели: ' + proc.stderr[-300:])
    matched = re.search(r'\bdev\s+([A-Za-z0-9_.-]{1,15})\b', proc.stdout)
    if not matched:
        raise OperatorError('Не удалось определить сетевой интерфейс')
    return matched.group(1)


def ask_approval(db, task_id, target, egress, *, show=True, auto=False):
    requested = target + '/32'
    row = db.execute('SELECT target, allowed, egress, closed_at FROM pm_operator_approvals WHERE task_id=?',
                     (task_id,)).fetchone()
    if row and row == (target, requested, egress, None):
        return False
    if row and row[3] is not None:
        raise OperatorError('Задача закрыта; повторная активация запрещена без новой задачи')
    if row and row[:3] != (target, requested, egress):
        raise OperatorError('IP/Scope/интерфейс изменились после подтверждения. Нужна новая задача.')
    if show:
        heading('Подтверждение разрешённой области')
        line(f'  Задача:       #{task_id}')
        line(f'  Цель:         {target}')
        line(f'  Разрешённый:  {requested}')
        line(f'  Выход:        {egress}')
        line('  Доступно:     ограниченные профили сетевой разведки')
        line('  Эксплуатация и повышение привилегий требуют отдельного подтверждения.')
    if auto:
        # Only called from the explicit NEW task workflow, after the operator
        # supplied the exact IPv4 target and the independently checked route.
        line('  ✓ Scope принят из новой задачи; отдельный ввод IP не требуется.')
    else:
        answer = input(f'Для подтверждения разрешения на проверку введите IP {target}: ').strip()
        if answer != target:
            raise OperatorError('Подтверждение не получено. Никакого сетевого выполнения.')
    with db:
        db.execute('''INSERT INTO pm_operator_approvals
            (task_id,target,allowed,egress,approved_at,closed_at) VALUES (?,?,?,?,?,NULL)''',
            (task_id, target, requested, egress, datetime.now(timezone.utc).isoformat()))
    return True


def sudo_checked(args, *, root=False, timeout=30, allow_error=False):
    argv = ['sudo', '-n', BROKER, *args]
    proc = subprocess.run(argv, env={**os.environ, **diagnostics.child_env()},
                          stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=timeout)
    try:
        obj = json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        raise OperatorError('NetGuard недоступен. Выполни sudo -v и повтори. ' +
                            (proc.stderr or proc.stdout)[-300:]) from exc
    if not isinstance(obj, dict):
        raise OperatorError('Некорректный ответ NetGuard')
    if not allow_error and (proc.returncode or obj.get('status') == 'blocked'):
        raise OperatorError('NetGuard отказал: ' + str(obj.get('error', proc.stderr)))
    return obj, proc.returncode


def sudo_authenticate():
    # Only once per explicitly approved task operation; never install sudoers.
    status = subprocess.run(['sudo', '-n', 'true'], capture_output=True,
                            stdin=subprocess.DEVNULL, timeout=5)
    if status.returncode:
        line('Для создания сетевой изоляции нужен sudo:')
        result = subprocess.run(['sudo', '-v'], timeout=45)
        if result.returncode:
            raise OperatorError('Права sudo не подтверждены')


def broker_is_callable():
    """True when the installed sudoers rule lets us call the broker unaided.

    The NOPASSWD entry covers pm-netguard only, so demanding a general sudo
    session (sudo -v) fails without a terminal even though teardown would work.
    """
    try:
        proc = subprocess.run(['sudo', '-n', BROKER, 'capabilities'],
                              capture_output=True, text=True,
                              stdin=subprocess.DEVNULL, timeout=20)
    except (OSError, subprocess.SubprocessError):
        return False
    return proc.returncode == 0


def broker_is_trusted():
    p = Path(BROKER)
    st = p.stat()
    if st.st_uid != 0 or st.st_mode & 0o022 or not p.is_file() or p.is_symlink():
        raise OperatorError('Привилегированный NetGuard должен быть root-owned и не writable группой/остальными')


def ensure_netguard(task_id, target, egress):
    broker_is_trusted()
    sudo_authenticate()
    existing, rc = sudo_checked(['status', '--task-id', str(task_id)], allow_error=True)
    if rc == 0 and existing.get('status') == 'configured':
        if (existing.get('allowed') != [target + '/32'] or
                existing.get('approved_egress', existing.get('egress')) != egress):
            raise OperatorError('Существующий NetGuard не соответствует подтверждённому scope')
        line(f'  ✓ NetGuard pmns{task_id}: уже настроен, правила не дублируются')
    else:
        # Only missing config may trigger setup. Other errors fail closed.
        error = str(existing.get('error', '')).lower()
        if 'not configured' not in error and 'not found' not in error:
            raise OperatorError('Невозможно проверить NetGuard: ' + str(existing.get('error')))
        result, _ = sudo_checked(['setup', '--task-id', str(task_id),
                                  '--owner', getpass.getuser(), '--allow', target + '/32',
                                  '--egress', egress], timeout=45)
        if result.get('status') != 'configured':
            raise OperatorError('Настройка NetGuard не подтверждена')
        line(f'  ✓ NetGuard pmns{task_id}: создан')
    state, _ = sudo_checked(['status', '--task-id', str(task_id)])
    if (state.get('allowed') != [target + '/32'] or
            state.get('approved_egress', state.get('egress')) != egress or
            not state.get('docker_forward_managed', False) and docker_forward_drop()):
        raise OperatorError('NetGuard не подтвердил изоляцию/DOCKER-USER; запуск отменён')
    # Do not auto-run sync-forward: root broker v2 setup must be atomic.
    line(f'  ✓ Сетевой выход: {egress}, только {target}/32')


def docker_forward_drop():
    proc = subprocess.run(['/usr/sbin/iptables', '-S', 'FORWARD'],
                          stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                          text=True, timeout=5)
    if proc.returncode:
        raise OperatorError('Не удалось проверить политику FORWARD')
    return '-P FORWARD DROP' in proc.stdout.splitlines()


def validate_hostnames(raw):
    if raw is None or not raw.strip():
        return []
    names = [x.strip().lower().rstrip('.') for x in raw.split(',')]
    if not 1 <= len(names) <= MAX_HOSTNAMES or len(set(names)) != len(names):
        raise OperatorError('Укажи 1–12 уникальных доменных имён')
    for name in names:
        labels = name.split('.')
        if (len(name) > 253 or name in ('localhost', 'localhost.localdomain') or
            not all(1 <= len(label) <= 63 and
                    re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', label)
                    for label in labels) or name.replace('.', '').isdigit()):
            raise OperatorError('Недопустимое имя хоста: ' + repr(name))
    return names


def configure_hostnames(db, task_id, target, raw):
    row = db.execute('SELECT hostnames_json FROM pm_task_hostnames WHERE task_id=?',
                     (task_id,)).fetchone()
    known = json.loads(row[0]) if row else []
    requested = validate_hostnames(raw) if raw is not None else known
    if not requested:
        return
    # Trusted broker checks the owner and the root-owned approved /32 again.
    response, _ = sudo_checked(['hosts', '--task-id', str(task_id),
                                *[arg for name in requested for arg in ('--hostname', name)]],
                               timeout=25)
    if response.get('status') != 'hosts_ready' or response.get('destination') != target:
        raise OperatorError('NetGuard не подтвердил изолированную привязку имён')
    with db:
        db.execute("INSERT INTO pm_task_hostnames(task_id,hostnames_json) VALUES (?,?) ON CONFLICT(task_id) DO UPDATE SET hostnames_json=excluded.hostnames_json",
                   (task_id, json.dumps(requested)))
    line('  ✓ Имена только внутри namespace: ' + ', '.join(requested) + ' → ' + target)


def read_planner_stream(process, api_key=None):
    """Consume planner's PTY: show prompts/progress, hide raw JSON, retain proposal.

    Child STDIN remains attached to the terminal. The caller-provided key is
    passed via a one-time inherited FD, never via argv, file or environment value.
    Only child's stdout/stderr are captured.
    """
    master, slave = pty.openpty()
    read_fd = None
    popen_options = {'env': {**os.environ, **diagnostics.child_env()}}
    if api_key is not None:
        secret = api_key.encode('utf-8')
        if not secret or len(secret) > 4096:
            raise OperatorError('Некорректная длина API-ключа')
        read_fd, write_fd = os.pipe()
        try:
            os.write(write_fd, secret)
        finally:
            os.close(write_fd)
        environment = {**os.environ, **diagnostics.child_env()}
        environment['PM_SESSION_KEY_FD'] = str(read_fd)
        popen_options = {'pass_fds': (read_fd,), 'env': environment}
        expected_planner = ROOT / 'orchestrator/planner.py'
        if len(process) < 2 or Path(process[1]).resolve() != expected_planner.resolve():
            raise OperatorError('Key descriptor can only be passed to the local Planner')
        process = [process[0], str(ROOT / 'runtime/planner_entry.py'), *process[1:]]
    try:
        child = subprocess.Popen(process, cwd=str(ROOT), stdin=None, stdout=slave,
                                 stderr=slave, close_fds=True, **popen_options)
    finally:
        if read_fd is not None:
            os.close(read_fd)
        os.close(slave)
    chunks = []
    pending = ''
    suppress = False
    try:
        while True:
            try:
                ready, _, _ = select.select([master], [], [], 0.2)
                if not ready:
                    if child.poll() is not None:
                        # Still wait for PTY EOF; normal process exits close the slave.
                        continue
                    continue
                data = os.read(master, 8192)
            except OSError:
                break
            if not data:
                break
            text = data.decode('utf-8', errors='replace')
            chunks.append(text)
            pending += text
            while '\n' in pending:
                part, pending = pending.split('\n', 1)
                part = part.rstrip('\r')
                if part.startswith(planner_protocol.RESULT_PREFIX):
                    continue
                if part.lstrip().startswith(('[EVENT]', '[DIAG-ERROR]')):
                    line('  ' + safe_display(part))
                    continue
                if part.startswith('PM_PLAN_VALIDATION_ERROR:'):
                    continue
                if part.lstrip().startswith('{'):
                    suppress = True
                if not suppress and part.strip():
                    line('  ' + part)
            # Show prompt without newline (planner may call input()).
            if not suppress and pending.endswith((': ', '? ')) and len(pending) < 250:
                line('  ' + pending, stream=sys.stderr)
                pending = ''
        return_code = child.wait(timeout=10)
    finally:
        os.close(master)
        if child.poll() is None:
            child.kill()
            child.wait()
    raw = ''.join(chunks)
    if return_code:
        if re.search(r'(?m)^PM_PLAN_VALIDATION_ERROR:', raw.replace('\r', '')):
            raise PlannerValidationError('Planner завершился с ошибкой; задачу не запускаем')
        raise OperatorError('Planner завершился с ошибкой; задачу не запускаем')
    ids = re.findall(r'(?m)^Task ID:\s*(\d+)\s*$', raw.replace('\r', ''))
    if len(ids) != 1:
        raise OperatorError('Planner не сообщил однозначный Task ID')
    try:
        plan = planner_protocol.decode_result(raw.replace('\r', ''), int(ids[0]))
    except ValueError as exc:
        raise OperatorError('Невозможно проверить план GLM; автоматический запуск запрещён') from exc
    return int(ids[0]), plan


def run_planner_with_validation_retry(target, task_text, key, context=None):
    command = [str(PYTHON), str(ROOT / 'orchestrator/planner.py'),
               '--target', target, '--task', task_text]
    context_path = None
    if context:
        descriptor, context_path = tempfile.mkstemp(prefix='.planner-context-',
                                                  suffix='.json', dir=ROOT / 'storage')
        try:
            os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, 'w', encoding='utf-8') as handle:
                json.dump(context, handle, ensure_ascii=False)
                handle.flush()
                os.fsync(handle.fileno())
            command += ['--context-file', context_path]
        except BaseException:
            Path(context_path).unlink(missing_ok=True)
            raise
    try:
        for attempt in range(2):
            try:
                return read_planner_stream(command, api_key=key)
            except PlannerValidationError as exc:
                if attempt:
                    raise OperatorError(str(exc)) from exc
                line('  [!] План не прошёл проверку; повторяю запрос планировщику один раз.')
    finally:
        if context_path:
            Path(context_path).unlink(missing_ok=True)


def planner_context_from_task(db, task_id):
    """Compact old-address hints, separate from the authorized target field."""
    from orchestrator import fact_state
    fact_state.import_capability_assets(
        db, task_id, ROOT / 'storage/capability_log' / f'task_{task_id}.jsonl')
    fact_state.import_legacy_reports(db, task_id)
    def clean(value):
        text = re.sub(r'\b[A-Z][A-Z0-9_]{1,19}\{[^}]{3,120}\}',
                      '[значение скрыто]', str(value or ''))
        return safe_display(text)[:180]
    closed = [dict(kind=item['kind'], key=clean(item['key']),
                   evidence=clean(item['evidence_quote']),
                   origin_task_id=item['origin_task_id'])
              for item in fact_state.list_assets(db, task_id, statuses=('dead',), limit=30)]
    opened = [dict(claim=clean(item['claim']), cost=item['cost'])
              for item in fact_state.list_hypotheses(db, task_id, status='untested', limit=10)]
    # The previous address is deliberately absent: any literal in this context
    # can be copied into a plan step, and a plan may name only the new target.
    return {'closed': closed, 'open': opened, 'prior_task_id': task_id,
            'address_note': ('Адрес машины изменился. Ключи активов ниже относятся '
                             'к authorized_target; иных адресов в плане быть не должно.'),
            'current_result_ids': []}


def show_plan(task_id, plan):
    heading(f'План задачи #{task_id}')
    summary = plan.get('summary')
    if isinstance(summary, str):
        line('  ' + safe_display(summary.strip()[:350]))
    for index, item in enumerate(plan['tasks'], 1):
        agent = str(item.get('agent', 'agent')).upper()
        description = ' '.join(str(item.get('instruction', '')).split())
        skipped = ' [пропущен: закрытый актив]' if item.get('status') == 'skipped' else ''
        line('  ' + tint(f'{index:>2}.', 'accent') + f' [{safe_display(agent)}] '
             f'{safe_display(description[:180])}{skipped}')
    checkpoints = plan.get('checkpoints') or []
    if checkpoints:
        line(f'  Контрольных точек: {len(checkpoints)}')
    line('  План GLM — предложение, не разрешение на эксплуатацию.')


def plan_reprobe(db, task_id, target, ports_raw):
    if not ports_raw:
        return None
    values = ports_raw.split(',')
    if not 1 <= len(values) <= PORTS_MAX or any(not re.fullmatch(r'\d{1,5}', x) for x in values):
        raise OperatorError('Для --reprobe укажи 1..32 порта через запятую')
    ports = [int(v) for v in values]
    if len(set(ports)) != len(ports) or any(not 1 <= p <= 65535 for p in ports):
        raise OperatorError('Недопустимые/повторяющиеся порты')
    from orchestrator import bootstrap_discovery
    port_string = ','.join(map(str, ports))
    argv = bootstrap_discovery.validate_plan(task_id, target, port_string)
    params = json.dumps({'ports': port_string}, sort_keys=True)
    existing = db.execute('''SELECT id FROM network_phase_plans
        WHERE task_id=? AND profile='tcp_ports' AND target=? AND parameters_json=?''',
                          (task_id, target, params)).fetchone()
    if existing:
        if db.execute('SELECT 1 FROM network_job_runs WHERE plan_id=? LIMIT 1', existing).fetchone():
            raise OperatorError('Этот точный набор портов уже проверен; повтор не создаётся автоматически')
        return existing[0]
    with db:
        new_id = db.execute('''INSERT INTO network_phase_plans
            (task_id,goal,profile,target,parameters_json,argv_json,model_summary,status,created_at)
            VALUES (?,?,'tcp_ports',?,?,?,?,'planned',?)''',
            (task_id, 'Повторная проверка после исправления сети', target,
             params, json.dumps(argv), 'Operator-approved connectivity recovery',
             datetime.now(timezone.utc).isoformat())).lastrowid
    line(f'  ✓ Повторная проверка TCP {port_string} поставлена в очередь (#{new_id})')
    return new_id


def render_results(db, result, *, json_output=False, verbose=False):
    if json_output:
        line(json.dumps(result, ensure_ascii=False, indent=2))
        return
    heading('Итоги запуска')
    line('  ' + tint('ЗАДАЧА', 'accent') + f' #{result["task_id"]}' + '   ' + tint(safe_display(result['target']), 'brand'))
    line('  ' + tint('Операций', 'muted') + f': {result.get("total_jobs", "—")}' +
         '    ' + tint('Находок', 'muted') + f': {result["network_observations"]}' +
         '    ' + tint('Burp', 'muted') + f': {result["burp_observations"]}')
    reasons = {
        'job_budget': 'достигнут лимит сетевых операций',
        'round_limit': 'достигнут лимит циклов',
        'plan_only': 'режим планирования без сети',
        'no_progress': 'пока нет новых действий',
        'no_new_evidence': 'нет новых подтверждённых находок',
        'queue_empty': 'нет оставшихся поддерживаемых проверок',
        'bootstrap_job_failed': 'ошибка сетевого Executor; остановка',
        'http_job_failed': 'HTTP Executor сообщил об ошибке; остановка',
    }
    reason = result.get('stop_reason')
    if reason:
        line('  ' + tint('Стоп', 'warning') + ': ' + safe_display(reasons.get(reason, reason)))
    if reason in ('no_progress', 'queue_empty', 'no_new_evidence'):
        # This mode is bounded recon: it stops when its closed check catalog is
        # exhausted, not when the target is done. Say so and point at the role
        # loop, which is the part that actually acts on leads like a login form.
        line('  ' + tint('Разведка', 'muted') +
             ': каталог поддерживаемых проверок исчерпан — это не конец работы.')
        line('  ' + tint('Продолжить (эксплуатация)', 'muted') +
             f': pm > 7 → задача {result.get("task_id", "?")}')
    if result.get('web_observations'):
        line('  ' + tint('HTTP-ресурсов', 'brand') + f': {result["web_observations"]}')
    web_progress = result.get('web_progress')
    if web_progress:
        states = {'request_budget': 'достигнут общий лимит запросов',
                  'queued': 'остались поддерживаемые проверки',
                  'limited_documents': 'остались неполные HTML-ответы; автоматическое дочитывание исчерпано',
                  'incomplete_responses': 'есть неполные загрузки; детали сохранены в артефактах',
                  'analysis_incomplete': 'есть ограничения разбора; артефакты доступны для локального анализа',
                  'catalog_exhausted': 'наблюдаемые поддерживаемые пути исчерпаны'}
        line('  HTTP-очередь: ' + states.get(web_progress['state'], web_progress['state']) +
             f'; ожидают={web_progress.get("pending", 0)}')
        if web_progress.get('unsupported_references'):
            line(f'  Ссылок без поддерживаемого GET/импорта: {web_progress["unsupported_references"]}; они не создают заданий.')
    # A complete full-port scan is audited separately from small follow-up
    # jobs, then its open ports are verified through network_jobs as usual.
    try:
        row = db.execute('SELECT status,open_ports_json FROM pm_tcp_full_scans WHERE task_id=? AND target=?',
                         (result['task_id'], result['target'])).fetchone()
        if row and row[0] == 'completed':
            line('  ' + tint('TCP полный', 'success') +
                 f': 65 535 портов · найдено открытых: {len(json.loads(row[1]))}')
    except (sqlite3.OperationalError, ValueError, KeyError):
        pass
    progress = result.get('bootstrap_progress')
    if progress:
        line(f'  TCP-разведка: проверено {progress.get("attempted_ranked_ports", 0)} '
             f'из {progress.get("ranked_pool", 1024)} популярных портов')
    try:
        from orchestrator import evidence_pipeline as evidence
        digest, bundle = evidence.make_snapshot(db, result['task_id'])
        records = bundle.get('network_observations', [])
        seen = set()
        for obs in records:
            data = obs.get('data') or {}
            kind = obs.get('kind')
            if kind == 'tcp_port_open':
                port = data.get('port')
                if type(port) is int and port not in seen:
                    seen.add(port)
                    line('  ' + tint('[OPEN]', 'success') + f' TCP/{port}: {safe_display(data.get("service_hint") or "сервис не определён")}')
            elif kind == 'http_response':
                status_line = data.get('status_line')
                if status_line:
                    line('  ' + tint('[HTTP]', 'brand') + ': ' + safe_display(status_line[:100]))
        if bundle.get('web_observations'):
            for web in bundle['web_observations'][-8:]:
                code = web.get('status_code') or 'ERR'
                line('  ' + tint('[WEB]', 'brand') + f' {code} ' +
                     safe_display(f"{web.get('hostname')}:{web.get('port')}{web.get('path')}") +
                     (f" | {safe_display(web.get('title'))}" if web.get('title') else '') +
                     (f" | assets={len(web.get('assets') or [])}" if web.get('assets') else '') +
                     (f" | paths={len(web.get('script_references') or [])}" if web.get('script_references') else '') +
                     (f' | {web["artifact"]["bytes_saved"]} Б, загрузка ' +
                      ('полная' if web['artifact']['download_complete'] else 'частичная') if web.get('artifact') else
                      ' | ответ ограничен' if web.get('response_limited') else ''))
                metrics = web.get('response_metrics') or {}
                if metrics.get('assets_not_queued'):
                    line(f'    Ресурсов вне поддерживаемых путей/scope: {metrics["assets_not_queued"]}')
                if metrics.get('asset_rejections',{}).get('query_not_supported'):
                    line('    Ресурсы с неподдерживаемыми query-параметрами: ' +
                         str(metrics['asset_rejections']['query_not_supported']))
                if metrics.get('metadata_limits'):
                    line('    Ограничения разбора: ' + safe_display(', '.join(metrics['metadata_limits'])))
                for hint in web.get('application_hints', [])[:4]:
                    line('    Версия в публичном тексте: ' + safe_display(hint.get('product')) + ' ' +
                         safe_display(hint.get('version_claim')) + ' (не подтверждена)')
        reports = evidence.saved_reports(db, result['task_id'], digest)
        if reports:
            heading('Вывод агентов')
            for agent in ('recon', 'vuln', 'access', 'verify'):
                report = reports.get(agent)
                if report:
                    limit = 650 if verbose else 200
                    summary = ' '.join(str(report.get('summary', '')).split())
                    line('  ' + tint(f'{agent.upper():<7}', 'accent') + ' ' + safe_display(summary[:limit]) +
                         ('…' if len(summary) > limit else ''))
            seen_checks = set()
            for report in reports.values():
                for check in report.get('recommended_checks') or []:
                    check = ' '.join(str(check).split())
                    if check and check.casefold() not in seen_checks:
                        seen_checks.add(check.casefold())
                        if len(seen_checks) <= (8 if verbose else 2):
                            line('  ' + tint('[>]', 'brand') + ' ' + safe_display(check[:200]))
    except (ValueError, KeyError, sqlite3.Error, ImportError) as exc:
        line('  Подробный разбор наблюдений пока недоступен: ' + str(exc)[:200])
    line('  ' + tint('[i]', 'muted') + ' Подробные данные и история остаются в SQLite.')


def session_api_key(args, *, required=False):
    """A single API key in process memory, never SQLite, argv, or environment."""
    if (not required and getattr(args, 'command', None) != 'new' and
            getattr(args, 'no_agents', False) and getattr(args, 'no_decide', False)):
        return None
    existing = getattr(args, '_session_key', None)
    if existing is not None:
        return existing
    key = getpass.getpass('Experiential API key (один раз за запуск): ').strip()
    if not key or len(key.encode('utf-8')) > 4096:
        raise OperatorError('API-ключ обязателен и не должен превышать 4096 байт')
    diagnostics.register_secret(key)
    args._session_key = key
    return key


@contextmanager
def session_getpass(key):
    """Legacy in-process agents ask getpass independently; reuse the session key."""
    original = getpass.getpass
    try:
        getpass.getpass = lambda prompt='Password: ', stream=None: key
        yield
    finally:
        getpass.getpass = original


class ConciseProgress:
    """Display only operator-useful scheduler progress; preserve saved SQLite data."""
    def __init__(self, stream=None):
        self.pending = ''
        self.stream = stream if stream is not None else sys.stdout
    def write(self, chunk):
        self.pending += str(chunk)
        while '\n' in self.pending:
            current, self.pending = self.pending.split('\n', 1)
            self._one(current)
    def _one(self, text):
        text = text.strip()
        if text.startswith(('[EVENT]', '[DIAG-ERROR]')):
            line('  ' + diagnostics.clean(text), stream=self.stream)
        elif text.startswith('[JOB]'):
            tone = 'success' if ': completed' in text else 'warning' if ': failed' in text else 'brand'
            line('  ' + tint('[+]', tone, stream=self.stream) + ' ' + safe_display(text), stream=self.stream)
        elif text.startswith('[AGENT]'):
            line('  ' + tint('[АНАЛИЗ]', 'accent', stream=self.stream) + ' ' + safe_display(text.replace('[AGENT]', '').strip()), stream=self.stream)
        elif text.startswith('[BOOTSTRAP]'):
            line('  ' + tint('[SCAN]', 'brand', stream=self.stream) + ' ' + safe_display(text), stream=self.stream)
        elif text.startswith('[WEB]'):
            line('  ' + tint('[WEB]', 'brand', stream=self.stream) + ' ' + safe_display(text[5:].strip()), stream=self.stream)
        elif text.startswith('[DECIDE]'):
            line('  ' + tint('[DECIDE]', 'accent', stream=self.stream) + ' ' + safe_display(text[len('[DECIDE]'):].strip()), stream=self.stream)
        elif text.startswith('[MODEL]'):
            line('  ' + tint('[MODEL]', 'warning', stream=self.stream) + ' ' +
                 safe_display(text[len('[MODEL]'):].strip()), stream=self.stream)
        elif text.startswith('[ROUND') and ('observations=' in text or 'No observations' in text):
            line('  ' + safe_display(text), stream=self.stream)
        elif text.startswith('[ОШИБКА]') or text.startswith('[ERROR]'):
            line('  ' + tint('[!]', 'danger', stream=self.stream) + ' ' + safe_display(text), stream=self.stream)
    def flush(self):
        if self.pending:
            self._one(self.pending)
            self.pending = ''


def call_scheduler(db, task_id, target, args, *, prior_jobs=0):
    from orchestrator import master_scheduler as scheduler
    from orchestrator import evidence_pipeline as evidence
    from orchestrator import decision_agent as decision
    from orchestrator import network_jobs as jobs
    # Suppress JSON-only end-of-run dumps while retaining verbose English progress.
    original = scheduler.emit, evidence.render, decision.emit
    scheduler.emit = lambda obj: None
    evidence.render = lambda obj: None
    decision.emit = lambda obj: None
    try:
        jobs.initialize(db)
        scheduler.validate_task(db, task_id)
        from contextlib import redirect_stdout
        progress = ConciseProgress(sys.stdout)
        with scheduler.exclusive_run_lock(), session_getpass(session_api_key(args)), redirect_stdout(progress):
            result = scheduler.auto(db, task_id, True, args.sync_burp,
                                    args.no_agents, args.max_jobs,
                                    not args.no_decide, args.max_rounds, True,
                                    web_enabled=True)
        progress.flush()
    finally:
        scheduler.emit, evidence.render, decision.emit = original
    if prior_jobs:
        result['total_jobs'] = result.get('total_jobs', 0) + prior_jobs
    render_results(db, result, json_output=args.json, verbose=getattr(args, 'verbose', False))
    offer_cleanup_if_verified(db, task_id, result)


def configure(db, task_id, args, *, create_scope=False, plan=None):
    target = task_target(db, task_id)
    if task_id > 200:
        raise OperatorError('NetGuard поддерживает только Task ID 1..200')
    ensure_task_scope(db, task_id, target, create=create_scope)
    egress = args.egress or get_egress(target)
    if not re.fullmatch(r'[A-Za-z0-9_.-]{1,15}', egress) or egress == 'auto':
        raise OperatorError('Нужен конкретный интерфейс, например tun0; auto запрещён в этом CLI')
    actual = get_egress(target)
    if actual != egress:
        raise OperatorError(f'Маршрут Kali идёт через {actual}, а указан {egress}. Проверь VPN до запуска.')
    if plan:
        show_plan(task_id, plan)
    ask_approval(db, task_id, target, egress, show=not create_scope, auto=create_scope)
    heading('Сетевая изоляция')
    ensure_netguard(task_id, target, egress)
    from orchestrator.http_discovery import require_capture_support
    require_capture_support()
    configure_hostnames(db, task_id, target, getattr(args, 'hostnames', None))
    return target


def save_task_intent(db, task_id, text):
    text = str(text).strip()
    validate_intent(text)
    with db:
        db.execute('INSERT OR IGNORE INTO pm_task_intents(task_id,intent,created_at) VALUES (?,?,?)',
                   (task_id, text, datetime.now(timezone.utc).isoformat()))


def restore_task_intent(db, task_id, text, source):
    text, source = str(text).strip(), str(source).strip()
    validate_intent(text)
    if not source or len(source) > 300:
        raise OperatorError('Нужен источник до 300 символов')
    if not db.execute('SELECT 1 FROM tasks WHERE id=?', (task_id,)).fetchone():
        raise OperatorError('Задача не найдена')
    with db:
        db.execute('CREATE TABLE IF NOT EXISTS pm_task_intent_history ('
                   'id INTEGER PRIMARY KEY,task_id INTEGER NOT NULL,previous_intent TEXT,'
                   'intent TEXT NOT NULL,source TEXT NOT NULL,created_at TEXT NOT NULL)')
        previous = previous_task_intent(db, task_id)
        if previous == text:
            return False
        stamp = datetime.now(timezone.utc).isoformat()
        db.execute('INSERT INTO pm_task_intent_history '
                   '(task_id,previous_intent,intent,source,created_at) VALUES (?,?,?,?,?)',
                   (task_id, previous, text, source, stamp))
        db.execute('INSERT INTO pm_task_intents VALUES (?,?,?) '
                   'ON CONFLICT(task_id) DO UPDATE SET intent=excluded.intent,created_at=excluded.created_at',
                   (task_id, text, stamp))
    return True


def op_intent(args):
    text = compose_task_description(args.task, '', read_hints(args))
    objective_specs(args)
    objective_mode(args)
    objective_numbers(args)
    with connect() as db:
        changed = restore_task_intent(db, args.task_id, text, args.source)
        save_flag_options(db, args.task_id, args)
        save_objective_options(db, args.task_id, args, str(args.task).splitlines()[0])
    line('Описание и ограничения сохранены с историей.' if changed else 'Описание уже сохранено.')


def previous_task_intent(db, task_id):
    row = db.execute('SELECT intent FROM pm_task_intents WHERE task_id=?', (task_id,)).fetchone()
    if row:
        return row[0]
    # Legacy tasks created before the v5 console did not save the original
    # operator objective in our own metadata table. Never invent it from GLM.
    return None


def validate_intent(text):
    if not text:
        raise OperatorError('Нужно непустое описание задачи')
    if len(text) > INTENT_MAX:
        raise OperatorError(f'Описание с подсказками {len(text)} символов, лимит {INTENT_MAX}; '
                            f'сократите на {len(text) - INTENT_MAX}; UTF-8: {len(text.encode("utf-8"))} байт')


def read_hints(args):
    hints = getattr(args, 'hints', None) or ''
    path = getattr(args, 'hints_file', None)
    if path:
        try:
            hints = Path(path).read_text(encoding='utf-8')
        except (OSError, UnicodeError) as exc:
            raise OperatorError('Не удалось прочитать файл подсказок UTF-8: ' + str(exc)) from exc
    if len(hints) > HINTS_MAX:
        raise OperatorError(f'Подсказки {len(hints)} символов, лимит {HINTS_MAX}; '
                            f'UTF-8: {len(hints.encode("utf-8"))} байт')
    return hints


def save_flag_options(db, task_id, args):
    from orchestrator.flag_verify import save_patterns
    prefixes = [part.strip() for item in (getattr(args, 'flag_prefix', None) or [])
                for part in item.split(',') if part.strip()]
    shapes = [part.strip() for item in (getattr(args, 'flag_shape', None) or [])
              for part in item.split(',') if part.strip()]
    expects = list(getattr(args, 'flag_expect', None) or [])
    path = getattr(args, 'flag_expect_file', None)
    if path:
        try:
            expects += [line.strip() for line in Path(path).read_text(encoding='utf-8').splitlines()
                        if line.strip()]
        except (OSError, UnicodeError) as exc:
            raise OperatorError('Не удалось прочитать файл ожидаемых флагов UTF-8: ' + str(exc)) from exc
    try:
        save_patterns(db, task_id, getattr(args, 'flag_pattern', None) or (),
                      prefixes, shapes, expects)
    except ValueError as exc:
        raise OperatorError(str(exc)) from exc


def objective_specs(args):
    """Read explicit secondary objectives without changing the task."""
    specs = list(getattr(args, 'objective', None) or [])
    path = getattr(args, 'objectives_file', None)
    if path:
        try:
            specs.extend(line.strip() for line in Path(path).read_text(encoding='utf-8').splitlines()
                         if line.strip() and not line.lstrip().startswith('#'))
        except (OSError, UnicodeError) as exc:
            raise OperatorError('Не удалось прочитать файл целей UTF-8: ' + str(exc)) from exc
    from orchestrator.objectives import MAX_OBJECTIVES, parse_objective_spec
    if len(specs) + 1 > MAX_OBJECTIVES:
        raise OperatorError(f'Можно задать не более {MAX_OBJECTIVES} целей')
    titles = [parse_objective_spec(item)[1] for item in specs]
    if len(set(titles)) != len(titles):
        raise OperatorError('Побочные цели не должны повторяться')
    return specs


def objective_mode(args, current=None):
    chosen = [name for name, enabled in (
        ('goal-exclusive', getattr(args, 'goal_exclusive', False)),
        ('goal-first', getattr(args, 'goal_first', False)),
        ('all-flags', getattr(args, 'all_flags', False))) if enabled]
    if len(chosen) > 1:
        raise OperatorError('Укажите один режим целей: --goal-exclusive, --goal-first или --all-flags')
    return chosen[0] if chosen else (current or 'goal-first')


def objective_numbers(args):
    try:
        weight = getattr(args, 'goal_weight', None)
        expected = getattr(args, 'expect_flags', None)
        weight = int(weight) if weight is not None else None
        expected = int(expected) if expected is not None else None
    except (ValueError, TypeError) as exc:
        raise OperatorError('Вес цели и число флагов должны быть целыми числами') from exc
    if weight is not None and not 1 <= weight <= 10000:
        raise OperatorError('Вес основной цели должен быть от 1 до 10000')
    if expected is not None and not 1 <= expected <= 30:
        raise OperatorError('Ожидаемое число флагов должно быть от 1 до 30')
    return weight, expected


def save_objective_options(db, task_id, args, primary_title=None):
    """Persist explicit objective options; leave old tasks untouched otherwise."""
    from orchestrator import objectives
    state = objectives.objective_status(db, task_id)
    specs = objective_specs(args)
    mode = objective_mode(args, state['mode'])
    requested_weight, requested_expect = objective_numbers(args)
    explicit = (bool(specs) or getattr(args, 'objectives_file', None) is not None or
                requested_weight is not None or
                getattr(args, 'goal_exclusive', False) or getattr(args, 'goal_first', False) or
                (getattr(args, 'all_flags', False) and state['primary']))
    if not explicit:
        return state
    if primary_title is None:
        stored_lines = (previous_task_intent(db, task_id) or '').splitlines()
        primary_title = (state['primary']['title'] if state['primary'] else
                         stored_lines[0] if stored_lines else '')
    if not primary_title:
        raise OperatorError('Не сохранено описание основной цели; сначала задайте intent')
    if not specs and getattr(args, 'objectives_file', None) is None:
        specs = [f'{row["weight"]}:{row["title"]}' for row in state['objectives']
                 if row['role'] == 'secondary']
    weight = (requested_weight if requested_weight is not None
              else state['primary']['weight'] if state['primary'] else 100)
    expected = requested_expect
    if expected is None and state['primary'] and not getattr(args, 'objective', None) and not getattr(args, 'objectives_file', None):
        expected = state['expected_flags']
    objectives.save_objectives(db, task_id, primary_title, weight,
                               mode == 'goal-exclusive', specs, mode=mode,
                               expected_flags=expected)
    return objectives.objective_status(db, task_id)


def full_scan_open_ports(stdout):
    """Extract open TCP ports from Nmap's plain output, never trust names as commands."""
    if (not isinstance(stdout, str) or 'Nmap done:' not in stdout or
            'host timeout' in stdout.lower() or 'skipping host' in stdout.lower()):
        raise OperatorError('Полный скан Nmap завершён не полностью или по тайм-ауту')
    result = set()
    for line_ in stdout.splitlines():
        match = re.match(r'^([0-9]{1,5})/tcp\s+open\s+', line_)
        if match:
            port = int(match.group(1))
            if 1 <= port <= 65535:
                result.add(port)
    return sorted(result)


@diagnostics.stage
def run_full_tcp_scan(db, task_id, target):
    """One bounded full scan per explicit console run, with durable retry audit.

    A previous COMPLETED positive scan is cached. A failure or empty result
    may be retried only after the operator explicitly resumes the task.
    """
    scan_columns = {row[1] for row in db.execute('PRAGMA table_info(pm_tcp_full_scans)')}
    if 'last_seen_at' not in scan_columns:
        db.execute('ALTER TABLE pm_tcp_full_scans ADD COLUMN last_seen_at TEXT')
    db.execute('''CREATE TABLE IF NOT EXISTS pm_tcp_full_scan_attempts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        task_id INTEGER NOT NULL,
        target TEXT NOT NULL,
        status TEXT NOT NULL,
        error TEXT,
        created_at TEXT NOT NULL
    )''')
    entry = db.execute('SELECT status,open_ports_json,error FROM pm_tcp_full_scans WHERE task_id=? AND target=?',
                       (task_id, target)).fetchone()
    if entry and entry[0] == 'completed':
        diagnostics.emit('cache.hit', name='tcp_full_scan', task_id=task_id, parameters={'target': target})
        scan = db.execute('SELECT created_at FROM pm_tcp_full_scans WHERE task_id=? AND target=?',
                          (task_id, target)).fetchone()
        try:
            minutes = max(1, int(os.environ.get('PM_TCP_SCAN_STALE_MINUTES', '30')))
        except ValueError as exc:
            raise OperatorError('PM_TCP_SCAN_STALE_MINUTES должен быть целым числом минут') from exc
        try:
            stale = scan and (datetime.now(timezone.utc) - datetime.fromisoformat(scan[0])).total_seconds() > minutes * 60
        except (ValueError, TypeError):
            stale = False
        if stale:
            line(f'  [!] Кэш полного TCP-скана старше {minutes} минут; список портов может быть устаревшим.')
        return 0
    if entry and entry[0] == 'running':
        raise OperatorError('Предыдущий TCP-скан был прерван без подтверждения завершения. '
                            'Сначала убедись, что процесс Nmap уже остановлен.')
    with db:
        if entry:
            db.execute("UPDATE pm_tcp_full_scans SET status='running',error=NULL WHERE task_id=? AND target=?",
                       (task_id, target))
        else:
            db.execute('INSERT INTO pm_tcp_full_scans(task_id,target,status,created_at) VALUES (?,?,?,?)',
                       (task_id, target, 'running', datetime.now(timezone.utc).isoformat()))
        attempt = db.execute('INSERT INTO pm_tcp_full_scan_attempts(task_id,target,status,created_at) VALUES (?,?,?,?)',
                             (task_id, target, 'running', datetime.now(timezone.utc).isoformat())).lastrowid
    line('  ' + tint('[SCAN]', 'brand') + f' TCP connect 1–65535 · {target} · --min-rate 1000')
    try:
        payload, rc = diagnostics.call('tcp_full', sudo_checked, ['run', '--task-id', str(task_id),
                                    '--profile', 'tcp_full', '--target', target],
                                   task_id=task_id, parameters={'target': target, 'profile': 'tcp_full'},
                                   timeout=270, allow_error=True)
        if rc or payload.get('status') != 'completed' or payload.get('output_truncated'):
            raise OperatorError('Nmap: ' + str(payload.get('stderr') or payload.get('error') or
                                                      payload.get('status'))[:300])
        ports = full_scan_open_ports(payload.get('stdout', ''))
        if ports:
            line('  ' + tint('[OPEN]', 'success') + ' Найдены порты: ' + ', '.join(map(str, ports[:40])) +
                 (' …' if len(ports)>40 else ''))
            # Reuse existing executor/observation pipeline instead of writing
            # ad-hoc, incompatible network_observations into SQLite.
            for offset in range(0, len(ports), PORTS_MAX):
                batch = ','.join(map(str, ports[offset:offset+PORTS_MAX]))
                try:
                    plan_reprobe(db, task_id, target, batch)
                except OperatorError as exc:
                    if 'уже проверен' not in str(exc):
                        raise
                    line('  Набор портов уже проверялся и не будет дублироваться: ' + batch)
        else:
            line('  ' + tint('[!]', 'warning') + ' Открытые TCP-порты не обнаружены; автоматическое исследование приостановлено.')
        final_state = 'completed' if ports else 'empty'
        with db:
            db.execute('UPDATE pm_tcp_full_scans SET status=?,open_ports_json=?,error=NULL,last_seen_at=? '
                       'WHERE task_id=? AND target=?',
                       (final_state, json.dumps(ports),
                        datetime.now(timezone.utc).isoformat() if ports else None, task_id, target))
            db.execute('UPDATE pm_tcp_full_scan_attempts SET status=? WHERE id=?',
                       (final_state, attempt))
        return 1
    except Exception as exc:
        with db:
            db.execute('UPDATE pm_tcp_full_scans SET status=?,error=? WHERE task_id=? AND target=?',
                       ('failed', str(exc)[:500], task_id, target))
            db.execute('UPDATE pm_tcp_full_scan_attempts SET status=?,error=? WHERE id=?',
                       ('failed', str(exc)[:500], attempt))
        raise


@diagnostics.stage
def preflight_target(db, task_id, target, ports, timeout=2.0):
    """Probe cached ports through the task broker and its existing NetGuard path."""
    try:
        selected = sorted({int(port) for port in ports if 1 <= int(port) <= 65535})
        timeout = min(2.0, max(0.05, float(timeout)))
    except (ValueError, TypeError) as exc:
        raise OperatorError('Некорректные порты или тайм-аут проверки доступности') from exc
    stamp = datetime.now(timezone.utc).isoformat()
    if not selected:
        return {'reachable': [], 'unreachable': [], 'checked_at': stamp}
    script = ('import json,socket,sys,time; host=sys.argv[1]; ports=json.loads(sys.argv[2]); '
              'limit=time.monotonic()+10; ok=[]; bad=[]; '
              'exec("for port in ports:\\n if time.monotonic()>=limit: break\\n try:\\n  s=socket.create_connection((host,port),timeout=min(float(sys.argv[3]),max(0.05,limit-time.monotonic()))); s.close(); ok.append(port)\\n except OSError:\\n  bad.append(port)\\n"); '
              'print(json.dumps({"reachable":ok,"unreachable":bad,"unchecked":ports[len(ok)+len(bad):]}))')
    argv = ['/usr/bin/python3', '-c', script, target, json.dumps(selected), str(timeout)]
    command = ['run', '--task-id', str(task_id), '--profile', 'exec', '--target', target,
               '--timeout', '12']
    for item in argv:
        command.append('--argv=' + item)
    try:
        payload, rc = diagnostics.call('preflight', sudo_checked, command, task_id=task_id,
                                       parameters={'target': target, 'profile': 'exec', 'ports': ','.join(map(str, selected))},
                                       timeout=20, allow_error=True)
        if rc or payload.get('status') != 'completed' or payload.get('exit_code') != 0:
            raise OperatorError('Проверка доступности через NetGuard не завершилась: ' +
                                str(payload.get('error') or payload.get('stderr') or 'ошибка')[:200])
        result = json.loads(payload.get('stdout', ''))
        if not isinstance(result, dict) or sorted(result['reachable'] + result['unreachable'] +
                                                  result['unchecked']) != selected:
            raise ValueError('invalid probe result')
    except OperatorError as exc:
        with db:
            db.execute('INSERT INTO pm_tcp_full_scan_attempts(task_id,target,status,error,created_at) '
                       'VALUES (?,?,?,?,?)', (task_id, target, 'preflight_fail', str(exc)[:500], stamp))
        raise
    except (OSError, subprocess.SubprocessError) as exc:
        with db:
            db.execute('INSERT INTO pm_tcp_full_scan_attempts(task_id,target,status,error,created_at) '
                       'VALUES (?,?,?,?,?)', (task_id, target, 'preflight_fail', str(exc)[:500], stamp))
        raise OperatorError('Проверка доступности через NetGuard не завершилась') from exc
    except (ValueError, KeyError, TypeError) as exc:
        with db:
            db.execute('INSERT INTO pm_tcp_full_scan_attempts(task_id,target,status,error,created_at) '
                       'VALUES (?,?,?,?,?)', (task_id, target, 'preflight_fail', str(exc)[:500], stamp))
        raise OperatorError('Некорректный результат проверки доступности NetGuard') from exc
    result['checked_at'] = stamp
    with db:
        db.execute('INSERT INTO pm_tcp_full_scan_attempts(task_id,target,status,error,created_at) '
                   'VALUES (?,?,?,?,?)', (task_id, target, 'preflight_ok' if result['reachable'] else
                   'preflight_fail', json.dumps(result, ensure_ascii=False), stamp))
        if result['reachable']:
            db.execute('UPDATE pm_tcp_full_scans SET last_seen_at=? WHERE task_id=? AND target=?',
                       (stamp, task_id, target))
    return result


def launch_configured_task(db, task_id, target, args):
    heading('Автономная разведка')
    # One brokered full scan consumes one of the network-operation slots.
    # Do not automatically repeat it after a restart.
    used = run_full_tcp_scan(db, task_id, target)
    scan_row = db.execute('SELECT open_ports_json,last_seen_at,created_at FROM pm_tcp_full_scans '
                          'WHERE task_id=? AND target=?', (task_id, target)).fetchone()
    ports = json.loads(scan_row[0])
    if not ports:
        line('  [!] Пока нет подтверждённых TCP-сервисов. Без новых фактов агенты не запускаются.')
        return
    preflight = preflight_target(db, task_id, target, ports)
    if not preflight['reachable'] and not getattr(args, 'force_unreachable', False):
        raise OperatorError('Цель не отвечает на проверенных портах ' +
                            ', '.join(map(str, preflight['unreachable'])) +
                            '; последняя удачная проверка: ' + (scan_row[1] or scan_row[2] or 'нет данных'))
    if used and args.max_jobs <= used:
        line('  Лимит операций исчерпан полным TCP-сканом. Возобнови задачу позже.')
        return
    if used:
        args = argparse.Namespace(**vars(args))
        args.max_jobs -= used
    call_scheduler(db, task_id, target, args, prior_jobs=used)


@diagnostics.stage
def op_new(args, *, defer_execution=False):
    target = validate_target(args.target)
    key = session_api_key(args, required=True)
    heading('Создание задачи')
    # Interactive mode already composed limits and hints; the CLI passes them
    # separately, so normalise here instead of duplicating the logic.
    task_text = compose_task_description(args.task, '', read_hints(args))
    validate_intent(task_text)
    objective_specs(args)
    objective_mode(args)
    objective_numbers(args)
    task_id, plan = run_planner_with_validation_retry(
        target, task_text, key, getattr(args, 'planner_context', None))
    with connect() as db:
        if task_target(db, task_id) != target:
            raise OperatorError('IP цели в SQLite не соответствует запросу; запуск запрещён')
        configured = configure(db, task_id, args, create_scope=True, plan=plan)
        save_task_intent(db, task_id, task_text)
        save_flag_options(db, task_id, args)
        save_objective_options(db, task_id, args, str(args.task).splitlines()[0])
        if not defer_execution:
            launch_configured_task(db, task_id, configured, args)
            line(f'Продолжить позже: pentest-master → [02] задача {task_id}')
    return task_id


@diagnostics.stage
def op_resume(args):
    session_api_key(args)
    with connect() as db:
        target = configure(db, args.task_id, args)
        save_flag_options(db, args.task_id, args)
        save_objective_options(db, args.task_id, args)
        if args.reprobe:
            plan_reprobe(db, args.task_id, target, args.reprobe)
        launch_configured_task(db, args.task_id, target, args)


def transition_path(new_id, transition_root=ROOT / 'storage/transitions', *, create=False):
    """Return an operator-owned, private path for an unfinished IP transition."""
    transition_root = Path(transition_root)
    if transition_root.is_symlink() or transition_root.parent.is_symlink():
        raise OperatorError('Каталог переходов не должен быть симлинком')
    if create:
        transition_root.mkdir(mode=0o700, exist_ok=True)
    info = transition_root.lstat()
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or
            info.st_mode & 0o077):
        raise OperatorError('Небезопасный каталог переходов')
    return transition_root / f'{int(new_id)}.json'


def save_transition_snapshot(new_id, old_id, old_ip, new_ip, transfer_enabled,
                             snapshot, archive=None,
                             transition_root=ROOT / 'storage/transitions'):
    """Persist bounded transfer data after teardown; never persist raw reports."""
    path = transition_path(new_id, transition_root, create=True)
    if path.exists() or path.is_symlink():
        raise OperatorError('Снимок перехода уже существует')
    compact = None
    if transfer_enabled:
        if not snapshot:
            raise OperatorError('Нет снимка для переноса')
        allowed = ('old_id', 'old_ip', 'artifacts', 'technical_findings',
                   'service_map', 'map_source_id', 'map_source_ip', 'confirmed_flags')
        compact = {key: snapshot[key] for key in allowed if key in snapshot}
        compact['notes_b64'] = base64.b64encode(snapshot['notes_bytes']).decode('ascii')
    payload = json.dumps({
        'old_id': int(old_id), 'new_id': int(new_id),
        'old_ip': old_ip, 'new_ip': new_ip,
        'transfer_enabled': bool(transfer_enabled),
        'archive_path': str(archive['path']) if archive else '',
        'snapshot': compact,
    }, ensure_ascii=False, separators=(',', ':')).encode('utf-8')
    if len(payload) > TRANSITION_MAX_BYTES:
        raise OperatorError('Снимок перехода превысит лимит 256 КБ')
    fd, temporary = tempfile.mkstemp(prefix='.transition-', dir=path.parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, 'wb') as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        dir_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
    finally:
        Path(temporary).unlink(missing_ok=True)
    return path


def load_transition_snapshot(new_id, old_id, old_ip, new_ip,
                             transition_root=ROOT / 'storage/transitions'):
    path = transition_path(new_id, transition_root)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or
                info.st_mode & 0o077 or info.st_size > TRANSITION_MAX_BYTES):
            raise OperatorError('Небезопасный снимок перехода')
        raw = os.read(fd, TRANSITION_MAX_BYTES + 1)
    finally:
        os.close(fd)
    if len(raw) > TRANSITION_MAX_BYTES:
        raise OperatorError('Снимок перехода превысил лимит 256 КБ')
    try:
        saved = json.loads(raw)
        if (saved['old_id'], saved['new_id'], saved['old_ip'], saved['new_ip']) != (
                int(old_id), int(new_id), old_ip, new_ip):
            raise OperatorError('Снимок не совпадает со связкой задач')
        snapshot = saved.get('snapshot')
        if saved.get('transfer_enabled'):
            if not isinstance(snapshot, dict):
                raise OperatorError('В снимке отсутствуют данные для переноса')
            notes_bytes = base64.b64decode(snapshot.pop('notes_b64'), validate=True)
            if len(notes_bytes) > 65536:
                raise OperatorError('NOTES.md в снимке превышает 64 КБ')
            snapshot['notes_bytes'] = notes_bytes
            if snapshot.get('old_id') != int(old_id) or snapshot.get('old_ip') != old_ip:
                raise OperatorError('Снимок старой задачи не совпадает со связкой')
        return saved
    except (KeyError, TypeError, ValueError, UnicodeError, binascii.Error) as exc:
        raise OperatorError('Снимок перехода повреждён') from exc


def remove_transition_snapshot(new_id, transition_root=ROOT / 'storage/transitions'):
    path = transition_path(new_id, transition_root)
    if path.exists() or path.is_symlink():
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid():
                raise OperatorError('Небезопасный снимок перехода')
        finally:
            os.close(fd)
        path.unlink()


def archived_transition(archive_path, old_id,
                        archive_root=ROOT / 'storage/work_archive'):
    """Reopen an optional archive after restart without reading old /work."""
    archive_root = Path(archive_root)
    expected = archive_root / f'task_{int(old_id)}'
    if Path(archive_path) != expected or archive_root.is_symlink() or expected.is_symlink():
        raise OperatorError('Архив перехода не совпадает со старой задачей')
    for directory in (archive_root, expected, expected / 'files'):
        info = directory.lstat()
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or
                info.st_mode & 0o077):
            raise OperatorError('Небезопасный каталог архива перехода')
    fd = os.open(expected / 'manifest.json', os.O_RDONLY | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or
                info.st_mode & 0o077 or info.st_size > 1024 * 1024):
            raise OperatorError('Небезопасный манифест архива перехода')
        manifest = json.loads(os.read(fd, 1024 * 1024 + 1))
    finally:
        os.close(fd)
    if (not isinstance(manifest, dict) or manifest.get('task_id') != int(old_id) or
            not isinstance(manifest.get('files'), list)):
        raise OperatorError('Манифест архива не совпадает со старой задачей')
    archive = {**manifest, 'path': str(expected)}
    verify_archive_contents(archive)
    return archive


def complete_pending_transition(db, old_id, new_id, *, broker_call=None,
                                work_root=Path('/var/lib/pentest-master/work'),
                                transition_root=ROOT / 'storage/transitions'):
    """Resume a pending move from disk, even if old teardown already ran."""
    old_id, new_id = int(old_id), int(new_id)
    row = db.execute(
        'SELECT previous_target,successor_target,transfer_enabled,transfer_state '
        'FROM pm_task_lineage WHERE previous_task_id=? AND successor_task_id=?',
        (old_id, new_id)).fetchone()
    if not row or row[3] != 'pending':
        raise OperatorError('Переход не найден или уже завершён')
    old_ip, new_ip, transfer_enabled, _ = row
    if task_target(db, old_id) != old_ip or task_target(db, new_id) != new_ip:
        raise OperatorError('IP связки не совпадают с задачами')
    approval = db.execute(
        'SELECT target,allowed,closed_at FROM pm_operator_approvals WHERE task_id=?',
        (new_id,)).fetchone()
    if approval != (new_ip, new_ip + '/32', None):
        raise OperatorError('У преемника нет действующего подтверждённого scope')
    saved = load_transition_snapshot(new_id, old_id, old_ip, new_ip, transition_root)
    if bool(transfer_enabled) != bool(saved.get('transfer_enabled')):
        raise OperatorError('Режим переноса в базе и снимке не совпадает')
    call = broker_call or sudo_checked
    if transfer_enabled or saved.get('archive_path'):
        ready, _ = call(['workdir', '--task-id', str(new_id)])
        if ready.get('status') != 'ready':
            raise OperatorError('Не удалось подготовить /work новой задачи')
    old_state, rc = call(['status', '--task-id', str(old_id)], allow_error=True)
    if rc == 0:
        if old_state.get('allowed') != [old_ip + '/32']:
            raise OperatorError('Старый NetGuard не совпадает с исходной задачей. Правила не удалены.')
        removed, _ = call(['teardown', '--task-id', str(old_id)], timeout=45)
        if removed.get('status') != 'removed':
            raise OperatorError('Старый NetGuard не подтвердил удаление')
    else:
        error = str(old_state.get('error') or '').lower()
        if 'not configured' not in error and 'not found' not in error:
            raise OperatorError('Ошибка проверки старой изоляции: ' + error)
    with db:
        db.execute('UPDATE pm_operator_approvals SET closed_at=COALESCE(closed_at,?) WHERE task_id=?',
                   (datetime.now(timezone.utc).isoformat(), old_id))
    moved = {'flags': 0, 'notes': 0}
    if transfer_enabled:
        moved = transfer_successor_evidence(db, old_id, new_id, work_root=work_root,
                                            snapshot=saved['snapshot'])
    with db:
        db.execute("UPDATE pm_task_lineage SET transfer_state='done' "
                   'WHERE previous_task_id=? AND successor_task_id=? AND transfer_state=\'pending\'',
                   (old_id, new_id))
    remove_transition_snapshot(new_id, transition_root)
    return moved


@diagnostics.stage
def op_change_ip(args):
    """Linked successor task: keep evidence honest across a machine reboot.

    Old evidence/report rows retain their original target and are not used as
    evidence for the new IP; the console links both stages via pm_task_lineage.
    """
    from orchestrator import master_scheduler as scheduler
    old_id = args.task_id
    new_ip = validate_target(args.target)
    successor_args = argparse.Namespace(**vars(args))
    successor_args.target = new_ip
    with scheduler.exclusive_run_lock():
        with connect() as db:
            old_ip = task_target(db, old_id)
            if old_ip == new_ip:
                raise OperatorError('Новый IP совпадает с текущим')
            linked = db.execute('SELECT successor_task_id,successor_target,transfer_state '
                                'FROM pm_task_lineage WHERE previous_task_id=?',
                                (old_id,)).fetchone()
            if linked:
                new_id, linked_ip, state = linked
                if new_ip != linked_ip:
                    raise OperatorError(f'У задачи #{old_id} уже есть продолжение #{new_id} '
                                        f'на {linked_ip}; следующую смену IP делай у задачи #{new_id}')
                state_label = {'pending': 'не завершён', 'done': 'завершён'}.get(state, state)
                line(f'  Переход #{old_id} → #{new_id}: {state_label}.')
                if state == 'done':
                    stale = ROOT / 'storage/transitions' / f'{new_id}.json'
                    if stale.exists() or stale.is_symlink():
                        remove_transition_snapshot(new_id)
                    line(f'  Переход завершён. Продолжить работу: pentest-master → [02] задача {new_id}.')
                    return
                if state != 'pending':
                    raise OperatorError('Неизвестное состояние перехода')
                choice = input('  1 — продолжить перенос; 2 — отменить сейчас; '
                               '3 — работать в новой задаче [1]: ').strip()
                if choice in ('2', '3'):
                    if choice == '3':
                        line(f'  Работа в новой задаче: pentest-master → [02] задача {new_id}; '
                             'перенос остаётся незавершённым.')
                    else:
                        line('  Переход оставлен незавершённым; повтори смену IP для продолжения.')
                    return
                if choice not in ('', '1'):
                    raise OperatorError('Выбери 1, 2 или 3')
                broker_is_trusted()
                sudo_authenticate()
                saved_archive = load_transition_snapshot(new_id, old_id, old_ip, new_ip).get('archive_path')
                moved = complete_pending_transition(db, old_id, new_id)
                line(f'  ✓ Переход завершён: кандидатов {moved["flags"]}; '
                     f'строк заметок {moved["notes"]}.')
                if saved_archive:
                    try:
                        offer_archive_restore(archived_transition(saved_archive, old_id), new_id)
                    except (OperatorError, OSError, ValueError) as exc:
                        line('  ' + tint('[!]', 'warning') +
                             ' Архив сохранён, но восстановление не удалось: ' + safe_display(exc))
                successor_args.hostnames = None
            else:
                permitted = db.execute(
                    'SELECT target,closed_at,egress FROM pm_operator_approvals WHERE task_id=?',
                    (old_id,)).fetchone()
                if not permitted or permitted[:2] != (old_ip, None):
                    raise OperatorError('Старая задача не имеет действующего подтверждённого scope')
                objective = previous_task_intent(db, old_id)
        if not linked:
            if not objective:
                objective = input('Описание задачи (старая версия не сохранила исходный текст): ').strip()
                if not objective:
                    raise OperatorError('Не задано описание задачи')
            heading('Смена IP лабораторной машины')
            line(f'  Старая цель: #{old_id} {old_ip}')
            line(f'  Новый IP:    {new_ip}')
            line('  Предыдущая история сохранится в старой записи; новая — в связанной задаче.')
            successor_args.task = objective
            successor_args.hostnames = None # hostname approval is IP-specific; never silently inherit
            # Validate route before paying for the new model plan.
            successor_args.egress = get_egress(new_ip)
            if successor_args.egress != permitted[2]:
                line('  ' + tint('[!]', 'warning') +
                     ' Интерфейс выхода изменился; он будет проверен в новом Task Scope.')
            choice = input('  Перенести факты, карту и флаги-кандидаты? [y/N]: ').strip().lower()
            transfer_requested = choice in ('y', 'yes', 'д', 'да')
            with connect() as db:
                snapshot = (collect_successor_snapshot(db, old_id)
                            if transfer_requested else None)
                successor_args.planner_context = (planner_context_from_task(db, old_id)
                                                  if transfer_requested else None)
            if snapshot is not None:
                snapshot['transfer_bytes'] = build_transfer_notes(snapshot, new_ip)
            archive = None
            if getattr(args, 'archive_work', False):
                archive = archive_task_work(old_id)
                line(f'  ✓ Архив старого /work: {archive["bytes"]} Б, '
                     f'{len(archive["files"])} файлов.')
            new_id = op_new(successor_args, defer_execution=True)
            # Save the snapshot and lineage before any destructive broker action.
            save_transition_snapshot(new_id, old_id, old_ip, new_ip,
                                     transfer_requested, snapshot, archive)
            with connect() as db:
                with db:
                    db.execute('INSERT INTO pm_task_lineage '
                               '(previous_task_id,successor_task_id,previous_target,successor_target,'
                               'changed_at,transfer_enabled,transfer_state) '
                               'VALUES (?,?,?,?,?,?,?)',
                               (old_id,new_id,old_ip,new_ip,datetime.now(timezone.utc).isoformat(),
                                int(transfer_requested),'pending'))
                broker_is_trusted()
                sudo_authenticate()
                moved = complete_pending_transition(db, old_id, new_id)
                line('  ✓ Старые правила удалены, отчёты сохранены.')
                line('  ✓ Продолжение расследования: задача #' + str(new_id))
                if transfer_requested:
                    line(f'  ✓ Перенесено флагов-кандидатов: {moved["flags"]}; '
                         f'строк заметок: {moved["notes"]}.')
                if archive:
                    offer_archive_restore(archive, new_id)
    # Exclusive migration lock has been released before scheduler takes its own lock.
    with connect() as db:
        launch_configured_task(db, new_id, new_ip, successor_args)


def artifact_kind(path):
    """Identify a regular file from its name and a four-byte signature."""
    name = path.name.lower()
    if name == 'notes.md':
        return 'заметки'
    if 'ld-linux' in name:
        return 'загрузчик ELF'
    if 'libc' in name or name.endswith('.so') or '.so.' in name:
        return 'библиотека'
    if name.endswith(('.py', '.sh', '.pl', '.rb')):
        return 'скрипт'
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise OperatorError('Артефакт перестал быть обычным файлом')
        magic = os.read(fd, 4)
    finally:
        os.close(fd)
    if magic.startswith(b'PK\x03\x04') or name.endswith('.zip'):
        return 'ZIP-архив'
    if magic == b'\x7fELF':
        return 'бинарный ELF'
    if name.endswith(('.txt', '.md', '.json', '.html')):
        return 'текстовые данные'
    return 'данные'


def build_transfer_notes(snapshot, new_ip):
    """Build a bounded note before teardown so a size error cannot lose work."""
    from orchestrator import agent_actions
    old_id, old_ip = snapshot['old_id'], snapshot['old_ip']
    map_ip = snapshot.get('map_source_ip') or old_ip
    header = f'# Перенесено из #{old_id} ({old_ip}), требует перепроверки на {new_ip}\n'
    chunks = [header.encode('utf-8'), snapshot['notes_bytes']]
    if chunks[-1] and not chunks[-1].endswith(b'\n'):
        chunks.append(b'\n')
    artifacts = [item for item in snapshot.get('artifacts', [])
                 if item.get('path') != 'NOTES.md']
    if artifacts:
        lines = ['# Было скачано в старом /work; после teardown файлы недоступны. '
                 'Восстанови из архива или скачай заново.']
        for item in artifacts:
            name = safe_display(item.get('path') or '')[:300]
            lines.append(f'- {name} · {int(item.get("bytes") or 0)} Б · '
                         f'{safe_display(item.get("kind") or "данные")[:40]}')
        chunks.append(('\n'.join(lines) + '\n').encode('utf-8'))
    technical = snapshot.get('technical_findings') or {}
    established = technical.get('findings') or []
    refuted = technical.get('refuted') or []
    finding_block = b''
    for heading_text, items, section_limit in (
            ('# Что уже выяснено на прежнем IP (перепроверь, но не выводи заново)',
             established, 3072 if refuted else 4096),
            ('# Опровергнуто, повторять не надо', refuted, 4096)):
        if not items:
            continue
        section = (heading_text + '\n').encode('utf-8')
        for item in items:
            source = f"отчёт #{item['task_id']} {item['role']} раунд {item['iteration']}"
            if item.get('result_id'):
                source += f" result_id={item['result_id']}"
            entry = ('- ' + safe_display(agent_actions.finding_hint(item)) +
                     ' · ' + source + '\n').encode('utf-8')
            if len(finding_block) + len(section) + len(entry) > section_limit:
                break
            section += entry
        if b'\n-' in section and len(finding_block) + len(section) <= 4096:
            finding_block += section
    if finding_block:
        chunks.append(finding_block)
    entries = snapshot.get('service_map', {}).get('entries') or []
    if entries:
        lines = ['# Карта прежней цели — перепроверь порты на новом IP']
        for item in entries:
            port = int(item['port'])
            if not 1 <= port <= 65535:
                continue
            service = str(item.get('service') or '')
            version = str(item.get('version') or '')
            label = ' '.join(part for part in (service, version) if part)
            if version and not service:
                label = 'версия ' + version
            evidence = (str(item.get('result_id') or '') or
                        f"{item.get('source') or 'отчёт'} round {item.get('round') or '?'}")
            lines.append(f'{port}/tcp {label} → прежний IP {map_ip}; evidence {safe_display(evidence)[:120]}')
        chunks.append(('\n'.join(lines) + '\n').encode('utf-8'))
    payload = b''.join(chunks)
    if len(payload) > 131072:
        raise OperatorError('Переносимый NOTES.md превысит лимит 128 КБ')
    return payload


def collect_successor_snapshot(db, old_id, work_root=Path('/var/lib/pentest-master/work')):
    """Read operator-owned task data before the broker removes its workspace."""
    from orchestrator import agent_actions
    work_root = Path(work_root)
    if work_root.is_symlink():
        raise OperatorError('Каталог /work не должен быть симлинком')
    old_work = work_root / str(int(old_id))
    notes_bytes = b''
    artifacts = []
    if old_work.is_symlink():
        raise OperatorError('Старый /work не должен быть симлинком')
    if old_work.exists():
        info = old_work.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise OperatorError('Небезопасный каталог старого /work')
        note = old_work / 'NOTES.md'
        if note.exists() or note.is_symlink():
            info = note.lstat()
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077 or info.st_size > 65536:
                raise OperatorError('Небезопасный или слишком большой NOTES.md')
            fd = os.open(note, os.O_RDONLY | os.O_NOFOLLOW)
            try:
                opened = os.fstat(fd)
                if not stat.S_ISREG(opened.st_mode) or opened.st_uid != os.getuid() or opened.st_size > 65536:
                    raise OperatorError('NOTES.md изменился во время чтения')
                notes_bytes = os.read(fd, 65537)
                if len(notes_bytes) > 65536:
                    raise OperatorError('NOTES.md превышает 64 КБ')
            finally:
                os.close(fd)
        for directory, dirs, files in os.walk(old_work, followlinks=False):
            dirs[:] = [name for name in dirs if not (Path(directory) / name).is_symlink()]
            for name in files:
                path = Path(directory) / name
                info = path.lstat()
                if not stat.S_ISREG(info.st_mode):
                    continue
                artifacts.append({'path': path.relative_to(old_work).as_posix(),
                                  'bytes': info.st_size, 'kind': artifact_kind(path)})
                if len(artifacts) > 1024:
                    raise OperatorError('Слишком много файлов в старом /work')
    try:
        row = db.execute('SELECT MAX(iteration) FROM pm_agent_action_reports '
                         'WHERE task_id=?', (old_id,)).fetchone()
        latest_round = int(row[0] or 1)
    except sqlite3.OperationalError:
        latest_round = 1
    service_map = agent_actions.service_map(db, old_id, latest_round,
                                            work_root=work_root, note_keep=None)
    map_source_id, map_source_ip = int(old_id), task_target(db, old_id)
    if not service_map['entries']:
        inherited = agent_actions.lineage_map_source(db, old_id, work_root=work_root)
        if inherited:
            service_map = inherited['map']
            map_source_id, map_source_ip = inherited['task_id'], inherited['target']
    technical_findings = agent_actions.report_findings_for_lineage(
        db, (old_id, map_source_id) if map_source_id != int(old_id) else (old_id,))
    try:
        confirmed_flags = [row[0] for row in db.execute(
            "SELECT value FROM pm_verified_flags WHERE task_id=? AND status='confirmed'",
            (old_id,)).fetchall()]
    except sqlite3.OperationalError:
        confirmed_flags = []
    return {'old_id': int(old_id), 'old_ip': task_target(db, old_id),
            'notes_bytes': notes_bytes, 'artifacts': artifacts,
            'technical_findings': technical_findings, 'service_map': service_map,
            'map_source_id': map_source_id, 'map_source_ip': map_source_ip,
            'confirmed_flags': confirmed_flags}


def transfer_successor_evidence(db, old_id, new_id, work_root=Path('/var/lib/pentest-master/work'),
                                snapshot=None):
    """Carry hints across an approved lineage, without inheriting confirmation."""
    old_id, new_id, work_root = int(old_id), int(new_id), Path(work_root)
    if work_root.is_symlink():
        raise OperatorError('Каталог /work не должен быть симлинком')
    linked = db.execute(
        'SELECT previous_target,successor_target FROM pm_task_lineage '
        'WHERE previous_task_id=? AND successor_task_id=?',
        (old_id, new_id)).fetchone()
    if not linked:
        raise OperatorError('Перенос возможен только между связанными задачами')
    from orchestrator.flag_verify import canonical_flag_value, ensure_schema, flag_patterns
    from orchestrator import fact_state, objectives
    ensure_schema(db)
    fact_state.import_capability_assets(
        db, old_id, ROOT / 'storage/capability_log' / f'task_{old_id}.jsonl')
    fact_state.import_legacy_reports(db, old_id)
    snapshot = snapshot if snapshot is not None else collect_successor_snapshot(db, old_id, work_root)
    if snapshot['old_id'] != int(old_id) or snapshot['old_ip'] != linked[0]:
        raise OperatorError('Снимок не совпадает со связкой задач')
    new_work = work_root / str(new_id)
    notes_bytes = snapshot['notes_bytes']
    transfer_bytes = snapshot.get('transfer_bytes') or build_transfer_notes(snapshot, linked[1])
    if transfer_bytes:
        new_info = new_work.lstat()
        if not stat.S_ISDIR(new_info.st_mode) or new_info.st_uid != os.getuid() or new_info.st_mode & 0o077:
            raise OperatorError('Небезопасный каталог новых заметок')
        new_note = new_work / 'NOTES.md'
        if new_note.exists() or new_note.is_symlink():
            info = new_note.lstat()
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
                raise OperatorError('Небезопасный файл новых заметок')
        marker = f'# Перенесено из #{old_id} ({linked[0]}), требует перепроверки на {linked[1]}'.encode('utf-8')
        fd = os.open(new_note, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077 or info.st_size > 131072:
                raise OperatorError('Небезопасный или слишком большой новый NOTES.md')
            existing = os.read(fd, 131073)
            if marker not in existing:
                addition = (b'\n' if existing and not existing.endswith(b'\n') else b'') + transfer_bytes
                if len(existing) + len(addition) > 131072:
                    raise OperatorError('Новый NOTES.md превысит лимит')
                staged_fd, staged = tempfile.mkstemp(prefix='.notes-transfer-', dir=new_work)
                try:
                    os.fchmod(staged_fd, 0o600)
                    with os.fdopen(staged_fd, 'wb') as handle:
                        handle.write(existing + addition)
                        handle.flush()
                        os.fsync(handle.fileno())
                    os.replace(staged, new_note)
                    dir_fd = os.open(new_work, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
                    try:
                        os.fsync(dir_fd)
                    finally:
                        os.close(dir_fd)
                finally:
                    Path(staged).unlink(missing_ok=True)
        finally:
            os.close(fd)
    stamp = datetime.now(timezone.utc).isoformat()
    values = snapshot.get('confirmed_flags')
    if values is None:
        values = [row[0] for row in db.execute(
            "SELECT value FROM pm_verified_flags WHERE task_id=? AND status='confirmed'",
            (old_id,)).fetchall()]
    patterns = flag_patterns(db, old_id)
    canonical_values = [(canonical_flag_value(value, patterns) or
                         canonical_flag_value('flag: ' + str(value), patterns)) for value in values]
    if any(value is None for value in canonical_values):
        raise OperatorError('Перенос содержит некорректное подтверждённое значение')
    canonical_values = dict.fromkeys(canonical_values)
    moved_flags = 0
    with db:
        db.execute('INSERT OR IGNORE INTO pm_flag_patterns(task_id,pattern,source,created_at) '
                   'SELECT ?,pattern,source,created_at FROM pm_flag_patterns WHERE task_id=?',
                   (new_id, old_id))
        inherited_assets = fact_state.inherit_assets(db, old_id, new_id, linked[0])
        fact_state.inherit_hypotheses(db, old_id, new_id)
        objectives.transfer_objectives(db, old_id, new_id)
        for value in canonical_values:
            matched_by = next((row[1] for row in db.execute(
                'SELECT pattern,source FROM pm_flag_patterns WHERE task_id=?', (old_id,))
                if re.fullmatch(row[0], value)),
                'default' if canonical_flag_value(value) else 'kv')
            source = json.dumps({'transfer': f'перенесено из #{old_id} ({linked[0]}), требует переподтверждения на {linked[1]}',
                                 'matched_by': matched_by, 'evidence_source': 'none'},
                                ensure_ascii=False)
            cursor = db.execute(
                'INSERT OR IGNORE INTO pm_verified_flags '
                '(task_id,value,status,evidence_count,reported_by,sources_json,created_at,updated_at,operator_confirmed) '
                'VALUES (?,?,?,?,?,?,?,?,0)',
                (new_id, value, 'candidate', 0, 'transfer', source, stamp, stamp))
            moved_flags += cursor.rowcount
    return {'flags': moved_flags, 'notes': len(notes_bytes.splitlines()),
            'map_entries': len(snapshot.get('service_map', {}).get('entries') or []),
            'artifacts': len(snapshot.get('artifacts') or []),
            'assets': inherited_assets}


def archive_relative_path(raw):
    """A single path below /work, with no traversal or control characters."""
    value = str(raw)
    pieces = value.split('/')
    if (not value or value.startswith('/') or '\\' in value or len(value) > 512 or
            any(part in ('', '.', '..') for part in pieces) or
            any(ord(char) < 32 or ord(char) == 127 for char in value)):
        raise OperatorError('Небезопасное имя файла архива')
    return PurePosixPath(value)


def copy_regular_file(source, target, *, max_bytes, hasher=None):
    """Copy through no-follow descriptors into a new 0600 file."""
    source_fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        info = os.fstat(source_fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1:
            raise OperatorError('Архив содержит небезопасный файл')
        target_fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            copied = 0
            while True:
                block = os.read(source_fd, 1024 * 1024)
                if not block:
                    break
                copied += len(block)
                if copied > max_bytes:
                    raise OperatorError('Архив превысил предел 200 МБ')
                if hasher is not None:
                    hasher.update(block)
                while block:
                    block = block[os.write(target_fd, block):]
            return copied
        except Exception:
            Path(target).unlink(missing_ok=True)
            raise
        finally:
            os.close(target_fd)
    finally:
        os.close(source_fd)


def hash_regular_file(path, max_bytes=200 * 1024 * 1024):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1:
            raise OperatorError('Небезопасный файл существующего архива')
        digest, size = hashlib.sha256(), 0
        while True:
            block = os.read(fd, 1024 * 1024)
            if not block:
                return size, digest.hexdigest()
            size += len(block)
            if size > max_bytes:
                raise OperatorError('Файл архива превышает лимит')
            digest.update(block)
    finally:
        os.close(fd)


def verify_archive_contents(archive):
    """Check every manifest entry and reject unlisted files or directories."""
    files_root = Path(archive['path']) / 'files'
    expected_files, expected_dirs = {}, set()
    for item in archive['files']:
        if (not isinstance(item, dict) or not isinstance(item.get('path'), str) or
                type(item.get('bytes')) is not int or item['bytes'] < 0 or
                not isinstance(item.get('sha256'), str) or
                not re.fullmatch(r'[0-9a-f]{64}', item['sha256'])):
            raise OperatorError('Некорректная запись манифеста архива')
        relative = archive_relative_path(item['path'])
        name = relative.as_posix()
        if name in expected_files:
            raise OperatorError('Повторяющийся файл в манифесте архива')
        expected_files[name] = (item['bytes'], item['sha256'])
        expected_dirs.update(PurePosixPath(*relative.parts[:index]).as_posix()
                             for index in range(1, len(relative.parts)))
    actual_files, actual_dirs = set(), set()
    for directory, dirs, files in os.walk(files_root, followlinks=False):
        for name in dirs:
            path = Path(directory) / name
            info = path.lstat()
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid():
                raise OperatorError('Симлинк или чужой каталог в архиве')
            actual_dirs.add(path.relative_to(files_root).as_posix())
        for name in files:
            path = Path(directory) / name
            if not stat.S_ISREG(path.lstat().st_mode):
                raise OperatorError('Симлинк или специальный файл в архиве')
            relative = path.relative_to(files_root).as_posix()
            if relative not in expected_files or hash_regular_file(path) != expected_files[relative]:
                raise OperatorError('Файл архива не совпадает с манифестом')
            actual_files.add(relative)
    if actual_files != set(expected_files) or actual_dirs != expected_dirs:
        raise OperatorError('Состав архива не совпадает с манифестом')


def archive_task_work(task_id, work_root=Path('/var/lib/pentest-master/work'),
                      archive_root=ROOT / 'storage/work_archive', limit=200 * 1024 * 1024):
    """Optional, bounded operator-owned archive made before task teardown."""
    work_root, archive_root = Path(work_root), Path(archive_root)
    if work_root.is_symlink():
        raise OperatorError('Каталог /work не должен быть симлинком')
    source = work_root / str(int(task_id))
    if source.is_symlink() or not source.is_dir():
        raise OperatorError('Старый /work отсутствует или небезопасен для архива')
    root_info = source.lstat()
    if root_info.st_uid != os.getuid() or root_info.st_mode & 0o077:
        raise OperatorError('Небезопасный владелец или режим старого /work')
    items, total = [], 0
    for directory, dirs, files in os.walk(source, followlinks=False):
        for name in dirs:
            info = (Path(directory) / name).lstat()
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid():
                raise OperatorError('Симлинк или чужой каталог в старом /work')
        for name in files:
            path = Path(directory) / name
            info = path.lstat()
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1:
                raise OperatorError('Симлинк или специальный файл в старом /work')
            relative = path.relative_to(source).as_posix()
            archive_relative_path(relative)
            total += info.st_size
            if total > limit or len(items) >= 1024:
                raise OperatorError('Старый /work превышает лимит архива 200 МБ или 1024 файла')
            items.append({'path': relative, 'bytes': info.st_size,
                          'kind': artifact_kind(path)})
    if archive_root.is_symlink():
        raise OperatorError('Каталог архива не должен быть симлинком')
    archive_root.mkdir(parents=True, exist_ok=True, mode=0o700)
    archive_info = archive_root.lstat()
    if not stat.S_ISDIR(archive_info.st_mode) or archive_info.st_uid != os.getuid() or archive_info.st_mode & 0o077:
        raise OperatorError('Небезопасный каталог архива')
    final = archive_root / f'task_{int(task_id)}'
    if final.is_symlink():
        raise OperatorError('Архив этой задачи не должен быть симлинком')
    if final.exists():
        final_info = final.lstat()
        files_root = final / 'files'
        files_info = files_root.lstat()
        if (not stat.S_ISDIR(final_info.st_mode) or final_info.st_uid != os.getuid() or
                final_info.st_mode & 0o077 or not stat.S_ISDIR(files_info.st_mode) or
                files_info.st_uid != os.getuid() or files_info.st_mode & 0o077):
            raise OperatorError('Небезопасный существующий архив')
        manifest_path = final / 'manifest.json'
        fd = os.open(manifest_path, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(fd, 'r', encoding='utf-8') as handle:
            existing = json.load(handle)
        old_items = existing.get('files') or []
        if (existing.get('task_id') != int(task_id) or
                [(item['path'], item['bytes']) for item in old_items] !=
                [(item['path'], item['bytes']) for item in items]):
            raise OperatorError('Существующий архив не совпадает со старым /work')
        for item in old_items:
            relative = archive_relative_path(item['path'])
            parent = files_root
            for part in relative.parts[:-1]:
                parent = parent / part
                parent_info = parent.lstat()
                if not stat.S_ISDIR(parent_info.st_mode) or parent_info.st_uid != os.getuid():
                    raise OperatorError('Симлинк в существующем архиве')
            expected = (int(item['bytes']), item.get('sha256'))
            if (not expected[1] or
                    hash_regular_file(source.joinpath(*relative.parts)) != expected or
                    hash_regular_file(files_root.joinpath(*relative.parts)) != expected):
                raise OperatorError('Существующий архив устарел или повреждён')
        archive = {'path': str(final), **existing}
        verify_archive_contents(archive)
        return archive
    temporary = Path(tempfile.mkdtemp(prefix='.work-archive-', dir=archive_root))
    try:
        files_root = temporary / 'files'
        files_root.mkdir(mode=0o700)
        copied_total = 0
        for item in items:
            relative = archive_relative_path(item['path'])
            target = files_root.joinpath(*relative.parts)
            target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            digest = hashlib.sha256()
            copied = copy_regular_file(source.joinpath(*relative.parts), target,
                                       max_bytes=limit - copied_total, hasher=digest)
            if copied != item['bytes']:
                raise OperatorError('Файл изменился во время архивации')
            item['sha256'] = digest.hexdigest()
            copied_total += copied
        manifest = {'task_id': int(task_id), 'bytes': copied_total, 'files': items,
                    'created_at': datetime.now(timezone.utc).isoformat()}
        manifest_fd = os.open(temporary / 'manifest.json',
                              os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(manifest_fd, 'w', encoding='utf-8') as handle:
            json.dump(manifest, handle, ensure_ascii=False)
        os.rename(temporary, final)
        return {'path': str(final), **manifest}
    finally:
        if temporary.exists():
            shutil.rmtree(temporary)


def restore_archive_files(archive, new_id, names,
                          work_root=Path('/var/lib/pentest-master/work')):
    """Restore only explicitly selected regular files into an empty path."""
    work_root = Path(work_root)
    if work_root.is_symlink():
        raise OperatorError('Каталог /work не должен быть симлинком')
    target_root = work_root / str(int(new_id))
    if target_root.is_symlink() or not target_root.is_dir():
        raise OperatorError('Новый /work отсутствует или небезопасен')
    target_info = target_root.lstat()
    if target_info.st_uid != os.getuid() or target_info.st_mode & 0o077:
        raise OperatorError('Небезопасный каталог нового /work')
    archive_path = Path(archive['path'])
    if archive_path.is_symlink() or not archive_path.is_dir():
        raise OperatorError('Небезопасный каталог архива')
    archive_info = archive_path.lstat()
    files_info = (archive_path / 'files').lstat()
    if (archive_info.st_uid != os.getuid() or archive_info.st_mode & 0o077 or
            not stat.S_ISDIR(files_info.st_mode) or files_info.st_uid != os.getuid() or
            files_info.st_mode & 0o077):
        raise OperatorError('Небезопасный владелец или режим архива')
    verify_archive_contents(archive)
    allowed = {item['path']: item for item in archive['files']}
    selected = list(dict.fromkeys(names))
    for name in selected:
        if name not in allowed or name == 'NOTES.md':
            raise OperatorError('Файл не входит в архив или NOTES.md уже перенесён отдельно')
        archive_relative_path(name)
    restored = []
    note_size = None
    try:
        for name in selected:
            relative = archive_relative_path(name)
            source = archive_path / 'files'
            destination = target_root
            for part in relative.parts[:-1]:
                source = source / part
                source_info = source.lstat()
                if not stat.S_ISDIR(source_info.st_mode) or source_info.st_uid != os.getuid():
                    raise OperatorError('Небезопасный путь внутри архива')
                destination = destination / part
                destination.mkdir(mode=0o700, exist_ok=True)
                target_info = destination.lstat()
                if not stat.S_ISDIR(target_info.st_mode) or target_info.st_uid != os.getuid() or target_info.st_mode & 0o022:
                    raise OperatorError('Небезопасный путь нового /work')
            digest = hashlib.sha256()
            copied = copy_regular_file(source / relative.name, destination / relative.name,
                                       max_bytes=int(allowed[name]['bytes']), hasher=digest)
            if (copied != int(allowed[name]['bytes']) or
                    digest.hexdigest() != allowed[name].get('sha256')):
                (destination / relative.name).unlink(missing_ok=True)
                raise OperatorError('Архивный файл изменился')
            restored.append(name)
        if restored:
            note = target_root / 'NOTES.md'
            fd = os.open(note, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
            try:
                fcntl.flock(fd, fcntl.LOCK_EX)
                info = os.fstat(fd)
                if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or
                        info.st_mode & 0o077 or info.st_size > 131000):
                    raise OperatorError('Небезопасный NOTES.md нового /work')
                note_size = info.st_size
                summary = ', '.join(safe_display(name)[:80] for name in restored[:10])
                text = f'\n# Восстановлено из архива в /work: {summary}'
                if len(restored) > 10:
                    text += f' и ещё {len(restored) - 10} файлов'
                addition = (text + '\n').encode('utf-8')
                if note_size + len(addition) > 131072:
                    raise OperatorError('Новый NOTES.md превысит лимит')
                os.lseek(fd, 0, os.SEEK_END)
                try:
                    while addition:
                        addition = addition[os.write(fd, addition):]
                except Exception:
                    os.ftruncate(fd, note_size)
                    raise
            finally:
                os.close(fd)
    except Exception:
        for name in reversed(restored):
            relative = archive_relative_path(name)
            target_root.joinpath(*relative.parts).unlink(missing_ok=True)
        raise
    return restored


def offer_archive_restore(archive, new_id):
    items = [item['path'] for item in archive['files'] if item['path'] != 'NOTES.md']
    if not items:
        return []
    line('  Файлы архива: ' + ', '.join(safe_display(name) for name in items[:20]) +
         (f' … (+{len(items) - 20})' if len(items) > 20 else ''))
    raw = input('  Восстановить файлы в новый /work (точные имена через запятую, Enter — нет): ').strip()
    if not raw:
        return []
    selected = [part.strip() for part in raw.split(',') if part.strip()]
    restored = restore_archive_files(archive, new_id, selected)
    line(f'  ✓ Восстановлено файлов в /work: {len(restored)}.')
    return restored


def op_status(args):
    with connect() as db:
        from orchestrator import master_scheduler as scheduler
        from orchestrator import network_jobs as jobs
        jobs.initialize(db)
        data = scheduler.compact_status(db, args.task_id)
        data['stop_reason'] = None
        render_results(db, data, json_output=args.json, verbose=args.verbose)
        approval = db.execute('SELECT allowed,egress,closed_at FROM pm_operator_approvals WHERE task_id=?',
                              (args.task_id,)).fetchone()
        if approval and not args.json:
            line(f'  Scope: {approval[0]} через {approval[1]}' +
                 (' (закрыт)' if approval[2] else ''))
        linkage = db.execute('''SELECT previous_task_id,previous_target FROM pm_task_lineage
                                WHERE successor_task_id=?''', (args.task_id,)).fetchone()
        if linkage and not args.json:
            line(f'  Предыдущая стадия: задача #{linkage[0]}, IP {linkage[1]} (история сохранена)')
        next_stage = db.execute('SELECT successor_task_id,successor_target FROM pm_task_lineage WHERE previous_task_id=?',
                                (args.task_id,)).fetchone()
        if next_stage and not args.json:
            line(f'  Продолжение: задача #{next_stage[0]}, IP {next_stage[1]}')
        aliases = db.execute('SELECT hostnames_json FROM pm_task_hostnames WHERE task_id=?',
                             (args.task_id,)).fetchone()
        if aliases and not args.json:
            line('  Имена хоста: ' + ', '.join(json.loads(aliases[0])))


def op_hosts(args):
    with connect() as db:
        target = configure(db, args.task_id, args)
        line('  Готово. Вне namespace системный /etc/hosts не менялся.')


@diagnostics.stage
def op_attack(args):
    """Run the role cycle in this process; the key never touches argv or env."""
    if str(ROOT) not in sys.path:
        sys.path.insert(0, str(ROOT))
    from orchestrator import attack_loop
    with connect() as db:
        save_flag_options(db, args.task_id, args)
        objective_state = save_objective_options(db, args.task_id, args)

    key = session_api_key(args, required=True)
    roles = tuple(item.strip().lower() for item in
                  str(getattr(args, 'roles', 'recon,vuln,access,verify')).split(',')
                  if item.strip())
    limit = int(getattr(args, 'max_tokens', None)
                or attack_loop.agent_actions.DEFAULT_MAX_TOKENS)
    expect = int(getattr(args, 'expect_flags', None) or
                 (objective_state['expected_flags'] or len(objective_state['objectives'])
                  if objective_state['primary'] else attack_loop.DEFAULT_EXPECTED_FLAGS))
    if not 1 <= expect <= attack_loop.MAX_EXPECTED_FLAGS:
        raise OperatorError(f'Ожидаемое число флагов должно быть от 1 до {attack_loop.MAX_EXPECTED_FLAGS}')
    heading(f'Ролевой цикл - задача #{args.task_id}')
    line('  ' + tint('решает оркестратор: ' + ' -> '.join(roles), 'bright'))
    line('  ' + tint(f'итераций {args.iterations} · шагов на роль {args.step_limit} '
                     f'· PoC-бюджет {args.poc_budget} · лимит вывода {limit} токенов '
                     f'· ожидается флагов {expect}', 'muted'))
    if objective_state['primary']:
        primary = objective_state['primary']
        sides = [row for row in objective_state['objectives'] if row['role'] == 'secondary']
        side_text = ', '.join(f'{row["title"][:24]} {row["weight"]}' for row in sides) or 'нет'
        mode_text = {'goal-exclusive': 'эксклюзивный', 'goal-first': 'сначала цель',
                     'all-flags': 'все флаги'}[objective_state['mode']]
        line(f'  Цели: [ЦЕЛЬ {primary["weight"]}] {primary["title"][:60]} · '
             f'побочные: {side_text} · режим: {mode_text} · '
             f'ожидается флагов {expect}')
    line('  ' + tint('ниже — живой ход: каждый вызов инструмента печатается по мере '
                     'выполнения', 'muted'))
    line('')
    try:
        result = attack_loop.run(args.task_id, args.iterations, roles,
                                 args.poc_budget, args.step_limit, api_key=key,
                                 max_tokens=limit, expect_flags=expect)
    except KeyboardInterrupt:
        line('')
        line('  ' + tint('[СТОП]', 'danger') +
             ' Цикл прерван оператором; завершённые этапы остались в storage.')
        return
    line('')
    heading('Итог цикла')
    line('  ' + tint('Остановка:', 'muted') + ' ' + safe_display(result['stop_reason']))
    for row in result.get('objectives_matrix') or []:
        line('  ' + safe_display(row))
    for stage in result.get('stages', []):
        ok = stage.get('status') == 'completed'
        head = f"  [итер {stage.get('iteration', '?')}] {stage.get('role', '?'):<7}"
        if ok:
            detail = (f"шагов {stage.get('steps_used', 0)} · "
                      f"находок {stage.get('findings', 0)}")
        else:
            detail = safe_display(stage.get('error', 'ошибка'))[:160]
        line(tint(head, 'bright') + ' ' + tint(detail, 'muted'))
        labels = attack_loop.stage_flags(stage)
        if labels:
            line('           ' + tint('флаги: ' + labels, 'brand'))
    flags = result.get('confirmed_flags') or []
    details = {item['value']: item for item in result.get('flag_details') or []}
    def show_flag(value):
        item = details.get(value, {})
        marker = ' · оператор' if item.get('operator_confirmed') else ''
        objective_key = item.get('objective_key')
        label = 'ЦЕЛЬ' if objective_key == 'goal' else objective_key or '—'
        return (f'[{label}] {value} [evidence_source: {item.get("evidence_source", "none")}; '
                f'matched_by: {item.get("matched_by", "default")}{marker}]')
    expected = result.get('expected_flags')
    line('')
    line('  ' + tint('Подтверждено:', 'muted') + ' ' +
         (tint(', '.join(show_flag(value) for value in flags), 'brand') if flags else tint('пока нет', 'muted')) +
         (tint(f'  ({len(flags)} из {expected})', 'muted') if expected else ''))
    candidates = result.get('candidate_flags') or []
    if candidates:
        line('  ' + tint('Кандидаты (требуют переподтверждения):', 'muted') + ' ' +
             tint(', '.join(show_flag(value) for value in candidates), 'warning'))
    report = result.get('loop_report', '')
    if report:
        line('  ' + tint('Отчёт цикла:', 'muted') + ' ' + safe_display(report))
    if result.get('last_summary'):
        line('')
        line('  ' + tint('Последняя сводка:', 'muted'))
        for chunk in result['last_summary'].splitlines()[:8]:
            line('   ' + safe_display(chunk))
    stale = 0
    try:
        with connect() as db:
            for task_id in netguard_live_tasks():
                state, _ = netguard_task_state(db, task_id)
                if state in ('closed', 'solved', 'orphan'):
                    stale += 1
    except (sqlite3.Error, OSError):
        stale = 0
    if stale:
        line('  ' + tint(f'Сетей закрытых/забытых задач: {stale} — убрать: pm > 8',
                         'muted'))


def flags_confirmed_by_evidence(db, task_id):
    """Two automatically confirmed flag values with captured evidence."""
    name = db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='pm_verified_flags'").fetchone()
    if not name:
        return False
    columns = {row[1] for row in db.execute('PRAGMA table_info(pm_verified_flags)')}
    if not {'value', 'status', 'evidence_count'}.issubset(columns):
        raise OperatorError('Схема реестра флагов несовместима: нужны value/status/evidence_count')
    rows = db.execute(
        "SELECT value, status, evidence_count FROM pm_verified_flags WHERE task_id=?",
        (task_id,),
    ).fetchall()
    return sum(1 for value, status, count in rows
               if value and status == 'confirmed' and int(count or 0) >= 2) >= 2


def offer_cleanup_if_verified(db, task_id, result):
    if not flags_confirmed_by_evidence(db, task_id):
        line('  Статус цели: флаги не подтверждены; изоляция сохранена.')
        return
    heading('Цель выполнена — завершение задачи')
    line('  Оба флага подтверждены записями инструмента в SQLite.')
    response = input('Удалить изолированную сеть и правила NetGuard? yes/no: ').strip().lower()
    if response != 'yes':
        line('  Правила сохранены, задачу можно продолжить.')
        return
    from argparse import Namespace
    op_close(Namespace(task_id=task_id, _confirmed_cleanup=True))


def op_close(args):
    with connect() as db:
        target = task_target(db, args.task_id)
        if not getattr(args, '_confirmed_cleanup', False):
            response = input(f'Удалить сетевые правила задачи #{args.task_id} ({target})? yes/no: ').strip().lower()
            if response != 'yes':
                line('  Сетевые правила сохранены. Задачу можно продолжить позже.')
                return
        broker_is_trusted()
        sudo_authenticate()
        data, rc = sudo_checked(['status', '--task-id', str(args.task_id)], allow_error=True)
        if rc == 0:
            result, _ = sudo_checked(['teardown', '--task-id', str(args.task_id)], timeout=45)
            if result.get('status') != 'removed':
                raise OperatorError('NetGuard не подтвердил удаление')
            line('  ✓ Сетевое пространство и правила удалены')
        else:
            error = str(data.get('error', '')).lower()
            if 'not configured' not in error and 'not found' not in error:
                raise OperatorError('Не удалось проверить состояние NetGuard: ' + error)
            line('  Сеть уже отсутствует')
        with db:
            db.execute('UPDATE pm_operator_approvals SET closed_at=? WHERE task_id=?',
                       (datetime.now(timezone.utc).isoformat(), args.task_id))
        line(f'Задача #{args.task_id} закрыта в интерфейсе Pentest Master.')
        line('Данные и отчёты SQLite сохранены.')


def netguard_live_tasks():
    """Task IDs that still own a host veth (pmh<id>), read without sudo."""
    try:
        proc = subprocess.run(['ip', '-o', 'link', 'show'], capture_output=True,
                              text=True, stdin=subprocess.DEVNULL, timeout=10)
    except (OSError, subprocess.SubprocessError):
        return []
    ids = set()
    for line in proc.stdout.splitlines():
        match = re.search(r'\bpmh(\d+)\b', line)
        if match:
            ids.add(int(match.group(1)))
    return sorted(ids)


def loop_goal_reached(task_id):
    """True when a loop run for this task captured the flags it was asked for.

    A confirmed-flag count is not a completion signal: task 18 held 2 of the 4
    flags it needed and would have been classified as solved, so `pm > 8` would
    have torn down a live room. Each loop report records what was asked for and
    what was captured, so completion is judged from that, never from a partial
    count.
    """
    directory = ROOT / 'storage/agent_reports' / f'task_{task_id}'
    for path in directory.glob('loop-*.json'):
        try:
            data = json.loads(path.read_text())
        except (ValueError, OSError):
            continue
        if data.get('status') != 'completed' or data.get('succeeded') is not True:
            continue
        if data.get('stop_reason') in ('goal_confirmed', 'objectives_done'):
            return True
        expected = int(data.get('expected_flags') or 0)
        confirmed = len(data.get('confirmed_flags') or [])
        if expected and confirmed >= expected:
            return True
    return False


def netguard_task_state(db, task_id):
    """closed / solved / orphan / active for a task that still holds a namespace.

    "solved" means a loop run captured every flag the operator asked for, so the
    room is done even though it was never closed explicitly.
    """
    row = db.execute('SELECT status, target FROM tasks WHERE id=?', (task_id,)).fetchone()
    if row is None:
        return 'orphan', 'нет в базе'
    status, target = str(row[0] or ''), str(row[1] or '')
    closed = db.execute('SELECT closed_at FROM pm_operator_approvals WHERE task_id=?',
                        (task_id,)).fetchone()
    if (closed and closed[0]) or status.lower() in ('completed', 'closed'):
        return 'closed', target
    if loop_goal_reached(task_id):
        return 'solved', target
    return 'active', target


def op_cleanup(args):
    """Remove namespaces of tasks that are finished or no longer known.

    Closing a task ([04]) always tore its namespace down, but nothing removed
    the namespaces of tasks that were simply left behind, so they accumulated
    as pmh10/pmh15/pmh16/pmh17. This lists them and removes the ones that are
    not active, using the same root broker teardown path as close.
    """
    live = netguard_live_tasks()
    heading('Уборка сетевых пространств')
    if not live:
        line('  ' + tint('Сетевых пространств нет — убирать нечего.', 'muted'))
        return
    with connect() as db:
        rows = [(task_id, *netguard_task_state(db, task_id)) for task_id in live]
    labels = {'closed': 'закрыта', 'solved': 'решена',
              'orphan': 'нет в базе', 'active': 'активна'}
    for task_id, state, target in rows:
        mark = '•' if state == 'active' else '✓'
        line(f'  {mark} pmns{task_id:<3} {safe_display(target)[:16]:<16} '
             + tint(labels[state], 'muted' if state == 'active' else 'warning'))
    removable = [task_id for task_id, state, _ in rows
                 if state in ('closed', 'solved', 'orphan')
                 or getattr(args, 'all_tasks', False)]
    if getattr(args, 'dry_run', False):
        line('')
        line('  ' + tint(f'К удалению: {len(removable)} из {len(live)} (dry-run, ничего не менялось)',
                         'muted'))
        return
    if not removable:
        line('')
        line('  ' + tint('Все пространства принадлежат активным задачам — ничего не удаляю.',
                         'muted'))
        return
    if not getattr(args, 'yes', False):
        names = ', '.join('pmns' + str(task_id) for task_id in removable)
        answer = input(f'  Удалить {len(removable)} ({names})? yes/no: ').strip().lower()
        if answer != 'yes':
            line('  Ничего не удалено.')
            return
    broker_is_trusted()
    if not broker_is_callable():
        # No NOPASSWD rule: ask for a password, but only where a terminal exists.
        if not sys.stdin.isatty():
            raise OperatorError('Нет доступа к NetGuard: установи правило sudoers '
                                '(scripts/install_netguard_sudoers.sh) или запусти из терминала')
        sudo_authenticate()
    removed, failed = [], []
    for task_id in removable:
        data, rc = sudo_checked(['teardown', '--task-id', str(task_id)],
                                timeout=45, allow_error=True)
        if rc == 0 and data.get('status') == 'removed':
            removed.append(task_id)
        else:
            failed.append((task_id, str(data.get('error') or data.get('status') or 'unknown')))
    line('')
    for task_id in removed:
        line('  ' + tint('✓', 'success') + f' pmns{task_id} удалён')
    for task_id, error in failed:
        line('  ' + tint('!', 'warning') + f' pmns{task_id} не удалён: '
             + safe_display(error)[:140])
    line('')
    line('  ' + tint(f'Удалено {len(removed)} из {len(removable)}', 'muted'))


def op_http_policy(args):
    from orchestrator import http_artifacts as artifacts, http_discovery as web
    with connect() as db:
        web.init(db)
        task_target(db,args.task_id)
        if args.response_limit_mib is not None:
            artifacts.set_response_limit(db,args.task_id,args.response_limit_mib*1024*1024,
                                         datetime.now(timezone.utc).isoformat())
        line(f'HTTP задачи #{args.task_id}: до {artifacts.response_limit(db,args.task_id)//(1024*1024)} МиБ на ответ; '
             f'до {artifacts.MAX_TASK_BYTES//(1024*1024)} МиБ артефактов; запросов до {web.MAX_TOTAL}.')


def op_http_artifacts(args):
    from orchestrator import http_artifacts as artifacts, http_discovery as web
    if args.show and not args.path:
        raise OperatorError('Для просмотра текста укажи --path')
    if not 1 <= args.max_chars <= 32000 or args.offset < 0:
        raise OperatorError('max-chars 1..32000, offset >= 0')
    with connect() as db:
        web.init(db)
        query = 'SELECT path,artifact_id FROM pm_http_discovery WHERE task_id=? AND artifact_id IS NOT NULL'
        params = [args.task_id]
        if args.path:
            query += ' AND path=?'
            params.append(web._safe_path(args.path))
        rows = db.execute(query+' ORDER BY id LIMIT 24',params).fetchall()
        if not rows:
            line('Сохранённых HTTP-артефактов нет. Следующий resume создаст их для доступных ресурсов.')
        remaining = args.max_chars
        for path, aid in rows:
            info = artifacts.info(db,aid)
            line(f'{safe_display(path)} | artifact={aid} | {info["bytes_saved"]} Б | загрузка ' +
                 ('полная' if info['download_complete'] else 'частичная') + f' | SHA256={info["sha256"]}')
            if args.show and remaining:
                body, metadata = artifacts.load(db,args.task_id,aid)
                text,flags = artifacts.decode_body(body,metadata['headers'])
                if flags['text_skipped']:
                    line('Текст не показан: '+safe_display(flags['text_skipped']))
                    continue
                # Redact before slicing so an offset cannot cut away a secret's key.
                view = artifacts.diagnostic_text(text)[args.offset:args.offset+remaining]
                line('\n'.join(safe_display(row) for row in view.splitlines()))
                remaining -= len(view)


def op_http_reparse(args):
    from orchestrator import http_discovery as web, master_scheduler as scheduler
    with scheduler.exclusive_run_lock(), connect() as db:
        results = web.reparse_saved(db,args.task_id,args.path)
    for result in results:
        line(f'{safe_display(result["path"])}: локальный разбор, assets={result["assets"]}, paths={result["references"]}')
    if not results:
        line('Нет сохранённых артефактов для разбора.')


def parser_main():
    parser = argparse.ArgumentParser(description='Pentest Master — удобная операторская консоль')
    sub = parser.add_subparsers(dest='command', required=False)
    policy = sub.add_parser('http-policy',help='Предел HTTP-ответа конкретной задачи')
    policy.add_argument('task_id',type=int)
    policy.add_argument('--response-limit-mib',type=int,choices=(2,8))
    artifacts = sub.add_parser('http-artifacts',help='Локальные HTTP-артефакты без сети и модели')
    artifacts.add_argument('task_id',type=int)
    artifacts.add_argument('--path')
    artifacts.add_argument('--show',action='store_true',help='Показать ограниченный диагностический текст')
    artifacts.add_argument('--offset',type=int,default=0)
    artifacts.add_argument('--max-chars',type=int,default=12000)
    reparse = sub.add_parser('http-reparse',help='Повторно разобрать HTTP-артефакты без сети и модели')
    reparse.add_argument('task_id',type=int)
    reparse.add_argument('--path')
    new = sub.add_parser('new', help='Создать задачу через GLM и начать разведку после подтверждения')
    new.add_argument('--target', required=True)
    new.add_argument('--task', required=True)
    new.add_argument('--hints', help='Зацепки оператора для агентов (проверяются инструментами)')
    new.add_argument('--hints-file', help='Файл подсказок UTF-8 с переносами строк')
    intent = sub.add_parser('intent', help='Восстановить описание и ограничения с историей')
    intent.add_argument('task_id', type=int)
    intent.add_argument('--task', required=True)
    intent.add_argument('--source', required=True)
    intent.add_argument('--hints', help='Зацепки оператора для агентов (проверяются инструментами)')
    intent.add_argument('--hints-file', help='Файл подсказок UTF-8 с переносами строк')
    intent.add_argument('--force-unreachable', action='store_true',
                        help='Флаг совместимости; проверка доступности выполняется при запуске задачи')
    resume = sub.add_parser('resume', help='Продолжить существующую задачу')
    resume.add_argument('task_id', type=int)
    resume.add_argument('--reprobe', help='Однократно перепроверить 1..32 порта после ремонта сети, напр. 22,80')
    status = sub.add_parser('status', help='Показать краткий отчёт')
    status.add_argument('task_id', type=int)
    close = sub.add_parser('close', help='Удалить NetGuard правила и namespace')
    close.add_argument('task_id', type=int)
    change = sub.add_parser('change-ip', help='Перенести расследование на новый IP с сохранением истории')
    change.add_argument('task_id', type=int)
    change.add_argument('--target', required=True)
    change.add_argument('--egress')
    change.add_argument('--max-jobs', type=int, default=8)
    change.add_argument('--max-rounds', type=int, default=4)
    change.add_argument('--no-agents', action='store_true')
    change.add_argument('--no-decide', action='store_true')
    change.add_argument('--sync-burp', action='store_true')
    change.add_argument('--json', action='store_true')
    change.add_argument('--verbose', action='store_true')
    change.add_argument('--archive-work', action='store_true',
                        help='Архивировать старый /work до teardown (не более 200 МБ)')
    attack = sub.add_parser('attack', help='Запустить ролевой цикл атаки (recon/vuln/access/verify)')
    attack.add_argument('task_id', type=int)
    attack.add_argument('--iterations', type=int, default=7)
    attack.add_argument('--roles', default='recon,vuln,access,verify')
    attack.add_argument('--poc-budget', type=int, default=7)
    attack.add_argument('--step-limit', type=int, default=15)
    attack.add_argument('--max-tokens', type=int, default=None,
                        help='Предел вывода на один ход роли (по умолчанию 24000)')
    attack.add_argument('--expect-flags', type=int, default=None,
                        help='Сколько флагов добыть (без целей — 2; с целями — 1 + число побочных)')
    for cmd in (new, intent, resume, attack):
        cmd.add_argument('--objective', action='append',
                         help='Побочная цель в формате вес:описание; повторяется')
        cmd.add_argument('--objectives-file', help='Файл побочных целей UTF-8, по одной в строке')
        cmd.add_argument('--goal-weight', default=None,
                         help='Вес основной цели от 1 до 10000 (по умолчанию 100)')
        cmd.add_argument('--goal-exclusive', action='store_true',
                         help='Остановиться сразу после подтверждения основной цели')
        cmd.add_argument('--goal-first', action='store_true',
                         help='Сначала основная цель, затем побочные до ожидаемого числа')
        cmd.add_argument('--all-flags', action='store_true',
                         help='Прежний режим: искать флаги до ожидаемого числа')
        cmd.add_argument('--flag-pattern', action='append', help='Дополнительный regex флага; повторяется')
        cmd.add_argument('--flag-prefix', action='append', help='Префиксы через запятую, например THM,HTB')
        cmd.add_argument('--flag-shape', action='append', help='Формы через запятую: uuid,uuid_nohyphen,hex32,hex40,b64,digits')
        cmd.add_argument('--flag-expect', action='append', help='Ожидаемое буквальное значение; повторяется')
        cmd.add_argument('--flag-expect-file', help='Файл ожидаемых значений UTF-8, по одному в строке')
    for cmd in (new, intent, resume):
        cmd.add_argument('--expect-flags', default=None,
                         help='Ожидаемое число флагов; с целями по умолчанию 1 + число побочных')
    cleanup = sub.add_parser('cleanup', help='Удалить namespace закрытых и забытых задач')
    cleanup.add_argument('--all', dest='all_tasks', action='store_true',
                         help='Включить и активные задачи')
    cleanup.add_argument('--yes', action='store_true', help='Без подтверждения')
    cleanup.add_argument('--dry-run', dest='dry_run', action='store_true',
                         help='Только показать, ничего не удалять')
    hosts = sub.add_parser('hosts', help='Задать домены для IP внутри NetGuard')
    hosts.add_argument('task_id', type=int)
    hosts.add_argument('--hostnames', required=True, help='Имена через запятую, все → IP задачи')
    hosts.add_argument('--egress')
    for cmd in (new, resume):
        cmd.add_argument('--force-unreachable', action='store_true',
                         help='Продолжить после неудачной проверки доступности цели')
        cmd.add_argument('--egress', help='Явно выбрать интерфейс (напр. tun0); по умолчанию берётся из маршрута')
        cmd.add_argument('--hostnames', help='Имена сайтов, разделённые запятыми; все → IP задачи')
        cmd.add_argument('--max-jobs', type=int, default=8)
        cmd.add_argument('--max-rounds', type=int, default=4)
        cmd.add_argument('--no-agents', action='store_true')
        cmd.add_argument('--no-decide', action='store_true')
        cmd.add_argument('--sync-burp', action='store_true')
        cmd.add_argument('--json', action='store_true', help='Показать полный машинный результат')
        cmd.add_argument('--verbose', action='store_true', help='Полные отчёты агентов')
    status.add_argument('--json', action='store_true')
    status.add_argument('--verbose', action='store_true')
    return parser, parser.parse_args()


def compose_task_description(objective, constraints, hints=''):
    """Per-task operator restrictions and leads; no hardcoded global prohibition.

    Hints are leads the operator already has (a login form, an odd port, a
    default credential to try). The text says they are unverified, so the
    planner and the action agents verify them with tools instead of treating
    them as an approved action or a reason to leave the task scope.
    """
    objective = str(objective or '').strip()
    constraints = str(constraints or '').strip()
    hints = str(hints or '').strip()
    if not objective:
        raise OperatorError('Нужно описание задачи')
    text = objective
    if constraints:
        text += '\nОграничения: ' + constraints
    if hints:
        text += ('\nПодсказки оператора (зацепки для проверки, не доказанные '
                 'факты; действовать только в рамках текущего scope): ' + hints)
    validate_intent(text)
    return text


def interactive():
    banner()
    session = argparse.Namespace(_session_key=None)
    # One input per session; never persist secrets.
    session_api_key(session)
    entries = (
        ('1', 'НОВАЯ ЦЕЛЬ', 'Создать задачу и запустить разведку'),
        ('2', 'ПРОДОЛЖИТЬ', 'Возобновить работу по задаче'),
        ('3', 'ОТЧЁТ', 'Краткий статус и находки'),
        ('4', 'ЗАКРЫТЬ', 'Удалить правила только после yes'),
        ('5', 'ДОМЕНЫ', 'Привязать имена к IP внутри namespace'),
        ('6', 'СМЕНИТЬ IP', 'Новый адрес машины с сохранением истории'),
        ('7', 'АТАКА', 'Ролевой цикл: recon -> vuln -> access -> verify'),
        ('8', 'УБОРКА', 'Удалить сети закрытых и забытых задач'),
        ('0', 'ВЫХОД', 'Оставить сетевые правила без изменений'),
    )
    while True:
        heading('Главное меню')
        for code, label, hint in entries:
            marker = '[' + code.zfill(2) + ']'
            line('  ' + tint(marker, 'muted' if code == '0' else 'brand') +
                 '  ' + tint(f'{label:<14}', 'bright') + ' ' + tint(hint, 'muted'))
        line('')
        choice = input(tint('  pm', 'brand') + tint(' > ', 'bright')).strip()
        if choice == '0':
            line('Завершено. Никаких фоновых задач не запущено.')
            return
        if choice not in ('1', '2', '3', '4', '5', '6', '7', '8'):
            line('  Выбери 0–8.')
            continue
        args = argparse.Namespace(
            _session_key=session._session_key, egress=None, max_jobs=8,
            max_rounds=4, no_agents=False, no_decide=False,
            sync_burp=False, json=False, verbose=False, reprobe=None,
            hostnames=None, hints=None, iterations=7,
            flag_pattern=None, flag_prefix=None, flag_shape=None,
            flag_expect=None, flag_expect_file=None, force_unreachable=False,
            objective=None, objectives_file=None, goal_weight=None,
            goal_exclusive=False, goal_first=False, all_flags=False,
            expect_flags=None,
            roles='recon,vuln,access,verify', poc_budget=7, step_limit=15,
            all_tasks=False, yes=False, dry_run=False, archive_work=False,
        )
        try:
            if choice == '1':
                args.target = validate_target(input('IP лабораторной машины: ').strip())
                task = input('Что требуется сделать: ').strip()
                side = input('Дополнительные флаги-цели (вес:описание через ; Enter — нет): ').strip()
                if side:
                    from orchestrator.objectives import split_specs
                    args.objective = split_specs(side)
                args.goal_exclusive = (input('Основная цель эксклюзивна (побочные не дают баллов)? [y/N]: ')
                                       .strip().lower() in ('y', 'yes', 'д', 'да'))
                default_expect = (1 + len(args.objective or []) if
                                  args.objective or args.goal_exclusive else 2)
                raw = input(f'Сколько флагов ожидать (Enter — {default_expect}): ').strip()
                args.expect_flags = int(raw) if raw else (
                    default_expect if args.objective or args.goal_exclusive else None)
                limits = input('Дополнительные ограничения (Enter — нет дополнительных): ').strip()
                hints = input('Подсказки и зацепки (Enter — нет): ').strip()
                args.task = compose_task_description(task, limits, hints)
                patterns = input('Дополнительные шаблоны флагов (Enter — стандартные): ').strip()
                args.flag_pattern = [patterns] if patterns else None
                args.force_unreachable = (input('Продолжить, если цель недоступна? [y/N]: ')
                                          .strip().lower() in ('y', 'yes', 'д', 'да'))
                args.hostnames = input('Домены сайта (через запятую, Enter если нет): ').strip()
                op_new(args)
            elif choice == '2':
                args.task_id = int(input('Номер задачи: ').strip())
                args.force_unreachable = (input('Продолжить, если цель недоступна? [y/N]: ')
                                          .strip().lower() in ('y', 'yes', 'д', 'да'))
                op_resume(args)
            elif choice == '3':
                args.task_id = int(input('Номер задачи: ').strip())
                op_status(args)
            elif choice == '4':
                args.task_id = int(input('Номер задачи: ').strip())
                op_close(args)
            elif choice == '5':
                args.task_id = int(input('Номер задачи: ').strip())
                args.hostnames = input('Доменные имена (через запятую): ').strip()
                op_hosts(args)
            elif choice == '6':
                args.task_id = int(input('Номер задачи с прежним IP: ').strip())
                args.target = validate_target(input('Новый IP машины: ').strip())
                args.archive_work = (input('Архивировать старый /work до смены IP? [y/N]: ')
                                     .strip().lower() in ('y', 'yes', 'д', 'да'))
                op_change_ip(args)
            elif choice == '8':
                op_cleanup(args)
            else:
                args.task_id = int(input('Номер задачи: ').strip())
                patterns = input('Дополнительные шаблоны флагов (Enter — стандартные): ').strip()
                args.flag_pattern = [patterns] if patterns else None
                raw = input('Итераций (Enter — 7): ').strip()
                args.iterations = int(raw) if raw else 7
                args.roles = (input('Роли через запятую '
                                    '(Enter — recon,vuln,access,verify): ').strip()
                              or 'recon,vuln,access,verify')
                raw = input('Шагов на роль (Enter — 15): ').strip()
                args.step_limit = int(raw) if raw else 15
                raw = input('PoC-бюджет на роль (Enter — 7): ').strip()
                args.poc_budget = int(raw) if raw else 7
                raw = input('Сколько флагов ожидать (Enter — из целей задачи, иначе 2): ').strip()
                args.expect_flags = int(raw) if raw else None
                op_attack(args)
        except (OperatorError, ValueError, RuntimeError, OSError, sqlite3.Error,
                subprocess.SubprocessError, ImportError) as exc:
            line('  ' + tint('[ОШИБКА]', 'danger', stream=sys.stderr) + ' ' + safe_display(exc), stream=sys.stderr)
        except KeyboardInterrupt:
            line('\nОперация прервана; сохранённые результаты остаются.')
            return


@diagnostics.entrypoint
def main():
    # The bundled Harness runtime needs IPv4-first connections without
    # AddressFamily auto-selection; without it every model call dies as
    # TRANSPORT before reaching the gateway. Children inherit NODE_OPTIONS.
    if str(ROOT) not in sys.path:
        sys.path.insert(0, str(ROOT))
    try:
        from orchestrator.harness_env import ensure_process_env
    except ImportError as exc:  # pragma: no cover - defensive only
        line('  ' + tint('[!]', 'warning') +
             ' Не удалось включить сетевые флаги Harness: ' + str(exc)[:160])
    else:
        ensure_process_env()

    parser, args = parser_main()
    if args.command is None:
        try:
            interactive()
        except KeyboardInterrupt:
            line('\nЗавершено оператором.')
        return
    if args.command in ('new', 'resume', 'change-ip'):
        if not 1 <= args.max_jobs <= 12 or not 1 <= args.max_rounds <= 8:
            parser.error('max-jobs 1..12, max-rounds 1..8')
    try:
        if args.command == 'new': op_new(args)
        elif args.command == 'intent': op_intent(args)
        elif args.command == 'resume': op_resume(args)
        elif args.command == 'status': op_status(args)
        elif args.command == 'http-artifacts': op_http_artifacts(args)
        elif args.command == 'http-reparse': op_http_reparse(args)
        elif args.command == 'http-policy': op_http_policy(args)
        elif args.command == 'close': op_close(args)
        elif args.command == 'hosts': op_hosts(args)
        elif args.command == 'attack': op_attack(args)
        elif args.command == 'cleanup': op_cleanup(args)
        elif args.command == 'change-ip': op_change_ip(args)
    except (OperatorError, ValueError, RuntimeError, OSError, sqlite3.Error,
            subprocess.SubprocessError, ImportError) as exc:
        line('\n' + tint('[ОШИБКА]', 'danger', stream=sys.stderr) + ' ' + safe_display(exc), stream=sys.stderr)
        raise SystemExit(1)
    except KeyboardInterrupt:
        line('\nОстановлено оператором. Завершённые результаты сохранены.', stream=sys.stderr)
        raise SystemExit(130)


if __name__ == '__main__':
    main()
