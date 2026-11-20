"""Read-only projections for the operator's diagrams and timeline."""
from datetime import datetime, timezone
import hashlib
import ipaddress
import json
import math
import re
from urllib.parse import urlsplit, urlunsplit

from orchestrator import diagnostics, pivoting, service_inventory, task_memory, task_view


EVENT_LABELS = {
    'run.start': 'Начало вызова PM', 'run.end': 'Завершение вызова PM', 'run.summary': 'Итог вызова PM',
    'stage.start': 'Начало стадии', 'stage.end': 'Завершение стадии', 'run.stop': 'Остановка',
    'coordinator.decision': 'Назначение координатора', 'coordinator.decision_rejected': 'Отклонено решение',
    'coordinator.pause': 'Пауза координатора', 'coordinator.pause_resolved': 'Пауза рассмотрена',
    'coordinator.state_changed': 'Обновлено состояние исследования',
    'specialist.start': 'Запуск специалиста', 'specialist.end': 'Завершение специалиста',
    'specialist.session': 'Сессия специалиста', 'specialist.cancel_requested': 'Запрошена отмена специалиста',
    'specialist.cancelled': 'Специалист отменён', 'state.change': 'Обновлена запись',
    'operator.question': 'Вопрос оператору', 'operator.answer': 'Ответ оператора',
    'tool.start': 'Начало вызова инструмента', 'tool.end': 'Результат инструмента',
    'capability.result': 'Сохранён результат операции', 'report.saved': 'Сохранён отчёт',
    'report.format_failed': 'Повреждённый отчёт', 'model.request_start': 'Запрос модели',
    'model.request_end': 'Ответ модели', 'model.retry': 'Повтор запроса модели',
    'model.response_rejected': 'Ответ модели отклонён', 'context.compact': 'Сжатие контекста',
    'check.start': 'Начало проверки', 'check.end': 'Результат проверки', 'poc.checks': 'Учтены проверки PoC',
    'scan.result': 'Результат разведки', 'scan.followups': 'Следующие проверки разведки',
    'preflight.summary': 'Доступность известных сервисов', 'network.diagnostic': 'Диагностика доступности',
    'job.plan': 'Запланирована проверка', 'job.execution': 'Выполнение проверки',
    'cache.hit': 'Использованы сохранённые данные', 'pivot.state': 'Состояние маршрута',
    'session.state': 'Состояние сессии', 'target.availability': 'Доступность цели',
    'resource.configured': 'Сохранена область', 'resource.relationship': 'Сохранена связь ресурсов',
    'resource.address_changed': 'Адрес цели изменён', 'budget.used': 'Учтён расход бюджета',
    'budget.extension': 'Ответ по бюджету', 'tool.state': 'Состояние запроса инструмента',
}
STATUS = {
    'completed': 'завершён', 'running': 'выполняется', 'planned': 'запланирован', 'pending': 'ожидает',
    'waiting_operator': 'ожидает оператора', 'failed': 'ошибка', 'error': 'ошибка', 'blocked': 'отказ',
    'unknown': 'исход неизвестен', 'interrupted': 'прервано', 'timeout': 'истекло время',
    'nonzero_exit': 'ненулевой код выхода', 'cancelled': 'отменено', 'open': 'открыта',
    'disconnected': 'разорвана', 'closed': 'закрыта', 'active': 'действует',
    'declined': 'отклонено', 'approved': 'одобрено', 'prepared': 'подготовлено',
    'creating': 'создаётся', 'established_unverified': 'доступность не подтверждена',
    'broken_source': 'исходная сессия недоступна', 'finished': 'ответ сохранён',
}
OPERATIONS = {
    'net_exec': 'Сетевая команда', 'research': 'Обращение за внешними данными',
    'http_capture': 'Получение HTTP-ответа', 'http_request': 'HTTP-запрос', 'http_ssrf': 'HTTP-запрос через приложение',
    'poc_run': 'Запуск PoC', 'network_probe': 'Сетевая проверка', 'session': 'Действие с сессией',
    'browser': 'Действие в браузере', 'capability_read': 'Чтение сохранённого результата',
    'check_series': 'Серия проверок', 'pivot_status': 'Проверка состояния маршрута',
    'target_availability': 'Доступность цели', 'tcp_full_scan': 'Полный TCP-скан',
}
REASONS = {'flag_confirmation': 'Подтверждение флага', 'pivoting': 'Разрешение маршрута',
           'tool': 'Получение инструмента', 'budget': 'Расширение бюджета',
           'operator_questions_pending': 'Ожидается ответ оператора'}


def clean(value):
    return diagnostics.clean(value, limit=None, preserve_lines=True) if value is not None else ''


def label_status(value):
    return STATUS.get(value, clean(value)) if isinstance(value, str) else clean(value)


def operation(value):
    name = clean(value)
    return OPERATIONS.get(name.removeprefix('pm_'), name)


def actor_label(value):
    actor = clean(value)
    return {'coordinator': 'Координатор', 'mcp': 'MCP', 'recon': 'RECON',
            'vuln': 'VULN', 'access': 'ACCESS', 'verify': 'VERIFY'}.get(actor, actor or 'Не записан')


def safe_url(value):
    try:
        parsed = urlsplit(value)
        host = parsed.netloc.rsplit('@', 1)[-1]
        if '@' in parsed.netloc:
            host = '[REDACTED]@' + host
        return clean(urlunsplit((parsed.scheme, host, parsed.path,
                                 '[REDACTED]' if parsed.query else '', '')))
    except ValueError:
        return '[REDACTED]'


# Retain only known displayable arguments. Opaque shell, bodies, credentials and
# unclassified positional values remain in the original log, outside this API.
PUBLIC_OPTIONS = {'--task-id', '--target', '--profile', '--port', '--ports', '--scheme', '--path',
                  '--research-host', '--research-path', '--action', '--session-id', '--timeout', '--host',
                  '--method', '--hostname', '-X', '--request', '-p'}
SECRET_OPTIONS = {'-H', '--header', '-u', '--user', '--password', '--token', '--data', '--cookie',
                  '--ssh-json', '--spec-json', '-d', '--data-raw', '-c', '--command', '--data-binary'}
SWITCHES = {'-n', '--execute', '-s', '-sS', '-I', '-i', '-v', '--verbose', '-Pn', '-sT', '-sV'}
COMMAND_WORDS = {'run', 'poc', 'research', 'session', 'callback', 'pivot', 'transfer', 'http-capture'}


def command_argv(argv, *, nested=False):
    if not isinstance(argv, list) or not argv or not all(isinstance(arg, str) for arg in argv):
        return ''
    result = [clean(argv[0])]
    cursor = iter(argv[1:])
    for arg in cursor:
        option, sep, inline = arg.partition('=')
        if option == '--argv-json' and not nested:
            raw = inline if sep else next(cursor, '')
            try:
                value = command_argv(json.loads(raw), nested=True) or '[REDACTED]'
            except ValueError:
                value = '[REDACTED]'
        elif option in SECRET_OPTIONS or (option == '-p' and argv[0].rsplit('/', 1)[-1] not in ('nmap', 'ssh')):
            if not sep:
                next(cursor, '')
            value = '[REDACTED]'
        elif option in PUBLIC_OPTIONS and (option != '-p' or argv[0].endswith(('nmap', 'ssh'))):
            value = safe_url(inline if sep else next(cursor, ''))
        else:
            if arg in SWITCHES or arg in COMMAND_WORDS or arg == '/usr/local/sbin/pm-netguard':
                result.append(arg)
            elif arg.startswith(('https://', 'http://')):
                result.append(safe_url(arg))
            else:
                try:
                    ipaddress.ip_address(arg)
                except ValueError:
                    result.append('[REDACTED]')
                else:
                    result.append(arg)
            continue
        if sep:
            result.append(f'{option}={value}')
        else:
            result.extend((option, value))
    return json.dumps(result, ensure_ascii=False)


def json_lines(path, problems):
    """Tolerate torn lines and only open regular, non-symlinked journal files."""
    if path.is_symlink() or not path.is_file():
        return
    with path.open('rb') as stream:
        for line in stream:
            try:
                value = json.loads(line)
            except ValueError:
                problems.append(path)
                continue
            if isinstance(value, dict):
                yield value
            else:
                problems.append(path)


def time_key(value):
    try:
        stamp = float(value) if type(value) in (int, float) else datetime.fromisoformat(value).timestamp()
        return stamp if math.isfinite(stamp) else None
    except (ValueError, TypeError, OverflowError, OSError):
        return None


def timeline_record(key, timestamp, actor, action, result, source, kind, details, recorded=''):
    stamp = time_key(timestamp)
    if stamp is None:
        return None
    try:
        date = datetime.fromtimestamp(stamp, timezone.utc).isoformat()
    except (ValueError, OverflowError, OSError):
        return None
    return {'id': key, 'timestamp': stamp, 'date': date, 'actor': actor_label(actor),
            'action': action, 'result': result or 'Результат не записан', 'source': source,
            'kind': clean(kind), 'details': {label: clean(value) for label, value in details.items() if value is not None},
            'recorded': recorded}


def diagnostic_events(directory, task_id):
    saved = []
    damaged = False
    for path in sorted(directory.glob('*.jsonl')):
        if not re.fullmatch(r'[a-f0-9]{32}', path.stem):
            continue
        problems, owned = [], []
        try:
            for event in json_lines(path, problems):
                if event.get('run_id') != path.stem:
                    continue
                group = event.get('task_ids')
                if event.get('task_id') == task_id or (event.get('task_id') is None
                        and event.get('kind') in ('run.start', 'run.end', 'run.summary')
                        and isinstance(group, list) and task_id in group):
                    owned.append(event)
        except OSError:
            problems.append(path)
        saved.extend(owned)
        damaged |= bool(owned and problems)
    return saved, damaged


def event_view(event):
    kind = clean(event.get('kind'))
    event_id = event.get('event_id')
    if not isinstance(event_id, str) or not re.fullmatch(r'[a-f0-9]{32}', event_id):
        event_id = None
    ident = event_id or hashlib.sha256(json.dumps(event, sort_keys=True).encode()).hexdigest()
    action = EVENT_LABELS.get(kind, 'Запись PM')
    name = operation(event.get('name'))
    if name and kind in ('tool.start', 'tool.end', 'stage.start', 'stage.end', 'cache.hit'):
        action += ' · ' + name
    details = {'Запуск': event['run_id'], 'Событие': event_id,
               'Действие': event.get('action_id'), 'Шаг': event.get('step_id'),
               'Результат': event.get('result_id'), 'Код выхода': event.get('exit_code')}
    identifiers = event.get('identifiers')
    if isinstance(identifiers, dict):
        details.update({label: identifiers.get(key) for key, label in (
            ('question_id', 'Вопрос'), ('resource_id', 'Ресурс'), ('route_id', 'Маршрут'))})
    actor = event.get('role')
    if kind in ('operator.question', 'operator.answer'):
        actor = 'PM' if kind == 'operator.question' else 'Оператор'
    if kind.startswith('coordinator.'):
        actor = 'Координатор'
    result = label_status(event.get('status') or event.get('current_state'))
    reason = clean(event.get('reason_summary') or event.get('reason'))
    reason = REASONS.get(reason, reason)
    return timeline_record(f"event:{event['run_id']}:{ident}", event.get('timestamp'), actor or event.get('source'),
                           action, ' · '.join(filter(None, (result, reason))), 'Диагностика PM', kind,
                           details, command_argv(event.get('argv') or event.get('command')))


def capability_events(path, task_id, problems):
    for row in json_lines(path, problems):
        if row.get('task_id') != task_id or not re.fullmatch(r'[a-f0-9]{24}', str(row.get('id'))):
            continue
        result = row.get('result')
        result = result if isinstance(result, dict) else {}
        status = label_status(result.get('status'))
        code = result.get('exit_code')
        if type(code) is int:
            status = ' · '.join(filter(None, (status, f'код выхода {code}')))
        command = command_argv(row.get('argv'))
        if command and row.get('argv_truncated'):
            command += '\nЖурнал сохранил часть аргументов.'
        yield timeline_record(f"capability:{row['id']}", row.get('timestamp'), row.get('actor_role'),
                              operation(row.get('tool')) or 'Операция MCP', status, 'Журнал возможностей MCP',
                              row.get('tool'), {'Результат': row['id'], 'Запуск': row.get('run_id'),
                                               'Действие': row.get('action_id'), 'Шаг': row.get('coordinator_step_id')},
                              command)


def agents(data, events):
    # An assignment event is evidence of who issued a step. run_id in a step
    # row alone only says where it was stored.
    assignments = {e['step_id']: e for e in events if e.get('kind') == 'coordinator.decision'
                   and type(e.get('step_id')) is int and type(e.get('coordinator_run_id')) is int}
    nodes = {}
    edges = []
    if data['coordinator']['data']:
        run = data['coordinator']['data']
        key = f"coordinator:{run['id']}"
        nodes[key] = {'id': key, 'column': 'coordinator', 'title': 'Координатор',
                      'status': label_status(run.get('status')), 'note': f"Запуск #{run['id']}",
                      'details': {'Причина остановки': clean(run.get('stop_reason'))}}
    for step in data['steps']['data'] or []:
        if not step.get('role') or (step.get('action') and step['action'] != 'run_role'):
            continue
        key = f"step:{step['id']}"
        assignment = assignments.get(step['id'])
        parent = f"coordinator:{assignment['coordinator_run_id']}" if assignment else None
        if parent and parent not in nodes:
            nodes[parent] = {'id': parent, 'column': 'coordinator', 'title': 'Координатор', 'status': '',
                             'note': f"Запуск #{assignment['coordinator_run_id']}", 'details': {}}
        if parent:
            edges.append({'id': key, 'from': parent, 'to': key, 'kind': 'confirmed'})
        role = clean(step['role']).upper()
        profile = clean(step.get('profile'))
        nodes[key] = {'id': key, 'column': 'specialists', 'title': role,
                      'status': 'исход неизвестен' if step.get('outcome_uncertain') else label_status(step.get('status')),
                      'note': ' · '.join(filter(None, (f"Шаг #{step['step_no']}", profile,
                                                       '' if parent else 'Кто назначил — не записано'))),
                      'details': {'Поручение': clean(step.get('question')), 'Ошибка': clean(step.get('error')),
                                  'Назначение': 'Событие координатора' if parent else 'Источник назначения неизвестен',
                                  'ID шага': str(step['id'])}}
    return {'nodes': list(nodes.values()), 'edges': edges}


def question_scope(row):
    parts = []
    if row.get('branch_id'):
        parts.append('Ветка · ' + clean(row['branch_id']))
    if row.get('boundaries'):
        parts.append('Границы · ' + clean(json.dumps(row['boundaries'], ensure_ascii=False)))
    return '\n'.join(parts)


def target_map(db, task_id, data):
    target = data.get('target')
    target_key = f'target:{task_id}'
    snapshot = (data['snapshot']['data'] or {}).get('findings', {})
    ports = {(proto, r['port']): clean(r['service']) for proto in ('tcp', 'udp') for r in snapshot.get(proto, [])}
    for port in task_view.full_scan_ports(db, task_id, target):
        ports.setdefault(('tcp', port), '')
    for service in service_inventory.collect_full(db, task_id)['entries']:
        key = (service['protocol'], service['port'])
        names = sorted({clean(item['service_hint']) for item in service['identifications'] if item['service_hint']})
        if not ports.get(key):
            ports[key] = ' / '.join(names)
    inventory = [{'id': f'{proto}:{port}', 'label': f'{proto.upper()}/{port}', 'value': service or 'Сервис не записан'}
                 for (proto, port), service in sorted(ports.items())]
    scope = data['scope']['data'] or {}
    for origin in scope.get('origins', []):
        address = origin.get('origin')
        if address:
            inventory.append({'id': 'origin:' + clean(address), 'label': 'Приложение', 'value': safe_url(address)})
    for item in snapshot.get('web', []):
        if item.get('path'):
            identity = task_memory.digest([item.get(key) for key in ('hostname', 'port', 'path')])
            inventory.append({'id': f'snapshot:app:{identity}', 'label': f"HTTP {clean(item.get('status_code'))}".strip(),
                              'value': ' · '.join(filter(None, (safe_url(item['path']), clean(item.get('title')))))})
    for row in task_memory.rows(db, 'pm_http_artifacts', task_id, target=target):
        if row.get('target') != target or not row.get('path'):
            continue
        path = safe_url(row['path'])
        host = clean(row.get('hostname'))
        identity = task_memory.digest([row.get(key) for key in ('scheme', 'hostname', 'port', 'path')])
        inventory.append({'id': f'http:app:{identity}', 'label': f"HTTP {clean(row.get('status_code'))}".strip(),
                          'value': host + path})
    nodes = [{'id': target_key, 'column': 'target', 'title': clean(target), 'note': 'Цель задачи',
              'status': label_status((data['availability']['data'] or {}).get('state')),
              'details': {'Источник': 'Задача, сохранённые наблюдения и область исследования'}}]
    edges = []
    sessions = {}
    for row in sorted(task_memory.rows(db, 'pm_task_sessions', task_id), key=lambda r: r['session_id']):
        source = row['resource']
        key = 'session:' + row['session_id']
        sessions[row['session_id']] = key
        direct = source == target or any(source == o.get('origin') and target in o.get('addresses', [])
                                         for o in scope.get('origins', []))
        nodes.append({'id': key, 'column': 'sessions', 'title': clean(source) or 'Сохранённая сессия',
                      'note': clean(row.get('purpose')) or 'Сессия', 'status': label_status(row['state']),
                      'details': {'Сессия': clean(row['session_id']), 'Ресурс': clean(source),
                                  'Пользователь': clean(row.get('username')), 'Запись обновлена': clean(row.get('updated_at')),
                                  'Связь с целью': 'Ресурс из записи сессии' if direct else 'Связь не записана',
                                  'Источник': 'SQLite · pm_task_sessions', 'Доступность': 'Последнее сохранённое состояние'}})
        if direct:
            edges.append({'id': key, 'from': target_key, 'to': key,
                          'kind': 'confirmed' if row['state'] == 'open' else 'inactive'})
    resources = {r['id']: r for r in task_memory.rows(db, 'pm_resources', task_id)}
    for row in pivoting.listing(db, task_id):
        resource = resources.get(row['resource_ref'])
        key = f"pivot:{row['id']}"
        receipt = row['receipt'] if isinstance(row['receipt'], dict) else {}
        confirmed = row['state'] == 'active' and not row.get('diagnostic')
        pending = row['state'] in ('pending', 'prepared', 'approved', 'creating')
        kind = 'confirmed' if confirmed else 'pending' if pending else 'inactive'
        state = 'Ожидает подтверждения' if pending else 'Связь сохранена' if confirmed else label_status(row['state'])
        if row['state'] == 'active' and not confirmed:
            state = 'Квитанция не подтверждена'
        nodes.append({'id': key, 'column': 'destinations', 'title': clean(resource['value']) if resource else 'Связанный ресурс',
                      'note': f"Маршрут #{row['id']}", 'status': state,
                      'details': {'Источник': 'SQLite · pm_pivot_routes', 'Сессия': clean(row['source_session']),
                                  'Ресурс': clean(row['resource_ref']), 'Вопрос': clean(row.get('question_id')),
                                  'Квитанция': clean(receipt.get('request_id')), 'Состояние': state,
                                  'Доступность': 'Состояние по сохранённому результату; свежая проверка отсутствует'}})
        if row['source_session'] in sessions and resource:
            edges.append({'id': key, 'from': sessions[row['source_session']], 'to': key, 'kind': kind})
    return {'nodes': nodes, 'edges': edges, 'inventory': inventory}


def load(database, task_id):
    with task_view.read_database(database) as db:
        if not task_memory.exists(db, 'tasks'):
            return None
        data = task_view.task(db, task_id)
        if data is None:
            return None
        graph = task_view.section(lambda: target_map(db, task_id, data))
        exchanges = task_view.section(lambda: task_memory.rows(db, 'pm_http_exchanges', task_id))
    events, damaged = diagnostic_events(database.parent / 'run_events', task_id)
    history = [event_view(e) for e in events]
    capability_problems = []
    capabilities = task_view.section(lambda: list(capability_events(
        database.parent / 'capability_log' / f'task_{task_id}.jsonl', task_id, capability_problems)))
    history.extend(capabilities['data'] or [])
    for row in exchanges['data'] or []:
        history.append(timeline_record(f"http:{row['id']}", row.get('created_at'), row.get('session_id'),
                                       'Запись HTTP-запроса', label_status(row.get('phase')), 'SQLite · HTTP',
                                       'http.exchange', {'Обмен': row['id'], 'Артефакт': row.get('artifact_id')},
                                       f"{clean(row.get('method'))} {safe_url(row.get('url') or '')}".strip()))
    unique = {event['id']: event for event in history if event is not None}
    return {'task': task_id, 'agents': agents(data, events),
            'agents_error': any(data[name]['state'] == 'error' for name in ('coordinator', 'steps')),
            'map': graph['data'], 'map_state': graph['state'],
            'history': sorted(unique.values(), key=lambda e: (e['timestamp'], e['id'])),
            'questions': [{**{k: clean(q.get(k)) for k in ('id', 'kind', 'question', 'reason')},
                           'scope': question_scope(q)} for q in data['questions']['data'] or []],
            'questions_state': data['questions']['state'],
            'outcome': clean((data['outcome']['data'] or {}).get('label')),
            'history_error': damaged or bool(capability_problems) or
            capabilities['state'] == 'error' or exchanges['state'] == 'error'}
