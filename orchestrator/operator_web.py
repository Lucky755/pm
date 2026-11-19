"""Local HTTP viewer for saved PM data."""
import errno
from functools import partial
from html import escape
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import re
import sqlite3
from urllib.parse import unquote, urlsplit

from operator_errors import OperatorError
from orchestrator import task_view
from orchestrator.method_library import Library


STATE_MESSAGES = {
    'missing': 'Источник данных отсутствует.',
    'empty': 'Сохранённых записей нет.',
    'error': 'Ошибка чтения сохранённых данных.',
}
STATE_LABELS = {
    'completed': 'завершён',
    'failed': 'ошибка',
    'waiting_operator': 'ожидает оператора',
    'running': 'выполняется',
    'pending': 'ожидает',
    'planned': 'запланирован',
    'closed': 'закрыта',
    'open': 'не закрыта',
    'unknown': 'неизвестно',
    'active': 'действует',
    'withdrawn': 'отозван',
    'deactivated': 'выключена',
}


def text(value):
    return escape(str(value)) if value is not None and value != '' else 'нет данных'


def status(value):
    return text(STATE_LABELS.get(value, value) if isinstance(value, str) else value)


def page(title, body):
    return ('<!doctype html><html lang="ru"><meta charset="utf-8">'
            '<meta name="viewport" content="width=device-width, initial-scale=1">'
            f'<title>{text(title)} | Pentest Master</title><body>'
            '<nav><a href="/">Задачи</a> · Управление → <a href="/methods">Советы</a></nav>'
            f'<main><h1>{text(title)}</h1>{body}</main></body></html>')


def list_html(items):
    return '<ul>' + ''.join(f'<li>{item}</li>' for item in items) + '</ul>'


def block(title, source, render, *, empty=None):
    state = source['state']
    if state == 'ok':
        contents = render(source['data'])
    else:
        message = empty if state == 'empty' and empty else STATE_MESSAGES[state]
        if source.get('error') == 'WalDatabaseError':
            message = task_view.WAL_ERROR
        contents = f'<p>{text(message)}</p>'
    return f'<section><h2>{text(title)}</h2>{contents}</section>'


def details(row, labels):
    entries = []
    for key, label in labels.items():
        if key in row and row[key] != '':
            value = row[key]
            if isinstance(value, (list, dict)):
                value = json.dumps(value, ensure_ascii=False)
            entries.append(f'<dt>{text(label)}</dt><dd>{text(value)}</dd>')
    return '<dl>' + ''.join(entries) + '</dl>' if entries else '<p>Нет сохранённых сведений.</p>'


def report_label(report):
    number = report['iteration']
    name = report['reference']
    return f'{report["role"].upper()} #{number}' if number else name


def run_view(data):
    latest = data['latest']
    result = ''
    if latest:
        result = (f'<p>Вызов PM · {status(latest["status"] or "исход не записан")}</p>'
                  + details(latest, {'id': 'Run ID', 'name': 'Команда',
                                     'started_at': 'Время записи', 'reason': 'Причина остановки'}))
    if data['damaged']:
        result += '<p>Некоторые строки журнала не удалось прочитать.</p>'
    return result


def step_view(step):
    label = (f'Шаг #{text(step.get("step_no"))} · {text(step.get("role") or step.get("action"))}'
             f' · {status(step.get("status"))}')
    if step.get('profile'):
        label += f' · {text(step["profile"])}'
    if step.get('outcome_uncertain'):
        label += ' · исход неизвестен'
    return label + details(step, {'question': 'Поручение', 'error': 'Причина',
                                  'decision_error': 'Ошибка чтения'})


def task_page(data):
    task_id = data['id']
    outcome = data['outcome']['data']
    body = (f'<p>Адрес · {text(data.get("target"))}</p>'
            f'<p>Статус в SQLite · {status(data.get("status"))}</p>'
            f'<p>Закрытие задачи · {status(data["closure"])}</p>'
            f'<p id="goal-outcome">{text(outcome["label"] if outcome else STATE_MESSAGES[data["outcome"]["state"]])}</p>')
    if outcome and outcome.get('remaining_goals'):
        body += '<p>Есть цели, ожидающие подтверждения.</p>'
    if outcome and outcome.get('legacy_evidence_count') is not None:
        body += f'<p>Флагов со свидетельствами в прежнем реестре · {text(outcome["legacy_evidence_count"])}</p>'
    if data['intent']['state'] in ('empty', 'missing') and data.get('description'):
        body += '<h2>Сохранённое описание планировщика</h2><pre>' + text(data['description']) + '</pre>'
    body += block('Исходное задание и ограничения оператора', data['intent'], lambda value: f'<pre>{text(value)}</pre>')
    body += block('Цели', data['goals'], lambda goals: list_html(
        f'{text(goal.get("title"))} · {status(goal.get("status"))}' for goal in goals))
    body += block('Область задачи', data['scope'], lambda value: details(value, {
        'entry': 'Исходный ввод', 'area': 'Область', 'addresses': 'Адреса', 'host_addresses': 'Разрешённые хосты',
        'networks': 'Сети', 'origins': 'Веб-область и пути', 'denied': 'Исключения', 'ssrf': 'Явные назначения SSRF'}))
    if data['scope_settings']['state'] != 'missing':
        body += block('Ограничения задачи', data['scope_settings'], lambda value: details(
            value, {'allow_pivot': 'Pivoting', 'allow_port_forward': 'Перенаправление портов'}))
    body += block('Сохранённый допуск', data['approval'], lambda value: details(
        value, {'allowed': 'Разрешённые адреса', 'egress': 'Интерфейс', 'closed_at': 'Дата закрытия'}))
    if data['availability']['state'] != 'missing':
        body += block('Доступность со слов оператора или последней проверки', data['availability'], lambda value: details(
            value, {'state': 'Состояние', 'reason': 'Причина'}))
    body += block('Последний запуск PM', data['last_run'], run_view)
    if data['legacy_run']['state'] != 'missing':
        body += block('Последний сохранённый запуск планировщика', data['legacy_run'], lambda rows: details(
            rows[0], {'id': 'Номер', 'status': 'Статус', 'stop_reason': 'Причина остановки',
                      'started_at': 'Начало', 'finished_at': 'Окончание'}))
    body += block('Состояние координатора', data['coordinator'], lambda value:
                  f'<p>Координатор · {status(value.get("status"))}</p>' + details(
                      value, {'id': 'Номер', 'stop_reason': 'Причина остановки', 'updated_at': 'Обновлено'}))
    if data['runtime']['state'] != 'missing':
        body += block('Режим задачи', data['runtime'], lambda value: details(
            value, {'mode': 'Режим', 'recon_status': 'Разведка', 'pause_reason': 'Причина паузы'}))
    body += '<p><a href="#questions">Ожидающие вопросы</a></p>'
    body += '<div id="questions">' + block('Ожидающие вопросы', data['questions'], lambda rows: list_html(
        f'#{text(q["id"])} · {text(q["kind"])} · {text(q["question"])}'
        + details(q, {'reason': 'Причина', 'branch_id': 'Ветка', 'boundaries': 'Границы'}) for q in rows),
        empty='Ожидающих вопросов нет.') + '</div>'
    body += block('Роли и шаги', data['steps'], lambda rows: list_html(step_view(step) for step in rows))
    if data['legacy_steps']['state'] != 'missing':
        body += block('Шаги прежнего планировщика', data['legacy_steps'], lambda rows: list_html(
            f'{text(row.get("step_index"))} · {text(row.get("agent"))} · {status(row.get("status"))}' for row in rows))
    if data['plan']['state'] != 'missing':
        body += block('Исходный план', data['plan'], lambda rows: list_html(
            f'{text(row.get("agent"))} · {text(row.get("instruction"))}' for row in rows))
    for name, title in zip(task_view.REPORT_TABLES, ('Отчёты ролей', 'Отчёты Evidence Hub', 'Лабораторные отчёты')):
        source = data['reports'][name]
        if name != 'pm_agent_action_reports' and source['state'] == 'missing':
            continue
        body += block(title, source, lambda rows: list_html(
            f'<a href="/tasks/{task_id}/reports/{text(row["reference"])}">{text(report_label(row))}</a>'
            f' · {text(row.get("created_at"))}' for row in rows))
    return page(f'Задача #{task_id}', body)


def methods_page(library, ident=None, version=None):
    try:
        methods = library.read()['methods']
    except (OSError, ValueError):
        return 500, page('Советы', '<p>Ошибка чтения каталога советов.</p>')
    if ident is None:
        body = list_html(
            f'<a href="/methods/{text(key)}">{text(rows[-1]["content"]["title"])}</a>'
            f' · версия {rows[-1]["version"]} · {status(rows[-1]["status"])}'
            for key, rows in sorted(methods.items(), key=lambda item: item[1][-1]['content']['title'])
        ) if methods else '<p>Сохранённых советов пока нет</p>'
        return 200, page('Советы', body)
    history = methods.get(ident, [])
    if not history or (version is not None and not 1 <= version <= len(history)):
        return 404, page('Совет', '<p>Совет или версия не найдены.</p>')
    item = history[(version or len(history)) - 1]
    spec = item['content']
    observed = item['observed_result']
    body = (f'<p>Версия {item["version"]} · {status(item["status"])}</p>'
            f'<h2>Условия применимости</h2><p>{text(spec["conditions"])}</p>'
            '<h2>Совет</h2><ol>' + ''.join(f'<li>{text(line)}</li>' for line in spec['method']) + '</ol>'
            '<h2>Проверенный результат</h2>' + details(observed if isinstance(observed, dict) else {}, {
                'kind': 'Тип проверки', 'meaning': 'Результат', 'status_code': 'HTTP-статус',
                'criterion': 'Критерий', 'source_complete': 'Полнота исходника',
                'transformation_complete': 'Полнота преобразования'})
            + '<h2>Ограничения</h2>' + list_html(map(text, spec['limitations']))
            + '<h2>Когда неприменим</h2>' + list_html(map(text, spec['not_applicable']))
            + '<h2>История версий</h2>' + list_html(
                f'<a href="/methods/{text(ident)}/{row["version"]}">Версия {row["version"]}</a>'
                f' · {status(row["status"])} · {text(row["created_at"])} · {text(row["reason"])}'
                for row in reversed(history)))
    return 200, page(spec['title'], body)


class Handler(BaseHTTPRequestHandler):
    timeout = 10

    def __init__(self, *args, database, library, **kwargs):
        self.database = database
        self.library = library
        super().__init__(*args, **kwargs)

    def log_message(self, *_):
        pass

    def dispatch(self, path):
        if path == '/':
            tasks = task_view.list_tasks(self.database)
            return (500 if tasks['state'] == 'error' else 200,
                    page('Pentest Master', block('Задачи', tasks, lambda rows: list_html(
                        f'<a href="/tasks/{text(row["id"])}">#{text(row["id"])} · {text(row.get("target"))}</a>'
                        f' · {status(row.get("status"))}' for row in rows),
                        empty='Сохранённых задач нет.')))
        if path == '/methods':
            return methods_page(self.library)
        method = re.fullmatch(r'/methods/(method:[a-f0-9]{24})(?:/([1-9][0-9]{0,8}))?', path)
        if method:
            return methods_page(self.library, method[1], int(method[2]) if method[2] else None)
        task = re.fullmatch(r'/tasks/([1-9][0-9]{0,17})(?:/reports/([a-z0-9-]{1,95}))?', path)
        if task:
            task_id, reference = int(task[1]), task[2]
            try:
                if reference:
                    with task_view.read_database(self.database) as db:
                        result = task_view.saved_report(db, task_id, reference)
                    if result['state'] == 'ok':
                        report = result['data']
                        title = 'Отчёт ' + report_label(report)
                        body = (f'<p><a href="/tasks/{task_id}">Задача #{task_id}</a></p>'
                                + details(report, {'target': 'Адрес отчёта', 'created_at': 'Сохранён',
                                                    'execution': 'Исход исполнения', 'report_warning': 'Предупреждение'})
                                + details(report.get('quality') or {}, {'status': 'Качество', 'reason': 'Причина'})
                                + f'<pre>{text(report.get("read_error") or report.get("summary"))}</pre>')
                        return 500 if report.get('read_error') else 200, page(title, body)
                    if result['state'] == 'error':
                        return 500, page('Отчёт', '<p>Ошибка чтения отчёта.</p>')
                else:
                    data = task_view.load_task(self.database, task_id)
                    if data is not None:
                        return 200, task_page(data)
            except FileNotFoundError:
                pass
            except task_view.WalDatabaseError:
                return 500, page('Задача', f'<p>{text(task_view.WAL_ERROR)}</p>')
            except (sqlite3.Error, OSError):
                return 500, page('Задача', '<p>Ошибка чтения базы задач.</p>')
        return 404, page('Не найдено', '<p>Страница или сохранённая запись не найдена.</p>')

    def do_GET(self):
        host = f'127.0.0.1:{self.server.server_port}'
        if self.headers.get_all('Host') != [host]:
            code, html = 400, page('Неверный адрес', '<p>Откройте URL из терминала.</p>')
        else:
            try:
                url = urlsplit(self.path)
                if url.scheme or url.netloc:
                    raise ValueError('Absolute URL')
            except ValueError:
                code, html = 400, page('Неверный адрес', '<p>Откройте URL из терминала.</p>')
            else:
                code, html = self.dispatch(unquote(url.path))
        body = html.encode('utf-8')
        self.send_response(code)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('Referrer-Policy', 'no-referrer')
        self.send_header('Content-Security-Policy', "default-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'")
        self.end_headers()
        if self.command != 'HEAD':
            self.wfile.write(body)

    do_HEAD = do_GET


def serve(database, *, port, library_root=None):
    handler = partial(Handler, database=database, library=Library(library_root))
    try:
        server = ThreadingHTTPServer(('127.0.0.1', port), handler)
    except OSError as exc:
        if exc.errno == errno.EADDRINUSE:
            raise OperatorError(f'Порт {port} занят. Укажите другой порт через --port.') from exc
        raise
    with server:
        print(f'Откройте в браузере Kali http://127.0.0.1:{server.server_port}/', flush=True)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            return
