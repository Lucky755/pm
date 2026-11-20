"""Local HTTP viewer for saved PM data."""
import errno
from functools import partial
from html import escape
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import hmac
import json
from pathlib import Path
import re
import secrets
import sqlite3
from urllib.parse import parse_qs, unquote, urlsplit

from operator_errors import OperatorError
from orchestrator import diagnostics, operator_web_data, task_view
from orchestrator.method_library import Library


STATE_MESSAGES = {
    'missing': 'Источник данных отсутствует.',
    'empty': 'Сохранённых записей нет.',
    'error': 'Ошибка чтения сохранённых данных.',
}
ASSETS = Path(__file__).with_name('operator_web_assets')
STATIC_TYPES = {'console.css': 'text/css; charset=utf-8',
                'console.js': 'text/javascript; charset=utf-8', 'saturn.webp': 'image/webp'}
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
    'answered': 'ответ сохранён',
    'cancelled': 'отменён',
    'confirmed': 'подтверждена',
}


def text(value):
    if value is None or value == '':
        return 'нет данных'
    return escape(diagnostics.clean(value, limit=None, preserve_lines=True))


def multiline(value):
    return text(value).replace('\n', '<br>')


def status(value):
    return text(STATE_LABELS.get(value, value) if isinstance(value, str) else value)


def page(title, body, *, task=False):
    script = '<script src="/assets/console.js" defer></script>' if task else ''
    return ('<!doctype html><html lang="ru"><head><meta charset="utf-8">'
            '<meta name="viewport" content="width=device-width, initial-scale=1">'
            '<link rel="stylesheet" href="/assets/console.css">'
            f'<title>{text(title)} | Pentest Master</title>{script}</head><body>'
            '<div class="sky" aria-hidden="true"></div>'
            '<header class="masthead"><a class="brand" href="/"><span class="brand-mark">PM</span>'
            '<span>PENTEST MASTER</span></a><nav aria-label="Навигация PM">'
            '<a href="/">Задачи</a><a href="/management">Управление</a></nav></header>'
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
            entries.append(f'<dt>{text(label)}</dt><dd>{multiline(value)}</dd>')
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
        result += list_html(f'Run ID · {text(run_id)}' for run_id in data['damaged_runs'])
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


def questions_view(source):
    message = STATE_MESSAGES.get(source['state'], '')
    if source['state'] == 'empty':
        message = 'Ожидающих вопросов нет.'
    items = ''.join(
        f'<li data-question="{text(q["id"])}"><span data-question-title>'
        f'#{text(q["id"])} · {text(q["kind"])}</span>'
        f'<p data-question-text>{text(q["question"])}</p>'
        f'<p data-question-reason>{text(q.get("reason"))}</p>'
        f'<p data-question-scope>{text(operator_web_data.question_scope(q))}</p></li>'
        for q in source['data'] or [])
    return ('<section id="questions" class="questions"><h2>Ожидающие вопросы</h2>'
            f'<p id="questions-info"{"" if message else " hidden"}>{text(message)}</p>'
            f'<ul id="question-rows">{items}</ul></section>')


def workspace(task_id):
    return f'''<div id="workspace" data-task="{task_id}">
      <nav class="tabs" aria-label="Представления задачи">
        <a href="#agents" aria-current="page">Агенты</a>
        <a href="#map">Карта цели</a><a href="#history">История</a>
      </nav>
      <div class="workgrid">
        <div class="views">
          <section id="agents" class="panel view">
            <header><h2>Импульсы</h2><p id="agent-info">Чтение сохранённых назначений…</p></header>
            <div class="diagram-scroll" tabindex="0" aria-label="Схема назначений">
              <div class="canvas agent-canvas"><div data-column="coordinator"></div>
                <div data-column="specialists"></div></div>
            </div>
          </section>
          <section id="map" class="panel view" hidden>
            <header><h2>Маршрут</h2><div class="legend">
              <span><i></i>Связь в карте</span><span><i class="pending"></i>Ожидает подтверждения</span>
            </div></header>
            <p id="map-info" hidden></p>
            <div class="diagram-scroll" tabindex="0" aria-label="Карта маршрута">
              <div class="canvas route-canvas"><div data-column="target"></div>
                <div data-column="sessions"></div><div data-column="destinations"></div></div>
            </div>
          </section>
          <section id="history" class="panel view" hidden>
            <header><h2>История</h2><a id="history-latest" href="#history">К последней записи</a></header>
            <div id="history-log" class="history-scroll" tabindex="0" aria-label="Журнал событий">
              <ol id="history-entries"></ol>
            </div>
            <p id="history-info">История включает только сохранённые записи PM.</p>
          </section>
        </div>
        <aside class="inspector panel">
          <h2>Сведения</h2>
          <p id="selection-hint">Выберите карточку или запись истории.</p>
          <div id="selection"></div>
          <section class="last-event"><h3>Событие</h3><a id="last-event" href="#history">Нет сохранённых событий</a></section>
          <p id="connection" aria-live="polite">Чтение сохранённых данных…</p>
        </aside>
      </div>
    </div>'''


def task_context_view(description, source):
    body = ''
    if description:
        body += ('<section><h2>Сохранённое описание планировщика</h2>'
                 f'<pre>{text(description)}</pre></section>')
    data = source['data'] or {}
    original = data.get('original')
    if source['state'] == 'error':
        original_view = '<p>Историю задания не удалось прочитать.</p>'
    else:
        original_view = f'<pre>{text(original)}</pre>' if original else '<p>Исходное задание неизвестно.</p>'
    body += '<section id="operator-intent"><h2>Исходное задание и ограничения оператора</h2>' + original_view + '</section>'
    for key, title, identity in (('clarifications', 'Уточнения оператора', 'saved-intent'),
                                 ('revisions', 'Другие редакции задания', 'intent-revisions')):
        entries = data.get(key) or []
        if entries:
            body += f'<section id="{identity}"><h2>{title}</h2>' + list_html(
                f'<p>{text(row["source"])} · {text(row["created_at"])}</p><pre>{text(row["text"])}</pre>'
                for row in entries) + '</section>'
    if data.get('unlinked'):
        body += ('<section><h2>Сохранённый текст без привязки к истории</h2>'
                 f'<pre>{text(data["unlinked"])}</pre></section>')
    return body


def task_page(data):
    task_id = data['id']
    outcome = data['outcome']['data']
    body = (f'<div class="overview"><p class="target-address">{text(data.get("target"))}</p>'
            f'<p id="goal-outcome">{text(outcome["label"] if outcome else STATE_MESSAGES[data["outcome"]["state"]])}</p></div>'
            + workspace(task_id) + '<div class="task-records">'
            f'<p>Статус в SQLite · {status(data.get("status"))}</p>'
            f'<p>Закрытие задачи · {status(data["closure"])}</p>')
    if outcome and outcome.get('remaining_goals'):
        body += '<p>Есть цели, ожидающие подтверждения.</p>'
    if outcome and outcome.get('legacy_evidence_count') is not None:
        body += f'<p>Флагов со свидетельствами в прежнем реестре · {text(outcome["legacy_evidence_count"])}</p>'
    body += task_context_view(data.get('description'), data['intent_provenance'])
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
    body += (f'<p><a href="/management/tasks/{task_id}/context">Уточнить контекст</a> · '
             f'<a href="/management/tasks/{task_id}/questions">Вопросы</a> · '
             f'<a href="/management/tasks/{task_id}/report">Итоговый отчёт</a></p>')
    body += questions_view(data['questions'])
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
    return page(f'Задача #{task_id}', body + '</div>', task=True)


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
        return 200, page('Советы', '<p><a href="/management/methods/new">Сохранить совет</a></p>' + body)
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
    if version is None:
        body += (f'<p><a href="/management/methods/{text(ident)}/edit">Исправить совет</a> · '
                 f'<a href="/management/methods/{text(ident)}/withdraw">Отозвать совет</a></p>')
    return 200, page(spec['title'], body)


class Handler(BaseHTTPRequestHandler):
    timeout = 10
    max_form = 3 * 16 * 1024 * 1024 + 65536

    def __init__(self, *args, database, library, admin, csrf_secret, **kwargs):
        self.database = database
        self.library = library
        self.admin = admin
        self.csrf_secret = csrf_secret
        super().__init__(*args, **kwargs)

    def log_message(self, *_):
        pass

    def dispatch(self, path):
        if path.startswith('/management'):
            response = self.admin.dispatch(path, self.form_token)
            if response is not None:
                return response
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

    def content(self, path):
        if path.startswith('/assets/') and (name := path.removeprefix('/assets/')) in STATIC_TYPES:
            return 200, STATIC_TYPES[name], (ASSETS / name).read_bytes()
        match = re.fullmatch(r'/tasks/([1-9][0-9]{0,17})/view\.json', path)
        if match:
            try:
                data = operator_web_data.load(self.database, int(match[1]))
                code = 200 if data is not None else 404
            except FileNotFoundError:
                code, data = 404, None
            except (OSError, sqlite3.Error):
                code, data = 500, None
            return code, 'application/json; charset=utf-8', json.dumps(data, ensure_ascii=False).encode('utf-8')
        code, html = self.dispatch(path)
        return code, 'text/html; charset=utf-8', html.encode('utf-8')

    def form_token(self, path):
        return hmac.digest(self.csrf_secret, path.encode('utf-8'), 'sha256').hex()

    def request_path(self, *, write=False):
        host = f'127.0.0.1:{self.server.server_port}'
        if self.headers.get_all('Host') != [host]:
            raise ValueError('Host')
        if write and self.headers.get_all('Origin') != ['http://' + host]:
            raise PermissionError('Origin')
        url = urlsplit(self.path)
        if url.scheme or url.netloc or (write and (url.query or url.fragment)):
            raise ValueError('URL')
        return unquote(url.path)

    def do_GET(self):
        error = '<p>Откройте URL из терминала.</p>'
        try:
            path = self.request_path()
        except ValueError:
            code, kind, body = 400, 'text/html; charset=utf-8', page('Неверный адрес', error).encode('utf-8')
        else:
            code, kind, body = self.content(path)
        self.respond(code, kind, body)

    def form_values(self):
        lengths = self.headers.get_all('Content-Length', [])
        if (len(lengths) != 1 or not re.fullmatch(r'[0-9]{1,9}', lengths[0])
                or self.headers.get('Transfer-Encoding')
                or self.headers.get_content_type() != 'application/x-www-form-urlencoded'):
            raise ValueError('Invalid form headers')
        count = int(lengths[0])
        if not 0 < count <= self.max_form:
            raise OverflowError('Form size')
        body = self.rfile.read(count)
        if len(body) != count:
            raise ValueError('Incomplete form')
        values = parse_qs(body.decode('ascii'), keep_blank_values=True, strict_parsing=True,
                          errors='strict', max_num_fields=32)
        if any(len(value) != 1 or '\x00' in value[0] for value in values.values()):
            raise ValueError('Ambiguous form')
        return {name: value[0].replace('\r\n', '\n').replace('\r', '\n') for name, value in values.items()}

    def do_POST(self):
        try:
            path = self.request_path(write=True)
            params = self.form_values()
            supplied = params.pop('csrf', '')
            if not re.fullmatch(r'[a-f0-9]{64}', supplied) or not hmac.compare_digest(supplied, self.form_token(path)):
                raise PermissionError('CSRF')
        except PermissionError:
            code, html = 403, page('Запрос отклонён', '<p>Откройте форму заново с локального адреса PM.</p>')
        except OverflowError:
            code, html = 413, page('Запрос слишком большой', '<p>Размер формы превышает допустимый предел.</p>')
        except (ValueError, TimeoutError):
            code, html = 400, page('Неверная форма', '<p>Не удалось прочитать форму запроса.</p>')
        else:
            result = self.admin.dispatch(path, self.form_token, params)
            code, html = result or (404, page('Не найдено', '<p>Действие недоступно в браузере.</p>'))
        if code == 303:
            self.respond(code, 'text/html; charset=utf-8', b'', location=html)
        else:
            self.respond(code, 'text/html; charset=utf-8', html.encode('utf-8'))

    def respond(self, code, kind, body, *, location=None):
        self.send_response(code)
        if location is not None:
            self.send_header('Location', location)
        self.send_header('Content-Type', kind)
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('Referrer-Policy', 'same-origin')
        self.send_header('Content-Security-Policy', "default-src 'none'; script-src 'self'; style-src 'self'; "
                         "img-src 'self'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
        self.end_headers()
        if self.command != 'HEAD':
            self.wfile.write(body)

    do_HEAD = do_GET


def serve(database, *, port, library_root=None, artifact_root=None):
    from orchestrator.operator_web_admin import Admin

    library = Library(library_root)
    handler = partial(Handler, database=database, library=library,
                      admin=Admin(database, library, artifact_root), csrf_secret=secrets.token_bytes(32))
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
