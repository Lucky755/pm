"""Explicit local operator forms. GET uses the same read-only task projections as PM."""
from contextlib import closing, contextmanager
from html import escape
import json
import os
import re
import sqlite3

from operator_errors import OperatorError
from orchestrator import diagnostics, flag_review, flag_verify, http_artifacts, method_library
from orchestrator import objectives, operator_context, operator_questions, resources, task_memory, task_view
from orchestrator.operator_web import details, list_html, page, status, text

TASK_ROUTES = re.compile(r'/management/tasks/([1-9][0-9]{0,17})/(context|questions|flags|report)(?:/([1-9][0-9]{0,17}))?')
METHOD_ROUTES = re.compile(r'/management/methods/(?:(new)|(method:[a-f0-9]{24})/(edit|withdraw))')
DRAFT_ROUTE = re.compile(r'/management/context(?:/([1-9][0-9]{0,17}))?')
AREAS = {'': 'По адресу · веб-ресурс для домена или URL, хост для IP',
         'web': 'Веб-ресурс · работа с сайтом без полного скана общего IP',
         'host': 'Хост · сервисы конкретной машины',
         'lab': 'Лаборатория · связанные узлы в заданных границах'}
MODES = {'coordinated': 'Координатор · выбирает специалиста по сохранённому состоянию задачи',
         'legacy': 'Evidence Hub / DECIDE · собирает снимок наблюдений, анализирует его и выбирает следующие проверки'}
GOAL_MODES = {'goal-first': 'Сначала основная цель, затем остальные цели',
              'goal-exclusive': 'Приоритет основной цели при сохранённых требованиях к итогу',
              'all-flags': 'Поиск до ожидаемого числа флагов'}
DRAFT_FIELDS = {
    'target': 'Адрес, домен или URL', 'domains': 'Известные домены через запятую',
    'description': 'Описание основной цели', 'constraints': 'Ограничения',
    'area': 'Область исследования', 'mode': 'Режим', 'expected': 'Ожидаемое число флагов',
    'goal_mode': 'Порядок целей', 'objectives': 'Дополнительные цели',
    'pattern': 'Регулярное выражение флага',
}
CONTEXT_FIELDS = ('target', 'domains', 'description', 'constraints', 'area', 'mode')
GOAL_FIELDS = ('expected', 'goal_mode', 'objectives', 'pattern')
METHOD_FIELDS = {
    'key': 'Ключ совета', 'title': 'Название', 'conditions': 'Условия применимости', 'method': 'Процедура',
    'limitations': 'Ограничения', 'not_applicable': 'Когда неприменим', 'profiles': 'Профили',
    'problem_tags': 'Теги', 'tools': 'Инструменты',
}
METHOD_LISTS = {'method', 'limitations', 'not_applicable', 'profiles', 'problem_tags', 'tools'}
EVIDENCE_FIELDS = {'kind': 'Тип основания', 'result_id': 'Result ID', 'artifact_ref': 'Артефакт',
                   'quote': 'Точная цитата из оригинала', 'series_id': 'ID серии проверок (если применимо)'}
EVIDENCE_KINDS = {'http_response': 'Сохранённый HTTP-ответ', 'http_criterion': 'Проверенный HTTP-критерий',
                  'material_transform': 'Проверенное преобразование материала'}
ANSWER_LABELS = {'approve': 'Принято оператором', 'decline': 'Отклонено оператором',
                 'information': 'Информация сохранена'}
FLAG_LABELS = {'pending': 'Ожидает решения', 'accepted': 'Принят', 'rejected': 'Отклонён'}


class FormError(ValueError):
    pass


def attr(value):
    return escape(str(value), quote=True)


def link(path, label, *, button=False):
    return f'<a{" class=button-link" if button else ""} href="{attr(path)}">{text(label)}</a>'


def notice(message, *, error=False):
    return f'<p class="form-notice" role="{"alert" if error else "status"}">{text(message)}</p>'


def hidden(values):
    return ''.join(f'<input type="hidden" name="{attr(name)}" value="{attr(value)}">' for name, value in values.items())


def field(name, label, values, *, options=None, multiline=False, error=None, required=False, hint=''):
    value = values.get(name, '')
    invalid = f' aria-invalid="true" aria-describedby="{name}-error"' if error else ''
    attrs = f'id="field-{name}" name="{name}"{invalid}' + (' required' if required else '')
    if options is not None:
        choices = ''.join(f'<option value="{attr(key)}"{" selected" if key == value else ""}>{text(title)}</option>'
                          for key, title in options.items())
        control = f'<select {attrs}>{choices}</select>'
    elif multiline:
        control = f'<textarea {attrs} rows="4">{escape(value)}</textarea>'
    else:
        control = f'<input {attrs} value="{attr(value)}">'
    help_text = f'<small>{text(hint)}</small>' if hint else ''
    problem = f'<p class="field-error" id="{name}-error" role="alert">{text(error)}</p>' if error else ''
    return f'<div class="form-field"><label for="field-{name}">{text(label)}</label>{help_text}{control}{problem}</div>'


def button(label, name='action', value='save', *, secondary=False):
    return f'<button{" class=secondary" if secondary else ""} type="submit" name="{name}" value="{value}">{text(label)}</button>'


def controls(*items):
    return '<div class="form-actions">' + ''.join(items) + '</div>'


def screen(title, body, *, back='/management'):
    return page(title, f'<div class="management"><p class="management-back">{link(back, "Назад к управлению")}</p>'
                f'<section class="panel management-panel">{body}</section></div>')


def input_values(params, fields):
    return {name: params.get(name, '') for name in fields}


def validate_visible(value):
    # Entered credentials cannot reappear through validation errors or later views.
    if diagnostics.clean(value, limit=None, preserve_lines=True) != value:
        raise FormError('Удалите ключ, пароль, cookie или другой секрет из поля.')
    return value


def public_form_values(values):
    return {key: diagnostics.clean(value, limit=None, preserve_lines=True) for key, value in values.items()}


def read_task(db, task_id):
    if not task_memory.exists(db, 'tasks'):
        return None
    row = db.execute('SELECT id,target,status FROM tasks WHERE id=?', (task_id,)).fetchone()
    return dict(row) if row is not None else None


def require_task(db, task_id):
    if (row := read_task(db, task_id)) is None:
        raise FileNotFoundError('task')
    return row


def field_errors(values, validations):
    errors = {}
    for field_name, validate in validations.items():
        try:
            validate(validate_visible(values[field_name]))
        except (ValueError, OperatorError, UnicodeError) as exc:
            errors[field_name] = str(exc)
    return errors


def context_errors(values):
    def target(value):
        try:
            resources.parse(value.strip())
        except (ValueError, UnicodeError) as exc:
            raise FormError('Укажите корректный IPv4, IPv6, домен или HTTP(S) URL. ' + str(exc)) from exc

    def configured_mode(mode):
        if mode not in MODES:
            raise FormError('Выберите поддержанный режим.')
        try:
            entry = resources.parse(values['target'].strip())
        except (ValueError, UnicodeError):
            return
        area = values['area'] or ('host' if entry['kind'] == 'address' else 'web')
        if mode == 'legacy' and resources.web_entry(entry, area):
            raise FormError('Для веб-области используется координатор.')

    def area(value):
        if value not in AREAS:
            raise FormError('Выберите поддержанную область.')
        try:
            entry = resources.parse(values['target'].strip())
        except (ValueError, UnicodeError):
            return
        if value == 'host' and not resources.concrete_host(entry):
            raise FormError('Для исследования хоста по имени CLI требует явно закреплённый IP. Укажите IP или выберите другую область.')

    errors = field_errors(values, {
        'target': target,
        'domains': operator_context.validate_hostnames,
        'description': lambda value: operator_context.compose_task_description(value, ''),
        'constraints': lambda value: operator_context.validate_intent('Задача\n' + value),
        'area': area, 'mode': configured_mode,
    })
    if 'description' not in errors and 'constraints' not in errors:
        try:
            operator_context.compose_task_description(values['description'], values['constraints'])
        except OperatorError as exc:
            errors['constraints'] = str(exc)
    return errors


def goal_errors(values):
    def expected(value):
        if value and (not re.fullmatch(r'[0-9]{1,2}', value) or not 1 <= int(value) <= objectives.MAX_OBJECTIVES):
            raise FormError(f'Введите целое число от 1 до {objectives.MAX_OBJECTIVES} или оставьте поле пустым.')

    def specs(value):
        titles = [objectives.parse_objective_spec(line.strip())[1] for line in value.splitlines() if line.strip()]
        if 1 + len(titles) > objectives.MAX_OBJECTIVES or len(titles) != len(set(titles)):
            raise FormError(f'Нужны уникальные цели. Допускается максимум {objectives.MAX_OBJECTIVES} вместе с основной.')

    def mode(value):
        if value not in GOAL_MODES:
            raise FormError('Выберите поддержанный порядок целей.')

    return field_errors(values, {'expected': expected, 'goal_mode': mode, 'objectives': specs,
                                 'pattern': lambda value: flag_verify.validate_pattern(value) if value else None})


def flag_summary(candidate):
    sources = candidate.get('sources') or []
    if isinstance(sources, list):
        return [{'Источник': s.get('source'), 'Способ': s.get('method')} for s in sources if isinstance(s, dict)]
    return []


def flag_card(candidate, *, reveal=False):
    body = details(candidate, {'id': 'Кандидат', 'objective_title': 'Цель'})
    body += f'<p>Статус · {text(FLAG_LABELS.get(candidate["status"], candidate["status"]))}</p>'
    for source in flag_summary(candidate):
        body += details(source, {'Источник': 'Источник', 'Способ': 'Способ получения'})
    if reveal:
        # The manual flag policy explicitly shows the exact selected candidate.
        # It is not echoed in the form payload, redirects, or other task views.
        body += f'<pre class="selected-flag">{escape(candidate["value"])}</pre>'
    return body


def question_saved_answer(row):
    answer = row.get('answer') or {}
    return details({'decision': ANSWER_LABELS.get(answer.get('decision')), 'text': answer.get('text'),
                    'date': row.get('answered_at')},
                   {'decision': 'Сохранённое решение', 'text': 'Ответ', 'date': 'Сохранено'})


class Admin:
    def __init__(self, database, library, artifact_root):
        self.database = database
        self.library = library
        self.artifact_root = artifact_root

    @contextmanager
    def writer(self, *, create=False):
        if create and not self.database.exists():
            self.database.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            try:
                os.close(os.open(self.database, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600))
            except FileExistsError:
                pass
        # Keep the offline-copy/WAL rules of the viewer on the write path too.
        with task_view.read_database(self.database):
            pass
        with closing(sqlite3.connect(self.database.resolve().as_uri() + '?mode=rw', uri=True, timeout=10)) as db:
            db.row_factory = sqlite3.Row
            with task_memory.atomic(db):
                yield db

    def form(self, path, token, body, values=None):
        return (f'<form method="post" action="{attr(path)}" autocomplete="off">'
                + hidden({'csrf': token(path), **(values or {})}) + body + '</form>')

    @staticmethod
    def review_token(path, token, values):
        return token(path + '#' + task_memory.digest(values))

    def index(self):
        tasks = task_view.list_tasks(self.database)
        rows = tasks['data'] or []
        task_items = list_html(
            link('/tasks/' + str(row['id']), 'Задача #' + str(row['id'])) + ' · ' + text(row.get('target'))
            + '<div class="task-links">' + self.task_links(row['id']) + '</div>' for row in rows
        ) if rows else '<p>Нет сохранённых задач для управления.</p>'
        if tasks['state'] == 'error':
            task_items = notice(task_view.WAL_ERROR if tasks.get('error') == 'WalDatabaseError'
                                else 'Список задач не удалось прочитать.', error=True)
        drafts = task_view.section(self.drafts)
        draft_links = list_html(link(f'/management/context/{row[0]}', f'Черновик #{row[0]} · {row[1]}')
                                for row in drafts['data'] or [])
        return screen('Управление',
                      controls(link('/management/context', 'Новый контекст', button=True),
                               link('/methods', 'Библиотека советов', button=True))
                      + '<h2>Задачи</h2>' + task_items + '<h2>Черновики контекста</h2>'
                      + (notice('Черновики не удалось прочитать.', error=True) if drafts['state'] == 'error'
                         else draft_links if drafts['data'] else '<p>Черновиков нет.</p>'))

    @staticmethod
    def task_links(task_id):
        base = f'/management/tasks/{task_id}'
        return ' '.join(link(base + path, label) for path, label in (
            ('/context', 'Уточнить контекст'), ('/questions', 'Вопросы'), ('/report', 'Итоговый отчёт')))

    def drafts(self):
        if not self.database.is_file():
            return []
        with task_view.read_database(self.database) as db:
            if not task_memory.exists(db, 'pm_context_drafts'):
                return []
            return [(row[0], json.loads(row[1])['target']) for row in db.execute(
                'SELECT id,context_json FROM pm_context_drafts ORDER BY id DESC')]

    @staticmethod
    def draft_summary(values):
        display = {**values, 'area': AREAS[values['area']], 'mode': MODES[values['mode']],
                   'goal_mode': GOAL_MODES[values['goal_mode']], 'pattern': values['pattern'] or 'Формат неизвестен',
                   'expected': values['expected'] or 'По правилам CLI для выбранных целей'}
        return details({key: value or 'Не указано' for key, value in display.items()}, DRAFT_FIELDS)

    def draft_page(self, token, values=None, *, step=0, errors=None):
        errors = errors or {}
        values = public_form_values(values or {**dict.fromkeys(DRAFT_FIELDS, ''), 'mode': 'coordinated', 'goal_mode': 'goal-first'})
        names = ('Контекст', 'Цели', 'Проверка')
        progress = '<ol class="wizard-stages">' + ''.join(
            f'<li{" aria-current=step" if index == step else ""}>{label}</li>' for index, label in enumerate(names)
        ) + '</ol>'
        fields = CONTEXT_FIELDS if step == 0 else GOAL_FIELDS if step == 1 else ()
        choices = {'area': AREAS, 'mode': MODES, 'goal_mode': GOAL_MODES}
        hints = {'pattern': 'Оставьте пустым, если формат неизвестен.', 'objectives': 'Одна цель на строку в формате вес:описание.',
                 'target': 'IPv4, IPv6, домен или HTTP(S) URL. Укажите порт и путь прямо в URL.'}
        form = ''.join(field(name, DRAFT_FIELDS[name], values, options=choices.get(name), error=errors.get(name),
                             multiline=name in ('description', 'constraints', 'objectives'), hint=hints.get(name, ''))
                       for name in fields)
        if step == 2:
            form = self.draft_summary(values)
        retained = {name: value for name, value in values.items() if name not in fields}
        if step == 2:
            retained['review'] = self.review_token('/management/context', token, values)
        actions = [button('Назад', value='back', secondary=True)] if step else []
        actions.append(button('Сохранить контекст' if step == 2 else 'Далее', value='save' if step == 2 else 'next'))
        return screen('Мастер контекста', progress + f'<h2>{names[step]}</h2>'
                      '<p>Сохраняется черновик для оператора. Запуск задачи остаётся отдельным действием CLI.</p>'
                      + self.form('/management/context', token, form + controls(*actions),
                                  {'step': step, **retained}))

    def draft_post(self, params, token):
        values = input_values(params, DRAFT_FIELDS)
        action = params.get('action')
        step = {'0': 0, '1': 1, '2': 2}.get(params.get('step'))
        if step is None or action not in ('back', 'next', 'save') or (action == 'save' and step != 2):
            raise FormError('Неверный шаг мастера.')
        if action == 'back' and step:
            return 200, self.draft_page(token, values, step=step-1)
        errors = context_errors(values)
        if errors:
            return 422, self.draft_page(token, values, errors=errors)
        if step == 0:
            return 200, self.draft_page(token, values, step=1)
        errors = goal_errors(values)
        if errors:
            return 422, self.draft_page(token, values, step=1, errors=errors)
        if action == 'next':
            return 200, self.draft_page(token, values, step=2)
        if params.get('review') != self.review_token('/management/context', token, values):
            return 409, self.draft_page(token, values, step=2)
        composed = operator_context.compose_task_description(values['description'], values['constraints'])
        values['task_text'] = composed
        with self.writer(create=True) as db:
            db.execute('CREATE TABLE IF NOT EXISTS pm_context_drafts (id INTEGER PRIMARY KEY,'
                       'fingerprint TEXT NOT NULL UNIQUE,context_json TEXT NOT NULL,created_at TEXT NOT NULL)')
            fingerprint = task_memory.digest(values)
            db.execute('INSERT OR IGNORE INTO pm_context_drafts(fingerprint,context_json,created_at) VALUES(?,?,?)',
                       (fingerprint, task_memory.encoded(values), task_memory.now()))
            ident = db.execute('SELECT id FROM pm_context_drafts WHERE fingerprint=?', (fingerprint,)).fetchone()[0]
        return 303, f'/management/context/{ident}'

    def draft_saved(self, ident):
        with task_view.read_database(self.database) as db:
            row = (db.execute('SELECT context_json FROM pm_context_drafts WHERE id=?', (ident,)).fetchone()
                   if task_memory.exists(db, 'pm_context_drafts') else None)
            if not row:
                raise FileNotFoundError('draft')
        values = json.loads(row[0])
        return screen(f'Контекст #{ident}', notice('Контекст сохранён как черновик.')
                      + self.draft_summary(values) + '<h2>Текст задания для CLI</h2>'
                      + f'<pre>{text(values["task_text"])}</pre>')

    def context_page(self, db, task, token, values=None, error=None):
        task_id = task['id']
        values = public_form_values(values or {})
        intent = operator_context.previous_task_intent(db, task_id)
        saved = resources.saved(db, task_id)
        row = task_view.one_row(db, 'pm_task_hostnames', task_id)
        hosts = json.loads(row['hostnames_json']) if row.get('hostnames_json') else []
        body = (f'<p>Задача #{task_id} · {text(task["target"])}</p>'
                '<p>Сохранение добавит уточнение в историю задания. Настройки области и привязки имён остаются прежними.</p>'
                '<h2>Применённые привязки из PM</h2>'
                + details({'hosts': hosts or 'Нет записи', 'entry': saved['entry'].get('input') if saved else 'Нет записи'},
                          {'hosts': 'Имена NetGuard', 'entry': 'Сохранённый входной ресурс'})
                + '<h2>Сохранённое задание и уточнения</h2>' + f'<pre id="saved-intent">{text(intent)}</pre>')
        form = (field('note', 'Уточнение оператора', values, multiline=True)
                + field('domains', 'Имена по сообщению оператора', values,
                        hint='Ввод добавляется в уточнение и не создаёт привязку.')
                + controls(button('Сохранить уточнение')))
        return screen(f'Контекст задачи #{task_id}', body + (notice(error, error=True) if error else '')
                      + self.form(f'/management/tasks/{task_id}/context', token, form,
                                  {'revision': task_memory.digest(intent)}))

    def context_post(self, db, task, params, token):
        values = input_values(params, ('note', 'domains'))
        intent = operator_context.previous_task_intent(db, task['id'])
        if params.get('revision') != task_memory.digest(intent):
            return 409, self.context_page(db, task, token, values, 'Задание уже изменилось. Проверьте сохранённый текст перед повторным сохранением.')
        try:
            note = validate_visible(values['note']).strip()
            domains = operator_context.validate_hostnames(validate_visible(values['domains']))
            if not note and not domains:
                raise FormError('Введите уточнение или известное имя.')
            if domains:
                note += ('\n' if note else '') + 'Имена по сообщению оператора: ' + ', '.join(domains)
            updated = (intent + '\n\n' if intent else '') + 'Уточнение оператора:\n' + note
            operator_context.restore_task_intent(db, task['id'], updated, 'PM Web · уточнение')
        except (ValueError, OperatorError) as exc:
            return 422, self.context_page(db, task, token, values, str(exc))
        return 303, f'/management/tasks/{task["id"]}/context'

    def questions_page(self, db, task):
        task_id = task['id']
        base = f'/management/tasks/{task_id}'
        questions = operator_questions.listing(db, task_id)
        rows = list_html(link(f'{base}/questions/{row["id"]}', f'#{row["id"]} · {row["question"]}')
                         + ' · ' + status(row['status']) for row in questions)
        steps = task_view.table(db, 'pm_coordinator_steps', lambda: task_view.steps(db, task_id))
        access = list_html(f'Шаг #{text(s["step_no"])} · {status(s.get("status"))}'
                           for s in steps['data'] or [] if s.get('role') == 'access')
        return screen(f'Вопросы задачи #{task_id}',
                      '<p>Информационные ответы и решения по сохранённым флагам записываются в PM.</p>'
                      + (rows if questions else '<p>Сохранённых вопросов нет.</p>')
                      + '<h2>Шаги ACCESS</h2>' + (access if access != '<ul></ul>' else '<p>Сохранённых шагов нет.</p>'))

    def question_page(self, task, row, token, *, message='', error=False):
        task_id = task['id']
        path = f'/management/tasks/{task_id}/questions/{row["id"]}'
        candidate = row.get('flag_candidate')
        boundaries = row.get('boundaries') or {}
        body = (f'<p>Задача #{task_id} · {text(task["target"])}</p>'
                + details({**row, 'resource_refs': ', '.join(boundaries.get('resource_refs', []))},
                          {'question': 'Вопрос', 'reason': 'Причина', 'resource_refs': 'Границы'})
                + f'<p>Статус вопроса · {status(row["status"])}</p>')
        for key, label, field_name in (('tool_request', 'Запрос инструмента', 'status'),
                                       ('pivot_request', 'Запрос маршрута', 'state'),
                                       ('budget_request', 'Запрос бюджета', 'decision')):
            if row.get(key):
                body += f'<p>{text(label)} · {status(row[key].get(field_name) or "pending")}</p>'
        if message:
            body += notice(message, error=error)
        if candidate:
            body += flag_card(candidate, reveal=True)
        if row['status'] == 'answered':
            body += question_saved_answer(row)
            if candidate and candidate['status'] == 'rejected':
                body += link(f'/management/tasks/{task_id}/flags/{candidate["id"]}', 'Пересмотреть кандидата')
        elif row['status'] == 'pending' and candidate and candidate['status'] == 'pending' and row['kind'] == 'flag_confirmation':
            body += self.form(path, token,
                              '<p>Подтвердите только после проверки показанного значения на CTF-платформе.</p>'
                              '<label class="checkbox"><input type="checkbox" name="checked" value="yes">'
                              'Проверено на платформе</label>'
                              + controls(button('Принять флаг', 'decision', 'approve'),
                                         button('Отклонить кандидата', 'decision', 'decline', secondary=True)),
                              {'candidate': candidate['id'], 'revision': candidate['revision']})
        elif row['status'] == 'pending' and operator_questions.informational(row):
            body += self.form(path, token, field('answer', 'Информационный ответ', {}, required=True)
                              + controls(button('Сохранить ответ', 'decision', 'information')))
        elif row['status'] == 'pending':
            body += '<p>Запрос действия доступен для чтения. Действия с разрешениями выполняются в CLI.</p>'
        return screen(f'Вопрос #{row["id"]}', body + controls(link(f'/management/tasks/{task_id}/questions', 'К вопросам'),
                                                               link(f'/management/tasks/{task_id}/report', 'Итоговый отчёт')))

    def answer(self, db, task, row, params, token):
        if row['status'] != 'pending':
            return 409, self.question_page(task, row, token, message='Вопрос уже обработан. Ниже показан сохранённый результат.', error=True)
        decision = params.get('decision')
        candidate = row.get('flag_candidate')
        try:
            if row['kind'] == 'flag_confirmation':
                if (not candidate or candidate['status'] != 'pending' or params.get('candidate') != str(candidate['id'])
                        or params.get('revision') != str(candidate['revision'])):
                    return 409, self.question_page(task, row, token, message='Кандидат изменился. Проверьте текущую запись.', error=True)
                if decision not in ('approve', 'decline'):
                    raise FormError('Для флага выберите принятие или отказ.')
                if decision == 'approve' and params.get('checked') != 'yes':
                    raise FormError('Подтвердите проверку значения на CTF-платформе.')
                note = ''
            elif operator_questions.informational(row) and decision == 'information':
                note = validate_visible(params.get('answer', '')).strip()
                if not note:
                    raise FormError('Введите информационный ответ.')
            else:
                return 403, self.question_page(task, row, token, message='В web для этого запроса запись недоступна.', error=True)
            operator_questions.answer(db, task['id'], row['id'], decision, note)
        except ValueError as exc:
            return 422, self.question_page(task, row, token, message=str(exc), error=True)
        return 303, f'/management/tasks/{task["id"]}/questions/{row["id"]}'

    def candidate_page(self, task, candidate, token, *, message='', error=False):
        base = f'/management/tasks/{task["id"]}'
        body = (f'<p>Задача #{task["id"]} · {text(task["target"])}</p>'
                + (notice(message, error=error) if message else '') + flag_card(candidate, reveal=True))
        if candidate['status'] == 'pending' and candidate.get('question_id'):
            body += link(f'{base}/questions/{candidate["question_id"]}', 'Открыть вопрос подтверждения')
        elif candidate['status'] in ('pending', 'rejected'):
            rejected = candidate['status'] == 'rejected'
            form = field('reason', 'Причина пересмотра', {}, required=True) if rejected else ''
            form += controls(button('Пересмотреть кандидата' if rejected else 'Поставить вопрос на подтверждение',
                                    value='reconsider' if rejected else 'enqueue'))
            body += self.form(f'{base}/flags/{candidate["id"]}', token, form,
                              {'revision': candidate['revision']})
        return screen(f'Кандидат #{candidate["id"]}', body + controls(link(base + '/report', 'Итоговый отчёт')))

    def candidate_post(self, db, task, candidate, params, token):
        if params.get('revision') != str(candidate['revision']):
            return 409, self.candidate_page(task, candidate, token, message='Кандидат уже изменился.', error=True)
        try:
            if params.get('action') == 'reconsider' and candidate['status'] == 'rejected':
                question = flag_review.reconsider(db, task['id'], candidate['id'], validate_visible(params.get('reason', '')))
            elif params.get('action') == 'enqueue' and candidate['status'] == 'pending':
                question = flag_review.enqueue(db, candidate['id'])
            else:
                raise FormError('Действие больше не применимо к этому кандидату.')
        except ValueError as exc:
            return 422, self.candidate_page(task, candidate, token, message=str(exc), error=True)
        return 303, f'/management/tasks/{task["id"]}/questions/{question["id"]}'

    def report(self, db, task):
        task_id = task['id']
        base = f'/management/tasks/{task_id}'
        data = task_view.task(db, task_id)
        outcome = data['outcome']['data'] or {}
        candidates = flag_review.listing(db, task_id)
        questions = operator_questions.listing(db, task_id, pending=True)
        goals = data['goals']['data'] or []

        def list_or_empty(rows, render, empty='Нет сохранённых записей.'):
            return list_html(render(row) for row in rows) if rows else f'<p>{text(empty)}</p>'

        body = (f'<p>Задача #{task_id} · {text(task["target"])}</p>'
                f'<p class="report-outcome" id="final-outcome">{text(outcome.get("label") or "Итог цели неизвестен")}</p>'
                f'<p>Закрытие задачи · {status(data["closure"])}</p><h2>Достигнутые цели</h2>'
                + list_or_empty([goal for goal in goals if goal['status'] == 'confirmed'], lambda goal: text(goal['title'])))
        old = outcome.get('legacy_evidence_count')
        if old is not None:
            body += f'<p>Подтверждения по прежнему реестру · {text(old)}</p>'
        for state, title in (('accepted', 'Принятые кандидаты'), ('legacy', 'Подтверждённые ранее кандидаты'),
                             ('pending', 'Кандидаты, ожидающие решения'),
                             ('rejected', 'Отклонённые кандидаты')):
            body += f'<h2>{title}</h2>' + list_or_empty([c for c in candidates if c['status'] == state],
                lambda c: link(f'{base}/flags/{c["id"]}', f'Кандидат #{c["id"]}') + ' · ' + text(c['objective_title']))
        body += '<h2>Открытые вопросы</h2>' + list_or_empty(questions,
            lambda q: link(f'{base}/questions/{q["id"]}', f'#{q["id"]} · {q["question"]}'))
        body += controls(link(f'/tasks/{task_id}', 'Открыть задачу'))
        return screen(f'Итоговый отчёт задачи #{task_id}', body)

    def method_form(self, path, token, ident, item, mode, params=None, message=''):
        if params is None:
            params = {key: '\n'.join(value) if isinstance(value, list) else value
                      for key, value in (item or {}).get('content', {}).items()}
            params['version'] = str((item or {}).get('version', 0))
            origins = (item or {}).get('origins', [])
            if origins:
                origin = origins[-1]
                params.update(task_id=str(origin.get('task_id', '')), kind=origin.get('evidence_kind', ''),
                              result_id=origin.get('result_id', ''), artifact_ref=origin.get('artifact_ref', ''))
        params = public_form_values(params)
        body = notice(message, error=True) if message else ''
        method_href = f'/methods/{ident}' if ident else '/methods'
        if mode == 'withdraw':
            body += self.method_description(item['content'])
            body += '<h2>Сохранённое основание</h2>' + details(item['origins'][-1], {
                'task_id': 'Задача', 'result_id': 'Result ID', 'artifact_ref': 'Артефакт'})
        else:
            body += ''.join(field(name, label, params, multiline=name in METHOD_LISTS or name == 'conditions',
                                  required=True, hint='По одному значению на строку.' if name in METHOD_LISTS else '')
                            for name, label in METHOD_FIELDS.items() if not ident or name != 'key')
            body += '<h2>Основание совета</h2>'
            body += field('task_id', 'Номер задачи с оригиналом', params, required=True)
            body += ''.join(field(name, label, params, options=EVIDENCE_KINDS if name == 'kind' else None,
                                  multiline=name == 'quote', required=name != 'series_id')
                            for name, label in EVIDENCE_FIELDS.items())
        body += field('reason', 'Причина изменения' if mode != 'new' else 'Причина сохранения', params,
                      required=mode != 'new')
        body += controls(button('Проверить совет' if mode != 'withdraw' else 'Проверить отзыв', value='preview'),
                         link(method_href, 'Отмена'))
        title = {'edit': 'Исправить совет', 'withdraw': 'Отозвать совет', 'new': 'Сохранить совет'}[mode]
        return screen(title, self.form(path, token, body, {'version': params['version']}))

    @staticmethod
    def method_description(spec):
        return details({key: '\n'.join(value) if isinstance(value, list) else value for key, value in spec.items()},
                       METHOD_FIELDS)

    def method_post(self, path, token, ident, mode, params):
        item = self.library.get(ident) if ident else None
        href = f'/methods/{ident}' if ident else '/methods'
        expected = (item or {}).get('version', 0)
        if params.get('version') != str(expected):
            return self.method_conflict(href)
        action = params.get('action')
        if action not in ('preview', 'save'):
            raise FormError('Неверное действие с советом.')
        values = {key: params[key] for key in (*METHOD_FIELDS, *EVIDENCE_FIELDS, 'task_id', 'reason', 'version')
                  if key in params}
        if action == 'save' and params.get('review') != self.review_token(path, token, values):
            return 409, self.method_form(path, token, ident, item, mode, params, 'Повторите проверку перед записью.')
        try:
            reason = validate_visible(params.get('reason', '')).strip()
            if not reason and mode == 'new':
                reason = 'selected_successful_method'
            if not reason or len(reason) > 500:
                raise FormError('Укажите причину до 500 символов.')
            if mode == 'withdraw':
                spec = item['content']
                origin = item['origins'][-1]
                observed = item['observed_result']
                if action == 'save':
                    self.library.withdraw(ident, expected, reason)
                    return 303, href
            else:
                spec = {key: validate_visible(params.get(key, '')).strip() for key in METHOD_FIELDS}
                if ident:
                    spec['key'] = item['content']['key']
                for key in METHOD_LISTS:
                    spec[key] = [line.strip() for line in spec[key].splitlines() if line.strip()]
                evidence = {k: validate_visible(params.get(k, '')) for k in EVIDENCE_FIELDS}
                if not evidence['series_id']:
                    del evidence['series_id']
                task_number = params.get('task_id', '')
                if not re.fullmatch(r'[1-9][0-9]{0,17}', task_number):
                    raise FormError('Укажите номер сохранённой задачи с оригиналом.')
                task_id = int(task_number)
                with task_view.read_database(self.database) as db, http_artifacts.saved_artifact_location(self.artifact_root):
                    require_task(db, task_id)
                    known = method_library.secret_values(db, task_id)
                    private = [key for key in (*METHOD_FIELDS, 'quote', 'reason')
                               if any(value in params.get(key, '') for value in known)]
                    if private:
                        params = {key: value for key, value in params.items() if key not in private}
                        raise FormError('В форме есть известное секретное значение задачи. Удалите его из совета и цитаты.')
                    log = self.database.parent / 'capability_log' / f'task_{task_id}.jsonl'
                    if action == 'save':
                        result = self.library.save(db, task_id, spec, evidence, log,
                                                   expected_version=expected, reason=reason)
                        return 303, '/methods/' + result['id']
                    spec, observed, origin = self.library.inspect(db, task_id, spec, evidence, log, reason=reason)
        except FileNotFoundError:
            return 422, self.method_form(path, token, ident, item, mode, params,
                                         'Задача, журнал операции или исходный материал не найдены.')
        except ValueError as exc:
            if str(exc) == 'method_version_conflict':
                return self.method_conflict(href)
            return 422, self.method_form(path, token, ident, item, mode, params, str(exc))
        preview = (self.method_description(spec) + '<h2>Проверенное основание</h2>'
                   + details(origin, {'task_id': 'Задача', 'result_id': 'Result ID', 'artifact_ref': 'Артефакт'})
                   + details(observed, {'kind': 'Тип результата', 'meaning': 'Что установлено'})
                   + f'<p>Причина · {text(reason)}</p>')
        values['review'] = self.review_token(path, token, values)
        return 200, screen('Проверка совета', preview + self.form(
            path, token, controls(button('Подтвердить отзыв' if mode == 'withdraw' else 'Сохранить совет'),
                                  link(href, 'Отмена')), values))

    @staticmethod
    def method_conflict(href):
        return 409, screen('Совет уже изменён', notice('Другая вкладка сохранила новую версию. Перечитайте карточку.', error=True)
                           + controls(link(href, 'Перечитать карточку')))

    def task_view(self, match, token, params):
        task_id, resource, number = int(match[1]), match[2], int(match[3]) if match[3] else None
        if (resource in ('context', 'report') and number is not None) or (resource == 'flags' and number is None):
            return None
        if params is not None and (resource == 'report' or (resource == 'questions' and number is None)):
            return None
        opener = task_view.read_database(self.database) if params is None else self.writer()
        with opener as db:
            task = require_task(db, task_id)
            if resource == 'context':
                if params is None:
                    return 200, self.context_page(db, task, token)
                return self.context_post(db, task, params, token)
            if resource == 'report':
                return 200, self.report(db, task)
            if resource == 'flags':
                candidate = next((item for item in flag_review.listing(db, task_id) if item['id'] == number), None)
                if candidate is None:
                    raise FileNotFoundError('candidate')
                return (200, self.candidate_page(task, candidate, token)) if params is None else self.candidate_post(
                    db, task, candidate, params, token)
            if number is None:
                return 200, self.questions_page(db, task)
            row = next((item for item in operator_questions.listing(db, task_id) if item['id'] == number), None)
            if row is None:
                raise FileNotFoundError('question')
            return (200, self.question_page(task, row, token)) if params is None else self.answer(db, task, row, params, token)

    def dispatch(self, path, token, params=None):
        try:
            if path == '/management' and params is None:
                return 200, self.index()
            if match := DRAFT_ROUTE.fullmatch(path):
                if params is None:
                    return 200, self.draft_saved(int(match[1])) if match[1] else self.draft_page(token)
                if not match[1]:
                    return self.draft_post(params, token)
            if match := TASK_ROUTES.fullmatch(path):
                return self.task_view(match, token, params)
            if match := METHOD_ROUTES.fullmatch(path):
                if not match[1] and not match[2]:
                    return None
                ident, mode = match[2], match[3] or 'new'
                if params is not None:
                    return self.method_post(path, token, ident, mode, params)
                item = self.library.get(ident) if ident else None
                return 200, self.method_form(path, token, ident, item, mode)
        except FileNotFoundError:
            return 404, screen('Запись не найдена', notice('Сохранённая запись отсутствует.', error=True))
        except task_view.WalDatabaseError:
            return 500, screen('Хранилище', notice(task_view.WAL_ERROR, error=True))
        except (OSError, sqlite3.Error):
            return 500, screen('Хранилище', notice('Не удалось открыть или обновить хранилище.', error=True))
        except FormError as exc:
            return 422, screen('Проверьте данные', notice(str(exc), error=True))
        except ValueError as exc:
            if str(exc) in ('method_unknown_id', 'method_unknown_version'):
                return 404, screen('Совет не найден', notice('Совет или версия отсутствуют.', error=True))
            return 500, screen('Хранилище', notice('Не удалось прочитать сохранённые данные.', error=True))
        except (KeyError, TypeError):
            return 500, screen('Хранилище', notice('Не удалось прочитать сохранённые данные.', error=True))
        return None
