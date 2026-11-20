"""Generated project launcher, local HTTP and Chromium over guarded test data."""
from contextlib import closing
from html import escape
import http.client
import io
import json
import os
from pathlib import Path
import runpy
import select
import shutil
import signal
import sqlite3
import subprocess
import tempfile
import unittest
from unittest.mock import patch
from urllib.parse import urlsplit

from executor.netguard_root import tool_digest
from orchestrator import coordinated_attack, flag_review, http_client, method_library, objectives, operator_questions
from orchestrator import pivoting, resources, task_memory, task_view
from tests.run_offline import ROOT, storage_guard


REPORT_CREDENTIAL_HEADERS = (
    'Начало заголовков <script>\n'
    'x-ApI-kEy: REPORT_API_TEXT_SYNTH\n'
    'pRoXy-AuThOrIzAtIoN: Basic REPORT_PROXY_TEXT_SYNTH\n'
    '{"X-API-Key": "REPORT_API_JSON_SYNTH", '
    '"Proxy-Authorization": "Basic REPORT_PROXY_JSON_SYNTH", "X-Trace": "Соседний заголовок"}\n'
    'Конец заголовков'
)
REPORT_HEADER_SECRETS = ('REPORT_API_TEXT_SYNTH', 'REPORT_PROXY_TEXT_SYNTH',
                         'REPORT_API_JSON_SYNTH', 'REPORT_PROXY_JSON_SYNTH')
REPORT_SENSITIVE_PAIRS = (
    ('x-aPi-kEy', 'PAIR_API_SYNTH'),
    ('pRoXy-aUtHoRiZaTiOn', 'Basic PAIR_PROXY_SYNTH'),
    ('X-API-Key', 'PAIR_API_REPEAT_SYNTH'),
)
REPORT_PAIR_SECRETS = tuple(value for _, value in REPORT_SENSITIVE_PAIRS)


def header_pairs_summary(*, redacted=False, indent=None):
    pairs = [(name, '[REDACTED]' if redacted else value) for name, value in REPORT_SENSITIVE_PAIRS]
    headers = http_client.pairs([*pairs, ('X-Trace', 'Обычное значение & <b>метка</b>')])
    fragment = json.dumps({'headers': headers}, ensure_ascii=False, indent=indent)
    return f'Перед списком <script>\n{fragment}\nПосле списка'


class WebRuntimeTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='pm-web-')
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.storage = self.root / 'fixture ? storage'
        self.database = self.storage / 'tasks.db'
        guard = self.root / 'guard'
        guard.mkdir()
        self.env = {**os.environ, 'PYTHONPATH': storage_guard(guard),
                    'PM_METHOD_LIBRARY_DIR': str(self.storage / 'method_library')}
        # Keep diagnostics from both the CLI and menu in the fixture directory.
        with (guard / 'sitecustomize.py').open('a') as source:
            source.write(f'\nfrom orchestrator import diagnostics\ndiagnostics.EVENT_DIR = Path({str(self.storage / "run_events")!r})\n')
        self.addCleanup(lambda: self.assertFalse((guard / 'storage-violation').exists()))
        for key in ('DEEPSEEK_API_KEY', 'EXPERIENTIAL_API_KEY', 'GLM_API_KEY'):
            self.env.pop(key, None)
        # Run the project installer with a disposable user directory. The
        # generated launcher execs the actual pm.py with the project Python.
        self.launcher = self.install_launcher(ROOT, self.root)

    def install_launcher(self, project, home):
        from contextlib import redirect_stdout
        with patch.object(Path, 'home', return_value=home), redirect_stdout(io.StringIO()):
            runpy.run_path(str(project / 'install_launcher.py'), run_name='__main__')
        return home / '.local/bin/pentest-master'

    def use_fixture_as_default_storage(self):
        project = self.root / 'project'
        project.mkdir()
        for filename in ('pm.py', 'install_launcher.py'):
            shutil.copyfile(ROOT / filename, project / filename)
        (project / '.venv').symlink_to(ROOT / '.venv', target_is_directory=True)
        (project / 'storage').symlink_to(self.storage, target_is_directory=True)
        self.launcher = self.install_launcher(project, self.root / 'operator')

    def cli(self, *args, **kwargs):
        return subprocess.run([self.launcher, *args], cwd=self.root, env=self.env,
                              capture_output=True, text=True, timeout=10, **kwargs)

    def serve(self):
        process = subprocess.Popen([self.launcher, 'web', '--storage', self.storage, '--port', '0'],
                                   cwd=self.root, env=self.env, stdin=subprocess.DEVNULL,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        def stop():
            if process.poll() is None:
                process.send_signal(signal.SIGINT)
            try:
                process.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.communicate(timeout=5)
        self.addCleanup(stop)
        self.assertTrue(select.select([process.stdout], [], [], 10)[0], 'PM web did not print a URL')
        startup = process.stdout.readline()
        if not startup:
            self.fail(process.communicate(timeout=5)[1])
        self.url = startup.strip().split()[-1]
        self.port = urlsplit(self.url).port
        self.assertEqual(self.url, f'http://127.0.0.1:{self.port}/')

    def get(self, path, *, method='GET', headers=None):
        with closing(http.client.HTTPConnection('127.0.0.1', self.port, timeout=5)) as connection:
            connection.request(method, path, headers=headers or {})
            response = connection.getresponse()
            return response.status, response.read().decode('utf-8')

    def seed_task(self, task_id=1, *, expected=None, accepted=0, target='192.0.2.10'):
        self.storage.mkdir(exist_ok=True)
        with closing(sqlite3.connect(self.database)) as db, db:
            db.execute('CREATE TABLE IF NOT EXISTS tasks(id INTEGER PRIMARY KEY,target TEXT,status TEXT,description TEXT)')
            db.execute("INSERT INTO tasks VALUES (?,?,'pending_review','Сохранённое описание')",
                       (task_id, target))
            if expected is not None:
                objectives.save_objectives(db, task_id, 'Найти флаг', expected_flags=expected)
                flag_review.activate(db, task_id, expected)
                for index in range(accepted):
                    proposal = flag_review.propose(db, task_id, f'fixture-flag-{index}', objective_key='goal')
                    question = flag_review.enqueue(db, proposal['id'])
                    operator_questions.answer(db, task_id, question['id'], 'approve')

    def snapshot(self):
        files = {path.relative_to(self.storage).as_posix(): path.read_bytes()
                 for path in self.storage.rglob('*') if path.is_file()}
        with closing(sqlite3.connect(self.database.as_uri() + '?mode=ro', uri=True)) as db:
            return files, list(db.iterdump())

    def test_empty_storage_and_occupied_port_via_launcher(self):
        self.serve()
        code, body = self.get('/')
        self.assertEqual(code, 200)
        self.assertIn('Источник данных отсутствует', body)
        self.assertIn('Сохранённых советов пока нет', self.get('/methods')[1])
        self.assertEqual(self.get('/tasks/1')[0], 404)
        self.assertEqual(self.get('/', method='HEAD'), (200, ''))
        self.assertEqual(self.get('/', headers={'Host': 'another.invalid'})[0], 400)
        occupied = self.cli('web', '--storage', self.storage, '--port', str(self.port))
        self.assertEqual(occupied.returncode, 1)
        self.assertIn(f'Порт {self.port} занят', occupied.stderr)
        self.assertFalse(self.storage.exists())
        ordinary = self.cli(input='0\n')
        self.assertEqual(ordinary.returncode, 0, ordinary.stderr)
        self.assertIn('ГЛАВНОЕ МЕНЮ', ordinary.stdout)
        self.assertFalse(self.storage.exists())

    def test_old_task_and_read_errors_without_migration(self):
        self.seed_task()
        before = self.snapshot()
        self.serve()
        self.assertIn('href="/tasks/1"', self.get('/')[1])
        code, body = self.get('/tasks/1')
        self.assertEqual(code, 200)
        self.assertIn('Итог цели неизвестен', body)
        self.assertIn('Сохранённое описание', body)
        self.assertEqual(before, self.snapshot())
        # A corrupt source gives a read error and preserves the original.
        corrupted = b'not SQLite'
        self.database.write_bytes(corrupted)
        self.assertEqual(self.get('/')[0], 500)
        self.assertEqual(self.get('/tasks/1')[0], 500)
        self.assertEqual(self.database.read_bytes(), corrupted)

    def test_wal_db_is_not_opened_when_sqlite_could_create_sidecars(self):
        self.seed_task()
        with closing(sqlite3.connect(self.database)) as db:
            self.assertEqual(db.execute('PRAGMA journal_mode=WAL').fetchone()[0], 'wal')
        before = {p.name: p.read_bytes() for p in self.storage.iterdir()}
        self.serve()
        for path in ('/', '/tasks/1'):
            code, body = self.get(path)
            self.assertEqual(code, 500)
            self.assertIn('WAL-базы', body)
        cli = self.cli('--diagnostic', 'status', '1', '--storage', self.storage)
        self.assertEqual(cli.returncode, 1)
        self.assertIn('WAL-базы', cli.stderr)
        self.assertEqual(before, {p.name: p.read_bytes() for p in self.storage.iterdir()})

    def test_delete_mode_rereads_committed_data_with_writer_open(self):
        self.seed_task()
        self.serve()
        with closing(sqlite3.connect(self.database)) as writer:
            self.assertEqual(writer.execute('PRAGMA journal_mode').fetchone()[0], 'delete')
            writer.execute("UPDATE tasks SET description='Новое описание после commit' WHERE id=1")
            self.assertIn('Сохранённое описание', self.get('/tasks/1')[1])
            writer.commit()
            before = self.snapshot()
            code, body = self.get('/tasks/1')
            self.assertEqual(code, 200)
            self.assertIn('Новое описание после commit', body)
            self.assertEqual(before, self.snapshot())

    def test_question_views_preserve_unqueued_candidate_and_answer_history(self):
        self.seed_task(expected=2, accepted=1, target='10.71.0.1')
        with closing(sqlite3.connect(self.database)) as db, db:
            flag_review.propose(db, 1, 'not-yet-queued', objective_key='goal')
        before = self.snapshot()
        self.use_fixture_as_default_storage()
        self.serve()
        self.assertIn('Ожидающих вопросов нет.', self.get('/tasks/1')[1])
        self.assertEqual(before, self.snapshot())
        result = self.cli('--diagnostic', 'questions', '1', '--json')
        self.assertEqual(result.returncode, 0, result.stderr)
        rows = json.loads(result.stdout)
        self.assertEqual([row['status'] for row in rows], ['answered'])
        self.assertEqual(rows[0]['answer']['decision'], 'approve')
        self.assertEqual(before, self.snapshot())
        menu = self.cli(input='9\n1\n\n0\n')
        self.assertEqual(menu.returncode, 0, menu.stderr)
        self.assertNotIn('[ОШИБКА]', menu.stderr)
        self.assertIn('ID вопроса для ответа', menu.stdout)
        self.assertEqual(before, self.snapshot())

    def test_explicit_cli_answer_writes_saved_question_and_goal(self):
        self.seed_task(expected=1, target='10.71.0.1')
        with closing(sqlite3.connect(self.database)) as db, db:
            proposal = flag_review.propose(db, 1, 'answer-fixture', objective_key='goal')
            question = flag_review.enqueue(db, proposal['id'])
        self.use_fixture_as_default_storage()
        result = self.cli('questions', '1', '--answer', str(question['id']), '--decision', 'approve', '--json')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)[0]['status'], 'answered')
        with task_view.read_database(self.database) as db:
            self.assertEqual(flag_review.completion(db, 1), 'objectives_done')
            self.assertEqual(operator_questions.listing(db, 1)[0]['answer']['decision'], 'approve')
        self.assertEqual(len(list((self.storage / 'run_events').glob('*.jsonl'))), 1)

    def test_status_and_report_menu_show_saved_findings(self):
        self.seed_task(expected=1, accepted=1)
        digest = 'c' * 64
        with closing(sqlite3.connect(self.database)) as db, db:
            db.execute('CREATE TABLE pm_tcp_full_scans(task_id INTEGER,target TEXT,status TEXT,open_ports_json TEXT)')
            db.execute("INSERT INTO pm_tcp_full_scans VALUES(1,'192.0.2.10','completed','[22,8080]')")
            db.execute("INSERT INTO pm_tcp_full_scans VALUES(1,'192.0.2.99','completed','[9999]')")
            db.execute('CREATE TABLE evidence_snapshots(task_id INTEGER,evidence_sha256 TEXT,evidence_json TEXT,created_at TEXT)')
            bundle = {'network_observations': [{'kind': 'tcp_port_open', 'data': {'port': 22, 'service_hint': 'ssh'}}],
                      'web_observations': [{'path': '/fixture', 'status_code': 200, 'title': 'Страница фикстуры'}]}
            db.execute("INSERT INTO evidence_snapshots VALUES(1,?,?,'t')", (digest, json.dumps(bundle)))
        before = self.snapshot()
        self.use_fixture_as_default_storage()
        for result in (self.cli('status', '1'), self.cli(input='3\n1\n0\n')):
            with self.subTest(output=result.stdout):
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertNotIn('[ОШИБКА]', result.stderr)
                for label in ('TCP/22', 'ssh', 'TCP/8080', '200', '/fixture', 'Страница фикстуры', 'Цель достигнута · 1 из 1'):
                    self.assertIn(label, result.stdout)
                self.assertNotIn('TCP/9999', result.stdout)
        result = self.cli('status', '1', '--json')
        self.assertEqual(result.returncode, 0, result.stderr)
        data = json.loads(result.stdout)
        self.assertEqual(data['evidence_sha256'], digest)
        self.assertEqual(data['network_observations'], 1)
        self.assertEqual(data['burp_observations'], 0)
        self.assertEqual(data['outcome']['data']['label'], 'Цель достигнута · 1 из 1')
        self.assertEqual(before, self.snapshot())
        with closing(sqlite3.connect(self.database)) as db, db:
            db.execute('DROP TABLE evidence_snapshots')
        before = self.snapshot()
        partial = self.cli('status', '1')
        self.assertEqual(partial.returncode, 0, partial.stderr)
        self.assertIn('TCP/8080', partial.stdout)
        self.assertEqual(before, self.snapshot())

    def test_status_preserves_protocol_and_excludes_non_open_probes(self):
        self.seed_task()
        records = [
            ('tcp_port_open', {'protocol': 'tcp', 'port': 22, 'state': 'open', 'service_hint': 'ssh'}),
            ('service_probe', {'protocol': 'udp', 'port': 53, 'state': 'open', 'service_hint': 'dns'}),
            ('service_probe', {'protocol': 'tcp', 'port': 53, 'state': 'open', 'service_hint': 'domain'}),
            ('service_probe', {'protocol': 'tcp', 'port': 443, 'state': 'closed', 'service_hint': 'https'}),
            ('service_probe', {'protocol': 'udp', 'port': 161, 'state': 'open|filtered'}),
            ('service_probe', {'protocol': 'tcp', 'port': 8443, 'state': 'unknown'}),
            ('service_probe', {'port': 8081, 'service_hint': 'legacy-http'}),
        ]
        bundle = {'network_observations': [{'kind': kind, 'data': data} for kind, data in records]}
        with closing(sqlite3.connect(self.database)) as db, db:
            db.execute('CREATE TABLE evidence_snapshots(task_id INTEGER,evidence_sha256 TEXT,evidence_json TEXT,created_at TEXT)')
            db.execute("INSERT INTO evidence_snapshots VALUES(1,?,?,'t')", ('c' * 64, json.dumps(bundle)))
            db.execute('CREATE TABLE pm_tcp_full_scans(task_id INTEGER,target TEXT,status TEXT,open_ports_json TEXT)')
            db.execute("INSERT INTO pm_tcp_full_scans VALUES(1,'192.0.2.10','completed','[22,8080]')")
        before = self.snapshot()
        result = self.cli('status', '1', '--storage', self.storage)
        self.assertEqual(result.returncode, 0, result.stderr)
        open_lines = [line.strip() for line in result.stdout.splitlines() if '[OPEN]' in line]
        self.assertCountEqual(open_lines, [
            '[OPEN] TCP/22: ssh', '[OPEN] TCP/53: domain', '[OPEN] UDP/53: dns',
            '[OPEN] TCP/8080: сервис не определён', '[OPEN] TCP/8081: legacy-http',
        ])
        result = self.cli('status', '1', '--json', '--storage', self.storage)
        self.assertEqual(result.returncode, 0, result.stderr)
        data = json.loads(result.stdout)
        self.assertEqual(data['network_observations'], len(records))
        self.assertEqual(data['findings']['tcp'], [
            {'port': 22, 'service': 'ssh'}, {'port': 53, 'service': 'domain'},
            {'port': 8080, 'service': None}, {'port': 8081, 'service': 'legacy-http'},
        ])
        self.assertEqual(data['findings']['udp'], [{'port': 53, 'service': 'dns'}])
        self.assertEqual(before, self.snapshot())

    def test_journal_damage_and_recovery_are_local_to_each_run(self):
        self.seed_task(1)
        self.seed_task(2)
        self.serve()
        journals = self.storage / 'run_events'
        journals.mkdir()
        # A path that cannot be opened as a log must not hide other runs.
        (journals / ('f' * 32 + '.jsonl')).mkdir()

        def records(task_id, run_id):
            start = {'run_id': run_id, 'kind': 'run.start', 'task_id': task_id,
                     'timestamp': task_id, 'name': 'Локальный отчёт'}
            end = {**start, 'kind': 'run.summary', 'status': 'completed', 'reason': 'Запись завершена'}
            return ((json.dumps(record, ensure_ascii=False) + '\n').encode('utf-8') for record in (start, end))

        first_id, second_id = 'a' * 32, 'b' * 32
        first_path, second_path = (journals / f'{ident}.jsonl' for ident in (first_id, second_id))
        first = b''.join(records(1, first_id))
        first_path.write_bytes(first)
        start, end = records(2, second_id)
        warning = 'Некоторые строки журнала не удалось прочитать.'
        utf8_split = end.index('Запись'.encode('utf-8')) + 1
        for cut in (10, utf8_split):
            with self.subTest(cut=cut):
                partial = start + end[:cut]
                second_path.write_bytes(partial)
                first_page = self.get('/tasks/1')[1]
                self.assertIn(first_id, first_page)
                self.assertIn('Вызов PM · завершён', first_page)
                self.assertNotIn(warning, first_page)
                second_page = self.get('/tasks/2')[1]
                self.assertIn(second_id, second_page)
                self.assertIn('исход не записан', second_page)
                self.assertIn(warning, second_page)
                self.assertEqual(second_path.read_bytes(), partial)
        with second_path.open('ab') as stream:
            stream.write(end[utf8_split:])
        second_page = self.get('/tasks/2')[1]
        self.assertIn('Вызов PM · завершён', second_page)
        self.assertIn('Запись завершена', second_page)
        self.assertNotIn(warning, second_page)
        self.assertIn(first_id, self.get('/tasks/1')[1])
        self.assertNotIn(warning, self.get('/tasks/1')[1])
        self.assertEqual(first_path.read_bytes(), first)
        self.assertEqual(second_path.read_bytes(), start + end)

    def test_cli_and_http_agree_on_manual_flag_outcome(self):
        cases = (
            (1, 1, 0, 'Цель ещё не достигнута · 0 из 1'),
            (2, 1, 1, 'Цель достигнута · 1 из 1'),
            (3, 2, 1, 'Цель ещё не достигнута · 1 из 2'),
        )
        for task_id, expected, accepted, _ in cases:
            self.seed_task(task_id, expected=expected, accepted=accepted)
        before = self.snapshot()
        self.serve()
        for task_id, expected, accepted, label in cases:
            with self.subTest(task=task_id):
                code, body = self.get(f'/tasks/{task_id}')
                self.assertEqual(code, 200)
                self.assertIn(f'id="goal-outcome">{label}</p>', body)
                result = self.cli('status', str(task_id), '--storage', self.storage)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn(label, result.stdout)
                result = self.cli('status', str(task_id), '--storage', self.storage, '--json')
                self.assertEqual(result.returncode, 0, result.stderr)
                verdict = json.loads(result.stdout)['outcome']['data']
                self.assertEqual((verdict['accepted'], verdict['expected']), (accepted, expected))
        self.assertEqual(before, self.snapshot())

    def seed_catalog(self):
        library = method_library.Library(self.storage / 'method_library')
        ident = 'method:' + 'a' * 24
        content = {'key': 'catalog-test', 'title': 'Сохранённый совет', 'profiles': ['verify'],
                   'problem_tags': ['capture'], 'conditions': 'Сохранён оригинал',
                   'method': ['Проверить контрольную сумму'], 'tools': ['pm_http_read'],
                   'limitations': ['Только сохранённые данные'], 'not_applicable': ['Оригинал отсутствует']}
        with library.writer() as catalog:
            catalog['methods'][ident] = [{
                'id': ident, 'version': 1, 'status': 'active', 'content': content,
                'content_sha256': task_memory.digest(content),
                'observed_result': {'kind': 'http_response', 'meaning': 'Квитанция сохранена'},
                'origins': [{'internal': 'origin-must-not-be-in-html'}],
                'created_at': '2026-11-18T00:00:00Z', 'reason': 'Проверено',
            }]
        library.withdraw(ident, 1, 'Отзыв для теста')
        return ident, library.root / 'catalog.json'

    def test_catalog_versions_and_corruption_do_not_hide_task(self):
        self.seed_task()
        ident, path = self.seed_catalog()
        self.serve()
        self.assertIn('версия 2 · отозван', self.get('/methods')[1])
        self.assertIn('Версия 2 · отозван', self.get(f'/methods/{ident}')[1])
        _, body = self.get(f'/methods/{ident}/1')
        for label in ('Версия 1 · действует', 'Сохранён оригинал', 'Проверить контрольную сумму',
                      'Квитанция сохранена', 'Только сохранённые данные', 'История версий', 'Отзыв для теста'):
            self.assertIn(label, body)
        self.assertNotIn('origin-must-not-be-in-html', body)
        broken = b'{"schema":1,"methods":'
        path.write_bytes(broken)
        code, body = self.get('/methods')
        self.assertEqual(code, 500)
        self.assertIn('Ошибка чтения каталога советов', body)
        self.assertEqual(self.get('/tasks/1')[0], 200)
        self.assertEqual(path.read_bytes(), broken)

    def seed_waiting_task(self):
        self.seed_task(expected=1)
        with closing(sqlite3.connect(self.database)) as db, db:
            coordinated_attack.ensure_schema(db)
            db.execute("CREATE TABLE pm_task_intents (task_id INTEGER PRIMARY KEY,intent TEXT)")
            db.execute("INSERT INTO pm_task_intents VALUES (1,'Найти флаг\nБез брутфорса <script>')")
            db.execute("INSERT INTO pm_coordinator_runs VALUES "
                       "(1,1,'192.0.2.10','waiting_operator','operator_questions_pending',NULL,'t','t')")
            db.execute("INSERT INTO pm_coordinator_steps (id,run_id,task_id,step_no,status,decision_json,"
                       "state_sha256,budgets_json,created_at,updated_at,report_iteration) "
                       "VALUES (1,1,1,1,'completed',?,'','{}','t','t',1)",
                       (json.dumps({'role': 'verify', 'profile': 'verify', 'question': 'Локальный аудит'}),))
            db.execute("CREATE TABLE pm_agent_action_reports "
                       "(task_id INTEGER,role TEXT,iteration INTEGER,report_json TEXT,created_at TEXT)")
            db.execute("INSERT INTO pm_agent_action_reports VALUES (1,'verify',1,?,'t')",
                       (json.dumps({'summary': 'Проверены сохранённые данные <script>', 'report_path': '/private.txt'}),))
            proposal = flag_review.propose(db, 1, 'fixture-candidate', objective_key='goal')
            flag_review.enqueue(db, proposal['id'])
            # A view must not reconcile this unqueued candidate.
            flag_review.propose(db, 1, 'other-unqueued-candidate', objective_key='goal')
        journals = self.storage / 'run_events'
        journals.mkdir()
        run_id = 'b' * 32
        records = [{'run_id': run_id, 'timestamp': 1, 'kind': 'run.start', 'name': 'pm:op_resume'},
                   {'run_id': run_id, 'timestamp': 2, 'kind': 'run.summary', 'task_id': 1,
                    'status': 'completed', 'reason': 'operator_questions_pending'}]
        (journals / f'{run_id}.jsonl').write_text(''.join(json.dumps(event) + '\n' for event in records))

    def test_two_chromium_tabs_refresh_questions_and_report_without_writes(self):
        from playwright.sync_api import sync_playwright

        self.seed_waiting_task()
        self.seed_catalog()
        before = self.snapshot()
        self.serve()
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(executable_path='/usr/bin/chromium', headless=True)
            try:
                task, other = browser.new_page(), browser.new_page()
                self.assertEqual(task.goto(self.url + 'tasks/1').status, 200)
                self.assertEqual(other.goto(self.url + 'tasks/1#questions').status, 200)
                self.assertIn('Вызов PM · завершён', task.locator('main').inner_text())
                self.assertIn('Координатор · ожидает оператора', task.locator('main').inner_text())
                self.assertIn('Закрытие задачи · неизвестно', task.locator('main').inner_text())
                self.assertIn('Без брутфорса <script>', task.locator('.task-records pre').inner_text())
                self.assertEqual(task.locator('script:not([src])').count(), 0)
                self.assertEqual(task.locator('script[src="/assets/console.js"]').count(), 1)
                self.assertEqual(other.locator('#questions li').count(), 1)
                for tab in (task, other):
                    self.assertEqual(tab.reload().status, 200)
                    self.assertEqual(tab.locator('#questions li').count(), 1)
                task.get_by_role('link', name='VERIFY #1').click()
                self.assertIn('Проверены сохранённые данные', task.locator('main').inner_text())
                self.assertNotIn('/private.txt', task.content())
                self.assertEqual(self.get('/tasks/2/reports/verify-1')[0], 404)
                self.assertEqual(self.get('/tasks/1/reports/%2e%2e%2fprivate.txt')[0], 404)
            finally:
                browser.close()
        self.assertEqual(before, self.snapshot())
        with task_view.read_database(self.database) as db:
            with self.assertRaisesRegex(sqlite3.OperationalError, 'readonly'):
                db.execute("UPDATE tasks SET status='closed'")

    def test_http_response_masks_report_credential_headers_without_browser(self):
        self.seed_waiting_task()
        summary = f'{REPORT_CREDENTIAL_HEADERS}\n{header_pairs_summary()}'
        with closing(sqlite3.connect(self.database)) as db, db:
            db.execute('UPDATE pm_agent_action_reports SET report_json=?',
                       (json.dumps({'summary': summary}),))
        before = self.snapshot()
        self.serve()
        code, raw = self.get('/tasks/1/reports/verify-1')
        self.assertEqual(code, 200)
        for secret in (*REPORT_HEADER_SECRETS, *REPORT_PAIR_SECRETS):
            with self.subTest(secret=secret):
                self.assertNotIn(secret, raw)
        self.assertIn('Начало заголовков &lt;script&gt;\nx-ApI-kEy: [REDACTED]\n'
                      'pRoXy-AuThOrIzAtIoN: [REDACTED]\n', raw)
        self.assertIn('Соседний заголовок', raw)
        self.assertIn('\nКонец заголовков', raw)
        self.assertIn(escape(header_pairs_summary(redacted=True)), raw)
        self.assertEqual(self.get('/tasks/1/reports/verify-1'), (200, raw))
        self.assertEqual(before, self.snapshot())

    def write_dashboard_step(self, db, number, role, profile, status, question):
        decision = json.dumps({'action': 'run_role', 'role': role, 'profile': profile, 'question': question})
        db.execute("INSERT INTO pm_coordinator_steps (id,run_id,task_id,step_no,status,decision_json,"
                   "state_sha256,budgets_json,created_at,updated_at) VALUES (?,1,1,?,?,?,'','{}','t','t')",
                   (number, number, status, decision))

    def write_dashboard_event(self, number, kind, **fields):
        run_id = 'b' * 32
        row = {'run_id': run_id, 'event_id': f'{number:032x}', 'task_id': 1, 'timestamp': 1795141800 + number,
               'kind': kind, **fields}
        with (self.storage / 'run_events' / f'{run_id}.jsonl').open('a', encoding='utf-8') as journal:
            journal.write(json.dumps(row, ensure_ascii=False) + '\n')

    def write_dashboard_route(self, db, number, address, state):
        ref = resources.node(db, 1, 'address', address)
        spec = {'source_session': '0123abcd', 'resource_ref': ref, 'destination': address,
                'port': 8080, 'local_port': 18887 + number, 'probe': 'http_headers', 'purpose': 'Лаборатория'}
        manifest = {'task_id': 1, 'spec': spec, 'source_ssh': {}, 'listener': '127.0.0.1:18888',
                    'rights': 'task user', 'actions': ['forward']}
        receipt = {'request_id': tool_digest(manifest), 'manifest': manifest, 'status': state}
        db.execute('INSERT INTO pm_pivot_routes VALUES (?,1,?,?,?,?,?,?)',
                   (number, f'route-fixture-{number}', '0123abcd', ref, 1, state, json.dumps(receipt)))
        return receipt['request_id']

    def seed_dashboard(self):
        self.seed_waiting_task()
        self.seed_task(2, target='198.51.100.10')
        with closing(sqlite3.connect(self.database)) as db, db:
            pivoting.initialize(db)
            resources.initialize(db)
            db.execute("INSERT INTO pm_task_sessions VALUES "
                       "(1,'0123abcd','192.0.2.10','student','Сохранённая SSH-сессия',1,'open','','run','{}','2026-11-20')")
            receipt = self.write_dashboard_route(db, 1, '192.0.2.30', 'active')
            self.write_dashboard_route(db, 2, '192.0.2.31', 'pending')
            db.execute('CREATE TABLE evidence_snapshots(task_id INTEGER,evidence_sha256 TEXT,evidence_json TEXT,created_at TEXT)')
            bundle = {'network_observations': [
                {'kind': 'service_probe', 'data': {'port': 22, 'protocol': 'tcp', 'state': 'open', 'service_hint': 'ssh'}},
                {'kind': 'service_probe', 'data': {'port': 443, 'protocol': 'tcp', 'state': 'open', 'service_hint': 'https'}},
                {'kind': 'service_probe', 'data': {'port': 53, 'protocol': 'udp', 'state': 'open', 'service_hint': 'dns'}},
            ], 'web_observations': [{'path': '/portal', 'status_code': 200, 'title': 'Портал лаборатории'}]}
            db.execute("INSERT INTO evidence_snapshots VALUES (1,?,?,'t')", ('d' * 64, json.dumps(bundle)))
            db.execute("UPDATE pm_coordinator_steps SET decision_json=? WHERE id=1", (
                json.dumps({'role': 'recon', 'profile': 'recon', 'question': 'Прочитать сохранённую карту сервисов'}),
            ))
            self.write_dashboard_step(db, 2, 'vuln', 'web', 'running', 'Сопоставить сохранённые HTTP-ответы')
            self.write_dashboard_step(db, 3, 'verify', 'http-audit', 'running', 'Проверить источник наблюдения')
            self.write_dashboard_step(db, 4, 'access', 'ssh', 'completed', 'Проверка сессии')
            http_client.initialize(db)
            db.execute("INSERT INTO pm_http_exchanges VALUES "
                       "(1,1,'web-session',NULL,'GET','https://192.0.2.10/portal?token=WEB_QUERY_SYNTH',"
                       "'192.0.2.10','digest','operation','finished',NULL,'{}','2026-11-20T02:30:12Z')")
        for number, role in enumerate(('recon', 'vuln', 'verify'), 1):
            self.write_dashboard_event(number, 'coordinator.decision', role=role, step_id=number, coordinator_run_id=1)
        for number in range(6, 16):
            self.write_dashboard_event(number, 'tool.end', role='recon', name='pm_http_capture', status='completed')
        self.write_dashboard_event(17, 'operator.question', reason='flag_confirmation', identifiers={'question_id': 1})
        caps = self.storage / 'capability_log'
        caps.mkdir()
        (caps / 'task_1.jsonl').write_text(json.dumps({
            'id': 'c' * 24, 'task_id': 1, 'tool': 'research', 'timestamp': '2026-11-20T02:30:15Z',
            'actor_role': 'vuln', 'argv': ['curl', '-H', 'X-API-Key: DASH_HEADER_SYNTH',
                                          'https://example.invalid/reference?token=DASH_QUERY_SYNTH'],
            'result': {'status': 'completed', 'exit_code': 0, 'stdout': 'DASH_OUTPUT_SYNTH'},
        }) + '\n', encoding='utf-8')
        return receipt

    def test_dashboard_updates_in_place_in_chromium(self):
        from playwright.sync_api import expect, sync_playwright

        receipt = self.seed_dashboard()
        original = self.snapshot()
        self.serve()
        code, raw = self.get('/tasks/1/view.json')
        self.assertEqual(code, 200)
        data = json.loads(raw)
        self.assertEqual(len(data['agents']['edges']), 3)
        self.assertNotIn('step:4', {edge['to'] for edge in data['agents']['edges']})
        self.assertIn('example.invalid/reference', raw)
        self.assertIn('Вопрос оператору', raw)
        self.assertIn('https://192.0.2.10/portal', raw)
        secrets = ('DASH_HEADER_SYNTH', 'DASH_QUERY_SYNTH', 'WEB_QUERY_SYNTH', 'DASH_OUTPUT_SYNTH')
        for secret in secrets:
            self.assertNotIn(secret, raw)
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(executable_path='/usr/bin/chromium', headless=True)
            try:
                tab = browser.new_page(viewport={'width': 1440, 'height': 1000})
                tab.goto(self.url + 'tasks/1')
                expect(tab.locator('[data-key="step:3"]')).to_be_visible()
                expect(tab.locator('[data-key="step:4"]')).to_contain_text('Кто назначил — не записано')
                expect(tab.locator('#agents .wire')).to_have_count(3)
                self.assertEqual(tab.locator('.sky').evaluate('(node) => getComputedStyle(node).animationName'), 'orbit')
                self.assertGreater(tab.locator('.workgrid').bounding_box()['width'], 1240)
                expect(tab.locator('#questions li')).to_have_count(1)
                self.assertEqual(original, self.snapshot())
                step = tab.locator('[data-key="step:3"]')
                step.evaluate('(node) => window.originalStep = node')
                previous_position = step.bounding_box()
                with closing(sqlite3.connect(self.database)) as db, db:
                    self.write_dashboard_step(db, 5, 'recon', 'service-review', 'running', 'Сохранённый TCP-инвентарь')
                assignment = {'role': 'recon', 'step_id': 5, 'coordinator_run_id': 1}
                self.write_dashboard_event(20, 'coordinator.decision', **assignment)
                self.write_dashboard_event(20, 'coordinator.decision', **assignment)
                self.write_dashboard_event(21, 'tool.end', task_id=2, task_ids=[1, 2], reason='Чужая запись')
                expect(tab.locator('[data-key="step:5"]')).to_be_visible()
                self.assertTrue(step.evaluate('(node) => node === window.originalStep'))
                self.assertEqual(step.bounding_box(), previous_position)
                expect(tab.locator('#agents .wire')).to_have_count(4)
                step.locator('button').click()
                self.save_dashboard_screenshot(tab, '01-agents')

                tab.get_by_role('link', name='Карта цели').click()
                expect(tab.locator('.inventory')).to_contain_text('UDP/53')
                expect(tab.locator('.inventory')).to_contain_text('/portal')
                expect(tab.locator('#map .pending .wire')).to_have_count(1)
                expect(tab.locator('#map .confirmed .wire')).to_have_count(2)
                old_route = tab.locator('[data-key="pivot:1"]')
                old_route.locator('button').click()
                expect(tab.locator('#selection')).to_contain_text(receipt)
                self.save_dashboard_screenshot(tab, '02-map')

                tab.set_viewport_size({'width': 390, 'height': 850})
                tab.emulate_media(reduced_motion='reduce')
                self.assertEqual(tab.locator('.sky').evaluate('(node) => getComputedStyle(node).animationName'), 'none')
                self.assertTrue(tab.locator('#map .pulse').first.is_hidden())
                self.assertTrue(tab.evaluate('document.documentElement.scrollWidth <= innerWidth'))
                map_scroll = tab.locator('#map .diagram-scroll')
                map_scroll.evaluate('(node) => { node.scrollLeft = 210 }')
                old_route.evaluate('(node) => window.originalRoute = node')
                old_left = map_scroll.evaluate('(node) => node.scrollLeft')
                self.assertGreater(old_left, 0)
                with closing(sqlite3.connect(self.database)) as db, db:
                    db.execute("UPDATE pm_pivot_routes SET state='unknown' WHERE id=1")
                    self.write_dashboard_route(db, 3, '192.0.2.32', 'pending')
                expect(tab.locator('[data-key="pivot:3"]')).to_be_visible()
                expect(tab.locator('#selection')).to_contain_text('исход неизвестен')
                self.assertTrue(old_route.evaluate('(node) => node === window.originalRoute'))
                expect(old_route.locator('button')).to_have_attribute('aria-pressed', 'true')
                self.assertEqual(map_scroll.evaluate('(node) => node.scrollLeft'), old_left)
                old_route.locator('button').click()
                expect(tab.locator('#selection')).to_contain_text(receipt)

                tab.get_by_role('link', name='История', exact=True).click()
                history = tab.locator('#history-entries')
                first = history.locator('li').first
                first.locator('summary').click()
                expect(first.locator('details')).to_have_attribute('open', '')
                history_scroll = tab.locator('#history-log')
                history_scroll.evaluate('(node) => { node.scrollTop = 0 }')
                connection = tab.locator('#connection')
                tab.route('**/view.json', lambda route: route.abort())
                expect(connection).to_contain_text('Источник временно недоступен')
                self.write_dashboard_event(22, 'session.state', role='access', current_state='open')
                tab.unroute('**/view.json')
                expect(connection).to_have_text('Чтение сохранённых данных')
                expect(history.get_by_text('Состояние сессии', exact=True)).to_have_count(1)
                expect(history.get_by_text('Назначение координатора', exact=True)).to_have_count(4)
                expect(history.get_by_text('Чужая запись', exact=True)).to_have_count(0)
                expect(first.locator('details')).to_have_attribute('open', '')
                self.assertEqual(history_scroll.evaluate('(node) => node.scrollTop'), 0)
                external = history.locator('li').filter(has_text='Обращение за внешними данными')
                external.locator('summary').click()
                expect(external.locator('pre')).to_contain_text('https://example.invalid/reference')
                for secret in secrets:
                    self.assertNotIn(secret, tab.content())
                tab.set_viewport_size({'width': 1440, 'height': 1000})
                tab.emulate_media(reduced_motion='no-preference')
                external.scroll_into_view_if_needed()
                external.evaluate('(node) => node.scrollIntoView({block: "center"})')
                tab.evaluate('window.scrollTo(0, 0)')
                self.save_dashboard_screenshot(tab, '03-history')
                final = self.snapshot()
                tab.goto(self.url + 'tasks/2#history')
                expect(tab.locator('#history-entries')).to_contain_text('Чужая запись')
                expect(tab.locator('#history-entries')).not_to_contain_text('Назначение координатора')
                self.assertEqual(final, self.snapshot())
            finally:
                browser.close()

    def save_dashboard_screenshot(self, tab, name):
        if destination := os.environ.get('PM_WEB_SCREENSHOTS'):
            folder = Path(destination)
            folder.mkdir(parents=True, exist_ok=True)
            tab.screenshot(path=folder / f'{name}.png', animations='disabled')

    def test_browser_masks_secrets_before_escaping_and_sending_html(self):
        from playwright.sync_api import sync_playwright

        self.seed_waiting_task()
        self.seed_task(2)
        report = {
            'summary': 'Обычный текст отчёта <script>\nAuthorization: Bearer REPORT_AUTH_SYNTH\n'
                       f'{REPORT_CREDENTIAL_HEADERS}\n{header_pairs_summary(indent=2)}\nКонец отчёта',
            'report_warning': 'Cookie: a=WARNING_COOKIE_SYNTH; b=SECOND_COOKIE_SYNTH\nОбычное предупреждение',
            'report_quality': {'reason': 'Причина отчёта token="QUALITY TOKEN SYNTH" далее'},
        }
        with closing(sqlite3.connect(self.database)) as db, db:
            db.execute('UPDATE pm_agent_action_reports SET report_json=?', (json.dumps(report),))
            db.execute("UPDATE pm_task_intents SET intent='Задание\nCookie: sid=INTENT_COOKIE_SYNTH\nОграничение остаётся'")
            db.execute("UPDATE tasks SET description='Описание password=DESCRIPTION_PASS_SYNTH далее' WHERE id=2")
            db.execute('UPDATE pm_coordinator_steps SET decision_json=?', (
                json.dumps({'role': 'verify', 'question': 'Поручение access_token=STEP_TOKEN_SYNTH далее'}),))
            db.execute('UPDATE pm_operator_questions SET question=?,reason=?', (
                'Вопрос: /fixture?password=QUESTION_PASS_SYNTH&page=2',
                'Причина: {"Authorization": "Basic REASON_AUTH_SYNTH", "text": "Пояснение остаётся"}'))
        before = self.snapshot()
        self.serve()
        secrets = ('REPORT_AUTH_SYNTH', 'WARNING_COOKIE_SYNTH', 'SECOND_COOKIE_SYNTH', 'QUALITY TOKEN SYNTH',
                   'INTENT_COOKIE_SYNTH', 'DESCRIPTION_PASS_SYNTH', 'STEP_TOKEN_SYNTH',
                   'QUESTION_PASS_SYNTH', 'REASON_AUTH_SYNTH', *REPORT_HEADER_SECRETS, *REPORT_PAIR_SECRETS)
        pages = {
            '/tasks/1': ('Задание\n', 'Ограничение остаётся', 'Поручение', 'далее', 'page=2', 'Пояснение остаётся'),
            '/tasks/2': ('Описание', 'далее'),
            '/tasks/1/reports/verify-1': ('Обычный текст отчёта', 'Конец отчёта', '[REDACTED]\nОбычное предупреждение',
                                          'Причина отчёта', 'далее', 'Соседний заголовок',
                                          'Начало заголовков <script>\nx-ApI-kEy: [REDACTED]\n'
                                          'pRoXy-AuThOrIzAtIoN: [REDACTED]\n',
                                          header_pairs_summary(redacted=True, indent=2)),
        }
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(executable_path='/usr/bin/chromium', headless=True)
            try:
                tab = browser.new_page()
                for path, ordinary in pages.items():
                    with self.subTest(path=path):
                        code, raw = self.get(path)
                        self.assertEqual(code, 200)
                        self.assertEqual(tab.goto(self.url.rstrip('/') + path).status, 200)
                        html = tab.content()
                        visible = tab.locator('main').inner_text()
                        for secret in secrets:
                            with self.subTest(secret=secret):
                                self.assertNotIn(secret, html)
                                self.assertNotIn(secret, visible)
                                self.assertNotIn(secret, raw)
                        for fragment in ordinary:
                            self.assertIn(fragment, visible)
                        self.assertIn('[REDACTED]', visible)
                self.assertIn('&lt;script&gt;', raw)
                self.assertEqual(tab.locator('script').count(), 0)
                self.assertEqual(tab.locator('pre b').count(), 0)
            finally:
                browser.close()
        self.assertEqual(before, self.snapshot())

if __name__ == '__main__':
    unittest.main()
