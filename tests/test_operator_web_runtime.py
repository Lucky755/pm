"""Generated project launcher, local HTTP and Chromium over guarded test data."""
from contextlib import closing
import http.client
import io
import json
import os
from pathlib import Path
import runpy
import select
import signal
import sqlite3
import subprocess
import tempfile
import unittest
from unittest.mock import patch
from urllib.parse import urlsplit

from orchestrator import coordinated_attack, flag_review, method_library, objectives, operator_questions
from orchestrator import task_memory, task_view
from tests.run_offline import ROOT, storage_guard


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
        self.addCleanup(lambda: self.assertFalse((guard / 'storage-violation').exists()))
        for key in ('DEEPSEEK_API_KEY', 'EXPERIENTIAL_API_KEY', 'GLM_API_KEY'):
            self.env.pop(key, None)
        # Run the project installer with a disposable user directory. The
        # generated launcher execs the actual pm.py with the project Python.
        from contextlib import redirect_stdout
        with patch.object(Path, 'home', return_value=self.root), redirect_stdout(io.StringIO()):
            runpy.run_path(str(ROOT / 'install_launcher.py'), run_name='__main__')
        self.launcher = self.root / '.local/bin/pentest-master'

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

    def seed_task(self, task_id=1, *, expected=None, accepted=0):
        self.storage.mkdir(exist_ok=True)
        with closing(sqlite3.connect(self.database)) as db, db:
            db.execute('CREATE TABLE IF NOT EXISTS tasks(id INTEGER PRIMARY KEY,target TEXT,status TEXT,description TEXT)')
            db.execute("INSERT INTO tasks VALUES (?,'192.0.2.10','pending_review','Сохранённое описание')",
                       (task_id,))
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
                self.assertIn('Без брутфорса <script>', task.locator('pre').inner_text())
                self.assertEqual(task.locator('script').count(), 0)
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


if __name__ == '__main__':
    unittest.main()
