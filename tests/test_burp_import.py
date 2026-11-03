"""Offline contract test: redacted Burp history is idempotently imported."""
import importlib.util
import json
import sqlite3
import sys
import tempfile
import types
from pathlib import Path

# Do not import the real Kali project or touch its tasks database.
sys.modules['executor'] = types.ModuleType('executor')
mod = types.ModuleType('executor.task_scope')
mod.check_action = lambda db, task_id, operation, target: {'decision': 'ALLOW' if target == '127.0.0.1' else 'DENY'}
sys.modules['executor.task_scope'] = mod

src = Path(__file__).resolve().parents[1] / 'integrations/burp-bridge/burp_import.py'
spec = importlib.util.spec_from_file_location('burp_import_tested', src)
bridge = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bridge)

with tempfile.TemporaryDirectory() as directory:
    bridge.DB_PATH = Path(directory) / 'test.db'
    with sqlite3.connect(bridge.DB_PATH) as db:
        db.execute('CREATE TABLE tasks (id INTEGER PRIMARY KEY, target TEXT)')
        db.execute('CREATE TABLE task_scope_settings (task_id INTEGER PRIMARY KEY, initial_target TEXT)')
        db.execute('INSERT INTO tasks VALUES (9, ?)', ('127.0.0.1',))
        db.execute('INSERT INTO task_scope_settings VALUES (9, ?)', ('127.0.0.1',))

    entry = {'id': 4, 'host': '127.0.0.1', 'port': 8999, 'tls': False,
             'method': 'GET', 'path_sha256': 'a' * 64,
             'has_response': True, 'status_code': 200, 'observed_at': '2026-10-31T08:00:00Z'}
    bridge.health = lambda: {'status': 'running', 'instance_id': '12345678-1234-1234-1234-123456789abc'}
    bridge.request = lambda path, params=None: {
        'status': 'ok', 'host': '127.0.0.1', 'instance_id': '12345678-1234-1234-1234-123456789abc',
        'entries': [entry] if params['after'] < 4 else []
    }
    first = bridge.import_history(9)
    second = bridge.import_history(9)
    found = bridge.list_history(9)
    assert first['inserted'] == 1, first
    assert second['inserted'] == 0, second
    assert len(found['observations']) == 1, found
    assert 'Authorization' not in json.dumps(found)
    print('[PASS] SQLite import and idempotent resume')
    print('[PASS] Scoped, metadata-only observation')
