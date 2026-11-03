"""Pure SQLite tests for master_scheduler's no-retry queue selection.

Run from the pentest-master project root:
  .venv/bin/python tests/test_master_scheduler.py
"""
import importlib.util
import sqlite3
import sys
import tempfile
import types
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
for name in ('orchestrator.evidence_pipeline', 'orchestrator.network_workflow',
             'orchestrator.network_enrichment', 'orchestrator.network_jobs'):
    sys.modules[name] = types.ModuleType(name)

spec = importlib.util.spec_from_file_location('master_scheduler',
                                                ROOT / 'orchestrator/master_scheduler.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

db = sqlite3.connect(':memory:')
db.executescript('''
CREATE TABLE network_phase_plans (
 id INTEGER PRIMARY KEY, task_id INTEGER, status TEXT, profile TEXT
);
CREATE TABLE network_job_runs (
 id INTEGER PRIMARY KEY, plan_id INTEGER, status TEXT
);
INSERT INTO network_phase_plans VALUES(1,9,'planned','tcp_ports');
INSERT INTO network_phase_plans VALUES(2,9,'planned','http_headers');
INSERT INTO network_phase_plans VALUES(3,9,'planned','service_versions');
INSERT INTO network_phase_plans VALUES(4,9,'planned','http_get');
INSERT INTO network_phase_plans VALUES(5,8,'planned','tcp_ports');
INSERT INTO network_job_runs VALUES(1,1,'completed');
INSERT INTO network_job_runs VALUES(2,3,'failed');
''')
assert module.pending(db, 9, module.BASE_PROFILES) == [
    {'plan_id': 2, 'profile': 'http_headers'}]
assert module.pending(db, 9, module.ENRICHMENT_PROFILES) == [
    {'plan_id': 4, 'profile': 'http_get'}]
assert module.pending(db, 8, module.BASE_PROFILES) == [
    {'plan_id': 5, 'profile': 'tcp_ports'}]
print('[PASS] completed and failed jobs are not run again')
print('[PASS] task and executor profiles are isolated')
