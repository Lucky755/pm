"""No network and no model: scope-constrained decision candidate and JSON tests."""
import importlib.util
import json
import sqlite3
import sys
import types
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
# Scope dependency is replaced by a restrictive test-only stub.
executor = types.ModuleType('executor')
scope = types.ModuleType('executor.task_scope')
def check_action(db, task_id, operation, target):
    return {'decision': 'ALLOW' if task_id == 9 and target == '127.0.0.1' else 'DENY',
            'reason': 'test scope'}
scope.check_action = check_action
sys.modules['executor'] = executor
sys.modules['executor.task_scope'] = scope

path = ROOT / 'orchestrator/decision_agent.py'
spec = importlib.util.spec_from_file_location('decision_agent', path)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

db = sqlite3.connect(':memory:')
db.executescript('''
CREATE TABLE network_phase_plans (
 id INTEGER PRIMARY KEY, task_id INTEGER, goal TEXT, profile TEXT,
 target TEXT, parameters_json TEXT, argv_json TEXT, model_summary TEXT,
 status TEXT, created_at TEXT
);
INSERT INTO network_phase_plans (id,task_id,profile,target,parameters_json,status)
VALUES (4,9,'http_headers','127.0.0.1','{"port": 8080}','planned');
''')

bundle = {
 'task_id': 9,
 'authorized_target': '127.0.0.1',
 'network_observations': [
  {'observation_id': 1, 'kind': 'tcp_port_open','target': '127.0.0.1',
   'data': {'port': 8080,'protocol':'tcp','state':'open','service_hint':'http-proxy'}},
  {'observation_id': 2, 'kind': 'http_response','target': '127.0.0.1',
   'plan_id':4,'data':{'status_line':'HTTP/1.0 200 OK'}},
 ],
 'burp_http_metadata': [
  {'observation_id': 3,'port':8999,'scheme':'http','status_code':200,'has_response':True}
 ]
}
candidates = module.candidates_from_evidence(db, 9, bundle)
assert {(c['profile'],json.dumps(c['parameters'],sort_keys=True)) for c in candidates} == {
 ('service_versions','{"ports": "8080"}'),
 ('http_get','{"port": 8080, "scheme": "http"}'),
 ('http_headers','{"port": 8999}'),
}, candidates
print('[PASS] Evidence -> three grounded candidates without duplicate HEAD')
assert module.parse_selection('```json\n{"select":["c1"]}\n```', candidates) == ['c1']
assert module.parse_selection('{"select":[]}', candidates) == []
for malformed in ['{"select":["c999"]}', '{"select":["c1","c1"]}',
                  '{"select":["c1"],"command":"rm -rf /"}', '{"select":"c1"}']:
    try:
        module.parse_selection(malformed, candidates)
        raise AssertionError('Invalid selection was accepted: ' + malformed)
    except ValueError:
        pass
print('[PASS] Strict model output IDs; rejects extra commands and invented IDs')
try:
    module.candidates_from_evidence(db, 10, dict(bundle, authorized_target='198.51.100.20'))
    raise AssertionError('Out of scope accepted')
except ValueError:
    pass
print('[PASS] Destination outside task scope blocked')
module.initialize(db)
module.initialize(db)
print('[PASS] Idempotent decision tracking schema')

# Full SQLite decision/persistence test with mocked model and executor.
# This never opens a socket and never requests an API key.
evidence = types.ModuleType('orchestrator.evidence_pipeline')
def make_snapshot(db, task_id):
    assert task_id == 9
    return 'a' * 64, bundle
evidence.make_snapshot = make_snapshot
sys.modules['orchestrator.evidence_pipeline'] = evidence
import orchestrator
orchestrator.evidence_pipeline = evidence
counter = {'model': 0, 'planner': 0}
def fake_choose(bundle_arg, candidate_items):
    counter['model'] += 1
    return ['c3']
def fake_executor(task_id, candidate):
    counter['planner'] += 1
    return ['/usr/bin/curl', '--head', '--', 'http://127.0.0.1:8999/']
module.choose_with_model = fake_choose
module.executor_plan = fake_executor
first = module.plan(db, 9)
assert first['status'] == 'completed' and first['api_called'] is True
assert first['selected'] == ['c3'] and len(first['new_plans']) == 1
assert first['new_plans'][0]['parameters'] == {'port': 8999}
second = module.plan(db, 9)
assert second['status'] == 'cached' and second['api_called'] is False
assert second['new_plans'] == []
assert counter == {'model':1,'planner':1}
assert db.execute('SELECT COUNT(*) FROM network_phase_plans').fetchone()[0] == 2
print('[PASS] One model decision, one saved plan, zero additional calls on resume')
