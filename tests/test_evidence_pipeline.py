"""Offline contract test, never touches Kali project DB or remote bridge."""
import importlib.util
import sqlite3
import sys
import tempfile
import types
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / 'orchestrator/evidence_pipeline.py'

# Stub the network and Burp sources with known provenance data.
network_module = types.ModuleType('orchestrator.network_workflow')
network_items = [{
    'observation_id': 7, 'run_id': 3, 'target': '127.0.0.1',
    'kind': 'tcp_port_open', 'data': {'port': 8999, 'state': 'open', 'protocol': 'tcp'},
    'source': 'completed_network_job'
}]
network_module.build_evidence_bundle = lambda db, task_id: {
    'authorized_target': '127.0.0.1', 'observations': list(network_items)
}
sys.modules['orchestrator'] = types.ModuleType('orchestrator')
sys.modules['orchestrator.network_workflow'] = network_module

spec = importlib.util.spec_from_file_location('evidence_pipeline_test', SRC)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

burp_items = [{
    'observation_id': 1, 'instance_id': 'instance-1', 'burp_id': 1,
    'port': 8999, 'scheme': 'http', 'method': 'GET',
    'path_sha256': 'a' * 64, 'has_response': True, 'status_code': 200
}]
module.load_burp = lambda: types.SimpleNamespace(
    list_history=lambda task_id, limit=50: {
        'host': '127.0.0.1', 'observations': list(burp_items)
    },
    import_history=lambda task_id, limit=50: {'status': 'completed', 'inserted': 0}
)

with tempfile.TemporaryDirectory() as temp:
    module.DB_PATH = Path(temp) / 'tmp.db'
    module.DB_PATH.touch()
    with module.connect() as db:
        first_hash, bundle = module.make_snapshot(db, 9)
        second_hash, _ = module.make_snapshot(db, 9)
        assert first_hash == second_hash
        assert db.execute('SELECT COUNT(*) FROM evidence_snapshots').fetchone()[0] == 1
        assert len(bundle['network_observations']) == 1
        assert len(bundle['burp_http_metadata']) == 1
        report = {
            'summary': 'Локальный ответ 200 не доказывает уязвимость.',
            'observations_used': ['network:7', 'burp:1'],
            'uncertainties': ['Неизвестна версия сервиса'],
            'recommended_checks': [],
        }
        module.validate_report(report, bundle)
        with db:
            db.execute('''INSERT INTO evidence_agent_reports
                (task_id, evidence_sha256, stage, report_json, created_at)
                VALUES (?, ?, ?, ?, ?)''', (9, first_hash, 'recon', '{}', module.now()))
        assert 'recon' in module.saved_reports(db, 9, first_hash)
        burp_items.append({**burp_items[0], 'observation_id': 2, 'burp_id': 2})
        updated_hash, _ = module.make_snapshot(db, 9)
        assert updated_hash != first_hash
        assert module.saved_reports(db, 9, updated_hash) == {}
        assert len(module.summary(db, 9)['pending_stages']) == 4
print('[PASS] Stable snapshots and deduplication')
print('[PASS] Scoped network + Burp metadata join')
print('[PASS] Agent report reference validation')
print('[PASS] New Burp evidence triggers a new report version')
print('[PASS] No network or model API calls')
