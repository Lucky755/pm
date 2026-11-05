"""Local flag witnesses rooted in the existing HTTP capture store, never PoC prose.

No commands, network, schema initialization, or task-state writes. Git decoding
is deliberately fixed: a zlib loose object must match its captured URL's SHA-1,
type and exact length. A self-reported hash in stdout is not an input here.
"""
import hashlib
import re
import sqlite3
import zlib

from orchestrator import http_artifacts as artifacts


def collect(db, task_id):
    from executor.task_scope import check_action
    from orchestrator.network_workflow import load_task_target
    witnesses, errors = [], []
    exists = db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='pm_http_artifacts'").fetchone()
    if not exists:
        return witnesses, errors
    try:
        target = load_task_target(db, task_id)
        if check_action(db, task_id, 'connect', target)['decision'] != 'ALLOW':
            return [], [{'reason': 'capture_scope_denied'}]
    except (sqlite3.Error, ValueError):
        return [], [{'reason': 'capture_scope_unavailable'}]
    rows = db.execute('SELECT id,path,sha256,status_code,complete,scheme,hostname,port FROM pm_http_artifacts '
                      'WHERE task_id=? AND target=? ORDER BY id', (task_id, target))
    seen = {}
    for aid, path, capture_sha, status, complete, scheme, hostname, port in rows:
        if not complete or not 200 <= status < 600:
            continue
        ref = f'http_artifact:{aid}'
        try:
            body, metadata = artifacts.load(db, task_id, aid)
        except (OSError, ValueError):
            errors.append({'capture_ref': ref, 'reason': 'capture_integrity_failed'})
            continue
        if not isinstance(metadata,dict) or not isinstance(metadata.get('headers',{}),dict):
            errors.append({'capture_ref':ref,'reason':'capture_metadata_invalid'})
            continue
        object_path = re.fullmatch(r'(.*/\.git)/objects/([0-9a-f]{2})/([0-9a-f]{38})', path)
        proof = {'kind': 'http_capture', 'task_id': task_id, 'target': target,
                 'capture_ref': ref, 'capture_refs':[ref], 'path': path, 'capture_sha256': capture_sha,
                 'scheme':scheme,'hostname':hostname,'port':port,'status_code':status}
        if object_path:
            try:
                decoder = zlib.decompressobj()
                raw = decoder.decompress(body, artifacts.MAX_BODY + 256)
                if not decoder.eof or decoder.unused_data or decoder.unconsumed_tail:
                    raise ValueError('incomplete_or_oversized_git_object')
                header, decoded = raw.split(b'\0', 1)
                match = re.fullmatch(rb'(blob|tree|commit) (0|[1-9][0-9]*)', header)
                oid = object_path[2] + object_path[3]
                if not match:
                    raise ValueError('git_object_header_invalid')
                if int(match[2]) != len(decoded) or len(decoded) > artifacts.MAX_BODY:
                    raise ValueError('git_object_size_mismatch')
                if hashlib.sha1(raw).hexdigest() != oid:
                    raise ValueError('git_object_hash_mismatch')
                if match[1] != b'blob':
                    continue  # Trees/commits are not flag-bearing file bodies.
                text = decoded.decode('utf-8')
                proof.update(kind='git_blob', object_id=oid)
                body = decoded
            except (ValueError, zlib.error, UnicodeError) as exc:
                reasons = {'incomplete_or_oversized_git_object','git_object_header_invalid',
                           'git_object_size_mismatch','git_object_hash_mismatch'}
                reason = str(exc) if str(exc) in reasons else 'git_object_decode_failed'
                errors.append({'capture_ref': ref, 'reason': reason})
                continue
        else:
            text, flags = artifacts.decode_body(body, metadata.get('headers', {}))
            if flags['text_skipped'] or flags['decode_limit'] or flags['decode_errors']:
                continue
        proof['sha256'] = hashlib.sha256(body).hexdigest()
        proof['bytes'] = len(body)
        # Reading/re-capturing identical bytes does not create another witness.
        key = (target, scheme, hostname, port, path, proof['sha256'])
        if key in seen:
            seen[key]['capture_refs'].append(ref)
            continue
        seen[key] = proof
        witnesses.append((proof, text))
    return witnesses, errors


def reference_matches(db, task_id, reference, proof, record=None):
    """A report must identify the original capture, not an arbitrary matching stdout."""
    if proof['task_id'] != task_id:
        return False
    if reference in proof['capture_refs']:
        return True
    record = record or {}
    payload = record.get('result') or {}
    return (record.get('id') == reference and record.get('task_id') == task_id
            and record.get('tool') in ('http_capture','http_document','http_path','http_get')
            and record.get('provenance') == 'network' and isinstance(payload,dict)
            and payload.get('task_id') == task_id and payload.get('target') == proof['target']
            and payload.get('status') in ('completed','ok') and payload.get('exit_code',0) == 0
            and type(payload.get('artifact_id')) is int
            and f"http_artifact:{payload['artifact_id']}" in proof['capture_refs'])
