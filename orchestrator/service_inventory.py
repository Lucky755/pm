"""Read-only, task/address-scoped service inventory over existing evidence tables.

Port reachability is evidence; product/version identification remains a hint.
The context view is bounded, while original rows and their references stay stored.
"""
from datetime import datetime, timezone
from collections import Counter
import json
import hashlib
import os
import re
import sqlite3

ENTRY_LIMIT = 12
SOURCE_LIMIT = 8
IDENTIFICATION_LIMIT = 8


def timestamp(value):
    try:
        parsed = datetime.fromisoformat(str(value).replace('Z', '+00:00'))
        return parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=timezone.utc)
    except (ValueError, TypeError):
        return None


def age_minutes():
    # Same explicit policy as the operator console's full-scan cache warning.
    return max(1, int(os.environ.get('PM_TCP_SCAN_STALE_MINUTES', '30')))


def decoded(value):
    try:
        return json.loads(value)
    except (ValueError, TypeError):
        return None


def collect_full(db, task_id, *, at=None, address=None):
    """Complete structured inventory for execution, with the shared source filters.

    Do not pass this unbounded view to a model; collect() provides that view.
    Text notes and previous-address hints are never execution inventory.
    """
    now = at or datetime.now(timezone.utc)
    ttl = age_minutes()
    entries, coverage = {}, None
    counts = {'pm_tcp_full_scans': 0, 'network_observations': 0}
    status = {}
    target, scope_valid = None, False

    def fresh(value):
        when = timestamp(value)
        return when is not None and 0 <= (now - when).total_seconds() <= ttl * 60

    def reference(table, key, when, **extra):
        parsed = timestamp(when)
        return {'table': table, 'key': key,
                'observed_at': parsed.isoformat() if parsed else None,
                'fresh': fresh(when), **extra}

    def add(port, protocol, source, identification=None):
        if type(port) is not int or not 1 <= port <= 65535 or protocol not in ('tcp', 'udp'):
            return False
        entry = entries.setdefault((protocol, port), {
            'target': target, 'protocol': protocol, 'port': port, 'state': 'open',
            'sources': [], 'identifications': []})
        entry['sources'].append(source)
        if identification is not None:
            entry['identifications'].append(identification)
        return True

    if isinstance(db, sqlite3.Connection):
        from orchestrator.network_workflow import load_task_target
        from executor.task_scope import check_action
        try:
            primary = load_task_target(db, task_id)
            target=address or primary
            if address and address!=primary:
                from orchestrator import resources
                state=resources.saved(db,task_id)
                if not state or address not in state['policy']['addresses']:raise ValueError('Address is not associated with this task')
            scope_valid = check_action(db, task_id, 'connect', target)['decision'] == 'ALLOW'
            status['scope'] = 'allowed' if scope_valid else 'denied'
        except (sqlite3.Error, ValueError):
            status['scope'] = 'unavailable_or_mismatched'

    if scope_valid:
        try:
            columns = {row[1] for row in db.execute('PRAGMA table_info(pm_tcp_full_scans)')}
            order = 'created_at DESC' + (',id DESC' if 'id' in columns else '')
            cursor = db.execute('SELECT * FROM pm_tcp_full_scans WHERE task_id=? AND target=? '
                                'ORDER BY ' + order + ' LIMIT 1', (task_id, target))
            row = cursor.fetchone()
            scan = dict(zip((c[0] for c in cursor.description), row)) if row else None
            status['pm_tcp_full_scans'] = scan['status'] if scan else 'absent'
            if scan and scan['status'] in ('completed','partial','empty'):
                ports = decoded(scan['open_ports_json'])
                if scan['status']=='empty' and ports:ports=None
                if isinstance(ports, list):
                    when, attempt_id = scan.get('created_at'), None
                    try:
                        attempt = db.execute("SELECT id,created_at FROM pm_tcp_full_scan_attempts "
                                             "WHERE task_id=? AND target=? AND status=? "
                                             'ORDER BY created_at DESC,id DESC LIMIT 1',
                                             (task_id, target,'failed' if scan['status']=='partial' else 'empty' if scan['status']=='empty' else 'completed')).fetchone()
                        if attempt and timestamp(attempt[1]) and (
                                not timestamp(when) or timestamp(attempt[1]) >= timestamp(when)):
                            attempt_id, when = attempt
                    except sqlite3.OperationalError:
                        pass  # Older databases have no attempt history.
                    key = {'id': scan['id']} if scan.get('id') is not None else {'task_id': task_id, 'target': target}
                    source = reference('pm_tcp_full_scans', key, when, task_id=task_id, target=target)
                    if attempt_id is not None:
                        source['attempt_id'] = attempt_id
                    valid_ports = sorted({p for p in ports if type(p) is int and 1 <= p <= 65535})
                    coverage = {'source': source, 'ports_total': len(valid_ports),'complete':scan['status'] in ('completed','empty'),'exhaustive_services':False,
                                'last_seen_at': timestamp(scan.get('last_seen_at')).isoformat()
                                if timestamp(scan.get('last_seen_at')) else None}
                    if attempt_id is not None:
                        try:
                            raw=db.execute('SELECT result_json FROM pm_tcp_full_scan_attempts WHERE id=?',(attempt_id,)).fetchone()
                            result=decoded(raw[0]) if raw else None
                            if isinstance(result,dict):coverage['discovery_summary']=result.get('port_discovery')
                        except sqlite3.OperationalError:pass
                    for port in valid_ports:
                        add(port, 'tcp', source)
                    counts['pm_tcp_full_scans'] = 1
                else:
                    status['pm_tcp_full_scans'] = 'invalid_ports'
        except sqlite3.OperationalError:
            status['pm_tcp_full_scans'] = 'unavailable'

        try:
            rows = db.execute('''SELECT o.id,o.kind,o.data_json,o.observed_at,r.id,p.id,
                                        p.profile,p.parameters_json,r.result_json
                FROM network_observations o
                JOIN network_job_runs r ON r.id=o.run_id
                JOIN network_phase_plans p ON p.id=r.plan_id
                WHERE o.task_id=? AND p.task_id=? AND o.target=? AND p.target=?
                  AND r.status='completed' ORDER BY o.id''', (task_id, task_id, target, target))
            status['network_observations'] = 'available'
            profiles = {'tcp_port_open': ('tcp_ports',), 'service_probe': ('service_versions',),
                        'http_response': ('http_headers', 'https_headers'), 'http_content': ('http_get',)}
            for oid, kind, raw, when, run_id, plan_id, profile, params_raw, result_raw in rows:
                if profile not in profiles.get(kind, ()):
                    continue
                data, result = decoded(raw), decoded(result_raw)
                if not isinstance(data, dict):
                    continue
                # An inconsistent completed row cannot promote a failed executor result.
                if isinstance(result, dict) and (
                        result.get('status') in ('failed', 'blocked', 'error', 'timeout')
                        or result.get('exit_code') not in (None, 0)
                        or result.get('task_id', task_id) != task_id
                        or result.get('target', target) != target):
                    continue
                params = decoded(params_raw)
                params = params if isinstance(params, dict) else {}
                port, protocol = data.get('port'), data.get('protocol', 'tcp')
                if kind == 'tcp_port_open' and (data.get('state') != 'open' or protocol != 'tcp'):
                    continue
                if kind == 'service_probe' and data.get('state', 'open') != 'open':
                    continue
                if kind in ('http_response', 'http_content'):
                    if not re.match(r'^HTTP/\d(?:\.\d)?\s+\d{3}\b', str(data.get('status_line', ''))):
                        continue
                    port, protocol = params.get('port'), 'tcp'
                source = reference('network_observations', {'id': oid}, when,
                                   task_id=task_id, target=target, run_id=run_id, plan_id=plan_id, kind=kind)
                if isinstance(result, dict) and re.fullmatch(r'[a-f0-9]{24}', str(result.get('result_id', ''))):
                    source['result_id'] = result['result_id']
                identification = None
                if data.get('service_hint') or data.get('version_hint'):
                    service, version = str(data.get('service_hint') or ''), str(data.get('version_hint') or '')
                    identification = {'service_hint': service[:80], 'version_hint': version[:240],
                                      'text_truncated': len(service) > 80 or len(version) > 240,
                                      'verified_product': data.get('verified_product') is True,
                                      'service_verified': data.get('service_verified') is True,
                                      'identification_uncertain': data.get('identification_uncertain', True) is not False,
                                      'source': source}
                    if len(service) > 80:
                        identification['service_hint_sha256'] = hashlib.sha256(service.encode()).hexdigest()
                    if len(version) > 240:
                        identification['version_hint_sha256'] = hashlib.sha256(version.encode()).hexdigest()
                if add(port, protocol, source, identification):
                    counts['network_observations'] += 1
        except sqlite3.OperationalError:
            status['network_observations'] = 'unavailable'

    def source_key(source):
        when = timestamp(source['observed_at'])
        return (-(when.timestamp() if when else 0), source['table'], json.dumps(source['key'], sort_keys=True))

    # Discovery states and availability are distinct from service identities.
    port_states=[]
    if scope_valid:
        try:
            from orchestrator import port_research
            latest={}
            for data in port_research.records(db,task_id,target):
                source=reference('network_observations',{'id':data['observation_id']},data['observed_at'],run_id=data['run_id'],plan_id=data['plan_id'],execution_outcome=data['job_outcome'])
                counts['network_observations']+=1
                latest[(data['protocol'],data['port'])]={**data,'source':source}
                if data['state']=='open':add(data['port'],data['protocol'],source)
            port_states=[latest[k] for k in sorted(latest)]
        except sqlite3.OperationalError:pass
    availability=[]
    if scope_valid:
        try:
            availability=[{'port':p,'protocol':'tcp','state':state,'checked_at':stamp,'purpose':'availability'} for p,state,stamp in db.execute('SELECT port,state,checked_at FROM pm_port_preflight WHERE task_id=? AND target=? ORDER BY port',(task_id,target))]
        except sqlite3.OperationalError:pass
    for entry in entries.values():
        sources, identities = entry['sources'], entry['identifications']
        services = {i.get('service_hint_sha256', i['service_hint']) for i in identities if i['service_hint']}
        versions = {i.get('version_hint_sha256', i['version_hint']) for i in identities if i['version_hint']}
        entry['identification_conflict'] = len(services) > 1 or len(versions) > 1
        entry['identification_uncertain'] = (not identities or entry['identification_conflict']
                                             or any(i['text_truncated'] or i['identification_uncertain'] or not i['verified_product']
                                                    for i in identities))
        entry['fresh'] = any(s['fresh'] for s in sources)
        entry['sources_total'] = len(sources)
        entry['sources_omitted'] = 0
        entry['identifications_total'] = len(identities)
        entry['identifications_omitted'] = 0
        entry['sources'] = sorted(sources, key=source_key)
        entry['identifications'] = sorted(identities, key=lambda i: source_key(i['source']))
    all_entries = [entries[key] for key in sorted(entries)]
    scan_fresh = bool(coverage and coverage['ports_total'] and coverage['source']['fresh'])
    is_fresh = any(e['fresh'] for e in all_entries)
    reason = ('fresh_full_tcp_scan' if scan_fresh else 'fresh_structured_observations' if is_fresh
              else 'structured_data_stale' if all_entries else 'no_structured_services')
    mode='spot_check' if is_fresh else 'full_scan'
    if coverage and coverage['source']['fresh']:
        mode='spot_check'
        if not coverage['ports_total']:reason='saved_tcp_discovery_no_open_ports_use_udp_or_targeted_queue'
        elif not coverage['complete']:reason='partial_tcp_discovery_resume_explicit_queue'
    if isinstance(db,sqlite3.Connection):
        from orchestrator import resources
        scope=resources.saved(db,task_id)
        if scope and (scope['policy']['area']=='web' or scope['policy']['origins'] and not scope['policy']['host_addresses']):
            mode,reason='web_only','web_scope_no_host_scan'
        elif scope and scope['migration']:
            mode,reason='spot_check','same_machine_address_change_reuse_saved_state'
        from orchestrator.target_availability import saved
        target_status=saved(db,task_id)
        if not target_status['network_allowed']:mode,reason='saved_only','target_'+target_status['state']
    return {'task_id': task_id, 'target': target, 'scope_valid': scope_valid,
            'max_age_minutes': ttl, 'full_scan': coverage, 'source_status': status,
            'source_counts': counts, 'fresh': is_fresh,
            'scan_mode':mode, 'scan_mode_reason': reason,
            'port_states':port_states,'port_availability':availability,'exhaustive_services':False,
            'port_state_counts':dict(Counter(r['state'] for r in port_states)),
            'port_availability_counts':dict(Counter(r['state'] for r in availability)),
            'total_entries': len(all_entries), 'omitted_entries': 0, 'entries': all_entries}


def collect(db, task_id, *, keep=ENTRY_LIMIT, at=None):
    """Bounded prompt representation of the same inventory; never execution input."""
    inventory = collect_full(db,task_id,at=at)
    limit = min(ENTRY_LIMIT,max(0,int(keep)))
    entries = [{**entry, 'sources':entry['sources'][:SOURCE_LIMIT],
                'sources_omitted':max(0,entry['sources_total']-SOURCE_LIMIT),
                'identifications':entry['identifications'][:IDENTIFICATION_LIMIT],
                'identifications_omitted':max(0,entry['identifications_total']-IDENTIFICATION_LIMIT)}
               for entry in inventory['entries'][:limit]]
    return {**inventory,'entries':entries,'omitted_entries':max(0,inventory['total_entries']-limit),
        'port_states':inventory['port_states'][:limit],'port_states_omitted':max(0,len(inventory['port_states'])-limit),
        'port_availability':inventory['port_availability'][:limit],'port_availability_omitted':max(0,len(inventory['port_availability'])-limit)}
