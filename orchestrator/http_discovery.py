"""Read-only bounded HTTP discovery using the root-owned isolated NetGuard broker.

For every task: manually launched, no brute force, no redirects followed by curl,
no forms submitted, no cookies or page bodies persisted. Finds paths from already
observed Location headers and public HTML href links on the *same* approved host.
"""
from __future__ import annotations

import html
import base64
from html.parser import HTMLParser
import ipaddress
import json
import os
import re
import sqlite3
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import unquote, urljoin, urlsplit
from orchestrator import diagnostics

ROOT = Path(__file__).resolve().parents[1]
BROKER = '/usr/local/sbin/pm-netguard'
MAX_TOTAL = 24
MAX_PER_ROUND = 3
MAX_STATIC_TOTAL = 6
MAX_BODY_PARSE = 20000
MAX_DOCUMENT_PARSE = 262144
MAX_DOCUMENT_REFRESH = 2
MAX_METADATA_REFRESH = 4
SKIP_SEGMENTS = {'logout', 'logoff', 'delete', 'remove', 'destroy', 'reset',
                 'signout', 'sign-off', 'unsubscribe', 'shutdown', 'install', 'setup'}


def now():
    return datetime.now(timezone.utc).isoformat()


def init(db):
    db.execute('''CREATE TABLE IF NOT EXISTS pm_http_discovery (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        task_id INTEGER NOT NULL,
        target TEXT NOT NULL,
        port INTEGER NOT NULL,
        scheme TEXT NOT NULL,
        hostname TEXT NOT NULL,
        path TEXT NOT NULL,
        status INTEGER,
        location TEXT,
        content_type TEXT,
        server TEXT,
        title TEXT,
        links_json TEXT NOT NULL DEFAULT '[]',
        forms_json TEXT NOT NULL DEFAULT '[]',
        error TEXT,
        assets_json TEXT NOT NULL DEFAULT '[]',
        meta_json TEXT NOT NULL DEFAULT '[]',
        created_at TEXT NOT NULL,
        UNIQUE(task_id,port,scheme,hostname,path)
    )''')
    db.execute("""CREATE TABLE IF NOT EXISTS pm_http_size_recovery (
        observation_id INTEGER PRIMARY KEY, previous_record_json TEXT NOT NULL,
        attempted_at TEXT NOT NULL)""")
    db.execute('''CREATE TABLE IF NOT EXISTS pm_http_metadata_refresh (
        observation_id INTEGER NOT NULL, parser_version INTEGER NOT NULL,
        previous_record_json TEXT NOT NULL, attempted_at TEXT NOT NULL,
        PRIMARY KEY(observation_id,parser_version))''')
    db.execute('''CREATE TABLE IF NOT EXISTS pm_http_document_refresh (
        observation_id INTEGER PRIMARY KEY, previous_record_json TEXT NOT NULL,
        attempted_at TEXT NOT NULL)''')
    db.execute('''CREATE TABLE IF NOT EXISTS pm_http_capture_refresh (
        observation_id INTEGER PRIMARY KEY, previous_record_json TEXT NOT NULL,
        attempted_at TEXT NOT NULL)''')
    db.execute('''CREATE TABLE IF NOT EXISTS pm_http_capture_upgrades (
        observation_id INTEGER PRIMARY KEY, previous_record_json TEXT NOT NULL,
        attempted_at TEXT NOT NULL)''')
    from orchestrator import http_artifacts
    http_artifacts.initialize(db)
    # Existing v2 database: NULL marks successful HTML pages that need
    # one bounded metadata refresh to discover script/style references.
    present = {row[1] for row in db.execute('PRAGMA table_info(pm_http_discovery)')}
    if 'response_limited' not in present:
        db.execute('ALTER TABLE pm_http_discovery ADD COLUMN response_limited INTEGER NOT NULL DEFAULT 0')
    if 'application_json' not in present:
        db.execute("ALTER TABLE pm_http_discovery ADD COLUMN application_json TEXT NOT NULL DEFAULT '[]'")
    for column in ('references_json', 'sources_json'):
        if column not in present:
            db.execute(f"ALTER TABLE pm_http_discovery ADD COLUMN {column} TEXT NOT NULL DEFAULT '[]'")
    if 'response_metrics_json' not in present:
        db.execute("ALTER TABLE pm_http_discovery ADD COLUMN response_metrics_json TEXT NOT NULL DEFAULT '{}'")
    if 'artifact_id' not in present:
        db.execute('ALTER TABLE pm_http_discovery ADD COLUMN artifact_id INTEGER')
    if 'parser_version' not in present:
        db.execute('ALTER TABLE pm_http_discovery ADD COLUMN parser_version INTEGER NOT NULL DEFAULT 0')
    if 'assets_json' not in present:
        db.execute('ALTER TABLE pm_http_discovery ADD COLUMN assets_json TEXT')
    if 'meta_json' not in present:
        db.execute('ALTER TABLE pm_http_discovery ADD COLUMN meta_json TEXT')
    db.commit()


def _safe_path(path):
    # Keep validation aligned with the root broker, which is the final authority.
    from executor.netguard_root import safe_http_path
    path = safe_http_path(path)
    decoded = path
    for _ in range(3):
        decoded = unquote(decoded)
    if any(segment.lower().split('.')[0] in SKIP_SEGMENTS for segment in decoded.split('/')):
        raise ValueError('Path matches potentially state-changing endpoint')
    return path


def normalize_href(href, base_url, target, allowed_hosts):
    """Return an approved (scheme, hostname, port, path), or None."""
    if not isinstance(href, str) or not 1 <= len(href) <= 300:
        return None
    href = html.unescape(href.strip())
    if not href or href.startswith(('#', '?')):
        return None
    try:
        url = urlsplit(urljoin(base_url, href))
        base = urlsplit(base_url)
        if (url.scheme not in ('http', 'https') or url.scheme != base.scheme or
                url.username is not None or url.password is not None or
                url.query or url.hostname not in allowed_hosts or
                (url.port or (443 if url.scheme == 'https' else 80)) != (base.port or (443 if base.scheme == 'https' else 80))):
            return None
        path = _safe_path(url.path or '/')
        return (url.scheme, url.hostname, url.port or (443 if url.scheme == 'https' else 80), path)
    except (ValueError, UnicodeError):
        return None


class PageMetadata(HTMLParser):
    def __init__(self, body_limit=MAX_BODY_PARSE):
        super().__init__(convert_charrefs=True)
        self._title = False
        self.title = ''
        self.links = []
        self.forms = []
        self.assets = []
        self.meta = []
        self._form = None
        self.script_blocks = []
        self._script = None
        self.body_limit = body_limit
        self.limits = set()
        self.assets_seen = 0
        self.base_href = None

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == 'title':
            self._title = True
        elif tag == 'base' and self.base_href is None and 'href' in attrs:
            self.base_href = str(attrs['href'] or '')
        elif tag == 'a':
            href = attrs.get('href')
            if href and len(self.links) < 45:
                self.links.append(href)
            elif href:
                self.limits.add('html_links')
        elif tag == 'script':
            self._script = None
            src = attrs.get('src')
            if src:
                self.assets_seen += 1
            if isinstance(src, str) and src and len(src) <= 250 and len(self.assets) < 16:
                self.assets.append({'kind': 'script', 'href': src})
            elif src:
                self.limits.add('html_asset_url_length' if len(src) > 250 else 'html_assets')
            script_type = str(attrs.get('type') or '').lower()
            if not src and script_type in ('', 'module', 'text/javascript', 'application/javascript') and len(self.script_blocks) < 8:
                self.script_blocks.append('')
                self._script = len(self.script_blocks) - 1
            elif not src and script_type in ('', 'module', 'text/javascript', 'application/javascript'):
                self.limits.add('inline_scripts')
        elif tag == 'link' and len(self.assets) < 16:
            rel = str(attrs.get('rel') or '').lower().split()
            src = attrs.get('href')
            if 'stylesheet' in rel and isinstance(src, str) and src:
                self.assets_seen += 1
                if len(src) <= 250:
                    self.assets.append({'kind': 'stylesheet', 'href': src})
                else:
                    self.limits.add('html_asset_url_length')
        elif tag == 'link' and 'stylesheet' in str(attrs.get('rel') or '').lower().split() and attrs.get('href'):
            self.assets_seen += 1
            self.limits.add('html_assets')
        elif tag == 'meta' and len(self.meta) < 8:
            name = str(attrs.get('name') or '').lower().strip()
            content = str(attrs.get('content') or '').strip()
            if name in ('generator', 'application-name') and content:
                self.meta.append({'name': name, 'content': content[:100]})
        elif tag == 'form' and len(self.forms) < 12:
            method = str(attrs.get('method') or 'GET').upper()
            action = str(attrs.get('action') or '')
            # Never save input values, cookies, page bodies, or hidden fields.
            self.forms.append({'method': method[:8], 'action': action if len(action) <= 300 else '', 'fields': []})
            if len(action) > 300:
                self.limits.add('html_form_action_length')
            self._form = self.forms[-1]
        elif tag == 'form':
            self._form = None
            self.limits.add('html_forms')
        elif tag in ('input', 'textarea', 'select') and self._form is not None:
            field_name = str(attrs.get('name') or '')
            field_type = str(attrs.get('type') or tag).lower()
            if (re.fullmatch(r'[A-Za-z0-9_.:-]{1,64}', field_name) and
                    re.fullmatch(r'[a-z0-9-]{1,24}', field_type) and
                    len(self._form['fields']) < 16):
                self._form['fields'].append({'name': field_name, 'type': field_type})

    def handle_endtag(self, tag):
        if tag == 'title':
            self._title = False
        elif tag == 'form':
            self._form = None
        elif tag == 'script':
            self._script = None

    def handle_data(self, data):
        if self._script is not None:
            self.script_blocks[self._script] += data[:self.body_limit - len(self.script_blocks[self._script])]
        if self._title and len(self.title) < 150:
            self.title += data[:150 - len(self.title)]


def _headers_and_body(stdout, body_limit=MAX_BODY_PARSE):
    # Curl --include; no automatic redirects. Bound to the first HTTP response.
    match = re.search(r'(?m)^HTTP/\d(?:\.\d)?\s+(\d{3})[^\r\n]*\r?\n', stdout)
    if not match:
        raise ValueError('No HTTP status line in isolated curl output')
    rest = stdout[match.end():]
    split = re.search(r'\r?\n\r?\n', rest)
    if rest.startswith('\r\n'):
        header_text, body = '', rest[2:]
    elif rest.startswith('\n'):
        header_text, body = '', rest[1:]
    elif split:
        header_text, body = rest[:split.start()], rest[split.end():]
    else:
        raise ValueError('No HTTP header/body separator')
    headers = {}
    for row in header_text.splitlines():
        if ':' in row:
            name, value = row.split(':', 1)
            name = name.strip().lower()
            if name in ('location', 'content-type', 'server', 'content-length'):
                headers[name] = value.strip()[:250]
    return int(match.group(1)), headers, HTTPResult(body[:body_limit], len(body) > body_limit)


def permitted_hosts(db, task_id, target):
    hosts = [target]
    exists = db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='pm_task_hostnames'").fetchone()
    if exists:
        row = db.execute('SELECT hostnames_json FROM pm_task_hostnames WHERE task_id=?', (task_id,)).fetchone()
        if row:
            hosts.extend(x for x in json.loads(row[0]) if isinstance(x, str))
    return list(dict.fromkeys(hosts))


def validate_scope(db, task_id):
    from orchestrator import network_workflow, network_enrichment
    target = network_workflow.load_task_target(db, task_id)
    if ipaddress.ip_address(target).version != 4:
        raise ValueError('HTTP Discovery needs an exact IPv4 target')
    network_enrichment.verify_scope(db, task_id, target)
    # Console's operator approval exists for real runs; no implicit override.
    row = db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='pm_operator_approvals'").fetchone()
    if row:
        approval = db.execute('''SELECT target,allowed,closed_at FROM pm_operator_approvals
                                 WHERE task_id=?''', (task_id,)).fetchone()
        if not approval or approval != (target, target + '/32', None):
            raise ValueError('Task has no active operator approval for the exact target')
    return target


def _observed_http_ports(db, task_id, target):
    from orchestrator.network_workflow import build_evidence_bundle
    raw = build_evidence_bundle(db, task_id)
    observations = raw.get('observations', [])
    chosen = {}
    for item in observations:
        if item.get('target') != target:
            continue
        kind = item.get('kind')
        data = item.get('data') or {}
        if kind == 'tcp_port_open' and data.get('state') == 'open':
            port = data.get('port')
            hint = str(data.get('service_hint') or '').lower()
            if type(port) is int and 1 <= port <= 65535 and ('http' in hint or port in (80, 8080, 8000, 443, 8443)):
                chosen[port] = 'https' if port in (443, 8443) else 'http'
        elif kind == 'http_response' and str(data.get('status_line', '')).startswith('HTTP/'):
            row = db.execute('SELECT profile,parameters_json FROM network_phase_plans WHERE id=? AND task_id=?',
                             (item.get('plan_id'), task_id)).fetchone()
            if not row:
                continue
            try:
                params = json.loads(row[1]); port = params.get('port')
                if type(port) is not int or not 1 <= port <= 65535:
                    continue
            except (ValueError, KeyError):
                continue
            scheme = 'https' if row[0] == 'https_headers' or params.get('scheme') == 'https' else 'http'
            chosen[port] = scheme
    return chosen, observations


def _candidates(db, task_id, target, hosts, *, capture=False):
    ports, observations = _observed_http_ports(db, task_id, target)
    if not ports:
        return []
    queue = []
    seen = set()

    def add(candidate):
        if candidate and ports.get(candidate[2]) == candidate[0] and candidate not in seen:
            seen.add(candidate); queue.append(candidate)

    # First: evidence-grounded redirects (e.g. ./mbilling from HTTP 302).
    for record in observations:
        if record.get('kind') != 'http_response':
            continue
        data = record.get('data') or {}
        headers = data.get('headers') or {}
        location = next((v for k, v in headers.items() if k.lower() == 'location'), None)
        row = db.execute('SELECT parameters_json FROM network_phase_plans WHERE id=? AND task_id=?',
                         (record.get('plan_id'), task_id)).fetchone()
        if not location or not row:
            continue
        try:
            port = json.loads(row[0]).get('port')
        except (ValueError, TypeError):
            continue
        if port not in ports:
            continue
        scheme = ports[port]
        add(normalize_href(location, f'{scheme}://{target}:{port}/', target, hosts))

    # Then: previously discovered public hrefs or Location redirects.
    asset_candidates = []
    for row in db.execute('''SELECT port,scheme,hostname,path,location,links_json,
                                    assets_json,meta_json,status,content_type,forms_json,references_json
                             FROM pm_http_discovery WHERE task_id=? AND error IS NULL ORDER BY id''',
                          (task_id,)):
        port, scheme, hostname, path, location, raw_links, raw_assets, _, status, ctype, raw_forms, raw_refs = row
        if port not in ports or hostname not in hosts:
            continue
        base = f'{scheme}://{hostname}:{port}{path}'
        if location:
            add(normalize_href(location, base, target, hosts))
        for link in json.loads(raw_links)[:25]:
            add(normalize_href(link, base, target, hosts))
        # Inspect only observed GET form entry pages; never submit fields.
        for form in json.loads(raw_forms or '[]')[:12]:
            if isinstance(form, dict) and form.get('method') == 'GET' and form.get('action'):
                add(normalize_href(form['action'], base, target, hosts))
        for ref in json.loads(raw_refs or '[]')[:16]:
            if not isinstance(ref, dict) or ref.get('eligible') is not True:
                continue
            candidate = normalize_href(ref.get('path'), base, target, [hostname])
            if candidate and candidate[3].lower().endswith(('.js', '.css')):
                asset_candidates.append(candidate)
            elif ref.get('kind') in ('fetch', 'ext_ajax') and ref.get('method') == 'GET':
                add(candidate)
        for asset in json.loads(raw_assets or '[]')[:16]:
            if not isinstance(asset, dict) or asset.get('kind') not in ('script', 'stylesheet'):
                continue
            candidate = normalize_href(asset.get('href'), base, target, hosts)
            if candidate and candidate[3].lower().endswith(('.js', '.css')):
                asset_candidates.append(candidate)

    # On-page links first, then bounded first-party script and style metadata.
    prior_static = {tuple(row) for row in db.execute('''
        SELECT scheme,hostname,port,path FROM pm_http_discovery WHERE task_id=?
        AND (lower(path) LIKE '%.js' OR lower(path) LIKE '%.css')''', (task_id,))}
    static_budget = max(0, MAX_STATIC_TOTAL - len(prior_static))
    for candidate in asset_candidates:
        if static_budget <= 0:
            break
        if candidate not in seen and candidate not in prior_static:
            add(candidate)
            static_budget -= 1

    # Retry only the historical, exact curl size failure, once per observation.
    recoverable = set()
    for oid, scheme, host, port, path, error in db.execute(
            "SELECT id,scheme,hostname,port,path,error FROM pm_http_discovery WHERE task_id=?",
            (task_id,)):
        if (error and 'curl: (63) Maximum file size exceeded' in error
                and host in hosts and ports.get(port) == scheme
                and not db.execute('SELECT 1 FROM pm_http_size_recovery WHERE observation_id=?', (oid,)).fetchone()):
            candidate = normalize_href(path, f'{scheme}://{host}:{port}/', target, hosts)
            if candidate:
                recoverable.add(candidate)
                add(candidate)

    document_refreshable = set()
    document_count = db.execute('SELECT COUNT(*) FROM pm_http_document_refresh r JOIN pm_http_discovery d '
                                'ON d.id=r.observation_id WHERE d.task_id=?', (task_id,)).fetchone()[0]
    for oid, scheme, host, port, path in db.execute(
            "SELECT id,scheme,hostname,port,path FROM pm_http_discovery WHERE task_id=? AND status=200 "
            "AND error IS NULL AND response_limited=1 AND lower(content_type) LIKE '%html%' ORDER BY id", (task_id,)):
        if document_count + len(document_refreshable) >= MAX_DOCUMENT_REFRESH:
            break
        if db.execute('SELECT 1 FROM pm_http_document_refresh WHERE observation_id=?', (oid,)).fetchone():
            continue
        candidate = normalize_href(path, f'{scheme}://{host}:{port}/', target, hosts)
        if candidate and ports.get(port) == scheme and host in hosts:
            document_refreshable.add(candidate)
            add(candidate)

    # Upgrade old successful public HTML/JS once, retaining its old evidence.
    refreshable = set()
    from orchestrator.application_discovery import PARSER_VERSION
    refreshed = db.execute('SELECT COUNT(*) FROM pm_http_metadata_refresh r JOIN pm_http_discovery d '
                           'ON d.id=r.observation_id WHERE d.task_id=?', (task_id,)).fetchone()[0]
    for oid, scheme, host, port, path, ctype, version in db.execute(
            'SELECT id,scheme,hostname,port,path,content_type,parser_version FROM pm_http_discovery '
            'WHERE task_id=? AND status=200 AND error IS NULL ORDER BY id', (task_id,)):
        if refreshed + len(refreshable) >= MAX_METADATA_REFRESH:
            break
        if version >= PARSER_VERSION or not any(x in (ctype or '').lower() for x in ('html', 'javascript', 'ecmascript')):
            continue
        if db.execute('SELECT 1 FROM pm_http_document_refresh WHERE observation_id=?', (oid,)).fetchone():
            continue
        if db.execute('SELECT 1 FROM pm_http_metadata_refresh WHERE observation_id=? AND parser_version=?',
                      (oid,PARSER_VERSION)).fetchone():
            continue
        candidate = normalize_href(path, f'{scheme}://{host}:{port}/', target, hosts)
        if candidate and ports.get(port) == scheme and host in hosts:
            refreshable.add(candidate)
            add(candidate)

    # Root pages for confirmed HTTP ports, then approved aliases.
    for port, scheme in sorted(ports.items()):
        for hostname in hosts[:4]:
            add((scheme, hostname, port, '/'))
    already = {tuple(row) for row in db.execute('''SELECT scheme,hostname,port,path FROM pm_http_discovery
                 WHERE task_id=?''', (task_id,))}
    if capture:
        # One upgrade for legacy successful text resources with no local body.
        upgrades = set()
        for oid, scheme, host, port, path, ctype in db.execute(
                'SELECT id,scheme,hostname,port,path,content_type FROM pm_http_discovery '
                'WHERE task_id=? AND status=200 AND error IS NULL AND artifact_id IS NULL ORDER BY id', (task_id,)):
            if db.execute('SELECT 1 FROM pm_http_capture_refresh WHERE observation_id=?',(oid,)).fetchone():
                continue
            if not any(x in (ctype or '').lower() for x in ('html','javascript','ecmascript','text/css','json','xml')):
                continue
            candidate = normalize_href(path,f'{scheme}://{host}:{port}/',target,hosts)
            if candidate and host in hosts and ports.get(port) == scheme:
                upgrades.add(candidate)
                add(candidate)
        from orchestrator import http_artifacts as artifacts
        limit = artifacts.response_limit(db,task_id)
        for oid, scheme, host, port, path, aid in db.execute(
                'SELECT id,scheme,hostname,port,path,artifact_id FROM pm_http_discovery '
                'WHERE task_id=? AND artifact_id IS NOT NULL AND error IS NULL ORDER BY id',(task_id,)):
            info = artifacts.info(db,aid)
            previous = info['processing']
            if (info['download_complete'] or not previous.get('download_limited')
                    or previous.get('capture_limit_bytes',limit) >= limit
                    or db.execute('SELECT 1 FROM pm_http_capture_upgrades WHERE observation_id=?',(oid,)).fetchone()):
                continue
            candidate = normalize_href(path,f'{scheme}://{host}:{port}/',target,hosts)
            if candidate and host in hosts and ports.get(port) == scheme:
                upgrades.add(candidate)
                add(candidate)
        return [item for item in queue if item in upgrades or item not in already]
    return [item for item in queue if item in recoverable or item in refreshable or item in document_refreshable or item not in already]


class HTTPResult(str):
    def __new__(cls, value, limited=False):
        obj = super().__new__(cls, value)
        obj.limited = limited
        return obj


@diagnostics.operation
def request(task_id, target, scheme, hostname, port, path, *, runner=subprocess.run, profile='http_path'):
    if profile not in ('http_path', 'http_document'):
        raise ValueError('Unsupported HTTP discovery profile')
    command = ['sudo', '-n', BROKER, 'run', '--task-id', str(task_id),
               '--profile', profile, '--target', target,
               '--port', str(port), '--scheme', scheme, '--path', path,
               '--hostname', hostname if hostname != target else '']
    result = runner(command, env={**os.environ, **diagnostics.child_env()}, stdin=subprocess.DEVNULL, capture_output=True,
                    text=True, errors='replace', timeout=60, check=False)
    diagnostics.execution_exit(result.returncode)
    try:
        payload = json.loads(result.stdout)
    except (ValueError, TypeError) as exc:
        raise ValueError('NetGuard HTTP probe did not return JSON') from exc
    if not isinstance(payload, dict) or not isinstance(payload.get('stdout', ''), str):
        raise ValueError('NetGuard HTTP probe returned an invalid result schema')
    diagnostics.record_result(payload, result.returncode)
    limited = (payload.get('status') == 'error' and payload.get('exit_code') == 63)
    if result.returncode or (payload.get('status') != 'completed' and not limited) or payload.get('profile') != profile:
        raise ValueError('NetGuard HTTP probe blocked or failed: ' + str(payload.get('error') or payload.get('stderr', ''))[:150])
    if payload.get('target') != target or payload.get('task_id') != task_id:
        raise ValueError('NetGuard HTTP result target/task mismatch')
    _headers_and_body(payload.get('stdout', ''))
    raw = HTTPResult(payload.get('stdout', ''), limited or bool(payload.get('stdout_truncated', payload.get('output_truncated'))))
    raw.download_limited = limited
    raw.broker_truncated = bool(payload.get('stdout_truncated', payload.get('output_truncated')))
    return raw


def request_document(*args, **kwargs):
    return request(*args, profile='http_document', **kwargs)


@diagnostics.operation
def require_capture_support(*, runner=subprocess.run):
    result = runner([BROKER,'capabilities'],env={**os.environ, **diagnostics.child_env()},
                    capture_output=True,text=True,timeout=5,check=False)
    try:
        payload = json.loads(result.stdout)
    except (ValueError,TypeError):
        payload = {}
    if (result.returncode or not isinstance(payload,dict) or payload.get('capture_protocol') != 1
            or not isinstance(payload.get('profiles'),list) or 'http_capture' not in payload['profiles']
            or not isinstance(payload.get('capture_limits'),list)
            or not all(limit in payload['capture_limits'] for limit in (2*1024*1024,8*1024*1024))):
        raise ValueError('NetGuard broker needs the HTTP capture update; install executor/netguard_root.py before resume')
    diagnostics.record_result({'status': 'completed'}, result.returncode)


@diagnostics.operation
def request_capture(task_id, target, scheme, hostname, port, path, *, runner=subprocess.run, limit_bytes=2*1024*1024):
    from orchestrator import http_artifacts as artifacts
    if limit_bytes not in (artifacts.DEFAULT_BODY,artifacts.MAX_BODY):
        raise ValueError('Unsupported HTTP capture limit')
    command = ['sudo','-n',BROKER,'run','--task-id',str(task_id),'--profile','http_capture',
               '--target',target,'--scheme',scheme,'--hostname',hostname,'--port',str(port),'--path',path,
               '--capture-limit',str(limit_bytes)]
    result = runner(command,env={**os.environ, **diagnostics.child_env()},stdin=subprocess.DEVNULL,capture_output=True,text=True,errors='replace',timeout=60,check=False)
    diagnostics.execution_exit(result.returncode)
    try:
        payload = json.loads(result.stdout)
    except (ValueError,TypeError) as exc:
        raise ValueError('HTTP capture broker returned no valid JSON') from exc
    diagnostics.record_result(payload, result.returncode)
    expected = {'capture_protocol':1,'task_id':task_id,'target':target,'profile':'http_capture',
                'port':port,'scheme':scheme,'hostname':hostname,'path':path}
    if result.returncode or not isinstance(payload,dict) or any(payload.get(k) != v for k,v in expected.items()):
        raise ValueError('HTTP capture broker rejected request or returned a scope/protocol mismatch')
    encoded = payload.get('response_b64')
    if not isinstance(encoded,str) or len(encoded) > ((limit_bytes+65536+2)//3)*4:
        raise ValueError('Invalid HTTP capture transport length')
    try:
        wire = base64.b64decode(encoded,validate=True)
    except ValueError as exc:
        raise ValueError('Invalid HTTP capture binary encoding') from exc
    if len(wire) != payload.get('response_bytes') or len(wire) > limit_bytes+65536:
        raise ValueError('HTTP capture byte count mismatch')
    try:
        status, headers, full_body = artifacts.split_response(wire)
    except ValueError as exc:
        raise ValueError(f'HTTP capture has no complete headers: status={payload.get("status")}, '
                         f'exit={payload.get("exit_code")}; {exc}') from exc
    body = full_body[:limit_bytes]
    limited = bool(payload.get('capture_truncated')) or len(full_body) > len(body) or payload.get('exit_code') == 63
    complete = payload.get('status') == 'completed' and payload.get('exit_code') == 0 and not limited
    text, decoding = artifacts.decode_body(body,headers)
    if headers.get('content-length','').isdigit() and int(headers['content-length']) != len(full_body):
        complete = False
    safe_headers = ''.join(f'{k}: {v}\r\n' for k,v in headers.items())
    raw = HTTPResult(f'HTTP/1.1 {status}\r\n'+safe_headers+'\r\n'+text, not complete or decoding['decode_limit'])
    raw.capture = {'body':body,'headers':headers,'status':status,'complete':complete,
                   'metadata':{'capture_limit_bytes':limit_bytes,'bytes_received':len(body),
                               'download_limited':limited,'text_chars':len(text),**decoding}}
    if headers.get('location'):
        location = normalize_href(headers['location'],f'{scheme}://{hostname}:{port}{path}',target,[hostname])
        if location:
            raw.capture['metadata']['approved_location'] = f'{scheme}://{hostname}:{port}{location[3]}'
    raw.probe_error = None if payload.get('exit_code') in (0,63) else 'HTTP capture failed: '+str(payload.get('status'))
    raw.download_limited = limited
    raw.broker_truncated = bool(payload.get('capture_truncated'))
    return raw


def attempts_used(db, task_id):
    total = db.execute('SELECT COUNT(*) FROM pm_http_discovery WHERE task_id=?', (task_id,)).fetchone()[0]
    for table in ('pm_http_size_recovery', 'pm_http_metadata_refresh', 'pm_http_document_refresh', 'pm_http_capture_refresh', 'pm_http_capture_upgrades'):
        total += db.execute(f'SELECT COUNT(*) FROM {table} r JOIN pm_http_discovery d '
                            'ON d.id=r.observation_id WHERE d.task_id=?', (task_id,)).fetchone()[0]
    return total


def script_references(source, base, target, *, inline=False, diagnostics=None, allow_relative=True):
    from orchestrator.application_discovery import references
    host = urlsplit(base).hostname
    result = []
    for ref in references(source,diagnostics):
        if not allow_relative and not ref['href'].startswith(('http://','https://')):
            continue
        if ref['kind'] == 'module_import' and not ref['href'].startswith(('/', './', '../', 'http://', 'https://')):
            # Bare module specifiers require an import map/package resolver.
            continue
        # fetch() resolves relative to its document, not the JS file's URL.
        # Without that document context only absolute references are resolvable.
        if not inline and ref['base'] == 'document' and not ref['href'].startswith(('/', 'http://', 'https://')):
            continue
        candidate = normalize_href(ref['href'], base, target, [host])
        if candidate is None:
            continue
        if ref['kind'] == 'module_import' and not candidate[3].lower().endswith(('.js', '.css')):
            continue
        entry = {'kind': ref['kind'], 'path': candidate[3], 'method': ref['method'],
                 'eligible': ref['eligible'], 'source': 'inline_script' if inline else 'javascript',
                 'selection_reason': 'literal_get_or_import' if ref['eligible'] else 'unsupported_method_or_url_literal',
                 'verified_endpoint': False}
        if entry not in result:
            result.append(entry)
    return result[:16]


def candidate_sources(db, task_id, candidate):
    scheme, host, port, path = candidate
    result = []
    for oid, source_host, source_path, refs, links, assets, forms, location in db.execute(
            'SELECT id,hostname,path,references_json,links_json,assets_json,forms_json,location '
            'FROM pm_http_discovery WHERE task_id=? '
            'AND scheme=? AND port=? AND error IS NULL ORDER BY id',
            (task_id,scheme,port)):
        base = f'{scheme}://{source_host}:{port}{source_path}'
        for ref in json.loads(refs or '[]')[:16]:
            if source_host == host and ref.get('eligible') is True and ref.get('path') == path:
                result.append({'observation': f'web:{oid}', 'path': source_path, 'kind': ref['kind']})
        observed = [(value, 'html_link') for value in json.loads(links or '[]')[:25]]
        observed += [(a.get('href'), 'html_asset') for a in json.loads(assets or '[]')[:16] if isinstance(a,dict)]
        observed += [(f.get('action'), 'get_form') for f in json.loads(forms or '[]')[:12]
                     if isinstance(f,dict) and f.get('method') == 'GET']
        if location:
            observed.append((location, 'redirect'))
        for href, kind in observed:
            if normalize_href(href, base, None, [host]) == candidate:
                entry = {'observation': f'web:{oid}', 'path': source_path, 'kind': kind}
                if entry not in result:
                    result.append(entry)
    return result[:8]


def has_more(db, task_id, *, capture=False):
    """Inspect remaining HTTP work without sending requests or calling the model."""
    target = validate_scope(db, task_id)
    return attempts_used(db, task_id) < MAX_TOTAL and bool(_candidates(db, task_id, target, permitted_hosts(db, task_id, target),capture=capture))


def queue_status(db, task_id, *, capture=False):
    target = validate_scope(db, task_id)
    used = attempts_used(db, task_id)
    pending = len(_candidates(db, task_id, target, permitted_hosts(db, task_id, target),capture=capture))
    unsupported = sum(1 for row in db.execute(
        'SELECT references_json FROM pm_http_discovery WHERE task_id=? AND error IS NULL', (task_id,))
        for ref in json.loads(row[0] or '[]')[:16] if ref.get('eligible') is not True)
    limited_html = db.execute("SELECT COUNT(*) FROM pm_http_discovery WHERE task_id=? AND error IS NULL "
                              "AND response_limited=1 AND lower(content_type) LIKE '%html%'", (task_id,)).fetchone()[0]
    incomplete = db.execute('SELECT COUNT(*) FROM pm_http_discovery d JOIN pm_http_artifacts a '
                            'ON a.id=d.artifact_id WHERE d.task_id=? AND a.complete=0',(task_id,)).fetchone()[0]
    analysis_warnings = 0
    for (rawmetrics,) in db.execute('SELECT response_metrics_json FROM pm_http_discovery WHERE task_id=?',(task_id,)):
        metrics = json.loads(rawmetrics or '{}')
        if (metrics.get('metadata_limits') or metrics.get('asset_rejections',{}).get('query_not_supported')
                or metrics.get('asset_rejections',{}).get('non_static_path')
                or metrics.get('relative_urls_skipped')
                or metrics.get('decode_limit') or metrics.get('decode_errors')
                or metrics.get('text_skipped') not in (None,'binary_or_unknown_content_type')):
            analysis_warnings += 1
    return {'attempts_used': used, 'request_limit': MAX_TOTAL,
            'pending': pending, 'unsupported_references': unsupported, 'limited_html': limited_html,
            'incomplete_downloads': incomplete,
            'analysis_warnings': analysis_warnings,
            'state': ('request_budget' if used >= MAX_TOTAL else 'queued' if pending
                      else 'incomplete_responses' if capture and incomplete
                      else 'analysis_incomplete' if capture and analysis_warnings
                      else 'limited_documents' if limited_html else 'catalog_exhausted')}


def analyze_http(raw, target, scheme, hostname, port, path, hosts, body_limit, profile):
    """Pure bounded interpretation, reusable against saved artifacts without network."""
    status, location, content_type, server, title = None, None, None, None, None
    links, forms, assets, meta, application, references = [], [], [], [], [], []
    status, headers, body = _headers_and_body(raw, body_limit)
    limited = bool(getattr(raw, "limited", False)) or body.limited
    metrics = {'body_chars_parsed': len(body), 'parse_limit': body_limit,
               'parse_truncated': body.limited, 'broker_truncated': bool(getattr(raw, 'broker_truncated', False)),
               'download_limited': bool(getattr(raw, 'download_limited', False)),
               'profile': profile}
    if hasattr(raw,'capture'):
        metrics.update(raw.capture['metadata'])
    if str(headers.get('content-length', '')).isdigit():
        metrics['content_length_bytes'] = int(headers['content-length'])
    content_type, server = headers.get('content-type'), headers.get('server')
    from orchestrator.application_metadata import extract
    application = extract(body, content_type)
    base = f'{scheme}://{hostname}:{port}{path}'
    script_diagnostics = {}
    if any(x in (content_type or '').lower() for x in ('javascript', 'ecmascript')):
        references = script_references(body, base, target,diagnostics=script_diagnostics)
    raw_location = headers.get('location')
    if raw_location:
        approved_location = normalize_href(raw_location,
            f'{scheme}://{hostname}:{port}{path}', target, hosts)
        if approved_location:
            location = f'{approved_location[0]}://{approved_location[1]}:{approved_location[2]}{approved_location[3]}'

    # Only extracted metadata enters evidence; raw bodies stay in private artifacts.
    if 'html' in (content_type or '').lower() or body.lstrip().startswith(("<!DOCTYPE", "<html", "<HTML")):
        html_parser = PageMetadata(body_limit)
        html_parser.feed(body)
        allow_relative = True
        if html_parser.base_href is not None:
            effective = normalize_href(html_parser.base_href or path,base,target,[hostname])
            if effective:
                base = f'{effective[0]}://{effective[1]}:{effective[2]}{effective[3]}'
            else:
                allow_relative = False
                metrics['relative_urls_skipped'] = 'unsupported_html_base'

        def resolve_href(href):
            if not allow_relative and not str(href).startswith(('http://','https://')):
                return None
            return normalize_href(href,base,target,hosts)

        for script in html_parser.script_blocks:
            for ref in script_references(script, base, target, inline=True,diagnostics=script_diagnostics,allow_relative=allow_relative):
                if ref not in references and len(references) < 16:
                    references.append(ref)
        title = html_parser.title.strip()[:120]
        links = []
        for link in html_parser.links:
            candidate = resolve_href(link)
            if candidate:
                links.append(f'{candidate[0]}://{candidate[1]}:{candidate[2]}{candidate[3]}')
        assets = []
        rejections = {}
        for asset in html_parser.assets:
            candidate = resolve_href(asset['href'])
            if candidate and candidate[3].lower().endswith(('.js', '.css')):
                assets.append({'kind': asset['kind'], 'path': candidate[3],
                               'hostname': candidate[1], 'port': candidate[2],
                               'scheme': candidate[0], 'href': f'{candidate[0]}://{candidate[1]}:{candidate[2]}{candidate[3]}'})
            else:
                try:
                    url = urlsplit(urljoin(base,asset['href']))
                    reason = ('unsupported_html_base' if not allow_relative and not asset['href'].startswith(('http://','https://'))
                              else 'query_not_supported' if url.query else 'outside_scope' if url.hostname not in hosts
                              else 'non_static_path' if candidate else 'unsafe_origin_or_path')
                except ValueError:
                    reason = 'invalid_url'
                rejections[reason] = rejections.get(reason,0)+1
        meta = html_parser.meta
        forms = [{'method': f['method'],
                  'action': resolve_href(f['action'])[3]
                  if f['action'] and resolve_href(f['action']) else '',
                  'fields': f['fields']}
                 for f in html_parser.forms]
        metrics['metadata_limits'] = sorted(html_parser.limits)
        metrics['assets_seen'] = html_parser.assets_seen
        metrics['assets_accepted'] = len(assets)
        metrics['assets_not_queued'] = html_parser.assets_seen - len(assets)
        metrics['asset_rejections'] = rejections
        metrics['inline_script_blocks'] = len(html_parser.script_blocks)
    if len(references) >= 16:
        metrics.setdefault('metadata_limits',[]).append('script_references')
    for flag in script_diagnostics:
        metrics.setdefault('metadata_limits',[]).append('script_'+flag)
    return {'status':status,'location':location,'content_type':content_type,'server':server,'title':title,
            'links':links,'forms':forms,'assets':assets,'meta':meta,'application':application,
            'references':references,'limited':limited,'metrics':metrics}


def reparse_saved(db, task_id, path=None):
    """Explicit local analysis of stored bodies. No broker, model or network."""
    from orchestrator import http_artifacts as artifacts
    init(db)
    query = 'SELECT * FROM pm_http_discovery WHERE task_id=? AND artifact_id IS NOT NULL'
    params = [task_id]
    if path is not None:
        query += ' AND path=?'
        params.append(_safe_path(path))
    query += ' ORDER BY id LIMIT 24'
    cursor = db.execute(query,params)
    columns = [d[0] for d in cursor.description]
    records = [dict(zip(columns,row)) for row in cursor.fetchall()]
    results = []
    db.execute('CREATE TABLE IF NOT EXISTS pm_http_local_reparse ('
               'id INTEGER PRIMARY KEY,observation_id INTEGER NOT NULL,previous_record_json TEXT NOT NULL,created_at TEXT NOT NULL)')
    for record in records:
        body,metadata = artifacts.load(db,task_id,record['artifact_id'])
        headers = dict(metadata['headers'])
        if metadata.get('approved_location'):
            headers['location'] = metadata['approved_location']
        text,decoding = artifacts.decode_body(body,headers)
        saved = artifacts.info(db,record['artifact_id'])
        raw = HTTPResult(f'HTTP/1.1 {saved["status_code"]}\r\n'+''.join(f'{k}: {v}\r\n' for k,v in headers.items())+'\r\n'+text,
                         not saved['download_complete'] or decoding['decode_limit'])
        raw.capture = {'metadata':{**metadata,**decoding}}
        parsed = analyze_http(raw,record['target'],record['scheme'],record['hostname'],record['port'],record['path'],
                              permitted_hosts(db,task_id,record['target']),artifacts.MAX_BODY,'local_artifact')
        with db:
            db.execute('INSERT INTO pm_http_local_reparse(observation_id,previous_record_json,created_at) VALUES(?,?,?)',
                       (record['id'],json.dumps(record),now()))
            db.execute('UPDATE pm_http_discovery SET title=?,links_json=?,forms_json=?,assets_json=?,meta_json=?,'
                       'application_json=?,references_json=?,response_limited=?,response_metrics_json=?,parser_version=? WHERE id=?',
                       (parsed['title'],json.dumps(parsed['links']),json.dumps(parsed['forms']),json.dumps(parsed['assets']),
                        json.dumps(parsed['meta']),json.dumps(parsed['application']),json.dumps(parsed['references']),
                        int(parsed['limited']),json.dumps(parsed['metrics']),1,record['id']))
        results.append({'path':record['path'],'artifact_id':record['artifact_id'],
                        'assets':len(parsed['assets']),'references':len(parsed['references'])})
    return results


@diagnostics.stage
def execute_round(db, task_id, max_requests=2, *, requester=request, document_requester=request_document,
                  capture=False, capture_requester=request_capture):
    """Execute up to N new GETs, after already-authenticated Console approval."""
    if type(max_requests) is not int or not 1 <= max_requests <= MAX_PER_ROUND:
        raise ValueError('HTTP request limit 1..3 required')
    if capture and capture_requester is request_capture:
        require_capture_support()
    init(db)
    target = validate_scope(db, task_id)
    hosts = permitted_hosts(db, task_id, target)
    attempted = attempts_used(db, task_id)
    if attempted >= MAX_TOTAL:
        return []
    candidates = _candidates(db, task_id, target, hosts,capture=capture)[:min(max_requests, MAX_TOTAL - attempted)]
    results = []
    for scheme, hostname, port, path in candidates:
        status, location, content_type, server, title, links, forms, error = None, None, None, None, None, [], [], None
        assets, meta = [], []
        limited = False
        application = []
        references = []
        sources = candidate_sources(db, task_id, (scheme,hostname,port,path))
        # Claim before I/O; interruptions cannot trigger an unbounded retry.
        recovery_id = None
        refresh_id = None
        document_id = None
        capture_id = None
        artifact_id = None
        metrics = {}
        from orchestrator.application_discovery import PARSER_VERSION
        with db:
            old = db.execute('SELECT * FROM pm_http_discovery WHERE task_id=? AND scheme=? '
                             'AND hostname=? AND port=? AND path=?',
                             (task_id,scheme,hostname,port,path)).fetchone()
            if old:
                cols = [r[1] for r in db.execute('PRAGMA table_info(pm_http_discovery)')]
                record = dict(zip(cols, old))
                if not sources:
                    sources = json.loads(record['sources_json'] or '[]')
                if capture:
                    upgrade_table = 'pm_http_capture_upgrades' if record.get('artifact_id') else 'pm_http_capture_refresh'
                    claimed = db.execute(f'INSERT OR IGNORE INTO {upgrade_table} VALUES (?,?,?)',
                                         (record['id'],json.dumps(record),now()))
                    if not claimed.rowcount:
                        continue
                    capture_id = record['id']
                elif record.get('error') and 'curl: (63) Maximum file size exceeded' in record['error']:
                    claimed = db.execute('INSERT OR IGNORE INTO pm_http_size_recovery VALUES (?,?,?)',
                                         (record['id'],json.dumps(record),now()))
                    if not claimed.rowcount:
                        continue
                    recovery_id = record['id']
                elif (record['status'] == 200 and record.get('error') is None and record['response_limited']
                      and 'html' in str(record['content_type'] or '').lower()
                      and db.execute('SELECT COUNT(*) FROM pm_http_document_refresh r JOIN pm_http_discovery d '
                                     'ON d.id=r.observation_id WHERE d.task_id=?', (task_id,)).fetchone()[0] < MAX_DOCUMENT_REFRESH):
                    claimed = db.execute('INSERT OR IGNORE INTO pm_http_document_refresh VALUES (?,?,?)',
                                         (record['id'],json.dumps(record),now()))
                    if not claimed.rowcount:
                        continue
                    document_id = record['id']
                elif record['status'] == 200 and record.get('error') is None and record['parser_version'] < PARSER_VERSION:
                    claimed = db.execute('INSERT OR IGNORE INTO pm_http_metadata_refresh VALUES (?,?,?,?)',
                                         (record['id'],PARSER_VERSION,json.dumps(record),now()))
                    if not claimed.rowcount:
                        continue
                    refresh_id = record['id']
        try:
            body_limit = MAX_DOCUMENT_PARSE if document_id else MAX_BODY_PARSE
            active_requester = capture_requester if capture else document_requester if document_id else requester
            if capture:
                from orchestrator import http_artifacts as artifacts
                raw = active_requester(task_id,target,scheme,hostname,port,path,limit_bytes=artifacts.response_limit(db,task_id))
            else:
                raw = active_requester(task_id, target, scheme, hostname, port, path)
            if capture:
                from orchestrator import http_artifacts as artifacts
                if not hasattr(raw,'capture'):
                    raise ValueError('HTTP capture requester did not supply an artifact')
                artifact_id = artifacts.save(db,task_id,target,scheme,hostname,port,path,raw.capture,now())
                if raw.probe_error:
                    raise ValueError(raw.probe_error)
                body_limit = artifacts.MAX_BODY
            parsed = analyze_http(raw,target,scheme,hostname,port,path,hosts,body_limit,
                                  'http_capture' if capture else 'http_document' if document_id else 'http_path')
            status, location, content_type, server, title = (parsed[k] for k in ('status','location','content_type','server','title'))
            links, forms, assets, meta = (parsed[k] for k in ('links','forms','assets','meta'))
            application, references, limited, metrics = (parsed[k] for k in ('application','references','limited','metrics'))
        except (ValueError, OSError, subprocess.SubprocessError) as exc:
            error = str(exc)[:160]
        # Replace only explicitly claimed refreshes; original records are archived.
        with db:
            if recovery_id or refresh_id or document_id or capture_id:
                cursor = db.execute('UPDATE pm_http_discovery SET status=?,location=?,content_type=?,server=?,title=?,'
                                    'links_json=?,forms_json=?,error=?,assets_json=?,meta_json=?,created_at=? WHERE id=?',
                                    (status,location,content_type,server,title,json.dumps(links),json.dumps(forms),
                                     error,json.dumps(assets),json.dumps(meta),now(),recovery_id or refresh_id or document_id or capture_id))
            else:
                cursor = db.execute('''INSERT OR IGNORE INTO pm_http_discovery
                  (task_id,target,port,scheme,hostname,path,status,location,content_type,server,
                   title,links_json,forms_json,error,assets_json,meta_json,created_at)
                  VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)''',
                  (task_id,target,port,scheme,hostname,path,status,location,content_type,server,
                   title,json.dumps(links,ensure_ascii=False),
                   json.dumps(forms,ensure_ascii=False),error,
                   json.dumps(assets,ensure_ascii=False),json.dumps(meta,ensure_ascii=False),now()))
            if cursor.rowcount:
                persisted_artifact_id = artifact_id
                if capture_id and artifact_id is None:
                    persisted_artifact_id = record.get('artifact_id')
                db.execute('UPDATE pm_http_discovery SET response_limited=?,application_json=?,references_json=?,sources_json=?,parser_version=?,response_metrics_json=?,artifact_id=? WHERE '
                           'task_id=? AND scheme=? AND hostname=? AND port=? AND path=?',
                           (int(limited),json.dumps(application),json.dumps(references),json.dumps(sources),PARSER_VERSION,json.dumps(metrics),persisted_artifact_id,
                            task_id,scheme,hostname,port,path))
        if cursor.rowcount:
            results.append({'path': path, 'host': hostname, 'port': port, 'status_code': status,
                            'title': title, 'forms': len(forms), 'links': len(links),
                            'assets': len(assets), 'status': 'completed' if error is None else 'blocked',
                            'error': error, 'response_limited': limited, 'references': len(references),
                            'sources': sources, 'metadata_refresh': bool(refresh_id), 'document_refresh': bool(document_id),
                            'artifact_id': artifact_id,'profile':'http_capture' if capture else 'http_document' if document_id else 'http_path'})
            safe_title = re.sub(r'[\x00-\x1f\x7f-\x9f]', ' ', title or '')
            print(f'[WEB] {hostname}:{port}{path} -> {status or "BLOCKED"}'
                  + (f' | title={safe_title[:48]}' if safe_title else '')
                  + (f' | assets={len(assets)}' if assets else '')
                  + (f' | paths={len(references)}' if references else '')
                  + (' | metadata refresh' if refresh_id else '')
                  + (' | document refresh' if document_id else '')
                  + (f' | сохранено={len(raw.capture["body"])} Б' if artifact_id else '')
                  + (' | загрузка='+('полная' if raw.capture['complete'] else 'частичная') if artifact_id else '')
                  + (' | разбор ограничен' if artifact_id and (metrics.get('parse_truncated') or metrics.get('decode_limit')) else '')
                  + (' | текст не разобран: '+str(metrics['text_skipped']) if artifact_id and metrics.get('text_skipped') else '')
                  + (' | ответ ограничен' if limited and not artifact_id else ''), flush=True)
        if error:
            # Do not continue enumerating when the broker or network has failed.
            break
    return results


def evidence_rows(db, task_id, limit=24):
    init(db)
    rows = db.execute('''SELECT id,hostname,port,scheme,path,status,location,content_type,
                                server,title,links_json,forms_json,created_at,error,
                                assets_json,meta_json,response_limited,application_json,references_json,sources_json,parser_version,response_metrics_json,artifact_id
                         FROM pm_http_discovery WHERE task_id=? ORDER BY id DESC LIMIT ?''',
                      (task_id, limit)).fetchall()
    return [dict(observation_id=id, hostname=host, port=port, scheme=scheme,
                 path=path, status_code=status, redirect_location=location,
                 content_type=ctype, server=server, title=title,
                 links=[normalize_href(x, f'{scheme}://{host}:{port}{path}', None, [host])[3]
                        for x in json.loads(rawlinks)[:10]
                        if normalize_href(x, f'{scheme}://{host}:{port}{path}', None, [host])],
                 forms=json.loads(rawforms)[:8],
                 assets=[{'kind': a.get('kind'), 'path': a.get('path')}
                         for a in json.loads(rawassets or '[]')[:12] if isinstance(a,dict)],
                 public_meta=json.loads(rawmeta or '[]')[:6],
                 application_hints=json.loads(rawapplication or '[]')[:4],
                 script_references=json.loads(rawrefs or '[]')[:16],
                 discovered_from=json.loads(rawsources or '[]')[:8],
                 application_parser_version=parser_version,
                 response_metrics=json.loads(rawmetrics or '{}'),
                 artifact=artifact_info(db,artifact_id),
                 source='isolated_http_get', observed_at=created, error=error,
                 response_limited=bool(limited))
            for (id,host,port,scheme,path,status,location,ctype,server,title,rawlinks,rawforms,created,error,rawassets,rawmeta,limited,rawapplication,rawrefs,rawsources,parser_version,rawmetrics,artifact_id)
            in reversed(rows)]


def artifact_info(db, artifact_id):
    if artifact_id is None:
        return None
    from orchestrator.http_artifacts import info
    return info(db,artifact_id)
