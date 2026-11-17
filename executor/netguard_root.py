#!/usr/bin/python3
"""Root-owned per-task network namespace broker for Pentest Master.

INSTALL THIS FILE ROOT-OWNED in /usr/local/sbin/pm-netguard.
Never import Python code from the user's project here.
All subprocesses use fixed binaries and argv, no shell.
"""
import argparse
import base64
import hashlib
import ipaddress
import json
import os
from pathlib import Path
from urllib.parse import unquote, quote, urlsplit, urlencode, parse_qsl
import pwd
import re
import shutil
import signal
import socket
import stat
import selectors
import shlex
import subprocess
import sys
import time
from contextlib import contextmanager

BASE = Path('/etc/pentest-master/netguard')
STATE = Path('/run/pentest-master-netguard')
PREV_FORWARD = STATE / 'ip_forward.previous'
DOCS = tuple(ipaddress.ip_network(v) for v in
             ('192.0.2.0/24', '198.51.100.0/24', '203.0.113.0/24','2001:db8::/32'))
MAX_TASK = 200
HTTP_CAPTURE_BODY_LIMIT = 2 * 1024 * 1024
HTTP_HEADER_LIMIT = 1024 * 1024
HTTP_CAPTURE_WIRE_LIMIT = HTTP_CAPTURE_BODY_LIMIT + HTTP_HEADER_LIMIT
HTTP_CAPTURE_LIMITS = (HTTP_CAPTURE_BODY_LIMIT, 8 * 1024 * 1024)
HTTP_CAPTURE_TIMEOUT = 48

# Research egress: fixed public sources for CVE/exploit lookup. Only these
# exact domains may be reached, only over 443, and only for a bounded time.
# Canonical API hosts only. The bare domains redirect (nvd.nist.gov -> 301),
# so the exact service hosts are listed here as well; nothing else is reachable.
RESEARCH_DOMAINS = ('nvd.nist.gov', 'services.nvd.nist.gov',
                    'exploit-db.com', 'www.exploit-db.com',
                    'api.github.com')
RESEARCH_PORT = 443
RESEARCH_TTL = '2h'
RESEARCH_MAX_IPS = 64

# Generic command execution inside the already-isolated task namespace.
EXEC_ARGS_MAX = 64
EXEC_ARG_LEN_MAX = 4096
EXEC_TOTAL_MAX = 16384
EXEC_TIMEOUT = 60
EXEC_TIMEOUT_MAX = 600
EXEC_PROFILE_TIMEOUT_MAX = 600
POC_TIMEOUT_MAX = 600

# Generated PoC scripts live only under the task's own artifact directory.
POC_MAX_BYTES = 64 * 1024 * 1024
POC_DEFAULT_TIMEOUT = 60
POC_NAME = re.compile(r'[A-Za-z0-9][A-Za-z0-9._-]{0,63}')
POC_SUFFIXES = ('.sh', '.py', '.pl', '.rb', '.txt')

# Per-task state that outlives a single call. /work used to be an empty tmpfs
# recreated for every call, so a downloaded binary, an unpacked archive or a
# compiled exploit was gone by the next call and had to be fetched again.
# The sandbox runs as the task user, so it must be able to traverse the path to
# its own workspace. /etc/pentest-master/netguard is root-only 0700 and cannot be
# traversed by that user, so workspaces live under /var/lib with 0711 parents and
# a 0700 leaf owned by the task user.
WORK_BASE = Path('/var/lib/pentest-master/work')
SESSIONS_BASE = BASE / 'sessions'
SESSION_MAX = 10
SESSION_IDLE = 1800
SESSION_IDLE_MAX = 7200
SESSION_OUTPUT_KEEP = 1024 * 1024
SESSION_REPLY_BYTES = 64 * 1024
SESSION_LOG_BYTES = 32 * 1024 * 1024
SESSION_DATA_MAX = 65536

# Local callback sink for blind execution results (reverse shells / exfil).
CALLBACK_PORTS = range(1024, 65536)
CALLBACK_MAX_BYTES = 4 * 1024 * 1024
TRANSFER_MAX_BYTES = 1024 * 1024 * 1024
TRANSFER_DEFAULT_BYTES = 512 * 1024 * 1024
TRANSFER_RESERVE_BYTES = 64 * 1024 * 1024
CALLBACK_DIR = Path('/var/lib/pentest-master/callbacks')

# Acquisition is a separate operator-granted capability, never generic root exec.
TOOL_PROTOCOL = 1
TOOL_MAX_BYTES = 16 * 1024 * 1024
SYSTEM_TOOLS = {'nmap': '/usr/bin/nmap', 'curl': '/usr/bin/curl', 'jq': '/usr/bin/jq'}
SYSTEM_TOOLS.update({'file':'/usr/bin/file','git':'/usr/bin/git','binutils':'/usr/bin/objdump',
    'poppler-utils':'/usr/bin/pdftotext','tesseract-ocr':'/usr/bin/tesseract',
    'tesseract-ocr-eng':'/usr/share/tesseract-ocr/5/tessdata/eng.traineddata',
    'tesseract-ocr-rus':'/usr/share/tesseract-ocr/5/tessdata/rus.traineddata'})
APT_CACHE = Path('/var/cache/apt/archives')
TOOL_ENV = {'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C','DEBIAN_FRONTEND':'noninteractive'}
RAW_SCAN_PROFILES = ('nmap_syn', 'nmap_udp', 'nmap_os')


class ToolError(ValueError):
    def __init__(self, category, message):
        self.category = category
        super().__init__(message)


def tool_spec(raw):
    """Shared pure validator, also imported by the unprivileged PM frontend."""
    if not isinstance(raw, dict): raise ToolError('invalid_request', 'Tool request must be an object')
    common = {'kind', 'name', 'purpose', 'version'}
    if not common <= raw.keys(): raise ToolError('invalid_request', 'Missing kind/name/purpose/version')
    kind = raw['kind']
    fields = common if kind == 'system_package' else common | {'source', 'channel', 'filename', 'sha256', 'interpreter'}
    if set(raw) != fields or kind not in ('user_tool', 'documentation', 'system_package'):
        raise ToolError('invalid_request', 'Unsupported tool specification fields')
    if not isinstance(raw['name'], str) or not POC_NAME.fullmatch(raw['name']):
        raise ToolError('invalid_request', 'Invalid tool name')
    for key, limit in [('purpose', 1000), ('version', 120)]:
        value = raw[key]
        if not isinstance(value, str) or not value.strip() or len(value) > limit or any(ord(c) < 32 for c in value):
            raise ToolError('invalid_request', 'Invalid '+key)
    spec = dict(raw)
    if kind == 'system_package':
        if spec['name'] not in SYSTEM_TOOLS or not re.fullmatch(r'[A-Za-z0-9.+:~_-]+', spec['version']):
            raise ToolError('invalid_request', 'Unsupported package/version (use candidate or an exact version)')
        return spec
    if not isinstance(spec['filename'], str) or not POC_NAME.fullmatch(spec['filename']):
        raise ToolError('invalid_request', 'Invalid filename')
    if spec['interpreter'] not in ('none', 'direct', 'python3', 'bash', 'perl', 'ruby'):
        raise ToolError('invalid_request', 'Unsupported interpreter')
    if kind == 'documentation' and spec['interpreter'] != 'none' or kind == 'user_tool' and spec['interpreter'] == 'none':
        raise ToolError('invalid_request', 'Documentation is data; user tools require an invocation')
    if not isinstance(spec['sha256'], str) or spec['sha256'] and not re.fullmatch(r'[a-f0-9]{64}', spec['sha256']):
        raise ToolError('invalid_request', 'Invalid optional SHA256')
    source = spec['source']
    if not isinstance(source, str) or len(source) > 2048 or any(ord(c) <= 32 for c in source):
        raise ToolError('invalid_request', 'Invalid source URL')
    try: url = urlsplit(source); port = url.port
    except ValueError: raise ToolError('invalid_request', 'Invalid source URL')
    if url.username or url.password or url.fragment:
        raise ToolError('invalid_request', 'Credentials and fragments are not download permissions')
    if any(re.search(r'token|api.?key|auth|password|secret|signature|cookie', key, re.I) for key,_ in parse_qsl(url.query)):
        raise ToolError('invalid_request', 'Secret-bearing source URLs are unsupported; use an operator-provided local file')
    channel = spec['channel']
    if channel == 'local_file':
        if url.scheme != 'file' or url.netloc or not url.path.startswith('/') or url.query:
            raise ToolError('invalid_request', 'local_file requires an absolute file:/// URL')
    elif channel == 'kali_local':
        if url.scheme != 'http' or url.hostname not in ('127.0.0.1', '::1', 'localhost'):
            raise ToolError('network_denied', 'kali_local grants only a Kali loopback HTTP source')
    elif channel == 'internet':
        if url.scheme != 'https' or not url.hostname:
            raise ToolError('network_denied', 'Internet acquisitions require one exact HTTPS URL')
        if url.hostname.lower() == 'localhost': raise ToolError('network_denied', 'Use explicit kali_local channel')
        try:
            if not ipaddress.ip_address(url.hostname).is_global:
                raise ToolError('network_denied', 'Laboratory/private sources use task isolation, not acquisition egress')
        except ValueError as exc:
            if isinstance(exc, ToolError): raise
    else: raise ToolError('invalid_request', 'Unknown source channel')
    return spec


def tool_digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def tool_receipt_path(task, request_id):
    if not re.fullmatch(r'[a-f0-9]{64}', request_id): raise ToolError('invalid_request', 'Invalid broker request ID')
    return BASE / f'tool-{int(task)}-{request_id}.json'


def tool_store(path, data):
    # Parent is a root-owned private broker directory, not the user's workspace.
    parent = path.parent.stat()
    if parent.st_uid != os.geteuid() or parent.st_mode & 0o077 or path.parent.is_symlink():
        raise ToolError('permission_denied', 'Unsafe broker receipt directory')
    temporary = path.with_suffix('.tmp')
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, 'w') as stream:
            json.dump(data, stream); stream.flush(); os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def tool_load(path):
    if path.is_symlink(): raise ToolError('permission_denied', 'Unsafe receipt')
    info = path.stat()
    if info.st_uid != os.geteuid() or info.st_mode & 0o077:
        raise ToolError('permission_denied', 'Unsafe receipt permissions')
    return json.loads(path.read_text())


def tool_package_plan(name, version):
    """APT is only a local metadata reader here. No update, repository edit or download."""
    if version == 'candidate':
        policy = cmd('/usr/bin/apt-cache', 'policy', name, env=TOOL_ENV).stdout
        match = re.search(r'^\s*Candidate:\s*(\S+)', policy, re.M)
        if not match or match[1] == '(none)': raise ToolError('tool_missing', 'No package candidate in configured APT metadata')
        version = match[1]
    exact = name + '=' + version
    args = ['/usr/bin/apt-get', '--yes', '--no-install-recommends', '--no-remove',
            '-o', 'APT::Get::AllowUnauthenticated=false']
    # --print-uris is not execution: APT checks metadata/authentication and prints
    # the exact archives, including dependencies. All downloads below are pinned.
    text = cmd(*args, '--print-uris', '--download-only', 'install', exact, timeout=40, env=TOOL_ENV).stdout
    archives = []
    for line in text.splitlines():
        if not line.startswith("'"): continue
        parts = shlex.split(line)
        if len(parts) != 4 or not parts[2].isdigit(): raise ToolError('installation_failed', 'Unrecognized APT URI record')
        url, filename, size, _ = parts
        if not re.fullmatch(r'[a-z0-9][a-z0-9+.-]*_[A-Za-z0-9%+.:~=-]+_[a-z0-9]+\.deb', filename):
            raise ToolError('installation_failed', 'Unsafe APT filename')
        # Use SHA256 from the same local APT metadata, never a model-supplied hash.
        pkg = filename.split('_')[0]
        metadata = cmd('/usr/bin/apt-cache', 'show', pkg, timeout=20, env=TOOL_ENV).stdout
        matches = []
        for record in metadata.split('\n\n'):
            values = dict(line.split(': ', 1) for line in record.splitlines() if ': ' in line and not line.startswith(' '))
            if (unquote(values.get('Filename', '')).rsplit('/', 1)[-1] == unquote(urlsplit(url).path).rsplit('/', 1)[-1]
                    and values.get('Size') == size and re.fullmatch(r'[a-f0-9]{64}', values.get('SHA256', ''))):
                matches.append(values)
        identities={tuple(m.get(k) for k in ('Package','Version','SHA256','Size','Filename')) for m in matches}
        if len(identities) != 1: raise ToolError('installation_failed', 'Cannot bind APT archive to one SHA256 metadata record')
        values = matches[0]
        if (urlsplit(url).scheme not in ('http', 'https') or urlsplit(url).username or urlsplit(url).password
                or any(re.search(r'token|api.?key|auth|password|secret|signature|cookie', key, re.I)
                       for key,_ in parse_qsl(urlsplit(url).query))):
            raise ToolError('network_denied', 'Only exact HTTP(S) APT archive resources are supported')
        archives.append({'url': url, 'filename': filename, 'bytes': int(size), 'sha256': values['SHA256'],
                         'package': values['Package'], 'version': values['Version']})
    if len(archives) > 32 or sum(a['bytes'] for a in archives) > 256 * 1024 * 1024:
        raise ToolError('installation_failed', 'Package acquisition exceeds bounded transaction; ask operator for another approach')
    return {'package': name, 'version': version, 'archives': archives}


def tool_prepare(task, raw):
    ensure_root(); _, config = owned_config(task)
    if os.environ.get('SUDO_UID') and int(os.environ['SUDO_UID']) != config['uid']:
        raise ToolError('permission_denied', 'Invoker is not the configured task owner')
    spec = tool_spec(raw)
    manifest = {'spec': spec, 'task_id': task, 'owner_uid': config['uid'], 'protocol': TOOL_PROTOCOL}
    if spec['kind'] == 'system_package':
        manifest['package_plan'] = tool_package_plan(spec['name'], spec['version'])
        manifest.update(destination=SYSTEM_TOOLS[spec['name']], invocation=[SYSTEM_TOOLS[spec['name']]],
            privileges='root: configured APT package and listed dependencies, including package scripts; no arbitrary PoC',
            actions=['download listed archives, verify SHA256', 'APT install exact version with --no-download in a networkless namespace'])
        if spec['name'] in ('tesseract-ocr-eng','tesseract-ocr-rus'):
            manifest['invocation']=['/usr/bin/tesseract','-l',spec['name'].rsplit('-',1)[1]]
    else:
        relative = ('docs' if spec['kind'] == 'documentation' else 'tools')+'/'+spec['name']+'/'+spec['filename']
        invocation = [] if spec['kind'] == 'documentation' else (
            ['/work/'+relative] if spec['interpreter'] == 'direct' else ['/usr/bin/'+spec['interpreter'], '/work/'+relative])
        manifest.update(destination='/work/'+relative, host_destination=str(WORK_BASE / str(task) / relative),
            invocation=invocation, privileges='task user; broker writes one file, never runs downloaded code as root',
            actions=['read exact source without redirects', 'verify optional SHA256; atomic non-overwriting workspace write'])
        if spec['channel'] == 'local_file':
            data = tool_read_local(spec['source'], config['uid'])
            manifest['local_sha256'] = hashlib.sha256(data).hexdigest()
    request_id = tool_digest(manifest); path = tool_receipt_path(task, request_id)
    if path.exists(): return tool_load(path)
    receipt = {'request_id': request_id, 'manifest': manifest, 'status': 'prepared', 'result': None}
    tool_store(path, receipt)
    return receipt


def tool_read_local(source, uid):
    # No root read of arbitrary user-chosen paths, symlink traversal or devices.
    path = Path(unquote(urlsplit(source).path))
    current = Path('/')
    for part in path.parts[1:]:
        current /= part
        if current.is_symlink(): raise ToolError('permission_denied', 'Local source must not traverse symlinks')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if info.st_uid != uid or not stat.S_ISREG(info.st_mode):
            raise ToolError('permission_denied', 'Local source must be a regular file owned by the task user')
        data = stream.read(TOOL_MAX_BYTES + 1)
    if len(data) > TOOL_MAX_BYTES: raise ToolError('download_failed', 'Source exceeds size limit')
    return data


def tool_download(url, channel, config, limit=TOOL_MAX_BYTES):
    """Normal Kali route, exact pinned URL only. Never used for laboratory traffic."""
    parsed = urlsplit(url); host = parsed.hostname; port = parsed.port or (443 if parsed.scheme == 'https' else 80)
    ips = sorted({item[4][0] for item in socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)})
    if not ips: raise ToolError('download_failed', 'Source DNS returned no address')
    for value in ips:
        ip = ipaddress.ip_address(value)
        if channel == 'kali_local':
            allowed = ip.is_loopback
        else:
            allowed = ip.is_global and not any(ip in ipaddress.ip_network(net) for net in config['allowed']
                if ip.version == ipaddress.ip_network(net).version)
        if not allowed: raise ToolError('network_denied', 'Source resolves outside the granted acquisition channel')
    target = ips[0]; pinned = '['+target+']' if ':' in target else target
    argv = ['/usr/bin/curl', '-q', '--globoff', '--path-as-is', '--silent', '--show-error', '--fail',
        '--noproxy', '*', '--proto', '=https,http' if channel in ('kali_local', 'apt') else '=https',
        '--max-redirs', '0', '--connect-timeout', '5', '--max-time', '45', '--include',
        '--max-filesize', str(limit)]
    try: ipaddress.ip_address(host)
    except ValueError: argv += ['--resolve', f'{host}:{port}:{pinned}']
    argv += ['--', url]
    # curl reads no user config and receives no keys/cookies/proxy credentials.
    result = capture_process(argv, limit, acquisition=True, process_env=TOOL_ENV)
    if result.get('exit_code') != 0 or result.get('capture_truncated'):
        raise ToolError('download_failed', 'Source transfer failed or exceeded the limit')
    wire = base64.b64decode(result['response_b64'])
    while True:
        headers, separator, data = wire.partition(b'\r\n\r\n')
        match = re.match(rb'HTTP/\S+ (\d{3})', headers)
        if not separator or not match: raise ToolError('download_failed', 'Invalid HTTP response')
        code = int(match[1])
        if 100 <= code < 200: wire = data; continue
        if not 200 <= code < 300: raise ToolError('download_failed', f'Source returned HTTP {code}; redirects need a separate request')
        if len(data) > limit:raise ToolError('download_failed', 'Source exceeds approved size limit')
        return data


def tool_write_file(workdir, relative, data, config, executable=False):
    """fd-relative writes: a task-user symlink can never redirect a root write."""
    parts = relative.split('/')
    if any(not POC_NAME.fullmatch(p) for p in parts): raise ToolError('invalid_request', 'Unsafe destination')
    directory = os.open(workdir, os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in parts[:-1]:
            created = False
            try: os.mkdir(part, 0o700, dir_fd=directory); created = True
            except FileExistsError: pass
            child = os.open(part, os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
            if created:os.fchown(child, config['uid'], config['gid'])
            info = os.fstat(child)
            if info.st_uid != config['uid'] or info.st_mode & 0o077:
                os.close(child); raise ToolError('permission_denied', 'Unsafe workspace directory')
            os.close(directory); directory = child
        name = parts[-1]; temporary = '.'+name+'.install'
        try:
            existing = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
        except FileNotFoundError: existing = None
        if existing is not None:
            with os.fdopen(existing, 'rb') as stream:
                info = os.fstat(stream.fileno())
                if (info.st_uid != config['uid'] or not stat.S_ISREG(info.st_mode)
                        or stream.read(len(data)+1) != data):
                    raise ToolError('integrity_error', 'Destination already contains different bytes; never overwritten')
            return
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                     0o700 if executable else 0o600, dir_fd=directory)
        try:
            with os.fdopen(fd, 'wb') as stream:
                stream.write(data); stream.flush(); os.fsync(stream.fileno())
                os.fchown(stream.fileno(), config['uid'], config['gid'])
            os.link(temporary, name, src_dir_fd=directory, dst_dir_fd=directory, follow_symlinks=False)
        finally: os.unlink(temporary, dir_fd=directory)
    finally: os.close(directory)


def tool_action(task, action, request_id):
    ensure_root(); _, config = owned_config(task)
    if os.environ.get('SUDO_UID') and int(os.environ['SUDO_UID']) != config['uid']:
        raise ToolError('permission_denied', 'Invoker is not the configured task owner')
    path = tool_receipt_path(task, request_id)
    # Serialize apply/authorize across CLI and MCP processes, not just SQLite.
    import fcntl
    lock = os.open(str(path)+'.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(lock, fcntl.LOCK_EX)
        receipt = tool_load(path); manifest = receipt['manifest']; spec = manifest['spec']
        if manifest['task_id'] != task or manifest['owner_uid'] != config['uid'] or tool_digest(manifest) != request_id:
            raise ToolError('permission_denied', 'Receipt does not match this task/owner')
        if action == 'authorize':
            if receipt['status'] == 'prepared':
                receipt['status'] = 'approved'; tool_store(path, receipt)
            return receipt
        if action == 'status': return receipt
        if action != 'apply': raise ToolError('invalid_request', 'Invalid tool action')
        if receipt['status'] != 'approved':
            return receipt # completed/failed/running are never automatically replayed
        receipt['status'] = 'running'; tool_store(path, receipt)
        try:
            if spec['kind'] == 'system_package':
                plan = manifest['package_plan']
                if tool_package_plan(spec['name'], plan['version']) != plan:
                    raise ToolError('conditions_changed', 'APT transaction changed; a new permission is required')
                # Cache is root-owned; filename validated by the metadata planner.
                cache = APT_CACHE
                info = cache.stat()
                if cache.is_symlink() or info.st_uid != os.geteuid() or info.st_mode & 0o022:
                    raise ToolError('permission_denied', 'Unsafe APT archive cache')
                for archive in plan['archives']:
                    data = tool_download(archive['url'], 'apt', config, archive['bytes'])
                    if len(data) != archive['bytes'] or hashlib.sha256(data).hexdigest() != archive['sha256']:
                        raise ToolError('integrity_error', 'APT archive hash/size differs from approved metadata')
                    destination = cache / archive['filename']
                    fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o644)
                    with os.fdopen(fd, 'wb') as stream: stream.write(data)
                # No network, arbitrary package arguments, scripts or repository changes supplied by the agent.
                cmd('/usr/bin/unshare', '--net', '/usr/bin/apt-get', '--yes', '--no-download', '--no-remove',
                    '--no-install-recommends', '-o', 'APT::Get::AllowUnauthenticated=false',
                    '-o','Dpkg::Options::=--force-confdef','-o','Dpkg::Options::=--force-confold',
                    'install', plan['package']+'='+plan['version'], timeout=180, env=TOOL_ENV)
                version = cmd('/usr/bin/dpkg-query', '-W', '-f=${Version}', plan['package'], env=TOOL_ENV).stdout.strip()
                if version != plan['version']: raise ToolError('installation_failed', 'Installed package version differs')
                receipt['result'] = {'version': version, 'version_provenance': 'dpkg-query', 'invocation': manifest['invocation'],
                    'source': {'archives':plan['archives'],'basis':'configured APT metadata and existing root cache',
                               'original_repository_for_preexisting_packages':'unknown'}, 'working_directory': '/work'}
            else:
                data = (tool_read_local(spec['source'], config['uid']) if spec['channel'] == 'local_file'
                        else tool_download(spec['source'], spec['channel'], config))
                sha = hashlib.sha256(data).hexdigest()
                if any(value and sha != value for value in (spec['sha256'], manifest.get('local_sha256'))):
                    raise ToolError('integrity_error', 'Source differs from approved hash')
                work = task_workdir(task, config)
                tool_write_file(work, manifest['destination'].removeprefix('/work/'), data, config,
                                spec['kind'] == 'user_tool' and spec['interpreter'] == 'direct')
                receipt['result'] = {'version': spec['version'], 'version_provenance': 'declared; not executed to discover version',
                    'sha256': sha, 'bytes': len(data), 'source': spec['source'], 'path': manifest['destination'],
                    'invocation': manifest['invocation'], 'working_directory': '/work'}
            receipt['status'] = 'completed'
        except Exception as exc:
            category = exc.category if isinstance(exc, ToolError) else 'permission_denied' if isinstance(exc, PermissionError) else (
                'outcome_unknown' if isinstance(exc, subprocess.TimeoutExpired) else 'installation_failed')
            receipt.update(status='unknown' if category == 'outcome_unknown' else 'failed',
                           result={'reason_category': category,
                                   'reason': str(exc)[:800] if isinstance(exc, ToolError) else type(exc).__name__+': installation failed; no automatic retry',
                                   'exit_code': getattr(exc, 'returncode', None)})
        tool_store(path, receipt)
        return receipt
    finally: os.close(lock)


def output(data, fail=False):
    print(json.dumps(data, ensure_ascii=False, indent=2), flush=True)
    if fail:
        raise SystemExit(1)


def cmd(*args, input=None, timeout=20, check=True, env=None,pass_fds=()):
    p = subprocess.run(args, input=input, text=True, capture_output=True,
                       timeout=timeout, check=False, **({'env':env} if env is not None else {}),
                       **({'pass_fds':pass_fds} if pass_fds else {}))
    if check and p.returncode:
        raise RuntimeError(f'{args[0]} failed ({p.returncode}): {p.stderr[-1200:]}')
    return p


def task_values(task):
    if type(task) is not int or not 1 <= task <= MAX_TASK:
        raise ValueError(f'task-id must be 1..{MAX_TASK} (fixed v1 addressing)')
    return dict(name=f'pmns{task}', host=f'pmh{task}',
                subnet=f'10.253.{task}.0/30', hostip=f'10.253.{task}.1',
                peerip=f'10.253.{task}.2',
                table=f'pm_t{task}', nat=f'pm_nat{task}',
                host6=f'fd7a:706d:{task:x}::1',peer6=f'fd7a:706d:{task:x}::2',
                subnet6=f'fd7a:706d:{task:x}::/64',nat6=f'pm_nat6{task}',
                config=BASE / f'task-{task}.json')


def http_origin(scheme,host,port):return scheme+'://'+('['+host+']' if ':' in host else host)+':'+str(port)


def resource_url(value):
    """Lossless request components; fragments are retained only as browser data."""
    if not isinstance(value,str) or not value or len(value)>8192 or any(ord(c)<=32 or ord(c)==127 for c in value) or '\\' in value:
        raise ValueError('Invalid resource: whitespace, controls or excessive length')
    original=value
    try:
        candidate=value[1:-1] if value.startswith('[') and value.endswith(']') and value.count('[')==value.count(']')==1 else value
        ip=ipaddress.ip_address(candidate)
        if '%' in value:raise ValueError('Scoped IPv6 zone identifiers are not supported')
        return {'input':original,'kind':'address','host':str(ip),'address':str(ip)}
    except ValueError:
        if ':' in value and '://' not in value:raise ValueError('IPv6 address or explicit http(s) URL required')
    if '://' not in value:
        host=value.rstrip('.').encode('idna').decode('ascii').lower()
        if '/' in value or '?' in value or '#' in value:raise ValueError('Use an explicit http(s) URL')
        if not re.fullmatch(r'(?=.{1,253}$)[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?',host) or any(not x or len(x)>63 or x.startswith('-') or x.endswith('-') for x in host.split('.')) or host.replace('.','').isdigit():
            raise ValueError('Invalid domain')
        return {'input':original,'kind':'domain','host':host}
    parsed=urlsplit(value)
    if parsed.scheme.lower() not in ('http','https') or not parsed.hostname or parsed.username is not None or parsed.password is not None:
        raise ValueError('Only http(s) URLs without embedded credentials are supported')
    host=parsed.hostname.encode('idna').decode('ascii').lower().rstrip('.')
    try:host=str(ipaddress.ip_address(host))
    except ValueError:host=resource_url(host)['host']
    if '%' in host:raise ValueError('IPv6 zone identifiers are not supported')
    port=parsed.port if parsed.port is not None else (443 if parsed.scheme.lower()=='https' else 80)
    if not 1<=port<=65535:raise ValueError('Invalid resource port')
    origin=http_origin(parsed.scheme.lower(),host,port)
    request_path=safe_http_path((parsed.path or '/')+('?' + parsed.query if '?' in value.split('#',1)[0] else ''))
    return {'input':original,'kind':'url','scheme':parsed.scheme.lower(),'host':host,'port':port,
            'origin':origin,'path':request_path.split('?',1)[0],'query':parsed.query,'fragment':parsed.fragment,
            'request_path':request_path,'request_url':origin+request_path}


def validate_resource_policy(policy,allowed):
    """Single policy contract shared with PM; the installed copy is root-owned."""
    if not isinstance(policy,dict) or policy.get('version')!=1 or policy.get('area') not in ('web','host','lab'):
        raise ValueError('Invalid resource policy')
    if set(policy)!={'version','area','machine','addresses','host_addresses','origins','networks','denied','ssrf'}:
        raise ValueError('Missing or unknown resource policy field')
    addresses=policy.get('addresses',[])
    if not addresses or len(addresses)>16 or any(check_target(a,allowed)!=a for a in addresses):raise ValueError('Invalid policy addresses')
    if any(a not in addresses for a in policy['host_addresses']) or policy['area']=='web' and policy['host_addresses']:
        raise ValueError('Invalid host investigation grants')
    origins=policy.get('origins',[])
    if policy['area']=='web' and not origins:raise ValueError('Web scope requires an origin')
    if len(origins)>32:raise ValueError('Too many authorized origins')
    for item in origins:
        value=resource_url(item['origin'])
        if value['kind']!='url' or value['request_path']!='/' or value['fragment'] or value['origin']!=item['origin']:
            raise ValueError('Invalid origin grant')
        if not item.get('addresses') or any(a not in addresses for a in item['addresses']):raise ValueError('Unpinned origin')
        prefix=item.get('path_prefix','/')
        if prefix!=safe_http_path(prefix) or '?' in prefix:raise ValueError('Invalid HTTP path boundary')
        if item.get('purpose')=='page_dependency' and item.get('request_path')!=safe_http_path(item.get('request_path','')):
            raise ValueError('Page dependency needs one exact request path')
    networks=policy.get('networks',[])
    if policy['area']!='lab' and networks:raise ValueError('Only lab scope grants networks')
    for network in networks:
        if str(ipaddress.ip_network(network)) not in allowed:raise ValueError('Lab network not in root scope')
    if len(policy.get('ssrf',[]))>32 or len(policy.get('denied',[]))>64:raise ValueError('Too many policy restrictions')
    for value in policy.get('denied',[]):
        try:ipaddress.ip_network(value)
        except ValueError:resource_url(value)
    for grant in policy.get('ssrf',[]):
        if grant.get('application') not in [x['origin'] for x in origins] or grant.get('context')!=policy.get('machine'):
            raise ValueError('SSRF must name its authorized application and target machine context')
        resource_url(grant['destination'])
    return policy


def resource_denied(policy,url):
    for denied in policy.get('denied',[]):
        try:
            net=ipaddress.ip_network(denied,strict=False)
            try:
                if ipaddress.ip_address(url['host']) in net:return True
            except ValueError:pass
        except ValueError:
            item=resource_url(denied)
            if item['kind']=='domain' and item['host']==url['host']:return True
            if item['kind']=='url' and item['origin']==url['origin']:
                import posixpath
                candidate=url['path']
                for _ in range(8):
                    if candidate.startswith(item['path']) or posixpath.normpath(candidate.replace('\\','/')).startswith(item['path']):return True
                    decoded=unquote(candidate)
                    if decoded==candidate:break
                    candidate=decoded
    return False


def authorize_resource(policy,operation,target,*,scheme='http',hostname='',port=80,path='/',destination='',context=''):
    """DNS/links never grant host scan authority. SSRF loopback is target-relative."""
    if not policy:return
    if operation in ('http','ssrf'):
        host=hostname or target
        if resource_denied(policy,{'host':target,'path':'/','origin':f'{scheme}://{target}:{port}'}):raise ValueError('Address explicitly excluded by room/task boundary')
        value=resource_url(f'{scheme}://'+('['+host+']' if ':' in host else host)+f':{int(port)}{path}')
        if resource_denied(policy,value):raise ValueError('Resource explicitly excluded by room/task boundary')
        matching=[o for o in policy['origins'] if o['origin']==value['origin'] and target in o['addresses']
                  and path_within(value['path'],o.get('path_prefix','/'))
                  and (o.get('purpose')!='page_dependency' or operation=='http' and o['request_path']==value['request_path'])]
        if policy['area']=='web' and not matching:raise ValueError('HTTP origin/address/path is outside web scope')
        if policy['area']!='web' and target not in policy['addresses'] and not any(ipaddress.ip_address(target) in ipaddress.ip_network(n) for n in policy.get('networks',[])):
            raise ValueError('HTTP destination outside task resources')
        if hostname and hostname!=target and not matching:raise ValueError('Virtual host is not authorized for this address')
        if not matching and any(o.get('path_prefix','/')!='/' for o in policy['origins']):raise ValueError('HTTP request does not match configured path boundaries')
        if operation=='ssrf':
            if context!=policy['machine']:raise ValueError('SSRF requires the target-machine context, not Kali')
            inner=resource_url(destination)
            if inner['kind']!='url' or resource_denied(policy,inner):raise ValueError('SSRF destination outside task boundaries')
            exact=any(g['application']==value['origin'] and g['destination']==inner['request_url']
                      and g['context']==context==policy['machine'] for g in policy.get('ssrf',[]))
            lab=False
            try:
                addr=ipaddress.ip_address(inner['host'])
                lab=policy['area']=='lab' and not addr.is_loopback and any(addr in ipaddress.ip_network(n) for n in policy.get('networks',[]))
            except ValueError:pass
            if not matching or not (exact or lab):raise ValueError('SSRF application/destination/route is not authorized')
    elif policy['area']=='web':
        raise ValueError('Web scope permits bounded HTTP tools, not host scans, shell or arbitrary PoC')
    else:
        address=ipaddress.ip_address(target)
        if resource_denied(policy,{'host':target,'path':'/','origin':f'http://{target}:80'}):
            raise ValueError('Address excluded by room/task boundary')
        if target not in policy['host_addresses'] and not any(address in ipaddress.ip_network(n) for n in policy.get('networks',[])):
            raise ValueError('Address outside task resources')
        if operation in ('exec','poc_run','session'):
            if (set(policy['addresses'])-set(policy['host_addresses']) or any(not _network_exclusion(d) for d in policy['denied'])
                    or any(o.get('path_prefix','/')!='/' for o in policy['origins'])):
                raise ValueError('Arbitrary execution cannot enforce origin-only grants/exclusions; use bounded HTTP tools')


def _network_exclusion(value):
    try:ipaddress.ip_network(value);return True
    except ValueError:return False


def path_within(path,prefix):
    # Traversal is a legitimate probe in a whole-site grant, but cannot escape
    # an explicit path boundary by encoding or dot segments.
    import posixpath
    if prefix=='/':return True
    for _ in range(8):
        if not (path==prefix.rstrip('/') or path.startswith(prefix.rstrip('/')+'/')):return False
        decoded=unquote(path).replace('\\','/')
        normal=posixpath.normpath(decoded.split('?',1)[0])
        if not (normal==prefix.rstrip('/') or normal.startswith(prefix.rstrip('/')+'/')):return False
        if decoded==path:break
        path=decoded
    return True


def resource_filter_rules(v,allowed,egress,policy=None):
    rules=filter_rules(v,allowed,egress)
    if not policy:return rules
    # Network exclusions also apply to arbitrary code, before every allow rule.
    drops=[]
    for value in policy['denied']:
        if _network_exclusion(value):
            net=ipaddress.ip_network(value)
            drops.append(f'add rule inet {v["table"]} forward iifname "{v["host"]}" '+('ip' if net.version==4 else 'ip6')+f' daddr {net} counter drop')
    marker=f'add rule inet {v["table"]} forward '
    index=rules.index(marker)
    return rules[:index]+('\n'.join(drops)+'\n' if drops else '')+rules[index:]


def allow_networks(raw):
    if not raw or len(raw) > 16:
        raise ValueError('Specify 1..16 allowed IP networks')
    nets = []
    for value in raw:
        net = ipaddress.ip_network(value, strict=False)
        if net.prefixlen < (8 if net.version==4 else 32):
            raise ValueError('Scope must be at least /8 (IPv4) or /32 (IPv6) specific')
        if net.overlaps(ipaddress.ip_network('127.0.0.0/8')) or net.overlaps(ipaddress.ip_network('::1/128')):
            raise ValueError('Host loopback cannot be exposed inside a namespace')
        if any(net.overlaps(doc) for doc in DOCS):
            raise ValueError('Documentation addresses cannot be used for live execution')
        if net.network_address.is_multicast or net.network_address.is_unspecified:
            raise ValueError('Invalid scope')
        nets.append(str(net))
    return list(dict.fromkeys(nets))


def validate_egress(value):
    if value == 'auto':
        return value
    if not re.fullmatch(r'[a-zA-Z0-9_.-]{1,15}', value):
        raise ValueError('Invalid egress interface')
    return value


def filter_rules(v, allowed, egress):
    # Early filter hooks fail closed for traffic from this task's veth.
    if any(ipaddress.ip_network(n).version==6 for n in allowed):
        return dual_stack_rules(v,allowed,egress)
    scope = '{ ' + ', '.join(allowed) + ' }'
    permitted_forward = (f'iifname "{v["host"]}" ip saddr {v["peerip"]} '
                         f'ip daddr {scope} ')
    if egress != 'auto':
        permitted_forward += f'oifname "{egress}" '
    permitted_forward += 'accept'
    local_ok = (f'iifname "{v["host"]}" ip saddr {v["peerip"]} '
                f'ip daddr {scope} accept\n') if egress == 'auto' else ''
    # Research set starts empty: nothing beyond the task scope is reachable
    # until an explicit research lookup adds a resolved address with a TTL.
    research_nat = (f'add rule ip {v["nat"]} postrouting ip saddr {v["peerip"]} '
                    f'oifname "{egress}" masquerade\n') if egress != 'auto' else ''
    return f'''add table inet {v['table']}
add set inet {v['table']} research_ips {{ type ipv4_addr; flags timeout; }}
add chain inet {v['table']} input {{ type filter hook input priority -150; policy accept; }}
add rule inet {v['table']} input {local_ok.strip() if local_ok else f'iifname "{v["host"]}" counter drop'}
{f'add rule inet {v["table"]} input iifname "{v["host"]}" counter drop' if local_ok else ''}
add chain inet {v['table']} forward {{ type filter hook forward priority -150; policy accept; }}
add rule inet {v['table']} forward {permitted_forward}
add rule inet {v['table']} forward ip saddr {v['peerip']} ip daddr @research_ips tcp dport {RESEARCH_PORT} accept
add rule inet {v['table']} forward iifname "{v['host']}" counter drop
add rule inet {v['table']} forward oifname "{v['host']}" ct state established,related accept
add rule inet {v['table']} forward oifname "{v['host']}" counter drop
add table ip {v['nat']}
add chain ip {v['nat']} postrouting {{ type nat hook postrouting priority 100; policy accept; }}
add rule ip {v['nat']} postrouting ip saddr {v['peerip']} ip daddr {scope} masquerade
{research_nat}'''


def dual_stack_rules(v,allowed,egress):
    lines=[f'add table inet {v["table"]}',
           f'add set inet {v["table"]} research_ips {{ type ipv4_addr; flags timeout; }}',
           f'add chain inet {v["table"]} input {{ type filter hook input priority -150; policy accept; }}',
           f'add rule inet {v["table"]} input iifname "{v["host"]}" icmpv6 type {{ nd-neighbor-solicit, nd-neighbor-advert }} accept',
           f'add rule inet {v["table"]} input iifname "{v["host"]}" counter drop',
           f'add chain inet {v["table"]} forward {{ type filter hook forward priority -150; policy accept; }}']
    interface=f'oifname "{egress}" ' if egress!='auto' else ''
    for family,peer,nat,version in (('ip',v['peerip'],v['nat'],4),('ip6',v['peer6'],v['nat6'],6)):
        scope=[n for n in allowed if ipaddress.ip_network(n).version==version]
        if scope:lines.append(f'add rule inet {v["table"]} forward iifname "{v["host"]}" {family} saddr {peer} {family} daddr {{ '+', '.join(scope)+f' }} {interface}accept')
        lines += [f'add table {family} {nat}',f'add chain {family} {nat} postrouting {{ type nat hook postrouting priority 100; policy accept; }}']
        if scope:lines.append(f'add rule {family} {nat} postrouting {family} saddr {peer} {family} daddr {{ '+', '.join(scope)+' } masquerade')
    lines += [f'add rule inet {v["table"]} forward ip saddr {v["peerip"]} ip daddr @research_ips tcp dport {RESEARCH_PORT} accept',
              f'add rule inet {v["table"]} forward iifname "{v["host"]}" counter drop',
              f'add rule inet {v["table"]} forward oifname "{v["host"]}" ct state established,related accept',
              f'add rule inet {v["table"]} forward oifname "{v["host"]}" counter drop']
    if egress!='auto':lines.append(f'add rule ip {v["nat"]} postrouting ip saddr {v["peerip"]} oifname "{egress}" masquerade')
    return '\n'.join(lines)+'\n'


# Docker's iptables-nft FORWARD chain may DROP traffic even after the
# earlier nftables NetGuard allow verdict. Bridge that single, scoped flow.
IPTABLES = '/usr/sbin/iptables'
IP6TABLES = '/usr/sbin/ip6tables'
HOSTS_BASE = Path('/etc/netns')


def docker_forward_rules(v, config, egress=None):
    allowed = config['allowed']
    egress = egress or config.get('current_egress', config['egress'])
    if egress == 'auto':
        raise ValueError('Docker forward integration needs explicit --egress, e.g. tun0')
    # No broad source/destination matches. The nftables early hook remains
    # the independent enforcement point for the entire root-owned task scope.
    if not config.get('resource_policy') and (len(allowed) != 1 or not ipaddress.ip_network(allowed[0]).prefixlen == 32):
        raise ValueError('Docker forwarding currently requires one exact /32 target')
    result=[]
    for destination in allowed:
        version=ipaddress.ip_network(destination).version
        if version not in config.get('docker_families',[4,6]):continue
        peer=(v['peerip']+'/32') if version==4 else (v['peer6']+'/128')
        result += [['-i',v['host'],'-o',egress,'-s',peer,'-d',destination,'-j','ACCEPT'],
                   ['-i',egress,'-o',v['host'],'-s',destination,'-d',peer,'-m','conntrack','--ctstate','ESTABLISHED,RELATED','-j','ACCEPT']]
    return result


def docker_chain_exists(binary=IPTABLES):
    return cmd(binary, '-w', '5', '-S', 'DOCKER-USER', check=False).returncode == 0


def docker_policy_drops_forward(version=4):
    result = cmd(IPTABLES if version==4 else IP6TABLES, '-w', '5', '-S', 'FORWARD')
    return any(line.strip() == '-P FORWARD DROP' for line in result.stdout.splitlines())


def docker_rule_exists(rule):
    return cmd(docker_rule_binary(rule), '-w', '5', '-C', 'DOCKER-USER', *rule, check=False).returncode == 0


def docker_rule_binary(rule):return IP6TABLES if ':' in rule[rule.index('-s')+1] else IPTABLES


def task_docker_families(config):
    versions=sorted({ipaddress.ip_network(n).version for n in config['allowed']})
    return [version for version in versions if (docker_policy_drops_forward() if version==4 else docker_policy_drops_forward(6))]


def remove_docker_rules(rules):
    # Ignore already-absent rules, but never silently ignore a failed delete.
    for rule in reversed(rules):
        if docker_rule_exists(rule):
            cmd(docker_rule_binary(rule), '-w', '5', '-D', 'DOCKER-USER', *rule)


def add_docker_rules(rules, adopt_existing=False):
    for binary in {docker_rule_binary(r) for r in rules}:
        if not (docker_chain_exists() if binary==IPTABLES else docker_chain_exists(binary)):
            raise RuntimeError('DOCKER-USER chain unavailable; refusing FORWARD DROP bypass')
    inserted = []
    try:
        for index, rule in enumerate(rules, start=1):
            if docker_rule_exists(rule):
                if not adopt_existing:
                    raise ValueError('Matching DOCKER-USER rule already exists; use sync-forward to adopt explicitly')
            else:
                cmd(docker_rule_binary(rule), '-w', '5', '-I', 'DOCKER-USER', str(index), *rule)
                inserted.append(rule)
    except BaseException:
        remove_docker_rules(inserted)
        raise
    return inserted


def sync_forward(task):
    """Explicitly adopt existing scoped manual Docker rules (or insert them)."""
    ensure_root()
    v, config = owned_config(task)
    families=task_docker_families(config)
    if not families:
        raise ValueError('FORWARD is not DROP; Docker bridge not required')
    config=dict(config,docker_families=families)
    rules = docker_forward_rules(v, config)
    added = add_docker_rules(rules, adopt_existing=True)
    try:
        # Fail-closed if config write fails: remove only rules inserted here.
        data = dict(config, docker_forward_managed=True)
        replace_config(v, data)
    except BaseException:
        remove_docker_rules(added)
        raise
    output({'status': 'forward_ready', 'task_id': task,
            'chain': 'DOCKER-USER', 'egress': config['egress'],
            'target': config['allowed'][0], 'rules': len(rules),
            'adopted': len(rules) - len(added)})


def validate_hostnames(names):
    """Only explicitly approved DNS aliases of the single authorized IP."""
    if not 1 <= len(names) <= 12:
        raise ValueError('Specify 1..12 hostnames')
    cleaned = []
    for raw in names:
        if not isinstance(raw, str) or not 1 <= len(raw) <= 253:
            raise ValueError('Invalid hostname length')
        name = raw.rstrip('.').lower()
        if (name in ('localhost', 'localhost.localdomain') or
            re.fullmatch(r'(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*'
                         r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', name) is None or
            name.replace('.', '').isdigit()):
            raise ValueError('Invalid hostname or forbidden local alias')
        cleaned.append(name)
    if len(set(cleaned)) != len(cleaned):
        raise ValueError('Duplicate hostname')
    return cleaned


def namespace_hosts_path(v):
    return HOSTS_BASE / v['name'] / 'hosts'


def set_hostnames(task, hostnames):
    ensure_root()
    v, config = owned_config(task)
    sudo_uid = os.environ.get('SUDO_UID')
    if sudo_uid is not None and int(sudo_uid) != config['uid']:
        raise ValueError('Invoker is not task owner')
    names = validate_hostnames(hostnames)
    policy=config.get('resource_policy')
    if policy:
        mapping={name:list(dict.fromkeys(a for o in policy['origins'] if resource_url(o['origin'])['host']==name for a in o['addresses'])) for name in names}
        if any(not values for values in mapping.values()):raise ValueError('Hostname not in approved resource policy')
        destination=policy['addresses'][0]
    else:
        if len(config['allowed']) != 1 or ipaddress.ip_network(config['allowed'][0]).num_addresses!=1:
            raise ValueError('Hostnames require one exact address scope')
        destination = str(ipaddress.ip_network(config['allowed'][0]).network_address)
        mapping={name:[destination] for name in names}
    if not HOSTS_BASE.exists():
        HOSTS_BASE.mkdir(mode=0o755)
    if (HOSTS_BASE.is_symlink() or HOSTS_BASE.stat().st_uid != 0 or
            HOSTS_BASE.stat().st_mode & 0o022):
        raise ValueError('Unsafe netns hosts directory')
    directory = HOSTS_BASE / v['name']
    if not directory.exists():
        directory.mkdir(mode=0o755)
    if (directory.is_symlink() or directory.stat().st_uid != 0 or
            directory.stat().st_mode & 0o022):
        raise ValueError('Unsafe task hosts directory')
    path = namespace_hosts_path(v)
    if path.exists() and not config.get('hosts_managed'):
        raise ValueError('Existing hosts file was not created by NetGuard; refusing overwrite')
    if path.is_symlink() or (path.exists() and
            (path.stat().st_uid != 0 or path.stat().st_mode & 0o022)):
        raise ValueError('Unsafe task hosts file')
    if config.get('hostnames') == names and path.is_file():
        output({'status': 'hosts_ready', 'task_id': task,
                'hostnames': names, 'destination': destination})
        return
    previous = path.read_text() if path.exists() else None
    content='127.0.0.1 localhost\n::1 localhost\n'+''.join(address+' '+name+'\n' for name in names for address in mapping[name])
    temporary = directory / '.hosts.tmp'
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
    try:
        with os.fdopen(fd, 'w') as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        try:
            replace_config(v, dict(config, hostnames=names, hosts_managed=True))
        except BaseException:
            if previous is None:
                path.unlink(missing_ok=True)
            else:
                path.write_text(previous)
            raise
    finally:
        if temporary.exists():
            temporary.unlink()
    output({'status': 'hosts_ready', 'task_id': task,
            'hostnames': names, 'destination': destination})


def replace_config(v, data):
    # No following symlinks: target remains root-owned / mode 0600.
    old = v['config']
    if old.is_symlink() or not old.is_file():
        raise ValueError('Unsafe config')
    temporary = old.with_suffix('.json.new')
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, 'w') as f:
            json.dump(data, f)
            f.flush()
            os.fsync(f.fileno())
        os.replace(temporary, old)
    finally:
        if temporary.exists():
            temporary.unlink()


def ensure_root():
    if os.geteuid() != 0:
        raise PermissionError('Run root broker through sudo')


def owned_config(task):
    v = task_values(task)
    path = v['config']
    if not path.is_file() or path.is_symlink():
        raise ValueError('Network namespace not configured for task')
    st = path.stat()
    if st.st_uid != 0 or (st.st_mode & 0o077):
        raise ValueError('Unsafe netguard configuration permissions')
    data = json.loads(path.read_text())
    if data.get('task_id') != task or data.get('name') != v['name']:
        raise ValueError('Root config does not match task')
    return v, data


def store_config(v, data):
    BASE.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd = os.open(v['config'], os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w') as f:
        json.dump(data, f)


def sysctl_forward(enable):
    p = Path('/proc/sys/net/ipv4/ip_forward')
    if enable:
        STATE.mkdir(parents=True, exist_ok=True, mode=0o700)
        if not PREV_FORWARD.exists():
            PREV_FORWARD.write_text(p.read_text().strip())
            PREV_FORWARD.chmod(0o600)
        p.write_text('1\n')
    elif PREV_FORWARD.exists() and not list(BASE.glob('task-*.json')):
        prior = PREV_FORWARD.read_text().strip()
        if prior in ('0', '1'):
            p.write_text(prior + '\n')
        PREV_FORWARD.unlink()


def sysctl_forward6(enable):
    path=Path('/proc/sys/net/ipv6/conf/all/forwarding')
    previous=STATE/'ip6_forward.previous'
    if enable:
        STATE.mkdir(parents=True,exist_ok=True,mode=0o700)
        if not previous.exists():
            previous.write_text(path.read_text().strip());previous.chmod(0o600)
        path.write_text('1\n')
    elif previous.exists() and not list(BASE.glob('task-*.json')):
        prior=previous.read_text().strip()
        if prior not in ('0','1'):raise ValueError('Invalid saved IPv6 forwarding state')
        path.write_text(prior+'\n');previous.unlink()


def setup(task, owner, allowed, egress, resource_policy=None):
    ensure_root()
    v = task_values(task)
    networks = allow_networks(allowed)
    policy=validate_resource_policy(resource_policy,networks) if resource_policy is not None else None
    egress = validate_egress(egress)
    account = pwd.getpwnam(owner)
    if account.pw_uid == 0:
        raise ValueError('Namespace tools must run as a non-root user')
    if v['config'].exists():
        raise ValueError('Task namespace already configured')
    present = {line.split()[0] for line in
               cmd('/usr/sbin/ip', 'netns', 'list').stdout.splitlines() if line.strip()}
    if v['name'] in present:
        raise ValueError('Conflicting namespace already exists')
    if egress != 'auto':
        cmd('/usr/sbin/ip', 'link', 'show', 'dev', egress)
    # Refuse subnet overlap with existing Kali VPN/NAT routes.
    new_subnet = ipaddress.ip_network(v['subnet'])
    routes = cmd('/usr/sbin/ip', '-4', 'route', 'show', 'table', 'all').stdout
    for line in routes.splitlines():
        words = line.split()
        if not words: continue
        destination = words[1] if words[0] in ('local','broadcast','unreachable','blackhole','prohibit','throw') and len(words) > 1 else words[0]
        if destination == 'default': continue
        try:
            existing = ipaddress.ip_network(destination, strict=False)
        except ValueError:
            continue
        if existing.version == 4 and existing.overlaps(new_subnet):
            raise ValueError(f'Veth subnet overlaps existing Kali route: {destination}')
    rules = resource_filter_rules(v, networks, egress,policy)
    cmd('/usr/sbin/nft', '-c', '-f', '-', input=rules)
    created = False
    docker_added = []
    docker_managed = False
    try:
        cmd('/usr/sbin/ip', 'netns', 'add', v['name']); created = True
        cmd('/usr/sbin/ip', 'link', 'add', v['host'], 'type', 'veth', 'peer', 'name', 'eth0', 'netns', v['name'])
        cmd('/usr/sbin/nft', '-f', '-', input=rules)
        cmd('/usr/sbin/ip', 'address', 'add', v['hostip'] + '/30', 'dev', v['host'])
        cmd('/usr/sbin/ip', 'link', 'set', v['host'], 'up')
        cmd('/usr/sbin/ip', 'netns', 'exec', v['name'], '/usr/sbin/ip', 'link', 'set', 'lo', 'up')
        cmd('/usr/sbin/ip', 'netns', 'exec', v['name'], '/usr/sbin/ip', 'address', 'add', v['peerip'] + '/30', 'dev', 'eth0')
        cmd('/usr/sbin/ip', 'netns', 'exec', v['name'], '/usr/sbin/ip', 'link', 'set', 'eth0', 'up')
        cmd('/usr/sbin/ip', 'netns', 'exec', v['name'], '/usr/sbin/ip', 'route', 'add', 'default', 'via', v['hostip'])
        if any(ipaddress.ip_network(n).version==6 for n in networks):
            cmd('/usr/sbin/ip','-6','address','add',v['host6']+'/64','dev',v['host'],'nodad')
            cmd('/usr/sbin/ip','netns','exec',v['name'],'/usr/sbin/ip','-6','address','add',v['peer6']+'/64','dev','eth0','nodad')
            cmd('/usr/sbin/ip','netns','exec',v['name'],'/usr/sbin/ip','-6','route','add','default','via',v['host6'])
            sysctl_forward6(True)
        sysctl_forward(True)
        config_data = {'task_id': task, 'name': v['name'], 'uid': account.pw_uid,
                       'gid': account.pw_gid, 'owner': owner, 'allowed': networks,
                       'egress': egress, 'approved_egress': egress,
                       'current_egress': egress,
                       'host_ip': v['hostip'], 'peer_ip': v['peerip']}
        if policy is not None:config_data['resource_policy']=policy
        # Docker's FORWARD DROP otherwise silently makes an authorized scan
        # return zero observations. Refuse unhandled DROP, never weaken it.
        families=task_docker_families(config_data)
        if families:
            config_data['docker_families']=families
            docker_rules = docker_forward_rules(v, config_data)
            docker_added = add_docker_rules(docker_rules)
            docker_managed = True
            config_data['docker_forward_managed'] = True
        store_config(v, config_data)
    except BaseException:
        # Never leave an unfiltered veth or forwarding change behind on setup failure.
        if docker_added:
            remove_docker_rules(docker_added)
        cmd('/usr/sbin/nft', 'delete', 'table', 'inet', v['table'], check=False)
        cmd('/usr/sbin/nft', 'delete', 'table', 'ip', v['nat'], check=False)
        cmd('/usr/sbin/nft','delete','table','ip6',v['nat6'],check=False)
        if created:
            cmd('/usr/sbin/ip', 'netns', 'delete', v['name'], check=False)
        if v['config'].exists():
            v['config'].unlink()
        sysctl_forward(False)
        sysctl_forward6(False)
        raise
    output({'status': 'configured', 'task_id': task, 'name': v['name'],
            'allowed': networks, 'egress': egress, 'host_veth_ip': v['hostip']})


def teardown(task):
    ensure_root()
    v, config = owned_config(task)
    name_exists = any(line.split()[0] == v['name'] for line in
                      cmd('/usr/sbin/ip', 'netns', 'list').stdout.splitlines() if line.strip())
    p = cmd('/usr/sbin/ip', 'netns', 'pids', v['name'], check=False) if name_exists else None
    pids = [int(x) for x in p.stdout.split() if x.isdigit()] if p else []
    for pid in pids:
        try: os.kill(pid, signal.SIGTERM)
        except ProcessLookupError: pass
    if pids:
        time.sleep(0.3)
    remaining = cmd('/usr/sbin/ip', 'netns', 'pids', v['name'], check=False) if name_exists else None
    for s in remaining.stdout.split() if remaining else []:
        if s.isdigit():
            try: os.kill(int(s), signal.SIGKILL)
            except ProcessLookupError: pass
    time.sleep(0.1)
    if name_exists:
        if cmd('/usr/sbin/ip', 'netns', 'pids', v['name'], check=False).stdout.strip():
            raise RuntimeError('Namespace still has processes; firewall retained')
        cmd('/usr/sbin/ip', 'netns', 'delete', v['name'])
    if config.get('research_forward_rules'):
        remove_docker_rules(config['research_forward_rules'])
    if config.get('docker_forward_managed'):
        remove_docker_rules(docker_forward_rules(v, config))
    cmd('/usr/sbin/nft', 'delete', 'table', 'inet', v['table'], check=False)
    cmd('/usr/sbin/nft', 'delete', 'table', 'ip', v['nat'], check=False)
    cmd('/usr/sbin/nft','delete','table','ip6',v['nat6'],check=False)
    # Sessions and the persistent workspace belong to the task lifetime.
    session_cleanup(task)
    v['config'].unlink()
    sysctl_forward6(False)
    if config.get('hosts_managed'):
        hosts_path = namespace_hosts_path(v)
        if hosts_path.is_file() and not hosts_path.is_symlink():
            hosts_path.unlink()
            try:
                hosts_path.parent.rmdir()
            except OSError:
                pass
    sysctl_forward(False)
    output({'status': 'removed', 'task_id': task})


def check_target(target, allowed):
    ip = ipaddress.ip_address(target)
    if ip.is_loopback or ip.is_multicast or ip.is_unspecified or '%' in target:
        raise ValueError('Only concrete non-loopback IP targets permitted')
    if any(ip in doc for doc in DOCS):
        raise ValueError('Documentation targets cannot be scanned')
    if not any(ip in ipaddress.ip_network(net) for net in allowed):
        raise ValueError('Destination denied by root-owned task scope')
    return str(ip)


def safe_http_path(path):
    """Bounded request target: preserve query exactly, discard browser fragment."""
    if not isinstance(path,str) or not 1<=len(path)<=8192 or not path.startswith('/') or path.startswith('//'):
        raise ValueError('Expected an absolute HTTP request path up to 8192 characters')
    path=quote(path.split('#',1)[0],safe="/._~!$&'()*+,;=:@%/?[]-")
    if len(path)>8192:raise ValueError('Encoded HTTP request target is too long')
    if not re.fullmatch(r"/[A-Za-z0-9._~!$&'()*+,;=:@%/?\[\]\-]*",path):
        raise ValueError('Unsafe HTTP request characters')
    decoded=path
    for _ in range(8):
        if any(ord(c)<32 or ord(c)==127 for c in decoded):raise ValueError('HTTP control characters denied')
        next_value=unquote(decoded)
        if next_value==decoded:break
        decoded=next_value
    return path


RESEARCH_PATH_CHARS = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    "._~!&'()*+,;=:@%/?-")


def safe_research_path(path):
    """Read-only path for allowlisted research hosts; queries allowed, no fragment."""
    if not isinstance(path, str) or not path.startswith('/') or not 1 <= len(path) <= 512:
        raise ValueError('Expected a research path up to 512 bytes')
    if any(char not in RESEARCH_PATH_CHARS for char in path):
        raise ValueError('Unsafe research path characters')
    if '#' in path or any(ord(char) < 32 or ord(char) == 127 for char in path):
        raise ValueError('Research fragment or control character denied')
    if '..' in unquote(path):
        raise ValueError('Research path traversal denied')
    return path


def reject_password_change(argv=(), text=''):
    """Deny supported credential mutations, not verify arbitrary code.

    This standalone broker imports no project code in its installed copy.
    MCP and the unprivileged wrapper reuse the same source.
    """
    tokens=[str(item) for item in argv]
    binary=Path(tokens[0]).name if tokens else ''
    if binary in ('passwd','chpasswd','smbpasswd','kpasswd','chntpw'):
        raise ValueError('Room rule: password changes are prohibited')
    if binary in ('usermod','useradd') and any(
            t=='-p' or t.startswith('-p') or t=='--password' or t.startswith('--password=') for t in tokens[1:]):
        raise ValueError('Room rule: password changes are prohibited')
    # A file argument such as cat /etc/passwd is not a command. Remote/shell
    # command strings containing whitespace are inspected separately.
    source=' '.join(tokens)+'\n'+'\n'.join(t for t in tokens[1:] if re.search(r'\s',t))+'\n'+str(text)
    patterns=(r'(?im)(?:^|[;&|\n])\s*(?:sudo\s+)?(?:/\S*/)?(?:passwd|chpasswd|smbpasswd|kpasswd|chntpw)\b',
        r'(?im)\bssh\s+[^\n;]*\s(?:/(?:usr/)?s?bin/)?(?:passwd|chpasswd|smbpasswd|kpasswd)\b',
        r'(?im)\b(?:usermod|useradd)\s+[^\n;]*?(?:--password(?:=|\s)|\s-p)',
        r'(?i)\bnet\s+(?:rpc\s+password|user\s+\S+\s+\S+)',
        r'(?i)\bsamba-tool\s+user\s+(?:setpassword|password)\b',
        r'(?i)\b(?:Set-ADAccountPassword|Set-LocalUser\s+[^\n;]*-Password)\b',
        r'(?i)\b(?:ALTER\s+USER\b[^;\n]*IDENTIFIED\s+BY|SET\s+PASSWORD\b)',
        r'(?im)(?:>|\btee\s+)(?:\s*)(?:/etc/(?:shadow|passwd))\b')
    if any(re.search(pattern,source) for pattern in patterns):
        raise ValueError('Room rule: password changes are prohibited')


def safe_exec_argv(argv):
    """Free-form argv for the isolated namespace. Never shell-interpreted."""
    if isinstance(argv, str) or not isinstance(argv, (list, tuple)) or not argv:
        raise ValueError('exec requires a non-empty argv list')
    tokens = [str(token) for token in argv]
    if len(tokens) > EXEC_ARGS_MAX:
        raise ValueError(f'exec accepts at most {EXEC_ARGS_MAX} argv tokens')
    total = 0
    for token in tokens:
        if '\x00' in token or len(token) > EXEC_ARG_LEN_MAX:
            raise ValueError('Invalid argv token')
        total += len(token) + 1
    if total > EXEC_TOTAL_MAX:
        raise ValueError('exec argv exceeds the total size limit')
    if not tokens[0].startswith('/'):
        raise ValueError('argv[0] must be an absolute binary path')
    reject_password_change(tokens)
    return tokens


def safe_payload_path(path, uid):
    """A PoC file the task owner wrote: regular, owner-owned, not group/world writable."""
    if not isinstance(path, str) or not path.startswith('/') or len(path) > 4096:
        raise ValueError('PoC path must be absolute')
    if '\x00' in path:
        raise ValueError('Invalid PoC path')
    real = os.path.realpath(path)
    for prefix in ('/proc', '/sys', '/dev', '/run'):
        if real == prefix or real.startswith(prefix + '/'):
            raise ValueError('PoC path in a protected location')
    st = os.lstat(path)
    if stat.S_ISLNK(st.st_mode):
        raise ValueError('PoC path must not be a symlink')
    if not stat.S_ISREG(st.st_mode):
        raise ValueError('PoC path must be a regular file')
    if st.st_uid != uid:
        raise ValueError('PoC file must be owned by the task owner')
    if st.st_mode & 0o022:
        raise ValueError('PoC file must not be group/world writable')
    if st.st_size > POC_MAX_BYTES:
        raise ValueError('PoC file too large')
    return real


POC_INTERPRETERS = ('bash', 'sh', 'python3', 'perl')


def poc_work_file(poc_file, uid, gid, workdir):
    """Copy once into the task workspace, then use its owner-edited version."""
    name = Path(str(poc_file)).name
    if not POC_NAME.fullmatch(name) or not name.endswith(POC_SUFFIXES):
        raise ValueError('Invalid PoC filename or suffix')
    directory = workdir / 'poc'
    try:
        os.mkdir(directory, 0o700)
        created = True
    except FileExistsError:
        created = False
    directory_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    local = directory / name
    try:
        if created:
            os.fchown(directory_fd, uid, gid)
        info = os.fstat(directory_fd)
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != uid or
                info.st_mode & 0o077):
            raise ValueError('Unsafe PoC work directory')
        try:
            os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            exists = True
        except FileNotFoundError:
            exists = False
        if not exists:
            original = safe_payload_path(poc_file, uid)
            source_fd = os.open(original, os.O_RDONLY | os.O_NOFOLLOW)
            try:
                source_info = os.fstat(source_fd)
                if (not stat.S_ISREG(source_info.st_mode) or source_info.st_uid != uid or
                        source_info.st_size > POC_MAX_BYTES):
                    raise ValueError('Unsafe PoC source file')
                try:
                    target_fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                                        os.O_NOFOLLOW, 0o700, dir_fd=directory_fd)
                except FileExistsError:
                    target_fd = None
                if target_fd is not None:
                    try:
                        os.fchown(target_fd, uid, gid)
                        os.fchmod(target_fd, 0o755)
                        copied = 0
                        while True:
                            block = os.read(source_fd, 65536)
                            if not block:
                                break
                            copied += len(block)
                            if copied > POC_MAX_BYTES:
                                raise ValueError('PoC file too large')
                            while block:
                                block = block[os.write(target_fd, block):]
                        os.fsync(target_fd)
                    except BaseException:
                        os.unlink(name, dir_fd=directory_fd)
                        raise
                    finally:
                        os.close(target_fd)
            finally:
                os.close(source_fd)
    finally:
        os.close(directory_fd)
    return local


def poc_file_metadata(path, uid):
    """Read only a regular owner-owned file; never follow a PoC symlink."""
    directory_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=directory_fd)
        try:
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != uid or
                    info.st_nlink != 1 or info.st_mode & 0o022 or
                    info.st_size > POC_MAX_BYTES):
                raise ValueError('Unsafe local PoC file')
            data = bytearray()
            while True:
                block = os.read(fd, 65536)
                if not block:
                    break
                data.extend(block)
                if len(data) > POC_MAX_BYTES:
                    raise ValueError('PoC file too large')
        finally:
            os.close(fd)
    finally:
        os.close(directory_fd)
    reject_password_change(text=data.decode('utf-8', errors='replace'))
    literals = sorted(set(re.findall(
        r'\b[A-Z][A-Z0-9_]{1,19}\{[A-Za-z0-9_!@#$%^&*+.:-]{3,120}\}',
        data.decode('utf-8', errors='replace'))))[:20]
    return {'poc_sha256': hashlib.sha256(data).hexdigest(),
            'poc_bytes': len(data), 'poc_source_flag_literals': literals}


def poc_argv(poc_file, interp, uid, gid, workdir):
    if interp not in POC_INTERPRETERS:
        raise ValueError('Unsupported PoC interpreter')
    binary = {'bash': '/bin/bash', 'sh': '/bin/sh',
              'python3': '/usr/bin/python3', 'perl': '/usr/bin/perl'}[interp]
    if not os.path.exists(binary):
        raise ValueError(f'Interpreter {interp} is not installed')
    local = poc_work_file(poc_file, uid, gid, workdir)
    return {'argv': [binary, '/work/poc/' + local.name],
            'local': local, **poc_file_metadata(local, uid)}


def network_diagnostic(task,target):
    config,_,_=session_invoker(task);check_target(target,config['allowed'])
    result=cmd('/usr/sbin/ip','-j','route','get',target,timeout=3)
    routes=json.loads(result.stdout);device=routes[0].get('dev') if routes else None
    if not device or not re.fullmatch(r'[A-Za-z0-9_.-]{1,15}',device):raise ValueError('No usable route')
    file=Path('/sys/class/net')/device/'operstate'
    return {'status':'observed','route_dev':device,'configured_egress':config.get('egress'),
        'route_matches':device==config.get('egress'),'interface_state':file.read_text().strip() if file.is_file() else 'unknown',
        'probe':'local route/interface lookup only; no ping or target packets','host_state':'unknown'}


def port_probe(target,port,protocol,timeout=2.0):
    """One unprivileged observation; UDP silence is explicitly ambiguous."""
    import errno,socket,time
    from datetime import datetime,timezone
    if protocol not in ('tcp','udp') or not 1<=int(port)<=65535 or not .01<=float(timeout)<=2:raise ValueError('Invalid probe')
    started=time.monotonic();state='timeout';error=None
    family=socket.AF_INET6 if ':' in target else socket.AF_INET
    try:
        with socket.socket(family,socket.SOCK_STREAM if protocol=='tcp' else socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout);sock.connect((target,port))
            if protocol=='tcp':state='open'
            else:
                sock.send(b'\x00');sock.recv(2048);state='open'
    except TimeoutError:state='open|filtered' if protocol=='udp' else 'timeout';error='TimeoutError'
    except OSError as exc:
        error=type(exc).__name__
        state='closed' if exc.errno==errno.ECONNREFUSED else 'filtered' if exc.errno in (errno.EACCES,errno.EPERM) else 'timeout'
    return {'port':port,'protocol':protocol,'state':state,'error_type':error,
            'elapsed_seconds':round(time.monotonic()-started,3),'service_verified':False,
            'probe_finished_at':datetime.now(timezone.utc).isoformat()}


def tool_args(profile, target, port, ports, scheme, path="/", hostname="", capture_limit=HTTP_CAPTURE_BODY_LIMIT):
    ipv6=ipaddress.ip_address(target).version==6
    nmap6=['-6'] if ipv6 else []
    def valid_port(raw):
        if not re.fullmatch(r'[0-9]{1,5}', str(raw)) or not 1 <= int(raw) <= 65535:
            raise ValueError('Invalid TCP port')
        return str(int(raw))
    def valid_ports(raw):
        parts = raw.split(',')
        if not 1 <= len(parts) <= 50:
            raise ValueError('1..50 TCP ports required')
        values = [valid_port(part) for part in parts]
        if len(set(values)) != len(values):
            raise ValueError('Duplicate TCP port')
        return ','.join(values)
    if profile == 'tcp_full':
        # Operator-initiated one-off full TCP connect discovery (no exploits,
        # no UDP, no NSE scripts, no credential attacks). Exact target is still
        # enforced by the root-owned per-task /32 firewall and owner checks.
        return ['/usr/bin/nmap', *nmap6, '-sT', '-Pn', '-n', '--min-rate', '1000',
                '--max-retries', '1', '--host-timeout', '240s',
                '-p-', target]
    if profile=='udp_ports':
        selected=valid_ports(ports)
        if len(selected.split(','))>8:raise ValueError('UDP operation supports 1..8 ports')
        return ['/usr/bin/python3','/usr/local/sbin/pm-netguard','port-worker','--target',target,'--ports',selected]
    if profile in ('tcp_ports', 'service_versions'):
        selected = valid_ports(ports)
        if profile == 'tcp_ports':
            return ['/usr/bin/nmap', *nmap6, '-sT', '-Pn', '-n', '--max-retries', '1',
                    '--host-timeout', '25s', '-p', selected, target]
        return ['/usr/bin/nmap', *nmap6, '-sT', '-sV', '--version-light', '-Pn', '-n', '--open',
                '--max-retries', '1', '--host-timeout', '30s', '-p', selected, target]
    if profile in RAW_SCAN_PROFILES:
        selected = valid_ports(ports)
        if profile == 'nmap_udp' and len(selected.split(',')) > 8:
            raise ValueError('UDP profile supports at most eight explicit ports')
        flags = {'nmap_syn': ['-sS'], 'nmap_udp': ['-sU'], 'nmap_os': ['-sS', '-O', '--osscan-limit']}[profile]
        return ['/usr/bin/nmap', '--datadir', '/usr/share/nmap', *nmap6, *flags, '-Pn', '-n',
                '--open', '--max-retries', '1', '--host-timeout', '30s', '-p', selected, target]
    if profile not in ('http_headers', 'http_get', 'https_headers', 'http_path', 'http_document', 'http_capture'):
        raise ValueError('Unknown profile')
    selected = valid_port(port)
    if profile == 'http_headers': scheme = 'http'
    if profile == 'https_headers': scheme = 'https'
    if scheme not in ('http', 'https'):
        raise ValueError('Invalid HTTP scheme')
    result = ['/usr/bin/curl', '--globoff','--path-as-is','--silent', '--show-error', '--noproxy', '*',
              '--proto', '=http,https', '--max-redirs', '0', '--connect-timeout', '3',
              '--max-time', '12']
    if profile in ('http_headers', 'https_headers'):
        result += ['--head']
    else:
        if profile == 'http_capture' and capture_limit not in HTTP_CAPTURE_LIMITS:
            raise ValueError('Unsupported HTTP capture limit')
        limit = capture_limit if profile == 'http_capture' else 262144 if profile == 'http_document' else 32768
        result += ['--include', '--max-filesize', str(limit)]
    if profile in ('http_path', 'http_document', 'http_capture'):
        path=safe_http_path(path)
        if hostname:
            if hostname == target:
                hostname = ''
            elif not re.fullmatch(r'[a-z0-9.-]{1,253}', hostname):
                raise ValueError('Invalid HTTP host')
        if hostname:
            result += ['--resolve', f'{hostname}:{selected}:'+('['+target+']' if ipv6 else target)]
        authority = hostname or ('['+target+']' if ipv6 else target)
        return result + ['--', f'{scheme}://{authority}:{selected}{path}']
    return result + ['--', f'{scheme}://'+('['+target+']' if ipv6 else target)+f':{selected}/']


def isolated_command(name, user, uid, gid, args, extra=(), workdir=None,
                     new_session=True):
    """Build the sandboxed command line for one task namespace.

    workdir: bind a persistent per-task directory at /work instead of creating
    an empty tmpfs one, so files survive between capability calls.
    new_session: bwrap's --new-session detaches the process from its controlling
    terminal. An interactive session needs that off, otherwise a PTY cannot
    drive the shell.

    No imports, paths, or commands from the user-writable project are executed
    as root: setpriv drops all caps before Bubblewrap and the tool are run.
    """
    work_mount = (['--bind', str(workdir), '/work'] if workdir
                  else ['--dir', '/work'])
    sandbox = ['--unshare-all', '--share-net', '--die-with-parent']
    if new_session:
        sandbox.append('--new-session')
    return ['/usr/sbin/ip', 'netns', 'exec', name, '/usr/bin/setpriv',
            '--reuid', str(uid), '--regid', str(gid), '--init-groups',
            '--bounding-set=-all', '--no-new-privs',
            '/usr/bin/bwrap', *sandbox,
            '--clearenv', '--setenv', 'PATH', '/usr/bin:/bin',
            '--setenv', 'HOME', '/tmp', '--setenv', 'LC_ALL', 'C',
            '--tmpfs', '/', '--ro-bind', '/usr', '/usr',
            '--ro-bind-try', '/bin', '/bin', '--ro-bind-try', '/lib', '/lib',
            '--ro-bind-try', '/lib64', '/lib64', '--dir', '/etc',
            '--ro-bind-try', '/etc/alternatives', '/etc/alternatives',
            '--ro-bind-try', '/etc/ld.so.cache', '/etc/ld.so.cache',
            '--ro-bind-try', '/etc/ssl/certs', '/etc/ssl/certs',
            '--ro-bind-try', '/etc/hosts', '/etc/hosts',
            '--proc', '/proc', '--dev', '/dev', '--dir', '/tmp',
            *work_mount, *extra, '--chdir', '/work', '--', *args]


def privileged_scan_command(name, args, workdir):
    """Fixed Nmap profiles only. CAP_NET_RAW in the task netns, no user namespace.

    The readonly workspace prevents root-owned agent output. DAC_OVERRIDE only
    permits traversal of the owner's 0700 workspace; every host mount is readonly.
    Generic exec, PoC and sessions keep their existing unprivileged builder.
    """
    if (args[0] != '/usr/bin/nmap' or '--datadir' not in args or
            any(arg in args for arg in ('--script', '-iL', '-oN', '-oX', '-oA'))):
        raise ValueError('Only fixed Nmap profiles support privileged execution')
    return ['/usr/sbin/ip', 'netns', 'exec', name, '/usr/bin/bwrap',
            '--unshare-pid', '--unshare-ipc', '--unshare-uts', '--unshare-cgroup-try',
            '--die-with-parent', '--new-session', '--cap-drop', 'ALL',
            '--cap-add', 'CAP_NET_RAW', '--cap-add', 'CAP_DAC_OVERRIDE',
            '--clearenv', '--setenv', 'PATH', '/usr/bin:/bin', '--setenv', 'HOME', '/tmp',
            '--setenv', 'LC_ALL', 'C', '--tmpfs', '/', '--ro-bind', '/usr', '/usr',
            '--ro-bind-try', '/bin', '/bin', '--ro-bind-try', '/lib', '/lib',
            '--ro-bind-try', '/lib64', '/lib64', '--dir', '/etc',
            '--ro-bind-try', '/etc/ld.so.cache', '/etc/ld.so.cache',
            '--proc', '/proc', '--remount-ro', '/proc', '--dev', '/dev', '--dir', '/tmp',
            '--ro-bind', str(workdir), '/work', '--chdir', '/work', '--', *args]


def task_workdir(task, config):
    """Persistent workspace for a task, owned by the sandbox user.

    The parent stays root-owned 0700 and the leaf is checked to be a real
    directory owned by the task user, so the bind source cannot be replaced
    with a symlink pointing somewhere else.
    """
    parent = WORK_BASE.parent
    parent.mkdir(parents=True, exist_ok=True, mode=0o755)
    WORK_BASE.mkdir(parents=True, exist_ok=True, mode=0o711)
    parent_stat = parent.stat()
    base_stat = WORK_BASE.stat()
    if parent_stat.st_uid != 0 or not parent_stat.st_mode & 0o001:
        raise RuntimeError('Unsafe work parent ownership or mode')
    if base_stat.st_uid != 0 or (base_stat.st_mode & 0o022):
        raise RuntimeError('Unsafe work base ownership or mode')
    path = WORK_BASE / str(task)
    if path.is_symlink():
        raise RuntimeError('Task work directory must not be a symlink')
    if not path.exists():
        path.mkdir(mode=0o700)
        os.chown(path, config['uid'], config['gid'])
    leaf = path.stat()
    if not stat.S_ISDIR(leaf.st_mode):
        raise RuntimeError('Task work path is not a directory')
    if leaf.st_uid != config['uid'] or (leaf.st_mode & 0o077):
        raise RuntimeError('Task work directory has unsafe owner or mode')
    return path


def workdir_init(task):
    """Create only the task owner's workspace using the existing safety checks."""
    ensure_root()
    _, config = owned_config(task)
    sudo_uid = os.environ.get('SUDO_UID')
    if sudo_uid is not None and int(sudo_uid) != config['uid']:
        raise ValueError('Invoker is not the configured task owner')
    path = task_workdir(task, config)
    return {'status': 'ready', 'task_id': task, 'workdir': str(path)}


def resolve_research_host(host):
    """Resolve a fixed research domain on the host and pin it into the nft set."""
    infos = socket.getaddrinfo(host, RESEARCH_PORT, socket.AF_INET, socket.SOCK_STREAM)
    addresses = list(dict.fromkeys(info[4][0] for info in infos))
    if not addresses:
        raise RuntimeError(f'No address resolved for {host}')
    for raw in addresses[:RESEARCH_MAX_IPS]:
        ip = ipaddress.ip_address(raw)
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast:
            raise ValueError(f'{host} resolved to a non-public address')
    return addresses[0]


def research_allow(v, ip):
    cmd('/usr/sbin/nft', 'add', 'element', 'inet', v['table'], 'research_ips',
        '{', ip, 'timeout', RESEARCH_TTL, '}')


def route_egress_interface(ip):
    """Find the interface the host would really use to reach a public address.

    The task namespace egress is usually the VPN interface, which only carries
    the lab scope. Research lookups follow the host's own default route, so the
    masquerade rule must target whatever device that route selects.
    """
    p = cmd('/usr/sbin/ip', '-6' if ipaddress.ip_address(ip).version==6 else '-4', 'route', 'get', ip, check=False)
    if p.returncode:
        raise RuntimeError(f'No route to {ip}: {p.stderr[-300:]}')
    words = p.stdout.split()
    for index, word in enumerate(words):
        if word == 'dev' and index + 1 < len(words):
            device = words[index + 1]
            if re.fullmatch(r'[a-zA-Z0-9_.-]{1,15}', device):
                return device
    raise RuntimeError(f'Cannot determine egress device for {ip}')


class EgressError(RuntimeError):
    pass


def ensure_target_egress(v, config, target):
    """Move this task's exact-target forwarding rule to the live host route."""
    current = config.get('current_egress', config['egress'])
    if current == 'auto':
        return config
    try:
        actual = route_egress_interface(target)
        if actual == current:
            return config
        allowed = config['allowed']
        if len(allowed) != 1 or ipaddress.ip_network(allowed[0]).num_addresses != 1:
            raise EgressError('Automatic egress repair requires one exact address')
        family='ip6' if ipaddress.ip_address(target).version==6 else 'ip'
        peer=v['peer6'] if family=='ip6' else v['peerip']
        nat_table=v['nat6'] if family=='ip6' else v['nat']
        old = current
        chain = cmd('/usr/sbin/nft', '-a', 'list', 'chain', 'inet', v['table'], 'forward').stdout
        old_rule = next((line for line in chain.splitlines()
                         if f'iifname "{v["host"]}"' in line
                         and f'oifname "{old}"' in line
                         and family+' daddr' in line and 'accept' in line), None)
        handle = re.search(r'# handle (\d+)', old_rule or '')
        if not handle:
            raise EgressError('Scoped forwarding rule is missing; refusing repair')
        destination = allowed[0]
        new_docker = []
        if task_docker_families(config):
            if not config.get('docker_forward_managed'):
                raise EgressError('Docker forwarding is not managed for this task')
            new_docker = add_docker_rules(docker_forward_rules(v, config, actual),
                                          adopt_existing=True)
        try:
            cmd('/usr/sbin/nft', 'replace', 'rule', 'inet', v['table'], 'forward',
                'handle', handle.group(1), 'iifname', v['host'], family, 'saddr',
                peer, family, 'daddr', destination, 'oifname', actual, 'accept')
            nat = cmd('/usr/sbin/nft', 'list', 'table', family, nat_table).stdout
            if f'oifname "{actual}" masquerade' not in nat:
                cmd('/usr/sbin/nft', 'add', 'rule', family, nat_table, 'postrouting',
                    family, 'saddr', peer, family, 'daddr', destination,
                    'oifname', actual, 'masquerade')
            updated = dict(config, approved_egress=config.get('approved_egress',
                                                              config['egress']),
                           current_egress=actual)
            replace_config(v, updated)
        except BaseException:
            remove_docker_rules(new_docker)
            raise
        if task_docker_families(config):
            remove_docker_rules(docker_forward_rules(v, config, old))
        return updated
    except (ValueError, RuntimeError, OSError, subprocess.SubprocessError) as exc:
        raise EgressError(f'Egress repair failed for {target}: {exc}') from exc


def verify_target_egress(config, target):
    current = config.get('current_egress', config['egress'])
    if current == 'auto':
        return
    try:
        actual = route_egress_interface(target)
    except (RuntimeError, OSError, subprocess.SubprocessError) as exc:
        raise EgressError(f'Host route unavailable for {target}: {exc}') from exc
    if actual != current:
        raise EgressError('Host route changed again during egress repair')


def research_docker_rules(v, ip, egress):
    """Mirror the research flow into DOCKER-USER when FORWARD is DROP.

    The nftables early hook stays the authoritative gate: this iptables pair
    only lets one pinned source/destination/port combination past Docker's
    policy DROP, and the nft set entry that permits it expires on its own.
    """
    destination = f'{ip}/32'
    forward = ['-i', v['host'], '-o', egress,
               '-s', v['peerip'] + '/32', '-d', destination,
               '-p', 'tcp', '--dport', str(RESEARCH_PORT), '-j', 'ACCEPT']
    reverse = ['-i', egress, '-o', v['host'],
               '-s', destination, '-d', v['peerip'] + '/32',
               '-p', 'tcp', '--sport', str(RESEARCH_PORT),
               '-m', 'conntrack', '--ctstate', 'ESTABLISHED,RELATED', '-j', 'ACCEPT']
    return [forward, reverse]


def ensure_research_egress(v, ip, config=None):
    """Add the research plumbing to namespaces created by an older broker.

    Older releases carried only the task-scope rules, so a live namespace can
    lack the research set, its forward accept rule and the research
    masquerade. Each object is added only when absent. The set is created
    empty, so on its own this never widens reachability beyond the task scope;
    only an explicit research lookup pins one resolved address with a TTL.
    """
    added = []
    p = cmd('/usr/sbin/nft', 'add', 'set', 'inet', v['table'], 'research_ips',
            '{', 'type', 'ipv4_addr;', 'flags', 'timeout;', '}', check=False)
    if p.returncode:
        if 'File exists' not in (p.stderr or ''):
            raise RuntimeError(f'nft add set failed: {p.stderr[-600:]}')
    else:
        added.append('research-set')

    forward = cmd('/usr/sbin/nft', 'list', 'chain', 'inet', v['table'],
                  'forward', check=False)
    if forward.returncode:
        raise RuntimeError(f'nft list forward failed: {forward.stderr[-600:]}')
    if '@research_ips' not in (forward.stdout or ''):
        # insert = prepend, so the verdict precedes this task's egress drops.
        cmd('/usr/sbin/nft', 'insert', 'rule', 'inet', v['table'], 'forward',
            'ip', 'saddr', v['peerip'], 'ip', 'daddr', '@research_ips',
            'tcp', 'dport', str(RESEARCH_PORT), 'accept')
        added.append('research-forward-rule')

    egress = route_egress_interface(ip)
    nat = cmd('/usr/sbin/nft', 'list', 'table', 'ip', v['nat'], check=False)
    if nat.returncode:
        raise RuntimeError(f'nft list nat failed: {nat.stderr[-600:]}')
    if f'oifname "{egress}" masquerade' not in (nat.stdout or ''):
        cmd('/usr/sbin/nft', 'add', 'rule', 'ip', v['nat'], 'postrouting',
            'ip', 'saddr', v['peerip'], 'oifname', egress, 'masquerade')
        added.append(f'research-masquerade:{egress}')

    if docker_policy_drops_forward():
        pending = [rule for rule in research_docker_rules(v, ip, egress)
                   if not docker_rule_exists(rule)]
        if pending:
            recorded = list(config.get('research_forward_rules', []))
            inserted = add_docker_rules(pending)
            try:
                replace_config(v, dict(config, research_forward_rules=recorded + inserted))
            except BaseException:
                remove_docker_rules(inserted)
                raise
            added.append(f'docker-forward:{egress}')
    return added


def poc_stdin(stdin_file,poc_file,uid,gid,workdir):
    if Path(stdin_file).parent.resolve()!=Path(poc_file).parent.resolve():raise ValueError('stdin must belong to the same task source directory')
    source=safe_payload_path(stdin_file,uid);directory=workdir/'poc'
    try:directory.mkdir(mode=0o700);os.chown(directory,uid,gid)
    except FileExistsError:pass
    directory_fd=os.open(directory,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    temporary='.stdin-'+os.urandom(12).hex();total=0;digest=hashlib.sha256()
    try:
        info=os.fstat(directory_fd)
        if info.st_uid!=uid or info.st_mode&0o077:raise ValueError('Unsafe stdin directory')
        source_fd=os.open(source,os.O_RDONLY|os.O_NOFOLLOW)
        try:
            info=os.fstat(source_fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid!=uid or info.st_nlink!=1 or info.st_mode&0o022:raise ValueError('Unsafe stdin file')
            target_fd=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=directory_fd)
            try:
                os.fchown(target_fd,uid,gid)
                while block:=os.read(source_fd,65536):
                    total+=len(block)
                    if total>POC_MAX_BYTES:raise ValueError('stdin exceeds explicit file bound')
                    digest.update(block)
                    while block:block=block[os.write(target_fd,block):]
                os.fsync(target_fd)
            finally:os.close(target_fd)
        finally:os.close(source_fd)
        name='stdin-'+digest.hexdigest()[:32]+'.txt'
        os.replace(temporary,name,src_dir_fd=directory_fd,dst_dir_fd=directory_fd)
        return {'local':directory/name,'poc_sha256':digest.hexdigest(),'poc_bytes':total}
    finally:
        try:os.unlink(temporary,dir_fd=directory_fd)
        except FileNotFoundError:pass
        os.close(directory_fd)


def operation_timeout(profile,timeout,reason=''):
    value=EXEC_TIMEOUT if timeout is None else int(timeout)
    if not 5<=value<=600:raise ValueError('Operation timeout must be 5..600 seconds')
    baseline=180 if profile=='exec' else 300
    if value>baseline and (not isinstance(reason,str) or not reason.strip() or len(reason)>1000):
        raise ValueError('A long operation needs a concrete bounded purpose (operation_reason)')
    return value


def run(task, profile, target, port, ports, scheme, path="/", hostname="",
        capture_limit=HTTP_CAPTURE_BODY_LIMIT, argv=None, poc_file=None,
        poc_interp='bash', research_host='', timeout=None,ssrf_destination='',ssrf_context='',ssrf_parameter='url',operation_reason='',stdin_file=''):
    ensure_root()
    v, config = owned_config(task)
    sudo_uid = os.environ.get('SUDO_UID')
    if sudo_uid is not None and int(sudo_uid) != config['uid']:
        raise ValueError('Invoker is not the configured task owner')
    policy=config.get('resource_policy')
    if profile.startswith(('http','https')):path=safe_http_path(path)
    if profile!='research':
        operation='ssrf' if ssrf_destination else 'http' if profile.startswith(('http','https')) else profile
        authorize_resource(policy,operation,target,scheme=scheme,hostname=hostname,port=port,path=path,
                           destination=ssrf_destination,context=ssrf_context)
        if ssrf_destination:
            if profile!='http_capture' or not re.fullmatch(r'[A-Za-z][A-Za-z0-9_.-]{0,63}',ssrf_parameter):raise ValueError('Unsupported SSRF request')
            from urllib.parse import parse_qsl
            if any(key==ssrf_parameter for key,_ in parse_qsl(urlsplit(path).query)):raise ValueError('Ambiguous duplicate SSRF parameter')
            if not policy:raise ValueError('SSRF requires explicit resource policy')
            path=safe_http_path(path)+('&' if '?' in path else '?')+urlencode({ssrf_parameter:resource_url(ssrf_destination)['request_url']})
    if isinstance(timeout, str) and timeout.isdigit():
        timeout = int(timeout)
    extra = ()
    workdir = None
    poc_details = None
    stdin_details=None
    check_egress = True
    if profile == 'research':
        # Fixed allowlist only. The resolved address is pinned in the nft set
        # with a TTL, so this cannot be used as a general egress bypass.
        host = (research_host or '').strip().lower()
        if host not in RESEARCH_DOMAINS:
            raise ValueError('Host is not in the fixed research allowlist')
        target = resolve_research_host(host)
        ensure_research_egress(v, target, config)
        research_allow(v, target)
        rpath = safe_research_path(path)
        args = ['/usr/bin/curl', '--silent', '--show-error', '--noproxy', '*',
                '--proto', '=https', '--max-redirs', '0', '--connect-timeout', '5',
                '--max-time', '25', '--max-filesize', '262144',
                '--resolve', f'{host}:{RESEARCH_PORT}:{target}', '--',
                f'https://{host}:{RESEARCH_PORT}{rpath}']
        run_timeout, stdout_limit = 45, 262144
        check_egress = False
    elif profile in ('exec', 'poc_run'):
        target = check_target(target, config['allowed'])
        # Files persist between calls: /work is the task's own directory.
        workdir = task_workdir(task, config)
        if profile == 'exec':
            args = safe_exec_argv(argv)
            binary = (workdir / args[0].removeprefix('/work/')) if args[0].startswith('/work/') else Path(args[0])
            if not binary.is_file() or not os.access(binary, os.X_OK):
                output({'operation': 'network_probe_isolated', 'task_id': task,
                        'profile': profile, 'target': target, 'status': 'error',
                        'kind': 'tool_missing', 'reason_category': 'tool_missing', 'error': f'Executable unavailable: {args[0]}',
                        'exit_code': None, 'nonzero_exit': False})
                return
        else:
            built = poc_argv(poc_file, poc_interp, config['uid'], config['gid'], workdir)
            args = built['argv']
            poc_details = built
            if stdin_file:stdin_details=poc_stdin(stdin_file,poc_file,config['uid'],config['gid'],workdir)
        run_timeout = operation_timeout(profile,timeout,operation_reason)
        stdout_limit = 120000
    else:
        target = check_target(target, config['allowed'])
        if profile in ('http_path', 'http_document', 'http_capture'):
            # Domain mapping is strictly per-task and points to the same /32 target.
            approved_hosts = config.get('hostnames', [])
            if not policy and hostname and hostname != target and hostname not in approved_hosts:
                raise ValueError('Hostname not approved for this NetGuard task')
        args = tool_args(profile, target, port, ports, scheme, path, hostname, capture_limit)
        run_timeout = 250 if profile == 'tcp_full' else 48
        stdout_limit = 8*1024*1024 if profile=='tcp_full' else 270336 if profile == 'http_document' else 24000
    if profile not in ('exec', 'poc_run') and not Path(args[0]).is_file():
        output({'status': 'error', 'kind': 'tool_missing', 'reason_category': 'tool_missing',
                'error': f'Executable unavailable: {args[0]}', 'task_id': task,
                'profile': profile, 'target': target, 'exit_code': None})
        return
    if profile in RAW_SCAN_PROFILES:
        binary = Path(args[0]).stat()
        if binary.st_uid != 0 or binary.st_mode & 0o022:
            raise PermissionError('Privileged Nmap requires a root-owned non-writable binary')
        workdir = task_workdir(task, config)
    if check_egress:
        config = ensure_target_egress(v, config, target)
        verify_target_egress(config, target)
    # Require firewall tables still present, otherwise fail closed.
    families=task_docker_families(config)
    if families:
        if not config.get('docker_forward_managed'):
            raise EgressError('Docker FORWARD DROP requires sync-forward --task-id N')
        rules = docker_forward_rules(v, config)
        if not all(docker_rule_exists(rule) for rule in rules) or set(families)-set(config.get('docker_families',[4])):
            raise EgressError('Task-specific Docker forwarding rules missing; refusing run')
    cmd('/usr/sbin/nft', 'list', 'table', 'inet', v['table'])
    cmd('/usr/sbin/nft', 'list', 'table', 'ip', v['nat'])
    if profile == 'http_capture':
        spec=http_spec({'method':'GET','target':target,'scheme':scheme,'hostname':hostname or target,'port':int(port),
            'path':path,'headers':[],'body_b64':'','session_id':'legacy','limit_bytes':capture_limit,
            'timeout':25,'tls_verify':True,'ssrf':None})
        captured=http_process(v,config,spec)
        wire=base64.b64decode(captured['headers_b64'])+base64.b64decode(captured['body_b64'])
        data={'status':'completed' if captured['transport_complete'] else 'incomplete',
              'exit_code':0 if captured['transport_complete'] else 63 if captured['body_truncated'] else 1,
              'response_b64':base64.b64encode(wire).decode(),'response_bytes':len(wire),
              'capture_truncated':captured['body_truncated'],'elapsed_seconds':captured['elapsed_seconds']}
        output({'operation': 'network_probe_isolated', 'capture_protocol': 1,
                'task_id': task, 'target': target, 'profile': profile,
                'port': int(port), 'scheme': scheme, 'path': path, 'hostname': hostname or target,
                'sandbox': 'netns+nft+bubblewrap', **data})
        return
    # Strictly bounded runtime and output (including potentially malicious service strings).
    started = time.monotonic()
    timed_out = False
    input_handle=None
    try:
        if stdin_details:input_handle=os.fdopen(os.open(stdin_details['local'],os.O_RDONLY|os.O_NOFOLLOW),'rb')
        process = subprocess.Popen(
            privileged_scan_command(v['name'], args, workdir) if profile in RAW_SCAN_PROFILES else
            isolated_command(v['name'], config['owner'], config['uid'], config['gid'], args, extra, workdir=workdir),
            stdin=input_handle or subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, errors='replace', start_new_session=True)
    except OSError as exc:
        if input_handle:input_handle.close()
        output({'operation': 'network_probe_isolated', 'task_id': task,
                'profile': profile, 'target': target, 'status': 'error',
                'kind': 'permission_denied' if isinstance(exc, PermissionError) else 'executor_unavailable',
                'error': str(exc), 'exit_code': None,
                'nonzero_exit': False})
        return
    try:
        stdout, stderr = process.communicate(timeout=run_timeout)
        code = process.returncode
    except subprocess.TimeoutExpired:
        timed_out = True
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        stdout, stderr = process.communicate()
        code = 124
    finally:
        if input_handle:input_handle.close()
    poc_result = {}
    if poc_details is not None:
        poc_result['network_isolated'] = True
        poc_result = {key: poc_details[key] for key in
                      ('poc_sha256', 'poc_bytes', 'poc_source_flag_literals')}
        poc_result['poc_path'] = args[1]
        if stdin_details:poc_result['stdin_file']={k:stdin_details[k] for k in ('poc_sha256','poc_bytes')}
        try:
            after = poc_file_metadata(poc_details['local'], config['uid'])
            poc_result['poc_changed_during_run'] = (
                after['poc_sha256'] != poc_details['poc_sha256'] or
                after['poc_bytes'] != poc_details['poc_bytes'])
        except (OSError, ValueError):
            poc_result['poc_changed_during_run'] = True
    output({'operation': 'network_probe_isolated', 'task_id': task,
            'profile': profile, 'target': target, 'sandbox': 'netns+nft+bubblewrap',
            'status': 'timeout' if timed_out else 'completed',
            'kind': 'timeout' if timed_out else None,
            'reason_category': 'timeout' if timed_out else 'utility_failed' if code else None,
            'exit_code': code, 'nonzero_exit': code != 0,
            'stdout': stdout[:stdout_limit], 'stderr': stderr[:5000],
            'stdout_truncated': len(stdout) > stdout_limit,
            'stdout_limit': stdout_limit,
            'output_truncated': len(stdout) > stdout_limit or len(stderr) > 5000,
            'executable': Path(args[0]).name,
            'elapsed_seconds': round(time.monotonic() - started, 3),
            **poc_result})


def capture_process(argv, body_limit=None, *, acquisition=False, process_env=None):
    """Drain binary pipes with hard byte/time caps; never buffer unbounded output."""
    started = time.monotonic()
    if body_limit is None:
        body_limit,wire_limit = HTTP_CAPTURE_BODY_LIMIT,HTTP_CAPTURE_WIRE_LIMIT
    else:
        if not (acquisition and type(body_limit) is int and 0 < body_limit <= 256 * 1024 * 1024) and body_limit not in HTTP_CAPTURE_LIMITS:
            raise ValueError('Unsupported HTTP capture limit')
        wire_limit = body_limit + HTTP_HEADER_LIMIT
    try:
        process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, start_new_session=True,
                                   **({'env':process_env} if process_env is not None else {}))
    except OSError as exc:
        return {'status': 'error', 'kind': 'broker', 'error': str(exc),
                'exit_code': None, 'nonzero_exit': False}
    stdout, stderr = bytearray(), bytearray()
    limited = timed_out = stderr_limited = False
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ, 'stdout')
            selector.register(process.stderr, selectors.EVENT_READ, 'stderr')
            while selector.get_map():
                remaining = HTTP_CAPTURE_TIMEOUT - (time.monotonic() - started)
                if remaining <= 0:
                    timed_out = True
                    break
                for key, _ in selector.select(min(remaining, 1)):
                    chunk = os.read(key.fileobj.fileno(), 65536)
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    destination = stdout if key.data == 'stdout' else stderr
                    cap = wire_limit if key.data == 'stdout' else 5000
                    available = cap - len(destination)
                    destination.extend(chunk[:available])
                    if len(chunk) > available:
                        if key.data == 'stdout':
                            limited = True
                            break
                        stderr_limited = True
                if limited:
                    break
        if not limited and not timed_out:
            try:
                process.wait(timeout=max(0.001, HTTP_CAPTURE_TIMEOUT - (time.monotonic() - started)))
            except subprocess.TimeoutExpired:
                timed_out = True
    finally:
        # Kill the group even if its parent exited but a child holds a pipe.
        if process.poll() is None or limited or timed_out:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        process.wait()
        process.stdout.close()
        process.stderr.close()
    code = 124 if timed_out else 63 if limited else process.returncode
    return {'status': 'timeout' if timed_out else 'completed',
            'kind': 'timeout' if timed_out else None,
            'exit_code': code, 'nonzero_exit': code != 0,
            'response_b64': base64.b64encode(stdout).decode('ascii'),
            'response_bytes': len(stdout), 'capture_limit_bytes': body_limit,
            'wire_limit_bytes': wire_limit, 'capture_truncated': limited,
            'stderr': stderr.decode('utf-8', errors='replace'), 'stderr_truncated': stderr_limited,
            'elapsed_seconds': round(time.monotonic() - started, 3)}


def http_spec(raw):
    fields={'method','target','scheme','hostname','port','path','headers','body_b64','session_id','limit_bytes','timeout','tls_verify','ssrf'}
    if not isinstance(raw,dict) or set(raw) not in (fields,fields|{'proxy'}):raise ValueError('Invalid HTTP request schema')
    spec=dict(raw)
    if spec.get('proxy') not in (None,'burp'):raise ValueError('Unsupported HTTP proxy')
    if not isinstance(spec['method'],str) or not re.fullmatch(r'[A-Z][A-Z0-9-]{0,31}',spec['method']) or spec['method']=='CONNECT':raise ValueError('Unsupported HTTP method/tunnel')
    spec['target']=str(ipaddress.ip_address(spec['target']))
    parsed=resource_url(http_origin(spec['scheme'],spec['hostname'],spec['port'])+spec['path'])
    if parsed['scheme']!=spec['scheme'] or parsed['host']!=spec['hostname'] or parsed['port']!=spec['port']:raise ValueError('Invalid HTTP authority')
    spec['path']=safe_http_path(spec['path'])
    if not re.fullmatch(r'[A-Za-z0-9_.-]{1,64}',spec['session_id']):raise ValueError('Invalid HTTP session')
    if spec['limit_bytes'] not in HTTP_CAPTURE_LIMITS or type(spec['timeout']) is not int or not 1<=spec['timeout']<=30:raise ValueError('Invalid HTTP budget')
    if type(spec['tls_verify']) is not bool:raise ValueError('Invalid TLS verification setting')
    if not isinstance(spec['headers'],list) or len(spec['headers'])>200:raise ValueError('Invalid HTTP headers')
    count=0
    single_headers=set()
    for pair in spec['headers']:
        if not isinstance(pair,list) or len(pair)!=2 or not all(isinstance(v,str) for v in pair):raise ValueError('Header must be a name/value pair')
        name,value=pair
        if not re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+",name) or any(ord(c)<32 and c!='\t' or ord(c)==127 for c in value):raise ValueError('Invalid HTTP header characters')
        if name.lower() in ('host','content-length','transfer-encoding','connection','expect','upgrade','proxy-authorization','x-pentest-master-scope'):raise ValueError('Use URL authority and supported body framing')
        if name.lower() in ('content-type','authorization','cookie'):
            if name.lower() in single_headers:raise ValueError('Ambiguous duplicate request header')
            single_headers.add(name.lower())
        count+=len(name.encode('ascii'))+len(value.encode('latin-1'))+4
    if count>HTTP_HEADER_LIMIT:raise ValueError('Request headers exceed 1 MiB')
    if not isinstance(spec['body_b64'],str) or len(spec['body_b64'])>((8*1024*1024+2)//3)*4:raise ValueError('Request body exceeds 8 MiB')
    body=base64.b64decode(spec['body_b64'],validate=True)
    if len(body)>8*1024*1024:raise ValueError('Request body exceeds 8 MiB')
    authority=('['+spec['hostname']+']' if ':' in spec['hostname'] else spec['hostname'])+':'+str(spec['port'])
    overhead=len((spec['method']+' '+spec['path']+' HTTP/1.1\r\nHost: '+authority+'\r\nConnection: close\r\n\r\n').encode('ascii'))
    if body or spec['method'] in ('POST','PUT','PATCH'):overhead+=len('Content-Length: '+str(len(body))+'\r\n')
    if count+overhead>HTTP_HEADER_LIMIT:raise ValueError('Total request headers exceed 1 MiB')
    path=spec['path']
    for _ in range(8):
        if spec['method'] not in ('GET','HEAD','OPTIONS') and re.search(r'(?i)(?:change|reset|set)[_-]?pass(?:word)?|pass(?:word)?[_-]?(?:change|reset|set)',path):raise ValueError('Room rule: password changes are prohibited')
        decoded=unquote(path)
        if decoded==path:break
        path=decoded
    query_names=[k for k,v in parse_qsl(urlsplit(spec['path']).query)]
    if any(re.fullmatch(r'(?i)new[_-]?pass(?:word)?|password_confirmation|change_password|set_password',name) for name in query_names):raise ValueError('Room rule: password changes are prohibited')
    if spec['method'] not in ('GET','HEAD','OPTIONS'):
        raw_ctype=next((v for k,v in spec['headers'] if k.lower()=='content-type'),'')
        ctype=raw_ctype.lower()
        names=[]
        if ctype.startswith('application/x-www-form-urlencoded'):names=[k for k,v in parse_qsl(body.decode('utf-8',errors='replace'))]
        elif ctype.startswith('application/json'):
            try:
                document=json.loads(body)
                def keys(value,depth=0):
                    if depth>16:return []
                    if isinstance(value,dict):return list(value)+[key for sub in value.values() for key in keys(sub,depth+1)]
                    if isinstance(value,list):return [key for sub in value for key in keys(sub,depth+1)]
                    return []
                names=keys(document)
            except ValueError:pass
        elif ctype.startswith('multipart/form-data'):
            boundary=re.search(r'(?i)boundary="?([^; "]+)',raw_ctype)
            if boundary:
                for part in body.split(boundary[1].encode()):
                    header=part.split(b'\r\n\r\n',1)[0]
                    names.extend(v.decode('utf-8',errors='replace') for v in re.findall(rb'(?i)\bname="([^"]+)"',header))
        if any(re.fullmatch(r'(?i)new[_-]?pass(?:word)?|password_confirmation|change_password|set_password',name) or
               spec['method'] in ('PUT','PATCH') and name.lower() in ('password','passwd') for name in names):raise ValueError('Room rule: password changes are prohibited')
    ssrf=spec['ssrf']
    if ssrf is not None:
        if not isinstance(ssrf,dict) or set(ssrf)!={'destination','context'} or resource_url(ssrf['destination'])['kind']!='url':raise ValueError('Invalid SSRF route declaration')
    return spec


def http_transport(raw,proxy=None):
    """One real HTTP/1.1 exchange, pinned socket + original headers, no redirects.

    Runs as the task user inside its namespace. No writable project imports,
    shell, proxy env, URL cache or automatic retry. The caller controls redirects.
    """
    import http.client
    import ssl
    from email.parser import BytesParser
    spec=http_spec(raw);started=time.monotonic();body=base64.b64decode(spec['body_b64'])
    class WireReader:
        def __init__(self,stream):self.stream=stream;self.raw=bytearray();self.truncated=False
        def keep(self,value):
            available=HTTP_HEADER_LIMIT+spec['limit_bytes']+65536-len(self.raw)
            self.raw.extend(value[:available]);self.truncated=self.truncated or len(value)>available
            return value
        def readline(self,*args):return self.keep(self.stream.readline(*args))
        def read(self,*args):return self.keep(self.stream.read(*args))
        def read1(self,*args):return self.keep(self.stream.read1(*args))
        def __getattr__(self,name):return getattr(self.stream,name)
    class Response(http.client.HTTPResponse):
        def __init__(self,*args,**kw):
            super().__init__(*args,**kw);self.recording=WireReader(self.fp);self.fp=self.recording
        def _read_and_discard_trailer(self):
            size=len(self.raw_headers)
            while True:
                line=self.fp.readline(HTTP_HEADER_LIMIT-size+1);size+=len(line)
                if size>HTTP_HEADER_LIMIT:raise ValueError('HTTP trailers exceed total header limit')
                if not line:raise ValueError('Incomplete HTTP trailers')
                if line in (b'\r\n',b'\n'):return
        def begin(self):
            if self.headers is not None:return
            self.raw_headers=bytearray()
            for _ in range(8):
                line=self.fp.readline(1025);self.raw_headers.extend(line)
                match=re.fullmatch(rb'HTTP/(1\.[01]) ([0-9]{3})([^\r\n]*)\r?\n',line)
                if not match:raise ValueError('Invalid HTTP response status')
                fields=bytearray()
                while True:
                    available=HTTP_HEADER_LIMIT-len(self.raw_headers)
                    line=self.fp.readline(available+1)
                    self.raw_headers.extend(line)
                    if len(self.raw_headers)>HTTP_HEADER_LIMIT:raise ValueError('Response headers exceed 1 MiB')
                    if not line:raise ValueError('Incomplete response headers')
                    if line in (b'\r\n',b'\n'):break
                    fields.extend(line)
                self.status=self.code=int(match[2]);self.reason=match[3].decode('latin-1').strip()
                if self.status not in (100,102,103):break
            else:raise ValueError('Too many interim responses')
            self.version=11 if match[1]==b'1.1' else 10
            self.headers=self.msg=BytesParser(_class=http.client.HTTPMessage).parsebytes(bytes(fields))
            if self.headers.defects:raise ValueError('Malformed HTTP headers')
            self.chunked=self.headers.get('transfer-encoding','').lower()=='chunked';self.chunk_left=None
            self.will_close=self._check_close();self.length=None
            lengths=self.headers.get_all('content-length',[])
            if lengths and (len(set(lengths))!=1 or not lengths[0].isdigit()):raise ValueError('Ambiguous HTTP body framing')
            if lengths and not self.chunked:self.length=int(lengths[0])
            if self.status in (204,304) or 100<=self.status<200 or self._method=='HEAD':self.length=0
            if not self.will_close and not self.chunked and self.length is None:self.will_close=True
    connection_type=http.client.HTTPSConnection if spec['scheme']=='https' else http.client.HTTPConnection
    options={'timeout':spec['timeout']}
    if spec['scheme']=='https':options['context']=ssl.create_default_context() if spec['tls_verify'] else ssl._create_unverified_context()
    connection=connection_type(spec['hostname'],spec['port'],**options)
    connection.response_class=Response
    connection._create_connection=lambda address,timeout,*a,**kw:socket.create_connection((spec['target'],spec['port']),timeout)
    if spec.get('proxy')=='burp':
        if not proxy:raise ValueError('Burp proxy is not configured for this task namespace')
        if spec['scheme']=='https':
            # Numeric CONNECT pins the destination; TLS still uses original SNI.
            def connect_proxy():
                tunnel=http.client.HTTPConnection('127.0.0.1',proxy['port'],timeout=spec['timeout'])
                tunnel.set_tunnel(spec['target'],spec['port']);tunnel.connect()
                context=ssl.create_default_context(cafile=proxy.get('ca')) if spec['tls_verify'] else ssl._create_unverified_context()
                connection.sock=context.wrap_socket(tunnel.sock,server_hostname=spec['hostname']);tunnel.sock=None
            connection.connect=connect_proxy
        else:connection._create_connection=lambda address,timeout,*a,**kw:socket.create_connection(('127.0.0.1',proxy['port']),timeout)
    authority=('['+spec['hostname']+']' if ':' in spec['hostname'] else spec['hostname'])+':'+str(spec['port'])
    headers=[['Host',authority],['Connection','close'],*spec['headers']]
    if spec.get('proxy')=='burp':headers.append(['X-Pentest-Master-Scope',proxy['grant']])
    if body or spec['method'] in ('POST','PUT','PATCH'):headers.append(['Content-Length',str(len(body))])
    destination=spec['path']
    if spec.get('proxy')=='burp' and spec['scheme']=='http':
        address='['+spec['target']+']' if ':' in spec['target'] else spec['target']
        destination=f'http://{address}:{spec["port"]}'+spec['path']
    request=(spec['method']+' '+destination+' HTTP/1.1\r\n'+''.join(k+': '+v+'\r\n' for k,v in headers)+'\r\n').encode('latin-1')+body
    response=None;received=bytearray();head=b'';complete=False;error=None;status=None;limited=False;sent=False
    try:
        connection.connect();connection.sock.sendall(request);sent=True
        response=Response(connection.sock,method=spec['method']);response.begin()
        head=bytes(response.raw_headers);status=response.status
        while True:
            if time.monotonic()-started>spec['timeout']:raise TimeoutError('HTTP deadline')
            chunk=response.read1(min(65536,spec['limit_bytes']+1-len(received)))
            if not chunk:
                complete=response.length in (None,0);break
            received.extend(chunk)
            if len(received)>spec['limit_bytes']:limited=True;break
    except (OSError,ValueError,http.client.HTTPException) as exc:
        error=type(exc).__name__
        if response is not None:head=bytes(getattr(response,'raw_headers',b''))[:HTTP_HEADER_LIMIT]
    finally:
        if response is not None:response.close()
        connection.close()
    return {'http_protocol':1,'request_sha256':tool_digest(spec),'request_b64':base64.b64encode(request).decode(),
        'transport_proxy':spec.get('proxy'),'proxy_instance_id':(proxy or {}).get('instance_id'),
        'proxy_request_nonce':(proxy or {}).get('nonce'),
        'request_write_completed':sent,
        'wire_b64':base64.b64encode(bytes(response.recording.raw) if response else b'').decode(),
        'wire_truncated':response.recording.truncated if response else False,
        'headers_b64':base64.b64encode(head).decode(),'body_b64':base64.b64encode(received[:spec['limit_bytes']]).decode(),
        'status_code':status,'transport_complete':complete and not limited,'body_truncated':limited,
        'error_type':error,'status':'completed' if complete and not limited else 'incomplete',
        'elapsed_seconds':round(time.monotonic()-started,3)}


def http_process(v,config,spec):
    extra=[];proxy=None
    if spec.get('proxy')=='burp':
        settings=config.get('browser',{}).get('burp')
        if not settings:raise ToolError('burp_unavailable','Burp proxy is not configured in this task namespace')
        proxy={'port':settings['proxy_port']}
        health=burp_read(config,v,'/health',{})
        if health.get('protocol')!=3 or health.get('edition')!='PROFESSIONAL' or health.get('guarded_proxy') is not True:raise ToolError('burp_unavailable','Burp Professional bridge v3/guard is unavailable')
        proxy['grant'],proxy['nonce']=burp_grant(spec,burp_token(config));proxy['instance_id']=health['instance_id']
        if settings.get('ca'):
            if hashlib.sha256(Path(settings['ca']).read_bytes()).hexdigest()!=settings['ca_sha256']:raise ValueError('Burp CA changed; operator reconfiguration required')
            extra=['--dir','/run','--ro-bind',settings['ca'],'/run/pm-burp-ca.pem'];proxy['ca']='/run/pm-burp-ca.pem'
    command=isolated_command(v['name'],config['owner'],config['uid'],config['gid'],
        ['/usr/bin/python3','/usr/local/sbin/pm-netguard','http-worker'],extra)
    result=subprocess.run(command,input=json.dumps({'spec':spec,'proxy':proxy} if proxy else spec),text=True,capture_output=True,timeout=spec['timeout']+5)
    payload=json.loads(result.stdout)
    if result.returncode or not isinstance(payload,dict) or payload.get('request_sha256')!=tool_digest(spec):raise ValueError('HTTP worker protocol failure')
    return payload


def http_run(task,raw):
    ensure_root();v,config=owned_config(task);spec=http_spec(raw)
    if int(os.environ.get('SUDO_UID',config['uid']))!=config['uid']:raise PermissionError('Wrong HTTP task owner')
    check_target(spec['target'],config['allowed'])
    policy=config.get('resource_policy');route=spec['ssrf'] or {}
    authorize_resource(policy,'ssrf' if route else 'http',spec['target'],scheme=spec['scheme'],hostname=spec['hostname'],
        port=spec['port'],path=spec['path'],destination=route.get('destination',''),context=route.get('context',''))
    if route and not policy:raise ValueError('SSRF requires explicit resource policy')
    if not policy and spec['hostname']!=spec['target'] and spec['hostname'] not in config.get('hostnames',[]):raise ValueError('Unapproved HTTP hostname')
    config=ensure_target_egress(v,config,spec['target']);verify_target_egress(config,spec['target'])
    if task_docker_families(config) and (not config.get('docker_forward_managed') or
        not all(docker_rule_exists(rule) for rule in docker_forward_rules(v,config))):raise EgressError('Task Docker forwarding rules missing')
    cmd('/usr/sbin/nft','list','table','inet',v['table']);cmd('/usr/sbin/nft','list','table','ip',v['nat'])
    return http_process(v,config,spec)


def burp_grant(spec,token):
    import hmac
    authority=('['+spec['hostname']+']' if ':' in spec['hostname'] else spec['hostname'])+':'+str(spec['port'])
    header={k.lower():value for k,value in spec['headers']};nonce=os.urandom(16).hex()
    payload='\n'.join((spec['method'],spec['target'],str(spec['port']),spec['scheme'],authority,spec['path'],
        hashlib.sha256(base64.b64decode(spec['body_b64'])).hexdigest(),
        hashlib.sha256(header.get('authorization','').encode()).hexdigest(),hashlib.sha256(header.get('cookie','').encode()).hexdigest(),
        nonce,str(int(time.time())+120))).encode()
    return (base64.urlsafe_b64encode(payload).decode().rstrip('=')+'.'+base64.urlsafe_b64encode(hmac.new(token.encode(),payload,hashlib.sha256).digest()).decode().rstrip('='),nonce)


def burp_token(config):
    home=Path(pwd.getpwuid(config['uid']).pw_dir)
    path=home/'.config/pentest-master/burp-bridge.token'
    if path.is_symlink() or not path.is_file():raise ToolError('burp_unavailable','Burp bridge token missing; start the dedicated instance and load the extension')
    info=path.stat()
    if info.st_uid!=config['uid'] or info.st_mode&0o077:raise PermissionError('Unsafe Burp bridge token')
    token=path.read_text().strip()
    if not re.fullmatch(r'[A-Za-z0-9_-]{40,100}',token):raise ValueError('Invalid Burp bridge token')
    return token


def burp_read(config,v,path,params):
    settings=config.get('browser',{}).get('burp')
    if not settings:raise ToolError('burp_unavailable','Task-local Burp proxy/bridge is not configured')
    command=isolated_command(v['name'],config['owner'],config['uid'],config['gid'],
        ['/usr/bin/python3','/usr/local/sbin/pm-netguard','burp-reader'])
    result=subprocess.run(command,input=json.dumps({'port':settings['bridge_port'],'path':path,'params':params,'token':burp_token(config)}),text=True,capture_output=True,timeout=12)
    reply=json.loads(result.stdout)
    if result.returncode or not isinstance(reply,dict):raise ToolError('burp_unavailable','Burp bridge unavailable')
    return reply


def burp_reader(raw):
    if os.geteuid()==0:raise PermissionError('Burp reader must be unprivileged')
    import http.client
    if raw['path'] not in ('/health','/messages'):raise ValueError('Unsupported read-only Burp endpoint')
    conn=http.client.HTTPConnection('127.0.0.1',callback_port(raw['port']),timeout=8)
    try:
        conn.request('GET',raw['path']+('?' +urlencode(raw['params']) if raw['params'] else ''),headers={'X-Pentest-Master-Token':raw['token']})
        response=conn.getresponse();data=response.read(40*1024*1024+1)
        if response.status!=200 or len(data)>40*1024*1024:raise ValueError('Burp read refused or oversized')
        return json.loads(data)
    finally:conn.close()


def burp_status(task,raw):
    session_invoker(task);v,config=owned_config(task)
    action=raw.get('action','status')
    if action=='status':return burp_read(config,v,'/health',{})
    if action!='history':raise ValueError('Burp adapter has no active send endpoint; use scoped HTTP proxy')
    url=resource_url(raw['url']);target=browser_endpoint(config,url)
    after=raw.get('after',0);limit=raw.get('limit',1)
    if type(after) is not int or after<0 or type(limit) is not int or not 1<=limit<=3:raise ValueError('Invalid Burp history range')
    return burp_read(config,v,'/messages',{'host':target,'hostname':url['host'],'port':url['port'],
        'scheme':url['scheme'],'path_prefix':url['path'],'after':after,'limit':limit})


def ip_in_allowed(ip, allowed):
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in ipaddress.ip_network(net) for net in allowed)


def callback_port(raw):
    if not re.fullmatch(r'[0-9]{1,5}', str(raw)):
        raise ValueError('Invalid callback port')
    port = int(raw)
    if port not in CALLBACK_PORTS:
        raise ValueError('Callback port must be 1024..65535')
    return port


def callback_paths(task):
    out = CALLBACK_DIR / f'task_{task}'
    pid = STATE / f'cb{task}'
    return out, pid


def callback_alive(info,task,port):
    pid=info.get('pid',0)
    try:
        if Path(f'/proc/{pid}').stat().st_uid!=os.geteuid():return False
        parts=Path(f'/proc/{pid}/cmdline').read_bytes().decode().split('\0')
        if 'callback' not in parts:return False
        if parts[parts.index('--task-id')+1]!=str(task) or parts[parts.index('--port')+1]!=str(port):return False
        return bool(not info.get('process_birth') or process_birth(pid)==info['process_birth'])
    except (OSError,ValueError,IndexError,UnicodeError):return False


def read_stream(conn, deadline, cap=CALLBACK_MAX_BYTES):
    buffer = bytearray()
    conn.settimeout(10)
    while len(buffer) < cap and time.monotonic() < deadline:
        try:
            chunk = conn.recv(65536)
        except socket.timeout:
            break
        except OSError:
            break
        if not chunk:
            break
        buffer.extend(chunk[:cap - len(buffer)])
    return bytes(buffer)


def log_callback_event(outdir, event):
    """Append one decision line immediately so a blocked callback is visible.

    The listener runs detached and may be killed before it can report totals,
    so every accept/reject is written as it happens instead of only at exit.
    """
    entry = dict(event, at=time.strftime('%Y-%m-%dT%H:%M:%S'),listener_pid=os.getpid(),listener_birth=process_birth(os.getpid()))
    try:
        with (outdir / 'events.jsonl').open('a', encoding='utf-8') as handle:
            handle.write(json.dumps(entry, ensure_ascii=False) + '\n')
    except OSError:
        pass


def callback_selection(task,bind=''):
    if bind:bind=str(ipaddress.ip_address(bind))
    _,config=owned_config(task)
    target=(config.get('resource_policy') or {}).get('addresses',[str(ipaddress.ip_network(config['allowed'][0]).network_address)])[0]
    route=json.loads(cmd('/usr/sbin/ip','-j','route','get',target).stdout)[0]
    override=config.get('callback_override')
    if override:
        address=override['bind'];interface=override['interface'];advertise=override['advertise'];source='operator'
    else:
        interface=route.get('dev','');address=route.get('prefsrc') or route.get('src','');advertise=address;source='route'
        if not re.match(r'^(tun|tap|wg|ppp|vpn)',interface):
            raise ToolError('callback_address_invalid','No unambiguous laboratory VPN route; configure callback address/interface explicitly, never guess NAT/VMware')
    if not address or ipaddress.ip_address(address).is_unspecified:raise ToolError('callback_address_invalid','Current route has no callback source address')
    configured=json.loads(cmd('/usr/sbin/ip','-j','address','show','dev',interface).stdout)
    addresses={entry['local'] for item in configured for entry in item.get('addr_info',[]) if 'local' in entry}
    if address not in addresses:raise ToolError('callback_address_invalid','Callback address is no longer configured; VPN/route changed')
    if bind and bind!=address:raise ToolError('callback_address_invalid','Requested callback address differs from current route/operator override; use callback-config')
    return {'target':target,'bind':address,'advertise':advertise,'interface':interface,'source':source,
            'route_fingerprint':tool_digest({'target':target,'dev':route.get('dev'),'src':route.get('prefsrc') or route.get('src'),
                                           'bind':address,'advertise':advertise})}


def callback_configure(task,address,interface,advertise,reason,variant_limit=None):
    config,_,_=session_invoker(task)
    if not re.fullmatch(r'[A-Za-z0-9_.:-]{1,32}',interface) or not reason.strip():raise ValueError('Interface and operator reason required')
    address=str(ipaddress.ip_address(address));advertise=str(ipaddress.ip_address(advertise or address))
    if ipaddress.ip_address(address).is_unspecified or ipaddress.ip_address(advertise).is_unspecified:raise ValueError('Unspecified callback address is not usable')
    v,_=owned_config(task)
    previous=config.get('callback_override')
    limit=variant_limit if variant_limit is not None else (previous or {}).get('variant_limit',3)
    if type(limit) is not int or not 1<=limit<=10:raise ValueError('Callback variant limit must be 1..10')
    config['callback_override']={'bind':address,'interface':interface,'advertise':advertise,'reason':reason[:1000],'variant_limit':limit}
    # Validate local ownership before persisting, while keeping the saved config unchanged on failure.
    local=json.loads(cmd('/usr/sbin/ip','-j','address','show','dev',interface).stdout)
    if address not in {a['local'] for item in local for a in item.get('addr_info',[])}:raise ValueError('Bind address is absent from the selected interface')
    config.setdefault('callback_override_history',[]).append({'previous':previous,'at':int(time.time()),'reason':reason[:1000]})
    replace_config(v,config)
    return {'status':'configured','callback_override':config['callback_override']}


def stream_transfer(conn,task,config,deadline,*,expected_bytes=None,expected_sha256='',max_bytes=TRANSFER_DEFAULT_BYTES):
    """Bounded memory, measured disk capacity, original file retained on failure."""
    if type(max_bytes) is not int or not 1<=max_bytes<=TRANSFER_MAX_BYTES:raise ValueError('Invalid transfer byte budget')
    if expected_bytes is not None and (type(expected_bytes) is not int or not 0<=expected_bytes<=max_bytes):raise ValueError('Invalid expected size')
    if expected_sha256 and not re.fullmatch(r'[a-f0-9]{64}',expected_sha256):raise ValueError('Invalid transfer SHA256')
    work=task_workdir(task,config);folder=os.open(work,os.O_DIRECTORY|os.O_NOFOLLOW)
    try:
        created=False
        try:os.mkdir('transfers',0o700,dir_fd=folder);created=True
        except FileExistsError:pass
        directory=os.open('transfers',os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=folder)
        if created:os.fchown(directory,config['uid'],config['gid'])
        try:os.mkdir('.transfer-staging',0o700,dir_fd=folder)
        except FileExistsError:pass
        staging=os.open('.transfer-staging',os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=folder)
    finally:os.close(folder)
    identifier=os.urandom(12).hex();name=identifier+'.part';total=0;digest=hashlib.sha256();eof=False;reason='timeout'
    try:
        info=os.fstat(directory)
        if info.st_uid!=config['uid'] or info.st_mode&0o077:raise PermissionError('Unsafe transfer directory')
        info=os.fstat(staging)
        if info.st_uid!=os.geteuid() or info.st_mode&0o077:raise PermissionError('Unsafe private transfer staging')
        fd=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=staging)
        with os.fdopen(fd,'wb',buffering=0) as stream:
            try:
                while time.monotonic()<deadline:
                    conn.settimeout(min(10,max(0.01,deadline-time.monotonic())))
                    chunk=conn.recv(min(65536,max_bytes-total+1))
                    if not chunk:eof=True;reason='eof';break
                    if total+len(chunk)>max_bytes:reason='byte_budget_exhausted';break
                    capacity=os.fstatvfs(stream.fileno())
                    if capacity.f_bavail*capacity.f_frsize<len(chunk)+TRANSFER_RESERVE_BYTES:reason='insufficient_disk_space';break
                    written=stream.write(chunk) or 0;digest.update(chunk[:written]);total+=written
                    if written!=len(chunk):reason='partial_write';break
                stream.flush();os.fsync(stream.fileno())
            except socket.timeout:reason='receive_timeout'
            except OSError as exc:reason='insufficient_disk_space' if exc.errno==28 else 'receive_io_error'
            os.fchown(stream.fileno(),config['uid'],config['gid'])
        actual=digest.hexdigest()
        complete=bool(eof and reason=='eof' and expected_bytes is not None and total==expected_bytes and (not expected_sha256 or actual==expected_sha256))
        if eof and expected_bytes is not None and total!=expected_bytes:reason='size_mismatch'
        elif eof and expected_sha256 and actual!=expected_sha256:reason='hash_mismatch'
        final=identifier+('.bin' if complete else '.part')
        # Publish only after receiving/fsync/hash checks. No agent can alter an
        # in-progress user-owned .part and invalidate the measured stream hash.
        os.link(name,final,src_dir_fd=staging,dst_dir_fd=directory,follow_symlinks=False)
        os.unlink(name,dir_fd=staging);name=final
        return {'transfer_id':identifier,'file':'/work/transfers/'+name,'bytes':total,'sha256':actual,
            'expected_bytes':expected_bytes,'expected_sha256':expected_sha256,'eof':eof,'complete':complete,
            'completeness':'verified_hash_and_size' if complete and expected_sha256 else 'verified_size' if complete else
                           'eof_unverified_size' if eof and expected_bytes is None else 'incomplete','reason':reason}
    finally:os.close(directory);os.close(staging)


def callback_diagnose(task,port):
    session_invoker(task);port=callback_port(port);_,directory=callback_paths(task)
    try:meta=json.loads((directory/f'{port}.pid').read_text())
    except (OSError,ValueError):return {'status':'not_listening','diagnosis':'receiver_unavailable','outbound_restrictions':'unknown'}
    pid=meta.get('pid',0)
    live=callback_alive(meta,task,port)
    try:selection=callback_selection(task)
    except (OSError,ValueError,RuntimeError):selection=None
    if not selection or selection['bind']!=meta.get('bind') or selection['advertise']!=meta.get('advertise'):
        diagnosis='wrong_or_stale_callback_address'
    elif not live:diagnosis='receiver_unavailable'
    else:diagnosis='waiting_no_callback; target_egress_restrictions_possible_not_proven'
    ready=directory/f'{port}.ready'
    try:listening=json.loads(ready.read_text()).get('pid')==pid
    except (OSError,ValueError):listening=False
    if diagnosis.startswith('waiting') and not listening:diagnosis='receiver_not_ready'
    received=[];outdir,_=callback_paths(task)
    try:
        for line in (outdir/'index.jsonl').read_text().splitlines():
            entry=json.loads(line)
            if entry.get('port')==port and entry.get('listener_pid')==pid and entry.get('listener_birth')==meta.get('process_birth'):received.append(entry)
    except (OSError,ValueError):pass
    if diagnosis.startswith('waiting') and received:
        last=received[-1]
        diagnosis=('receiver_session_limit' if last.get('reason')=='session_limit' else
                   'transfer_received_complete' if last.get('complete') else 'transfer_received_unverified_or_incomplete'
                   if last.get('mode')=='transfer' else 'callback_received')
    return {'status':'listening' if live and listening else 'not_listening','selection':selection,
        'diagnosis':diagnosis,'target_network_reachability':'unknown; use saved/current scoped preflight',
        'outbound_restrictions':'possible, not established by silence','listener':meta}


def callback_listen(task, port, bind, timeout,mode='interactive',expected_bytes=None,expected_sha256='',max_bytes=TRANSFER_DEFAULT_BYTES):
    """Detached worker: accepts connections only from the task's own scope."""
    ensure_root()
    v, config = owned_config(task)
    port = callback_port(port)
    outdir, piddir = callback_paths(task)
    outdir.mkdir(parents=True, exist_ok=True, mode=0o700)
    piddir.mkdir(parents=True, exist_ok=True, mode=0o700)
    deadline = time.monotonic() + max(10, min(int(timeout), 3600))
    accepted = rejected = 0
    sock = socket.socket(socket.AF_INET6 if ':' in bind else socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((bind or '0.0.0.0', port))
        sock.listen(8)
        tool_store(piddir/f'{port}.ready',{'pid':os.getpid(),'bind':bind,'port':port})
        sock.settimeout(1.0)
        while time.monotonic() < deadline:
            try:
                conn, peer = sock.accept()
            except socket.timeout:
                continue
            with conn:
                ip = peer[0]
                _,current=owned_config(task)
                if (current.get('resource_policy') or {}).get('area')=='web' or not ip_in_allowed(ip, current['allowed']):
                    rejected += 1
                    log_callback_event(outdir, {'peer': ip, 'port': port,
                                                'decision': 'rejected'})
                    continue
                accepted += 1
                log_callback_event(outdir, {'peer': ip, 'port': port,
                                            'decision': 'accepted'})
                if mode=='transfer':entry=stream_transfer(conn,task,config,deadline,expected_bytes=expected_bytes,expected_sha256=expected_sha256,max_bytes=max_bytes)
                elif mode=='interactive':entry=session_accept(task,conn,ip,port,config)
                else:raise ValueError('Unknown callback mode')
                entry.update(peer=ip,port=port,mode=mode,at=time.strftime('%Y-%m-%dT%H:%M:%S'),
                             listener_pid=os.getpid(),listener_birth=process_birth(os.getpid()))
                with (outdir / 'index.jsonl').open('a', encoding='utf-8') as handle:
                    handle.write(json.dumps(entry, ensure_ascii=False) + '\n')
    finally:
        sock.close()
        (piddir/f'{port}.ready').unlink(missing_ok=True)
        try:
            (piddir / f'{port}.pid').unlink()
        except FileNotFoundError:
            pass
    return {'status': 'listener_exit', 'task_id': task, 'port': port,
            'accepted': accepted, 'rejected_peers': rejected}


def callback_open(task, port, bind, timeout,mode='interactive',expected_bytes=None,expected_sha256='',max_bytes=TRANSFER_DEFAULT_BYTES):
    ensure_root()
    v, config = owned_config(task)
    session_invoker(task)
    if (config.get('resource_policy') or {}).get('area')=='web':raise ValueError('Web scope does not authorize a host callback listener')
    port = callback_port(port)
    if mode not in ('interactive','transfer'):raise ValueError('Unsupported callback mode')
    if mode=='transfer':
        if type(max_bytes) is not int or not 1<=max_bytes<=TRANSFER_MAX_BYTES:raise ValueError('Invalid transfer budget')
        if expected_bytes is not None and (type(expected_bytes) is not int or not 0<=expected_bytes<=max_bytes):raise ValueError('Invalid expected file size')
        if expected_sha256 and not re.fullmatch(r'[a-f0-9]{64}',expected_sha256):raise ValueError('Invalid expected file hash')
    selection=callback_selection(task,bind);bind=selection['bind']
    if bind:
        addr = ipaddress.ip_address(bind)
        if addr.is_multicast or addr.is_unspecified:
            raise ValueError('Invalid bind address')
    if not config['allowed']:
        raise ValueError('Task has no allowed scope')
    self_path = os.path.realpath(sys.argv[0])
    if not self_path.startswith(('/usr/local/sbin/', '/usr/sbin/')):
        raise RuntimeError('Listener must be started from the installed broker')
    outdir, piddir = callback_paths(task)
    outdir.mkdir(parents=True, exist_ok=True, mode=0o700)
    piddir.mkdir(parents=True, exist_ok=True, mode=0o700)
    pidfile = piddir / f'{port}.pid'
    if pidfile.exists():
        try:
            info=json.loads(pidfile.read_text());old = int(info.get('pid'))
        except (ValueError, OSError, TypeError,AttributeError):
            raise ToolError('outcome_unknown','Callback listener state is unreadable; inspect it before reopening')
        if callback_alive(info,task,port):
            current=json.loads(pidfile.read_text())
            if (current.get('bind')==bind and current.get('mode')==mode and current.get('advertise')==selection['advertise']
                    and (mode!='transfer' or (current.get('expected_bytes'),current.get('expected_sha256'),current.get('max_bytes'))==
                         (expected_bytes,expected_sha256,max_bytes))):return {'status':'listening','already_running':True,**current}
            raise ValueError('Existing callback has different conditions; close it explicitly')
        pidfile.unlink(missing_ok=True)
    attempts=outdir/'open_attempts.jsonl'
    if mode=='interactive':
        previous=[]
        if attempts.exists():
            for line in attempts.read_text().splitlines():
                try:previous.append(json.loads(line))
                except ValueError:raise ValueError('Callback attempt journal is damaged; operator review required')
        if sum(a['route_fingerprint']==selection['route_fingerprint'] for a in previous)>=config.get('callback_override',{}).get('variant_limit',3):
            raise ToolError('callback_budget_exhausted','callback_variant_budget_exhausted: diagnose routing/listener/network before another attempt')
        with attempts.open('a') as stream:stream.write(json.dumps({**selection,'port':port,'at':int(time.time())})+'\n')
    argv = [self_path, 'callback', '--action', 'listen', '--task-id', str(task),
            '--port', str(port), '--timeout', str(int(timeout)),'--mode',mode,'--max-bytes',str(max_bytes)]
    if expected_bytes is not None:argv+=['--expected-bytes',str(expected_bytes)]
    if expected_sha256:argv+=['--expected-sha256',expected_sha256]
    if bind:
        argv += ['--bind', bind]
    ready=piddir/f'{port}.ready';ready.unlink(missing_ok=True)
    with (outdir / 'listener.log').open('ab') as log:
        process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=log,
                                  stderr=log, start_new_session=True,
                                  env={'PATH': '/usr/bin:/bin', 'HOME': '/root', 'LC_ALL': 'C'})
    pidfile.write_text(json.dumps({'pid': process.pid, 'process_birth':process_birth(process.pid),'port': port,**selection,'mode':mode,
                                   'expected_bytes':expected_bytes,'expected_sha256':expected_sha256,'max_bytes':max_bytes,
                                   'scope': config['allowed'],
                                   'expires': int(time.time() + int(timeout))}))
    def is_ready():
        try:return json.loads(ready.read_text()).get('pid')==process.pid
        except (OSError,ValueError):return False
    for _ in range(60):
        if is_ready() or process.poll() is not None:break
        time.sleep(0.05)
    if not is_ready():return {'status':'error','reason_category':'receiver_unavailable','error':'Callback worker did not bind its socket','selection':selection}
    return {'status': 'listening', 'task_id': task, 'port': port,
            **selection,'mode':mode, 'pid': process.pid,
            'accepts_from': config['allowed'], 'timeout': int(timeout),
            'output_dir': str(outdir)}


def callback_read(task, since=None, limit=50):
    ensure_root()
    v, config = owned_config(task)
    outdir, _ = callback_paths(task)
    entries = []
    index = outdir / 'index.jsonl'
    if index.exists():
        for line in index.read_text(errors='replace').splitlines()[-max(1, limit):]:
            try:
                entry = json.loads(line)
            except ValueError:
                continue
            if since and str(entry.get('at', '')) < str(since):
                continue
            entries.append(entry)
    # Connection decisions (including rejected peers) so a silent listener is
    # distinguishable from a listener that was never called at all.
    events = []
    events_file = outdir / 'events.jsonl'
    if events_file.exists():
        for line in events_file.read_text(errors='replace').splitlines()[-max(1, limit):]:
            try:
                event = json.loads(line)
            except ValueError:
                continue
            if since and str(event.get('at', '')) < str(since):
                continue
            events.append(event)
    return {'status': 'ok', 'task_id': task, 'entries': entries,
            'count': len(entries), 'events': events, 'event_count': len(events),
            'sessions':session_list(task)['sessions'],
            'output_dir': str(outdir)}


def callback_close(task, port=None):
    ensure_root()
    v, config = owned_config(task)
    _, piddir = callback_paths(task)
    killed = []
    for path in sorted(piddir.glob('*.pid')):
        if port and path.stem != str(callback_port(port)):
            continue
        try:
            info = json.loads(path.read_text())
        except (ValueError, OSError):
            info = {}
        pid = int(info.get('pid') or 0)
        if pid:
            try:
                cmdline = Path(f'/proc/{pid}/cmdline').read_bytes().decode('utf-8', 'replace')
            except OSError:
                cmdline = ''
            if callback_alive(info,task,path.stem):
                try:
                    os.kill(pid, signal.SIGTERM)
                    killed.append(pid)
                except ProcessLookupError:
                    pass
        path.unlink(missing_ok=True)
    return {'status': 'closed', 'task_id': task, 'killed': killed}


def browser_configure(task,runtime,chromium,proxy_port=0,bridge_port=17779,ca=''):
    if ca and not proxy_port:raise ValueError('Burp CA requires a Proxy listener')
    config,_,_=session_invoker(task);v,_=owned_config(task)
    runtime=Path(runtime).resolve();binary=Path(chromium).resolve()
    if not (runtime/'bin/python').is_file() or not list((runtime/'lib').glob('python*/site-packages/playwright')):raise ValueError('Playwright runtime missing')
    info=binary.stat()
    if info.st_uid!=0 or info.st_mode&0o022 or not os.access(binary,os.X_OK):raise ValueError('Chromium must be root-owned and not writable')
    settings={'runtime':str(runtime),'chromium':str(binary)}
    if proxy_port:
        settings['burp']={'proxy_port':callback_port(proxy_port),'bridge_port':callback_port(bridge_port)}
        if ca:
            path=Path(ca).resolve();info=path.stat()
            if (not stat.S_ISREG(info.st_mode) or info.st_uid not in (0,config['uid']) or info.st_mode&0o022
                    or info.st_uid==0 and not info.st_mode&0o004):raise ValueError('Unsafe or unreadable Burp CA file')
            settings['burp'].update(ca=str(path),ca_sha256=hashlib.sha256(path.read_bytes()).hexdigest())
    config['browser']=settings;replace_config(v,config)
    return {'status':'configured','browser_protocol':1,'browser':settings}


def browser_engine_command(task,config):
    # No page can contact Kali or a target directly: the browser's netns is
    # empty. Only the root-controlled HTTP callback can perform target I/O.
    v,_=owned_config(task);settings=config.get('browser')
    if not settings:raise ToolError('browser_unavailable','Configure the task Playwright runtime and Chromium first')
    argv=isolated_command(v['name'],config['owner'],config['uid'],config['gid'],
        ['/opt/pm-browser/bin/python','/usr/local/sbin/pm-netguard','browser-engine'],
        ['--dir','/opt','--ro-bind',settings['runtime'],'/opt/pm-browser'],workdir=task_workdir(task,config))
    argv.remove('--share-net')
    return argv


def browser_open(task,raw,owner='',owner_pid=0):
    config,owner,pid=session_invoker(task,owner,owner_pid)
    if not config.get('browser'):raise ToolError('browser_unavailable','Browser runtime is not configured')
    if not isinstance(raw,dict) or set(raw)!={'url','username','purpose','proxy'}:raise ValueError('Browser needs url, username, purpose and proxy')
    url=resource_url(raw['url']);browser_endpoint(config,url)
    if not isinstance(raw['username'],str) or not 1<=len(raw['username'])<=120 or not isinstance(raw['purpose'],str) or not 1<=len(raw['purpose'])<=1000:raise ValueError('Browser user/purpose required')
    if raw['proxy'] not in (None,'burp') or raw['proxy']=='burp' and not config['browser'].get('burp'):raise ToolError('burp_unavailable','Task-local Burp is not configured')
    if raw['proxy']=='burp':
        health=burp_status(task,{'action':'status'})
        if health.get('protocol')!=3 or health.get('edition')!='PROFESSIONAL' or not health.get('guarded_proxy'):raise ToolError('burp_unavailable','Dedicated Burp Professional bridge v3 is unavailable')
    with session_lock(task):
        entries=session_list(task)['sessions']
        if sum(s.get('running') is not False for s in entries)>=SESSION_MAX:raise ValueError('Task session limit reached')
        sid=new_session_id(session_dir(task));work=task_workdir(task,config)
        tool_write_file(work,f'browser/{sid}/session-id',sid.encode(),config)
        meta={'task_id':task,'session_id':sid,'pid':0,'socket':str(session_dir(task)/f'{sid}.sock'),
            'log':str(session_dir(task)/f'{sid}.log'),'workdir':str(work),'idle':SESSION_IDLE,'created':int(time.time()),
            'owner':owner,'owner_pid':pid,'owner_birth':process_birth(pid) if pid else '',
            'resource':url['request_url'],'username':raw['username'],'purpose':raw['purpose'],'transport':'browser',
            'proxy':raw['proxy'],'pending_unknown':False}
        tool_store(session_dir(task)/f'{sid}.json',meta)
        return start_browser_worker(task,meta)


def start_browser_worker(task,meta):
    sid=meta['session_id'];owner=meta.get('owner','')
    with open(meta['log'],'ab') as log:
        process=subprocess.Popen([os.path.realpath(sys.argv[0]),'browser-worker','--task-id',str(task),'--session-id',sid],
            stdin=subprocess.DEVNULL,stdout=log,stderr=log,start_new_session=True,
            env={'PATH':'/usr/bin:/bin','HOME':'/root','LC_ALL':'C'})
    meta.update(pid=process.pid,process_birth=process_birth(process.pid));tool_store(session_dir(task)/f'{sid}.json',meta)
    for _ in range(200):
        if Path(meta['socket']).is_socket():
            try:
                health=session_request(meta,{'op':'status'},timeout=2)
                if health.get('running'):return {**health,'status':'opened','session_id':sid,'owner':owner,
                    'resource':meta['resource'],'username':meta['username'],'purpose':meta['purpose'],'transport':'browser'}
            except (OSError,RuntimeError):pass
        if process.poll() is not None:break
        time.sleep(.05)
    return {'status':'unknown','session_id':sid,'running':None,'reason_category':'browser_unavailable','error':'Browser worker did not become ready; inspect its log, no automatic reopen'}


def browser_endpoint(config,url):
    if url.get('kind')!='url':raise ValueError('Browser requires an HTTP(S) resource')
    policy=config.get('resource_policy')
    origin=next((o for o in (policy or {}).get('origins',[]) if o['origin']==url['origin']),None)
    target=origin['addresses'][0] if origin else url['host']
    check_target(target,config['allowed'])
    authorize_resource(policy,'http',target,scheme=url['scheme'],hostname=url['host'],port=url['port'],path=url['request_path'])
    if not policy and url['host']!=target and url['host'] not in config.get('hostnames',[]):raise ValueError('Unapproved browser hostname')
    return target


def browser_restore(task,sid,owner='',owner_pid=0):
    config,owner,pid=session_invoker(task,owner,owner_pid)
    with session_lock(task):
        meta=session_meta(task,sid)
        if meta.get('transport')!='browser':raise ValueError('Not a browser session')
        if session_alive(meta):raise ValueError('Browser is alive; reuse the existing session')
        if meta.get('pending_unknown'):raise ValueError('Interrupted browser action requires review; restoration never replays it')
        birth=process_birth(meta.get('owner_pid',0))
        if meta.get('owner') not in ('',owner) and birth and birth==meta.get('owner_birth'):raise ValueError('Browser owned by another live agent')
        browser_endpoint(config,resource_url(meta['resource']))
        if sum(s.get('running') is not False for s in session_list(task)['sessions'])>=SESSION_MAX:raise ValueError('Task session limit reached')
        Path(meta['socket']).unlink(missing_ok=True)
        meta.update(last_owner=meta.get('owner') or meta.get('last_owner'),owner='',owner_pid=0,owner_birth='')
        return start_browser_worker(task,meta)


def browser_action_spec(value):
    if not isinstance(value,dict):raise ValueError('Browser action must be an object')
    action=value.get('action')
    fields={'open':{'action','url'},'fill':{'action','selector','value'},'click':{'action','selector'},
            'wait':{'action','selector','timeout_ms'},'read':{'action','read_selector'}}
    if not isinstance(action,str) or action not in fields or set(value)-fields[action]:raise ValueError('Unsupported browser action/fields')
    if action=='open' and resource_url(value.get('url','')).get('kind')!='url':raise ValueError('Browser requires HTTP(S) navigation')
    if action in ('fill','click','wait'):
        if not isinstance(value.get('selector'),str) or not 1<=len(value['selector'])<=1000:raise ValueError('Selector required')
    if action=='fill' and (not isinstance(value.get('value'),str) or len(value['value'])>8192):raise ValueError('Invalid fill value')
    if 'read_selector' in value and (not isinstance(value['read_selector'],str) or not 1<=len(value['read_selector'])<=1000):raise ValueError('Invalid read selector')
    if 'timeout_ms' in value and (type(value['timeout_ms']) is not int or not 1<=value['timeout_ms']<=12000):raise ValueError('Browser wait budget exceeded')
    return value


def browser_result(task,sid,receipt_id=''):
    session_invoker(task);sid=session_id_valid(sid)
    if receipt_id and not re.fullmatch(r'[a-f0-9]{64}',receipt_id):raise ValueError('Invalid browser receipt ID')
    file=session_dir(task)/(f'{sid}.{receipt_id}.http-receipt' if receipt_id else f'{sid}.browser-result')
    if not file.exists():return {'status':'unavailable','reason':'No saved browser receipt'}
    value=tool_load(file)
    if receipt_id and (value.get('task_id')!=task or value.get('session_id')!=sid or
            tool_digest({k:v for k,v in value.items() if k!='receipt_id'})!=receipt_id):raise ValueError('Browser receipt integrity mismatch')
    return value


def browser_action(task,sid,action,owner='',owner_pid=0,max_requests=0):
    config,owner,pid=session_invoker(task,owner,owner_pid)
    action=browser_action_spec(action)
    if action['action']=='open':browser_endpoint(config,resource_url(action['url']))
    if type(max_requests) is not int or not 0<=max_requests<=24:raise ValueError('Invalid browser HTTP budget')
    with session_lock(task):
        meta=session_meta(task,sid)
        if meta.get('transport')!='browser':raise ValueError('Session is not a browser')
        if not session_alive(meta):return {'status':'disconnected','session_id':sid,'running':False}
        other=meta.get('owner','');birth=process_birth(meta.get('owner_pid',0))
        if other and other!=owner and birth and birth==meta.get('owner_birth'):return {'status':'blocked','kind':'session_busy','execution_started':False}
        if other!=owner and meta.get('last_owner') not in (None,'',owner) and action.get('action') not in ('read','wait'):
            return {'status':'blocked','kind':'session_read_required','execution_started':False,'error':'Read retained browser state after handoff before controlling it'}
        if meta.get('pending_unknown') and action.get('action') not in ('read','wait'):return {'status':'blocked','reason_category':'outcome_unknown','execution_started':False,'error':'Previous browser action outcome unknown; inspect retained state, no automatic replay'}
        prior_unknown=meta.get('pending_unknown',False)
        meta.update(owner=owner,owner_pid=pid,owner_birth=process_birth(pid),pending_unknown=True)
        tool_store(session_dir(task)/f'{sid}.json',meta)
        records=[];denials=[];used=0;sock=socket.socket(socket.AF_UNIX);sock.settimeout(45)
        ledger_file=BASE/f'browser-http-{task}.json'
        ledger=tool_load(ledger_file) if ledger_file.exists() else {}
        try:
            sock.connect(meta['socket']);stream=sock.makefile('rwb',buffering=0)
            stream.write((json.dumps({'op':'browser','action':action})+'\n').encode())
            while True:
                raw=stream.readline(40*1024*1024+1)
                if not raw or len(raw)>40*1024*1024:raise ValueError('Browser IPC incomplete or oversized')
                message=json.loads(raw)
                if message.get('kind')!='http':
                    result=message;break
                item=message['request'];response={'status':'blocked','reason':
                    'Browser action material budget exhausted' if used>=32*1024*1024 else 'HTTP request budget exhausted'}
                if len(records)<max_requests and used<32*1024*1024:
                    try:
                        url=resource_url(item['url']);target=browser_endpoint(config,url)
                        if item.get('body_complete') is False:raise ValueError('Browser request body unavailable; no sending')
                        headers=[[k,v] for k,v in item['headers'] if k.lower() not in ('host','content-length','connection','accept-encoding','transfer-encoding','expect','upgrade','proxy-authorization')]
                        spec=http_spec({'method':item['method'],'target':target,'scheme':url['scheme'],'hostname':url['host'],
                            'port':url['port'],'path':url['request_path'],'headers':headers,'body_b64':item['body_b64'],
                            'session_id':sid,'limit_bytes':HTTP_CAPTURE_BODY_LIMIT,'timeout':12,'tls_verify':True,'ssrf':None,
                            **({'proxy':'burp'} if meta.get('proxy')=='burp' else {})})
                        fingerprint=tool_digest({k:v for k,v in spec.items() if k not in ('session_id','limit_bytes','timeout','proxy')})
                        previous=ledger.get(fingerprint)
                        if previous and (previous=='unknown' or spec['method'] not in ('GET','HEAD','OPTIONS')):raise ValueError('Browser HTTP repeat or unknown outcome; no replay')
                        ledger[fingerprint]='unknown';tool_store(ledger_file,ledger)
                        response=http_run(task,spec);used+=len(json.dumps(response))+len(json.dumps(spec))
                        ledger[fingerprint]='finished' if response['transport_complete'] else 'unknown';tool_store(ledger_file,ledger)
                        record={'task_id':task,'session_id':sid,'spec':spec,'response':response,'observed_at':time.time()}
                        record['receipt_id']=tool_digest(record)
                        # Immutable originals survive failed frontend import and
                        # subsequent DOM reads. They are not capability result IDs.
                        tool_store(session_dir(task)/f'{sid}.{record["receipt_id"]}.http-receipt',record)
                        records.append(record)
                        # Private receipt remains available after lost frontend output.
                        tool_store(session_dir(task)/f'{sid}.browser-result',{'session_id':sid,'network':records,'status':'unknown'})
                        if used>32*1024*1024:response={'status':'blocked','reason':'Browser action material budget exhausted'}
                    except (ValueError,OSError,RuntimeError,subprocess.SubprocessError) as exc:
                        response={'status':'blocked','reason':str(exc)[:160] if isinstance(exc,ValueError) else type(exc).__name__+': scoped HTTP unavailable'}
                if response.get('status')=='blocked':
                    denials.append(response.get('reason','HTTP denied'))
                    if len(denials)>24:raise ValueError('Browser denied-request budget exhausted')
                stream.write((json.dumps(response)+'\n').encode())
            meta['pending_unknown']=prior_unknown or result.get('status') not in ('completed','closed')
            tool_store(session_dir(task)/f'{sid}.json',meta)
        except (OSError,ValueError,RuntimeError) as exc:result={'status':'unknown','reason_category':'outcome_unknown','error':type(exc).__name__}
        finally:sock.close()
        result={**result,'session_id':sid,'running':session_alive(meta),'owner':owner,'transport':'browser',
            'username':meta['username'],'purpose':meta['purpose'],'resource':meta['resource'],'network':records,'network_denials':denials}
        tool_store(session_dir(task)/f'{sid}.browser-result',result)
        return result


def browser_worker(task,sid):
    ensure_root();_,config=owned_config(task);meta=session_meta(task,sid)
    process=subprocess.Popen(browser_engine_command(task,config),stdin=subprocess.PIPE,stdout=subprocess.PIPE,text=True,bufsize=1)
    process.stdin.write(json.dumps({'chromium':config['browser']['chromium'],'directory':'/work/browser/'+sid})+'\n');process.stdin.flush()
    ready=process.stdout.readline()
    if not ready or json.loads(ready).get('status')!='ready':raise RuntimeError('Browser engine startup failed')
    listener=socket.socket(socket.AF_UNIX);listener.bind(meta['socket']);os.chmod(meta['socket'],0o600);listener.listen(4)
    listener.settimeout(SESSION_IDLE)
    try:
        while process.poll() is None:
            try:connection,_=listener.accept()
            except socket.timeout:break
            with connection:
                stream=connection.makefile('rwb',buffering=0)
                request=json.loads(stream.readline(65537))
                op=request.get('op')
                if op in ('status','read'):
                    reply={'status':'running','running':True,'worker_pid':os.getpid(),'worker_birth':process_birth(os.getpid())}
                    stream.write((json.dumps(reply)+'\n').encode());continue
                if op=='close':
                    stream.write(b'{"status":"closed","running":false}\n');break
                if op!='browser':stream.write(b'{"status":"blocked","error":"Use pm_browser typed actions"}\n');continue
                process.stdin.write(json.dumps(request['action'])+'\n');process.stdin.flush()
                while True:
                    line=process.stdout.readline(40*1024*1024+1)
                    if not line:raise RuntimeError('Browser engine exited during an action')
                    stream.write(line.encode());item=json.loads(line)
                    if item.get('kind')!='http':break
                    response=stream.readline(40*1024*1024+1)
                    if not response:raise RuntimeError('Browser caller disconnected; action outcome unknown')
                    process.stdin.write(response.decode());process.stdin.flush()
    finally:
        listener.close();Path(meta['socket']).unlink(missing_ok=True)
        process.stdin.close()
        try:process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.terminate()
            try:process.wait(timeout=5)
            except subprocess.TimeoutExpired:process.kill();process.wait()


def browser_engine():
    if os.geteuid()==0:raise PermissionError('Browser engine must be unprivileged')
    from playwright.sync_api import sync_playwright
    from email.parser import BytesParser
    initial=json.loads(sys.stdin.readline());directory=Path(initial['directory']);directory.mkdir(parents=True,exist_ok=True,mode=0o700)
    os.environ['HOME']=str(directory)
    for key,leaf in (('XDG_CONFIG_HOME','.config'),('XDG_CACHE_HOME','.cache')):
        folder=directory/leaf;folder.mkdir(mode=0o700,exist_ok=True);os.environ[key]=str(folder)
    def send(value):print(json.dumps(value,ensure_ascii=True),flush=True)
    with sync_playwright() as playwright:
        browser=playwright.chromium.launch(executable_path=initial['chromium'],headless=True,
            args=['--no-sandbox','--disable-dev-shm-usage','--disable-background-networking',
                  '--force-webrtc-ip-handling-policy=disable_non_proxied_udp','--proxy-server=http://127.0.0.1:9','--proxy-bypass-list=<-loopback>'])
        state_file=directory/'state.json'
        state=json.loads(state_file.read_text()) if state_file.exists() else None
        context=browser.new_context(storage_state=state,service_workers='block',accept_downloads=False)
        session_file=directory/'session-storage.json'
        session_storage=json.loads(session_file.read_text()) if session_file.exists() else {}
        context.add_init_script('(()=>{const pmSaved='+json.dumps(session_storage)+'; if(pmSaved[location.origin]) for(const [k,v] of Object.entries(pmSaved[location.origin]))sessionStorage.setItem(k,v);})();')
        context.set_default_timeout(12000)
        # BrowserContext.route deliberately skips redirected requests. Chromium's
        # supported CDP Fetch layer pauses EVERY hop before any network I/O.
        # Network remains empty even if an unsupported target escapes interception.
        page=context.new_page();cdp=context.new_cdp_session(page)
        cdp.send('Network.enable');cdp.send('Network.setCacheDisabled',{'cacheDisabled':True})
        def route_request(event):
            request=event['request'];entries=request.get('postDataEntries')
            complete=True
            if entries is not None and all('bytes' in entry for entry in entries):
                body=b''.join(base64.b64decode(entry['bytes'],validate=True) for entry in entries)
            elif 'postData' in request:body=request['postData'].encode()
            else:body=b'';complete=not request.get('hasPostData',False)
            send({'kind':'http','request':{'url':request['url'],'method':request['method'],
                'headers':[[k,v] for k,v in request['headers'].items()],
                'body_b64':base64.b64encode(body).decode(),'body_complete':complete}})
            response=json.loads(sys.stdin.readline())
            if not response.get('transport_complete') or response.get('body_truncated'):
                cdp.send('Fetch.failRequest',{'requestId':event['requestId'],'errorReason':'BlockedByClient'});return
            head=base64.b64decode(response['headers_b64'])
            matches=list(re.finditer(rb'(?m)^HTTP/1\.[01] [0-9]{3}[^\r\n]*\r?\n',head))
            fields=BytesParser().parsebytes(head[matches[-1].end():]);headers=[]
            for k,v in fields.items():
                k=k.lower()
                if k in ('content-length','transfer-encoding','connection'):continue
                headers.append({'name':k,'value':v})
            cdp.send('Fetch.fulfillRequest',{'requestId':event['requestId'],'responseCode':response['status_code'],
                'responseHeaders':headers,'body':response['body_b64']})
        cdp.on('Fetch.requestPaused',route_request)
        cdp.send('Fetch.enable',{'patterns':[{'urlPattern':'*','requestStage':'Request'}]})
        context.route_web_socket('**/*',lambda ws:ws.close())
        page.on('dialog',lambda dialog:dialog.dismiss())
        send({'status':'ready'})
        for line in sys.stdin:
            try:
                action=json.loads(line);kind=action['action']
                if kind=='open':page.goto(action['url'],wait_until='domcontentloaded')
                elif kind=='fill':page.locator(action['selector']).fill(action['value'])
                elif kind=='click':page.locator(action['selector']).click(no_wait_after=True)
                elif kind=='wait':page.locator(action['selector']).wait_for(state='visible',timeout=action.get('timeout_ms',12000))
                elif kind!='read':raise ValueError('Unsupported browser action')
                text=page.locator(action.get('read_selector','body')).inner_text(timeout=3000)
                full=page.content().encode();limited=len(full)>2*1024*1024
                (directory/'dom.html').write_bytes(full[:2*1024*1024])
                temporary=directory/'state.tmp';context.storage_state(path=temporary,indexed_db=True);os.replace(temporary,state_file)
                values=page.locator('input,textarea,select').evaluate_all('(nodes)=>nodes.map(n=>({id:n.id,name:n.name,type:n.type,value:n.value,checked:n.checked}))')
                if page.url.startswith(('http://','https://')):
                    current=page.evaluate('()=>({origin:location.origin,values:Object.fromEntries(Object.entries(sessionStorage))})')
                    session_storage[current['origin']]=current['values'];session_file.write_text(json.dumps(session_storage))
                send({'status':'completed','observed_url':page.url,'title':page.title(),'text':text[:6000],
                    'dom_b64':base64.b64encode(full[:2*1024*1024]).decode(),
                    'text_truncated':len(text)>6000,'dom_truncated':limited,'dom_sha256':hashlib.sha256(full[:2*1024*1024]).hexdigest(),
                    'state_sha256':tool_digest([json.loads(state_file.read_text()),session_storage,values]),
                    'interpretation':'observed DOM only; action completion is not authentication or goal confirmation'})
            except Exception as exc:send({'status':'unknown','reason_category':'outcome_unknown','error_type':type(exc).__name__})
        context.close();browser.close()


def session_dir(task):
    """Root-only directory holding one task's interactive sessions."""
    SESSIONS_BASE.mkdir(parents=True, exist_ok=True, mode=0o700)
    base_stat = SESSIONS_BASE.stat()
    if base_stat.st_uid != 0 or (base_stat.st_mode & 0o077):
        raise RuntimeError('Unsafe session base ownership or mode')
    path = SESSIONS_BASE / str(task)
    if path.is_symlink():
        raise RuntimeError('Session directory must not be a symlink')
    path.mkdir(mode=0o700, exist_ok=True)
    return path


def session_id_valid(raw):
    if not re.fullmatch(r'[a-f0-9]{8}', str(raw or '')):
        raise ValueError('Invalid session id')
    return str(raw)


def new_session_id(directory):
    # Callers hold the task lock. Never reuse an ID whose original log survives.
    for _ in range(32):
        sid=os.urandom(4).hex()
        if not any((directory/(sid+suffix)).exists() for suffix in ('.json','.log','.sock','-control')):return sid
    raise RuntimeError('Cannot allocate a unique session ID')


def session_meta(task, session_id):
    path = session_dir(task) / f'{session_id_valid(session_id)}.json'
    if not path.is_file() or path.is_symlink():
        raise ValueError('Session not found')
    try:
        meta = json.loads(path.read_text())
    except (ValueError, OSError):
        raise ValueError('Session metadata is unreadable')
    if int(meta.get('task_id') or 0) != int(task):
        raise ValueError('Session does not belong to this task')
    # A parent can die after spawning the worker but before publishing its PID.
    # Recover from the existing private control socket, never by spawning again.
    if not meta.get('pid') and Path(meta.get('socket','')).is_socket():
        try:
            health=session_request(meta,{'op':'status'},timeout=2)
            candidate={**meta,'pid':health.get('worker_pid',0),'process_birth':health.get('worker_birth','')}
            if candidate['pid'] and session_alive(candidate):
                meta=candidate;tool_store(path,meta)
        except (OSError,ValueError,RuntimeError):pass
    return meta


def session_alive(meta):
    pid = int(meta.get('pid') or 0)
    if pid <= 0 or not Path(f'/proc/{pid}').exists():
        return False
    try:
        cmdline = Path(f'/proc/{pid}/cmdline').read_bytes().decode('utf-8', 'replace')
    except OSError:
        return False
    return (any(mode in cmdline for mode in ('session-worker','browser-worker')) and str(meta.get('session_id','')) in cmdline
            and (not meta.get('process_birth') or meta['process_birth']==process_birth(pid)))


def process_birth(pid):
    try:return Path(f'/proc/{int(pid)}/stat').read_text().rsplit(')',1)[1].split()[19]
    except (OSError,ValueError,IndexError):return ''


@contextmanager
def session_lock(task):
    import fcntl
    fd=os.open(session_dir(task)/'.lock',os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600)
    try:
        fcntl.flock(fd,fcntl.LOCK_EX);yield
    finally:os.close(fd)


def session_invoker(task,owner='',owner_pid=0):
    ensure_root();_,config=owned_config(task)
    if os.environ.get('SUDO_UID') and int(os.environ['SUDO_UID'])!=config['uid']:raise PermissionError('Wrong task owner')
    owner=owner or 'operator:'+str(config['uid'])
    if not re.fullmatch(r'[A-Za-z0-9:_-]{1,100}',owner):raise ValueError('Invalid session owner')
    pid=int(owner_pid or 0)
    if pid and Path(f'/proc/{pid}').stat().st_uid!=config['uid']:raise PermissionError('Owner process has a different uid')
    return config,owner,pid


def session_access(task,sid,action,*,owner='',owner_pid=0,data='',wait=0):
    config,owner,pid=session_invoker(task,owner,owner_pid)
    with session_lock(task):
        meta=session_meta(task,sid)
        other=meta.get('owner','')
        birth=process_birth(meta['owner_pid']) if meta.get('owner_pid') else ''
        owner_live=bool(other and (not meta.get('owner_pid') or birth and birth==meta.get('owner_birth')))
        if other and other!=owner and owner_live:
            return {'status':'blocked','kind':'session_busy','error':'Terminal is owned by another live agent',
                    'execution_started':False,'session_id':sid,'owner':other}
        if action=='release':
            meta.update(last_owner=other or meta.get('last_owner',''),owner='',owner_pid=0,owner_birth='')
            tool_store(session_dir(task)/f'{sid}.json',meta)
            return {'status':'released','session_id':sid,'running':session_alive(meta),'owner':''}
        if not session_alive(meta):return {'status':'disconnected','session_id':sid,'running':False,'reason':'worker_not_alive'}
        if action in ('send','interrupt') and meta.get('transport') in ('ssh','callback'):
            peer=(meta.get('ssh') or {}).get('target') or meta['resource']
            try:
                if meta['transport']=='callback':
                    if not ip_in_allowed(peer,config['allowed']):raise ValueError('Accepted peer no longer in scope')
                else:check_target(peer,config['allowed'])
                authorize_resource(config.get('resource_policy'),'session',peer)
            except ValueError:return {'status':'blocked','kind':'scope','error':'Session peer is outside current task scope; read history or close it',
                                     'execution_started':False,'session_id':sid}
        if action=='send' and other!=owner and (other or meta.get('last_owner') not in (None,'',owner)):
            return {'status':'blocked','kind':'session_read_required','error':'Read the retained terminal after handoff before sending input',
                    'execution_started':False,'session_id':sid}
        if action=='send' and meta.get('pending_unknown'):
            return {'status':'blocked','kind':'outcome_unknown','reason_category':'outcome_unknown',
                    'error':'Previous input has unknown outcome; read/interrupt or operator review required',
                    'execution_started':False,'session_id':sid}
        meta.update(owner=owner,owner_pid=pid,owner_birth=process_birth(pid) if pid else '')
        if action=='send':meta['pending_unknown']=True
        tool_store(session_dir(task)/f'{sid}.json',meta)
        try:
            result=session_request(meta,{'op':action,'data':data,'wait':float(wait or 0)})
        except (OSError,ValueError,RuntimeError) as exc:
            return {'status':'unknown','running':None,'session_id':sid,'owner':owner,
                    'reason_category':'outcome_unknown','error':type(exc).__name__}
        if action=='send' or result.get('prompt_seen') is True:meta['pending_unknown']=False
        tool_store(session_dir(task)/f'{sid}.json',meta)
        transport=meta.get('transport','pty')
        remote=transport=='callback' or transport=='ssh' and (Path(meta['ssh']['control_root'])/'control').is_socket()
        return {**result,'session_id':sid,'owner':owner,'running':result.get('running',result.get('status')!='closed'),
                'transport':transport,'task_id':task,'target':(meta.get('ssh') or {}).get('target') or meta.get('resource'),
                'network_contact':True if action=='send' and remote else None}


def session_request(meta, payload, timeout=20):
    """One request/one answer over the session socket."""
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    buffer = b''
    try:
        sock.connect(str(meta['socket']))
        sock.sendall((json.dumps(payload) + '\n').encode('utf-8'))
        while b'\n' not in buffer and len(buffer) < SESSION_OUTPUT_KEEP + 65536:
            chunk = sock.recv(65536)
            if not chunk:
                break
            buffer += chunk
    finally:
        sock.close()
    line = buffer.split(b'\n', 1)[0].decode('utf-8', 'replace').strip()
    if not line:
        raise RuntimeError('Session did not answer; it may have exited')
    return json.loads(line)


def session_open(task,*args,**kwargs):
    ensure_root();_,config=owned_config(task)
    if config.get('resource_policy'):authorize_resource(config['resource_policy'],'session',config['resource_policy']['addresses'][0])
    with session_lock(task):return _session_open(task,*args,**kwargs)


def _session_open(task, argv, idle,owner='',owner_pid=0,ssh_spec=None,resource='',username='',purpose=''):
    """Start a long-lived interactive session inside the task namespace."""
    ensure_root()
    v, config = owned_config(task)
    config,owner,owner_pid=session_invoker(task,owner,owner_pid)
    policy=config.get('resource_policy')
    if policy:authorize_resource(policy,'session',policy['addresses'][0])
    if not config['allowed']:
        raise ValueError('Task has no allowed scope')
    directory = session_dir(task)
    live = 0
    for path in sorted(directory.glob('*.json')):
        try:
            meta = session_meta(task,path.stem)
        except (ValueError, OSError):
            live+=1 # Unknown occupied slot; do not erase possibly live state.
            continue
        if session_alive(meta):
            live += 1
        elif meta.get('pid'):
            path.unlink(missing_ok=True)
        else:live+=1
    if live >= SESSION_MAX:
        raise ValueError(f'Too many open sessions (max {SESSION_MAX}); close one first')
    shell = [str(item) for item in (argv or ['/bin/bash', '--noprofile', '--norc', '-i'])]
    reject_password_change(shell)
    if len(shell) > EXEC_ARGS_MAX:
        raise ValueError('Session argv is too long')
    if any(len(item) > EXEC_ARG_LEN_MAX for item in shell):
        raise ValueError('Session argv element is too long')
    if not shell[0].startswith('/'):
        raise ValueError('Session argv[0] must be an absolute path')
    self_path = os.path.realpath(sys.argv[0])
    if not self_path.startswith(('/usr/local/sbin/', '/usr/sbin/')):
        raise RuntimeError('Sessions must be started from the installed broker')
    workdir = task_workdir(task, config)
    session_id = new_session_id(directory)
    ssh=None
    if ssh_spec is not None:
        if argv:raise ValueError('Choose generic argv or managed SSH, not both')
        ssh=managed_ssh(task,session_id,ssh_spec,config)
        shell=ssh['argv']
    socket_path = directory / f'{session_id}.sock'
    log_path = directory / f'{session_id}.log'
    idle = max(60, min(int(idle or SESSION_IDLE), SESSION_IDLE_MAX))
    meta = {'task_id': task, 'session_id': session_id, 'pid': 0,
            'socket': str(socket_path), 'log': str(log_path),
            'workdir': str(workdir), 'argv': shell, 'idle': idle,
            'created': int(time.time()), 'scope': config['allowed']}
    meta.update(owner=owner,owner_pid=owner_pid,owner_birth=process_birth(owner_pid) if owner_pid else '',
                resource=ssh['target'] if ssh else resource or 'task',username=ssh['user'] if ssh else username or 'unknown',
                purpose=purpose[:1000],transport='ssh' if ssh else 'pty',ssh=ssh)
    meta['username_provenance']='configured login; not verified identity' if ssh else 'declared; not verified identity'
    meta_path = directory / f'{session_id}.json'
    fd = os.open(meta_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w') as handle:
        json.dump(meta, handle)
    with log_path.open('ab') as log:
        process = subprocess.Popen(
            [self_path, 'session-worker', '--task-id', str(task),
             '--session-id', session_id],
            stdin=subprocess.DEVNULL, stdout=log, stderr=log,
            start_new_session=True,
            env={'PATH': '/usr/bin:/bin', 'HOME': '/root', 'LC_ALL': 'C'})
    meta['pid'] = process.pid
    meta['process_birth']=process_birth(process.pid)
    tool_store(meta_path,meta)
    for _ in range(120):
        if socket_path.exists() or process.poll() is not None:
            break
        time.sleep(0.05)
    if not socket_path.exists():
        process.kill()
        return {'status':'unknown','running':None,'reason_category':'outcome_unknown','session_id':session_id,
                'execution_started':True,'error':'Session worker did not become ready; inspect its log before retrying','log':str(log_path)}
    return {'status': 'opened', 'task_id': task, 'session_id': session_id,
            'pid': process.pid, 'argv': shell, 'workdir': str(workdir),
            'idle_timeout': idle, 'accepts_from': config['allowed'],
            'owner':owner,'transport':meta['transport'],'resource':meta['resource'],'username':meta['username'],
            'username_provenance':meta['username_provenance'],'purpose':purpose,
            'note': 'state persists: send input, then read output; /work keeps files'}


def managed_ssh(task,sid,raw,config):
    binary=Path('/usr/bin/ssh')
    if not binary.is_file() or not os.access(binary,os.X_OK):raise ToolError('tool_missing','OpenSSH client is unavailable')
    if not isinstance(raw,dict) or set(raw)!={'target','user','port','identity'}:raise ValueError('Invalid managed SSH spec')
    target=check_target(raw['target'],config['allowed'])
    authorize_resource(config.get('resource_policy'),'session',target)
    if not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_.-]{0,63}',raw['user']):raise ValueError('Invalid SSH user')
    port=raw['port']
    if type(port) is not int or not 1<=port<=65535:raise ValueError('Invalid SSH port')
    identity=raw['identity']
    if identity and (not isinstance(identity,str) or not re.fullmatch(r'/work/(?:[A-Za-z0-9_.-]+/)*[A-Za-z0-9_.-]+',identity)
                     or '..' in identity.split('/')):raise ValueError('SSH identity must be a task workspace file')
    work=task_workdir(task,config)
    tool_write_file(work,f'ssh/{sid}/metadata.json',b'{}',config)
    # Root-private parent: other task PoCs cannot access the multiplex socket.
    control_root=session_dir(task)/(sid+'-control');control_root.mkdir(mode=0o700)
    os.chown(control_root,config['uid'],config['gid'])
    control='/run/pm-control/control'
    args=['/usr/bin/ssh','-F','/dev/null','-o','ControlMaster=yes','-o','ControlPersist=no',
          '-o','ControlPath='+control,'-o','ServerAliveInterval=15','-o','ServerAliveCountMax=2',
          '-o','UserKnownHostsFile=/work/ssh/'+sid+'/known_hosts','-o','StrictHostKeyChecking=accept-new',
          '-o','PermitLocalCommand=no','-o','EscapeChar=none','-o','ForwardAgent=no','-p',str(port),'-tt']
    if identity:args+=['-i',identity]
    args+=['--',raw['user']+'@'+target]
    return {'target':target,'user':raw['user'],'port':port,'control':control,'control_root':str(control_root),'argv':args}


def pivot_spec(raw):
    fields={'source_session','resource_ref','destination','port','local_port','probe','purpose'}
    if not isinstance(raw,dict) or set(raw)!=fields:raise ValueError('Invalid SSH-forward specification')
    if not isinstance(raw['source_session'],str):raise ValueError('Source session ID must be a string')
    session_id_valid(raw['source_session'])
    if not re.fullmatch(r'resource:[A-Za-z0-9:_-]+',str(raw['resource_ref'])):raise ValueError('Pivot needs a saved resource reference')
    target=str(ipaddress.ip_address(raw['destination']))
    if ipaddress.ip_address(target).is_loopback or ipaddress.ip_address(target).is_unspecified:
        raise ValueError('This forward profile requires an explicitly scoped internal address, not ambiguous loopback')
    if type(raw['port']) is not int or not 1<=raw['port']<=65535:raise ValueError('Invalid destination port')
    local_port=callback_port(raw['local_port'])
    if raw['probe'] not in ('http_headers','banner'):raise ValueError('Supported route probes: http_headers or banner')
    if not isinstance(raw['purpose'],str) or not raw['purpose'].strip() or len(raw['purpose'])>1000:raise ValueError('Invalid pivot purpose')
    return {**raw,'destination':target,'local_port':local_port}


def pivot_prepare(task,raw):
    config,_,_=session_invoker(task)
    spec=pivot_spec(raw);check_target(spec['destination'],config['allowed'])
    authorize_resource(config.get('resource_policy'),'session',spec['destination'])
    if spec['probe']=='http_headers':authorize_resource(config.get('resource_policy'),'http',spec['destination'],port=spec['port'])
    source=session_meta(task,spec['source_session'])
    if source.get('transport')!='ssh' or not source.get('ssh') or not session_alive(source):
        raise ValueError('Pivot requires a live managed SSH ControlMaster session')
    check_target(source['ssh']['target'],config['allowed']);authorize_resource(config.get('resource_policy'),'session',source['ssh']['target'])
    if not (Path(source['ssh']['control_root'])/'control').is_socket():raise ValueError('SSH is not authenticated/connected: no ControlMaster socket')
    health=session_request(source,{'op':'status'},timeout=3)
    if not health.get('running'):raise ValueError('Source terminal did not pass its health check')
    manifest={'task_id':task,'owner_uid':config['uid'],'protocol':1,'spec':spec,
        'source_ssh':source['ssh'],'listener':'127.0.0.1:'+str(spec['local_port']),
        'listener_context':'task_namespace','rights':'task user, fixed SSH forward through existing ControlMaster',
        'actions':['one local TCP forward to the specified internal address/port','one bounded destination probe']}
    rid=tool_digest(manifest);path=BASE/f'pivot-{task}-{rid}.json'
    if path.exists():return tool_load(path)
    result={'request_id':rid,'manifest':manifest,'status':'prepared'};tool_store(path,result);return result


def pivot_control(task,receipt,operation):
    v,config=owned_config(task);ssh=receipt['manifest']['source_ssh'];spec=receipt['manifest']['spec']
    destination='['+spec['destination']+']' if ':' in spec['destination'] else spec['destination']
    args=['/usr/bin/ssh','-F','/dev/null','-S',ssh['control'],'-o','ExitOnForwardFailure=yes',
        '-o','ProxyCommand=/usr/bin/false','-o','BatchMode=yes',
        '-O',operation,'-L',f"127.0.0.1:{spec['local_port']}:{destination}:{spec['port']}",
        '-p',str(ssh['port']),'--',ssh['user']+'@'+ssh['target']]
    control=os.open(ssh['control_root'],os.O_DIRECTORY|os.O_NOFOLLOW)
    try:
        extra=['--dir','/run','--bind',f'/proc/self/fd/{control}','/run/pm-control']
        return cmd(*isolated_command(v['name'],config['owner'],config['uid'],config['gid'],args,extra,
                    workdir=task_workdir(task,config)),timeout=15,check=False,pass_fds=(control,))
    finally:os.close(control)


def pivot_probe(task,receipt):
    v,config=owned_config(task);spec=receipt['manifest']['spec'];port=spec['local_port']
    if spec['probe']=='http_headers':
        host='['+spec['destination']+']' if ':' in spec['destination'] else spec['destination']
        args=['/usr/bin/curl','-q','--noproxy','*','--silent','--show-error','--head',
            '--max-redirs','0','--connect-timeout','3','--max-time','5','--max-filesize','8192',
            '--connect-to',f'{host}:{spec["port"]}:127.0.0.1:{port}','--',f'http://{host}:{spec["port"]}/']
    else:
        # Fixed program, no user code/argv. Bytes from the remote end are required:
        # a connect to a local SSH listener alone cannot prove destination access.
        code='import socket,sys;s=socket.create_connection(("127.0.0.1",int(sys.argv[1])),3);s.settimeout(3);sys.stdout.buffer.write(s.recv(1024));s.close()'
        args=['/usr/bin/python3','-c',code,str(port)]
    result=cmd(*isolated_command(v['name'],config['owner'],config['uid'],config['gid'],args,
                               workdir=task_workdir(task,config)),timeout=8,check=False)
    text=result.stdout[:4096]
    verified=bool(result.returncode==0 and (re.match(r'HTTP/\S+ \d{3}',text) if spec['probe']=='http_headers' else text))
    return {'status':'responded' if verified else 'not_verified','exit_code':result.returncode,
        'output':text,'reason':'destination_bytes_received' if verified else 'no_destination_evidence',
        'observed_at':int(time.time()),'local_connect_alone_is_evidence':False}


def pivot_action(task,action,rid):
    config,_,_=session_invoker(task)
    if not re.fullmatch(r'[a-f0-9]{64}',rid):raise ValueError('Invalid pivot receipt ID')
    path=BASE/f'pivot-{task}-{rid}.json'
    import fcntl
    fd=os.open(str(path)+'.lock',os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600)
    try:
        fcntl.flock(fd,fcntl.LOCK_EX)
        receipt=tool_load(path);manifest=receipt['manifest'];spec=manifest['spec']
        if manifest['task_id']!=task or manifest['owner_uid']!=config['uid'] or tool_digest(manifest)!=rid:raise ValueError('Wrong pivot receipt owner/task')
        if action!='close':
            check_target(spec['destination'],config['allowed']);authorize_resource(config.get('resource_policy'),'session',spec['destination'])
            check_target(manifest['source_ssh']['target'],config['allowed'])
            authorize_resource(config.get('resource_policy'),'session',manifest['source_ssh']['target'])
        if action=='authorize':
            if receipt['status']=='prepared':receipt['status']='approved';tool_store(path,receipt)
            return receipt
        if receipt['status']=='prepared':return receipt
        try:source=session_meta(task,spec['source_session']);alive=session_alive(source) and session_request(source,{'op':'status'},timeout=2).get('running')
        except (OSError,ValueError,RuntimeError):alive=False
        if not alive:
            receipt.update(status='broken_source',reason='source_session_unavailable');tool_store(path,receipt);return receipt
        if source.get('ssh')!=manifest['source_ssh']:raise ValueError('Source session changed; new permission required')
        probed=False
        if action=='close':
            result=pivot_control(task,receipt,'cancel')
            receipt.update(status='closed' if result.returncode==0 else 'unknown',exit_code=result.returncode)
        elif action=='apply' and receipt['status']=='approved':
            receipt['status']='creating';tool_store(path,receipt)
            try:
                result=pivot_control(task,receipt,'forward')
                if result.returncode:receipt.update(status='failed',reason='ssh_forward_refused',exit_code=result.returncode)
                else:
                    receipt['probe']=pivot_probe(task,receipt);probed=True
                    receipt['status']='active' if receipt['probe']['status']=='responded' else 'established_unverified'
            except (OSError,RuntimeError,subprocess.TimeoutExpired):receipt.update(status='unknown',reason='forward_outcome_unknown_no_replay')
        elif action=='probe' and receipt['status'] in ('active','established_unverified'):
            receipt['probe']=pivot_probe(task,receipt);probed=True
            receipt['status']='active' if receipt['probe']['status']=='responded' else 'established_unverified'
        # status and repeated apply never create another forward or probe.
        tool_store(path,receipt)
        if probed:return {**receipt,'route_state':receipt['status'],'status':'completed',
            'probe_performed':True,'task_id':task,'target':spec['destination'],
            'stdout':receipt['probe']['output'],'exit_code':receipt['probe']['exit_code']}
        return receipt
    finally:os.close(fd)


def session_accept(task,connection,peer,port,config):
    """Adopt an already scoped incoming socket as an interactive task connection."""
    with session_lock(task):
        directory=session_dir(task)
        live=sum(session_alive(json.loads(p.read_text())) for p in directory.glob('*.json'))
        if live>=SESSION_MAX:return {'status':'rejected','reason':'session_limit','running':False}
        sid=new_session_id(directory);path=directory/f'{sid}.json'
        meta={'task_id':task,'session_id':sid,'pid':0,'socket':str(directory/f'{sid}.sock'),
            'log':str(directory/f'{sid}.log'),'argv':[],'idle':SESSION_IDLE,'created':int(time.time()),
            'scope':config['allowed'],'transport':'callback','resource':peer,'username':'unknown',
            'purpose':'incoming interactive connection','callback_port':port,'owner':'','owner_pid':0}
        tool_store(path,meta)
        self_path=os.path.realpath(sys.argv[0])
        if not self_path.startswith(('/usr/local/sbin/','/usr/sbin/')):raise ValueError('Callback session must use the installed broker')
        with open(meta['log'],'ab') as log:
            child=subprocess.Popen([self_path,'session-worker','--task-id',str(task),'--session-id',sid,
                '--accepted-fd',str(connection.fileno())],pass_fds=(connection.fileno(),),
                stdin=subprocess.DEVNULL,stdout=log,stderr=log,start_new_session=True,env={'PATH':'/usr/bin:/bin','LC_ALL':'C'})
        meta.update(pid=child.pid,process_birth=process_birth(child.pid));tool_store(path,meta)
        for _ in range(120):
            if Path(meta['socket']).exists() or child.poll() is not None:break
            time.sleep(0.05)
        if not Path(meta['socket']).exists():
            if child.poll() is None:child.terminate()
            return {'status':'failed','reason':'incoming_session_worker_not_ready','session_id':sid,'running':False}
        return {'status':'connected','session_id':sid,'resource':peer,'transport':'callback',
                'running':True,'owner':'','username':'unknown'}


def session_worker(task, session_id,accepted_fd=-1):
    """Detached worker: owns the PTY and keeps the sandbox alive between calls."""
    ensure_root()
    v, config = owned_config(task)
    session_id_valid(session_id)
    directory = session_dir(task)
    meta_path = directory / f'{session_id}.json'
    meta = session_meta(task, session_id)
    if int(meta.get('pid') or 0) not in (0, os.getpid()):
        raise ValueError('Session belongs to another process')
    socket_path = Path(meta['socket'])
    log_path = Path(meta['log'])
    workdir = task_workdir(task, config)
    idle = int(meta.get('idle') or SESSION_IDLE)
    argv = [str(item) for item in meta.get('argv') or []]
    control=-1;extra=()
    if meta.get('ssh'):
        control=os.open(meta['ssh']['control_root'],os.O_DIRECTORY|os.O_NOFOLLOW)
        os.set_inheritable(control,True)
        extra=['--dir','/run','--bind',f'/proc/self/fd/{control}','/run/pm-control']
    command = isolated_command(v['name'], config['owner'], config['uid'],
                               config['gid'], argv, extra,workdir=workdir,
                               new_session=False)
    default_shell = argv == ['/bin/bash', '--noprofile', '--norc', '-i']
    if default_shell:
        separator = command.index('--')
        command[separator:separator] = ['--setenv', 'PS1', 'PM_SESSION> ']
    incoming=None
    if meta.get('transport')=='callback':
        if accepted_fd<0:raise ValueError('Incoming session needs its accepted socket')
        incoming=socket.socket(fileno=accepted_fd)
        peer=incoming.getpeername()[0]
        if peer!=meta['resource'] or not ip_in_allowed(peer,config['allowed']):raise ValueError('Incoming session peer differs from scope')
        child=0;master=incoming.fileno()
    else:
        if accepted_fd>=0:raise ValueError('Unexpected incoming socket')
        child, master = os.forkpty()
        if child == 0:
            try:os.execv(command[0], command)
            except OSError:os._exit(127)
    os.set_blocking(master, False)
    if control>=0:os.close(control)
    buffer = bytearray()
    cursor = 0
    last_request = time.monotonic()
    log = open(log_path, 'ab', buffering=0)
    log_bytes=os.fstat(log.fileno()).st_size;log_truncated=False;dropped_bytes=0

    def drain(seconds=0.0):
        """Move PTY output into the buffer; False means the child is gone."""
        nonlocal cursor,log_bytes,log_truncated,dropped_bytes
        drained=0
        deadline = time.monotonic() + max(0.0, seconds)
        while True:
            try:
                chunk = os.read(master, 65536)
            except BlockingIOError:
                chunk = None
            except OSError:
                return False
            if chunk:
                buffer.extend(chunk)
                try:
                    writable=max(0,SESSION_LOG_BYTES-log_bytes)
                    log.write(chunk[:writable]);log_bytes+=min(writable,len(chunk))
                    if len(chunk)>writable:log_truncated=True
                except OSError:
                    log_truncated=True
                overflow = len(buffer) - SESSION_OUTPUT_KEEP
                if overflow > 0:
                    del buffer[:overflow]
                    dropped_bytes+=overflow
                    cursor = max(0, cursor - overflow)
                drained+=len(chunk)
                if drained>=SESSION_OUTPUT_KEEP:return True # service interrupt/control even under continuous output
                continue
            if chunk==b'':return False
            if time.monotonic() >= deadline:
                return True
            time.sleep(0.05)

    def take():
        nonlocal cursor
        end=min(len(buffer),cursor+SESSION_REPLY_BYTES)
        text = bytes(buffer[cursor:end]).decode('utf-8', 'replace')
        cursor = end
        return text

    def prompt_seen():
        if not default_shell:
            return None
        tail = bytes(buffer[-256:]).decode('utf-8', 'replace')
        tail = re.sub(r'\x1b\[[0-9;]*[A-Za-z]', '', tail).replace('\r', '')
        return tail.endswith('PM_SESSION> ')

    def heredoc_warning(data):
        markers = re.findall(r"<<-?\s*(['\"]?)([A-Za-z_][A-Za-z0-9_]*)\1", data)
        if not markers:
            return None
        lines = data.splitlines()
        for _, marker in markers:
            if marker not in (line.strip() for line in lines[1:]):
                return f'Незавершённый heredoc ({marker}); используйте interrupt перед следующей командой'
        return None

    def answer(request):
        """Return (reply, should_close)."""
        op = str(request.get('op') or '')
        wait = min(max(float(request.get('wait') or 0), 0.0), 5.0)
        if op == 'status':
            alive=drain(0)
            return {'status': 'running' if alive else 'disconnected','running':alive,'pid': child, 'session_id': session_id,
                    'worker_pid':os.getpid(),'worker_birth':process_birth(os.getpid()),
                    'workdir': str(workdir),
                    'prompt_seen':prompt_seen(),
                    'buffered': len(buffer) - cursor,'log_truncated':log_truncated,'dropped_bytes':dropped_bytes,
                    'stream_state_sha256':hashlib.sha256(buffer).hexdigest(),'has_more':cursor<len(buffer)}, False
        if op == 'read':
            alive=drain(wait)
            text = take()
            return {'status': 'ok' if alive else 'disconnected','running':alive, 'output': text, 'chars': len(text),
                    'prompt_seen': prompt_seen(),'has_more':cursor<len(buffer),'log_truncated':log_truncated,'dropped_bytes':dropped_bytes,
                    'stream_state_sha256':hashlib.sha256(buffer).hexdigest()}, False
        if op in ('send', 'interrupt'):
            data = str(request.get('data') or '') if op == 'send' else '\x03'
            if len(data.encode('utf-8')) > SESSION_DATA_MAX:
                return {'status': 'error', 'error': 'Session input is too large'}, False
            try:
                os.write(master, data.encode('utf-8'))
            except OSError as exc:
                return {'status': 'error', 'error': f'PTY write failed: {exc}'}, False
            drain(wait)
            text = take()
            reply = {'status': 'ok', 'output': text, 'chars': len(text),
                     'prompt_seen': prompt_seen(),'has_more':cursor<len(buffer),'log_truncated':log_truncated,'dropped_bytes':dropped_bytes,
                     'stream_state_sha256':hashlib.sha256(buffer).hexdigest()}
            warning = heredoc_warning(data) if op == 'send' else None
            if warning:
                reply['warning'] = warning
            return reply, False
        if op == 'close':
            return {'status': 'closed'}, True
        return {'status': 'error', 'error': 'Unknown session operation'}, False

    selector = None
    listener = None
    try:
        socket_path.unlink(missing_ok=True)
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        listener.bind(str(socket_path))
        os.chmod(socket_path, 0o600)
        listener.listen(8)
        listener.setblocking(False)
        selector = selectors.DefaultSelector()
        selector.register(listener, selectors.EVENT_READ, 'accept')
        running = True
        while running:
            for key, _ in selector.select(timeout=0.5):
                if key.data != 'accept':
                    continue
                conn, _ = listener.accept()
                with conn:
                    conn.settimeout(10)
                    raw = b''
                    while b'\n' not in raw and len(raw) <= SESSION_DATA_MAX + 4096:
                        chunk = conn.recv(65536)
                        if not chunk:
                            break
                        raw += chunk
                    line = raw.split(b'\n', 1)[0].decode('utf-8', 'replace').strip()
                    try:
                        request = json.loads(line)
                        if not isinstance(request, dict):
                            raise ValueError('Malformed request')
                        reply, should_close = answer(request)
                    except (ValueError, TypeError) as exc:
                        reply, should_close = {'status': 'error', 'error': str(exc)}, False
                    # answer() reports "should close", not "still running". With the
                    # polarity reversed every session died after its first command,
                    # which is exactly what the live test caught.
                    if should_close:
                        reply = {'status': 'closed', 'session_id': session_id}
                        running = False
                    try:
                        conn.sendall((json.dumps(reply, ensure_ascii=False)
                                      + '\n').encode('utf-8'))
                    except OSError:
                        pass
                last_request = time.monotonic()
            if not drain(0):
                break
            if time.monotonic() - last_request > idle:
                break
    finally:
        if child:
            try:os.killpg(child, signal.SIGKILL)
            except (ProcessLookupError, PermissionError):pass
        if incoming:incoming.close()
        try:
            log.close()
        except OSError:
            pass
        for handle in (selector, listener):
            try:
                if handle is not None:
                    handle.close()
            except OSError:
                pass
        socket_path.unlink(missing_ok=True)
        meta_path.unlink(missing_ok=True)


def session_send(task, session_id, data, wait,owner='',owner_pid=0):
    reject_password_change(text=data)
    ensure_root()
    owned_config(task)
    if len(str(data).encode('utf-8')) > SESSION_DATA_MAX:
        raise ValueError('Session input is too large')
    return session_access(task,session_id,'send',owner=owner,owner_pid=owner_pid,data=str(data),wait=wait)


def session_interrupt(task, session_id, wait,owner='',owner_pid=0):
    ensure_root()
    owned_config(task)
    return session_access(task,session_id,'interrupt',owner=owner,owner_pid=owner_pid,wait=wait)


def session_read(task, session_id, wait,owner='',owner_pid=0):
    ensure_root()
    owned_config(task)
    return session_access(task,session_id,'read',owner=owner,owner_pid=owner_pid,wait=wait)


def session_close(task, session_id,owner='',owner_pid=0):
    ensure_root()
    owned_config(task)
    meta = session_meta(task, session_id)
    released=session_access(task,session_id,'close',owner=owner,owner_pid=owner_pid)
    if released.get('status') in ('blocked','unknown'):return released
    pid = int(meta.get('pid') or 0)
    killed = False
    for _ in range(40):
        if not pid or not session_alive(meta):
            break
        time.sleep(0.05)
    if pid and session_alive(meta):
        try:
            os.kill(pid, signal.SIGKILL)
            killed = True
        except ProcessLookupError:
            pass
    directory = session_dir(task)
    safe_id = session_id_valid(session_id)
    (directory / f'{safe_id}.json').unlink(missing_ok=True)
    (directory / f'{safe_id}.sock').unlink(missing_ok=True)
    return {'status': 'closed', 'task_id': task, 'session_id': safe_id,
            'killed': killed, 'log': meta.get('log')}


def ssh_health(task,meta):
    v,config=owned_config(task);ssh=meta['ssh']
    try:check_target(ssh['target'],config['allowed']);authorize_resource(config.get('resource_policy'),'session',ssh['target'])
    except ValueError:return {'status':'unverified','operation':'not_started: source outside current task scope'}
    control=os.open(ssh['control_root'],os.O_DIRECTORY|os.O_NOFOLLOW)
    try:
        # Existing master only: if multiplexing is gone, ProxyCommand=false
        # forbids a new connection or authentication attempt during recovery.
        args=['/usr/bin/ssh','-F','/dev/null','-S',ssh['control'],'-o','ControlMaster=no',
            '-o','BatchMode=yes','-o','ProxyCommand=/usr/bin/false','-p',str(ssh['port']),
            '--',ssh['user']+'@'+ssh['target'],'true']
        result=cmd(*isolated_command(v['name'],config['owner'],config['uid'],config['gid'],args,
            ['--dir','/run','--bind',f'/proc/self/fd/{control}','/run/pm-control'],workdir=task_workdir(task,config)),
            timeout=3,check=False,pass_fds=(control,))
        return {'status':'verified_remote_exec' if result.returncode==0 else 'unverified',
                'exit_code':result.returncode,'operation':'fixed POSIX true via existing SSH master; no fallback login'}
    except (OSError,RuntimeError,subprocess.TimeoutExpired):return {'status':'unverified','operation':'existing SSH master health check failed'}
    finally:os.close(control)


def session_list(task,check_remote=False):
    ensure_root()
    session_invoker(task)
    directory = session_dir(task)
    sessions = []
    for path in sorted(directory.glob('*.json')):
        try:
            meta = session_meta(task,path.stem)
        except (ValueError, OSError):
            sessions.append({'session_id':path.stem,'running':None,'reason':'metadata_unreadable'})
            continue
        alive = session_alive(meta) if meta.get('pid') else None
        health={}
        if alive:
            try:
                health=session_request(meta,{'op':'status'},timeout=2)
                alive=bool(health.get('running'))
            except (OSError,ValueError,RuntimeError):alive=None
        if alive and meta.get('transport')=='ssh' and check_remote:health['ssh']=ssh_health(task,meta)
        sessions.append({'session_id': meta.get('session_id'),
                         'pid': meta.get('pid'), 'running': alive,
                         'argv': meta.get('argv'),
                         'idle_timeout': meta.get('idle'),
                         'created': meta.get('created'),
                         'owner':meta.get('owner',''),'resource':meta.get('resource','task'),
                         'username':meta.get('username','unknown'),'purpose':meta.get('purpose',''),
                         'transport':meta.get('transport','pty'),'health':health,
                         'connection_ready':bool(alive and (meta.get('transport')!='ssh' or
                             health.get('ssh',{}).get('status')=='verified_remote_exec')),
                         'remote_liveness':'unknown unless validated by current I/O or explicit SSH health check',
                         'authentication_status':'not inferred from process liveness',
                         'log': meta.get('log')})
    return {'status': 'ok', 'task_id': task, 'count': len(sessions),
            'sessions': sessions, 'max': SESSION_MAX,
            'workdir': str(WORK_BASE / str(task))}


def session_cleanup(task):
    """Kill every session of a task and delete its persistent workspace."""
    killed = []
    directory = SESSIONS_BASE / str(task)
    if directory.is_dir() and not directory.is_symlink():
        for path in sorted(directory.glob('*.json')):
            try:
                meta = json.loads(path.read_text())
            except (ValueError, OSError):
                meta = {}
            pid = int(meta.get('pid') or 0)
            if pid and session_alive(meta):
                try:
                    os.kill(pid, signal.SIGTERM)
                    killed.append(pid)
                except ProcessLookupError:
                    pass
            path.unlink(missing_ok=True)
        for path in directory.glob('*.sock'):
            path.unlink(missing_ok=True)
        shutil.rmtree(directory, ignore_errors=True)
    work = WORK_BASE / str(task)
    if work.is_dir() and not work.is_symlink():
        shutil.rmtree(work, ignore_errors=True)
    return {'sessions_killed': killed, 'work_removed': not work.exists()}


def main():
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest='command', required=True)
    sub.add_parser('capabilities')
    sub.add_parser('http-worker')
    sub.add_parser('browser-engine')
    route=sub.add_parser('network-diagnostic');route.add_argument('--task-id',type=int,required=True);route.add_argument('--target',required=True)
    worker=sub.add_parser('port-worker');worker.add_argument('--target',required=True);worker.add_argument('--ports',required=True)
    sub.add_parser('burp-reader')
    bu=sub.add_parser('burp-read');bu.add_argument('--task-id',type=int,required=True)
    bw=sub.add_parser('browser-worker');bw.add_argument('--task-id',type=int,required=True);bw.add_argument('--session-id',required=True)
    bc=sub.add_parser('browser-config');bc.add_argument('--task-id',type=int,required=True)
    bc.add_argument('--runtime',required=True);bc.add_argument('--chromium',required=True)
    bc.add_argument('--proxy-port',type=int,default=0);bc.add_argument('--bridge-port',type=int,default=17779);bc.add_argument('--ca',default='')
    br=sub.add_parser('browser');br.add_argument('--task-id',type=int,required=True)
    br.add_argument('--action',choices=('open','restore','control','result'),required=True);br.add_argument('--session-id',default='')
    br.add_argument('--receipt-id',default='')
    br.add_argument('--owner',default='');br.add_argument('--owner-pid',type=int,default=0);br.add_argument('--max-requests',type=int,default=0)
    http_parser=sub.add_parser('http')
    http_parser.add_argument('--task-id',type=int,required=True)
    s = sub.add_parser('setup')
    s.add_argument('--task-id', type=int, required=True)
    s.add_argument('--owner', required=True)
    s.add_argument('--allow', action='append', required=True)
    s.add_argument('--egress', default='auto')
    s.add_argument('--resource-policy',help='Explicit operator-configured JSON resource grants')
    t = sub.add_parser('teardown')
    t.add_argument('--task-id', type=int, required=True)
    wi = sub.add_parser('workdir')
    wi.add_argument('--task-id', type=int, required=True)
    ti = sub.add_parser('tool', help='Bounded, operator-approved acquisition; no generic root execution')
    ti.add_argument('--task-id', type=int, required=True)
    ti.add_argument('--action', choices=('prepare', 'authorize', 'apply', 'status'), required=True)
    ti.add_argument('--spec-json', default='')
    ti.add_argument('--request-id', default='')
    r = sub.add_parser('run')
    r.add_argument('--task-id', type=int, required=True)
    r.add_argument('--profile', required=True)
    r.add_argument('--target', required=True)
    r.add_argument('--port', default='80')
    r.add_argument('--ports', default='80,443')
    r.add_argument('--scheme', default='http')
    r.add_argument('--path', default='/')
    r.add_argument('--hostname', default='')
    r.add_argument('--ssrf-destination',default='')
    r.add_argument('--ssrf-context',default='')
    r.add_argument('--ssrf-parameter',default='url')
    r.add_argument('--capture-limit',type=int,choices=HTTP_CAPTURE_LIMITS,default=HTTP_CAPTURE_BODY_LIMIT)
    r.add_argument('--argv', action='append', default=None)
    r.add_argument('--poc-file', default='')
    r.add_argument('--stdin-file',default='')
    r.add_argument('--poc-interp', default='bash', choices=POC_INTERPRETERS)
    r.add_argument('--research-host', default='')
    r.add_argument('--timeout', default='')
    r.add_argument('--operation-reason',default='')
    hs = sub.add_parser('hosts')
    hs.add_argument('--task-id', type=int, required=True)
    hs.add_argument('--hostname', action='append', required=True)
    cb = sub.add_parser('callback')
    cb.add_argument('--action', required=True, choices=('open', 'read', 'close', 'listen','diagnose','configure'))
    cb.add_argument('--task-id', type=int, required=True)
    cb.add_argument('--port', default='')
    cb.add_argument('--bind', default='')
    cb.add_argument('--timeout', default='300')
    cb.add_argument('--since', default='')
    cb.add_argument('--mode',choices=('interactive','transfer'),default='interactive')
    cb.add_argument('--expected-bytes',type=int,default=None)
    cb.add_argument('--expected-sha256',default='')
    cb.add_argument('--max-bytes',type=int,default=TRANSFER_DEFAULT_BYTES)
    cb.add_argument('--interface',default='')
    cb.add_argument('--advertise',default='')
    cb.add_argument('--reason',default='')
    cb.add_argument('--variant-limit',type=int,choices=range(1,11),default=None)
    pi=sub.add_parser('pivot')
    pi.add_argument('--task-id',type=int,required=True)
    pi.add_argument('--action',choices=('prepare','authorize','apply','status','probe','close'),required=True)
    pi.add_argument('--spec-json',default='');pi.add_argument('--request-id',default='')
    se = sub.add_parser('session')
    se.add_argument('--action', required=True,
                    choices=('open', 'send', 'read', 'interrupt', 'close', 'list','release'))
    se.add_argument('--owner',default='')
    se.add_argument('--owner-pid',type=int,default=0)
    se.add_argument('--ssh-json',default='')
    se.add_argument('--resource',default='')
    se.add_argument('--username',default='')
    se.add_argument('--purpose',default='')
    se.add_argument('--check-remote',type=int,choices=(0,1),default=0)
    se.add_argument('--task-id', type=int, required=True)
    se.add_argument('--session-id', default='')
    se.add_argument('--argv', action='append', default=None)
    se.add_argument('--data', default='')
    se.add_argument('--wait', default='0.8')
    se.add_argument('--idle', default=str(SESSION_IDLE))
    sw = sub.add_parser('session-worker')
    sw.add_argument('--task-id', type=int, required=True)
    sw.add_argument('--session-id', required=True)
    sw.add_argument('--accepted-fd',type=int,default=-1)
    sf = sub.add_parser('sync-forward')
    sf.add_argument('--task-id', type=int, required=True)
    st = sub.add_parser('status')
    st.add_argument('--task-id', type=int, required=True)
    args = parser.parse_args()
    try:
        if args.command == 'capabilities':
            output({'capture_protocol': 1,'resource_policy_protocol':1,'ipv6':True, 'tool_protocol': TOOL_PROTOCOL,
                    'http_protocol':1,'http_header_limit':HTTP_HEADER_LIMIT,
                    'browser_protocol':1,'burp_proxy_protocol':1,
                    'session_protocol':2,'pivot_protocol':1,'transfer_protocol':1,
                    'system_tools': SYSTEM_TOOLS, 'privileged_scan_profiles': list(RAW_SCAN_PROFILES),
                    'profiles': ['http_capture', 'exec', 'poc_run', 'research', 'session', *RAW_SCAN_PROFILES],
                    'research_domains': list(RESEARCH_DOMAINS),
                    'session': {'max': SESSION_MAX, 'idle_default': SESSION_IDLE,
                                'idle_max': SESSION_IDLE_MAX,
                                'workdir': str(WORK_BASE)},
                    'exec_timeout_max': EXEC_PROFILE_TIMEOUT_MAX,
                    'poc_timeout_max': POC_TIMEOUT_MAX,
                    'run_status': 'completed means the command ran; inspect exit_code and nonzero_exit',
                    'poc_interpreters': list(POC_INTERPRETERS),
                    'callback': {'ports_min': 1024, 'max_bytes': CALLBACK_MAX_BYTES},
                    'capture_limit_bytes': HTTP_CAPTURE_BODY_LIMIT,'capture_limits':list(HTTP_CAPTURE_LIMITS)})
        elif args.command in ('burp-read','burp-reader'):
            value=json.loads(sys.stdin.read(65537));output(burp_status(args.task_id,value) if args.command=='burp-read' else burp_reader(value))
        elif args.command=='browser-config':output(browser_configure(args.task_id,args.runtime,args.chromium,args.proxy_port,args.bridge_port,args.ca))
        elif args.command=='network-diagnostic':output(network_diagnostic(args.task_id,args.target))
        elif args.command=='port-worker':
            if os.geteuid()==0:raise PermissionError('Port worker must be unprivileged')
            selected=[int(p) for p in args.ports.split(',')]
            if not 1<=len(selected)<=8:raise ValueError('Invalid UDP batch')
            output({'observations':[port_probe(args.target,p,'udp') for p in selected]})
        elif args.command=='browser-engine':browser_engine()
        elif args.command=='browser-worker':browser_worker(args.task_id,args.session_id)
        elif args.command=='browser':
            if args.action=='result':
                output(browser_result(args.task_id,args.session_id,args.receipt_id))
            elif args.action=='restore':output(browser_restore(args.task_id,args.session_id,args.owner,args.owner_pid))
            else:
                raw=sys.stdin.read(65537)
                if len(raw)>65536:raise ValueError('Browser action input too large')
                value=json.loads(raw)
                output(browser_open(args.task_id,value,args.owner,args.owner_pid) if args.action=='open' else
                    browser_action(args.task_id,args.session_id,value,args.owner,args.owner_pid,args.max_requests))
        elif args.command in ('http','http-worker'):
            if args.command=='http-worker' and os.geteuid()==0:raise PermissionError('HTTP worker must run as the unprivileged task user')
            text=sys.stdin.read(20*1024*1024+1)
            if len(text)>20*1024*1024:raise ValueError('HTTP input budget exceeded')
            raw=json.loads(text)
            output(http_run(args.task_id,raw) if args.command=='http' else http_transport(raw['spec'],raw.get('proxy')) if 'spec' in raw else http_transport(raw))
        elif args.command == 'setup': setup(args.task_id, args.owner, args.allow, args.egress,
                                          json.loads(args.resource_policy) if args.resource_policy else None)
        elif args.command == 'teardown': teardown(args.task_id)
        elif args.command == 'workdir': output(workdir_init(args.task_id))
        elif args.command == 'tool':
            output(tool_prepare(args.task_id, json.loads(args.spec_json)) if args.action == 'prepare'
                   else tool_action(args.task_id, args.action, args.request_id))
        elif args.command == 'run': run(args.task_id, args.profile, args.target,
                                        args.port, args.ports, args.scheme, args.path, args.hostname,args.capture_limit,
                                        argv=args.argv, poc_file=args.poc_file, poc_interp=args.poc_interp,stdin_file=args.stdin_file,
                                        research_host=args.research_host, timeout=args.timeout or None,operation_reason=args.operation_reason,
                                        ssrf_destination=args.ssrf_destination,ssrf_context=args.ssrf_context,ssrf_parameter=args.ssrf_parameter)
        elif args.command == 'sync-forward': sync_forward(args.task_id)
        elif args.command=='pivot':
            output(pivot_prepare(args.task_id,json.loads(args.spec_json)) if args.action=='prepare' else pivot_action(args.task_id,args.action,args.request_id))
        elif args.command == 'callback':
            action = args.action
            if action == 'open':
                output(callback_open(args.task_id, args.port or '4444', args.bind, args.timeout,args.mode,args.expected_bytes,args.expected_sha256,args.max_bytes))
            elif action == 'read':
                output(callback_read(args.task_id, args.since or None))
            elif action == 'close':
                output(callback_close(args.task_id, args.port or None))
            elif action=='diagnose':output(callback_diagnose(args.task_id,args.port or '4444'))
            elif action=='configure':output(callback_configure(args.task_id,args.bind,args.interface,args.advertise,args.reason,args.variant_limit))
            else:
                output(callback_listen(args.task_id, args.port or '4444', args.bind, args.timeout,args.mode,args.expected_bytes,args.expected_sha256,args.max_bytes))
        elif args.command == 'session-worker':
            session_worker(args.task_id, args.session_id,args.accepted_fd)
        elif args.command == 'session':
            action = args.action
            if action == 'open':
                output(session_open(args.task_id, args.argv, args.idle,args.owner,args.owner_pid,
                    json.loads(args.ssh_json) if args.ssh_json else None,args.resource,args.username,args.purpose))
            elif action == 'list':
                output(session_list(args.task_id,bool(args.check_remote)))
            elif action=='release':output(session_access(args.task_id,args.session_id,'release',owner=args.owner,owner_pid=args.owner_pid))
            elif action == 'send':
                output(session_send(args.task_id, args.session_id, args.data, args.wait,args.owner,args.owner_pid))
            elif action == 'read':
                output(session_read(args.task_id, args.session_id, args.wait,args.owner,args.owner_pid))
            elif action == 'interrupt':
                output(session_interrupt(args.task_id, args.session_id, args.wait,args.owner,args.owner_pid))
            else:
                output(session_close(args.task_id, args.session_id,args.owner,args.owner_pid))
        elif args.command == 'hosts': set_hostnames(args.task_id, args.hostname)
        else:
            _, config = owned_config(args.task_id)
            output({'status': 'configured', 'task_id': args.task_id,
                    'allowed': config['allowed'], 'egress': config['egress'],
                    'approved_egress': config.get('approved_egress', config['egress']),
                    'current_egress': config.get('current_egress', config['egress']),
                    'host_veth_ip': config['host_ip'],
                    'docker_forward_managed': config.get('docker_forward_managed', False),
                    'hostnames': config.get('hostnames', []),
                    'resource_policy':config.get('resource_policy')})
    except ToolError as e:
        output({'status': 'blocked', 'kind': e.category, 'reason_category': e.category, 'error': str(e)}, fail=True)
    except PermissionError as e:
        output({'status': 'blocked', 'kind': 'permission_denied', 'reason_category': 'permission_denied', 'error': str(e)}, fail=True)
    except EgressError as e:
        output({'status': 'blocked', 'kind': 'egress', 'error': str(e)}, fail=True)
    except TimeoutError as e:
        output({'status': 'timeout', 'kind': 'timeout', 'error': str(e)}, fail=True)
    except (ValueError, PermissionError, RuntimeError, OSError,
            subprocess.SubprocessError, KeyError) as e:
        output({'status': 'blocked', 'error': str(e)}, fail=True)


if __name__ == '__main__': main()
