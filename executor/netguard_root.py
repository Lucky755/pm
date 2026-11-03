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
from urllib.parse import unquote
import pwd
import re
import shutil
import signal
import socket
import stat
import selectors
import subprocess
import sys
import time

BASE = Path('/etc/pentest-master/netguard')
STATE = Path('/run/pentest-master-netguard')
PREV_FORWARD = STATE / 'ip_forward.previous'
DOCS = tuple(ipaddress.ip_network(v) for v in
             ('192.0.2.0/24', '198.51.100.0/24', '203.0.113.0/24'))
MAX_TASK = 200
HTTP_CAPTURE_BODY_LIMIT = 2 * 1024 * 1024
HTTP_CAPTURE_WIRE_LIMIT = HTTP_CAPTURE_BODY_LIMIT + 65536
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
EXEC_TIMEOUT_MAX = 300
EXEC_PROFILE_TIMEOUT_MAX = 180
POC_TIMEOUT_MAX = 300

# Generated PoC scripts live only under the task's own artifact directory.
POC_MAX_BYTES = 256 * 1024
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
SESSION_MAX = 6
SESSION_IDLE = 1800
SESSION_IDLE_MAX = 7200
SESSION_OUTPUT_KEEP = 1024 * 1024
SESSION_DATA_MAX = 65536

# Local callback sink for blind execution results (reverse shells / exfil).
CALLBACK_PORTS = range(1024, 65536)
CALLBACK_MAX_BYTES = 4 * 1024 * 1024
CALLBACK_DIR = Path('/var/lib/pentest-master/callbacks')


def output(data, fail=False):
    print(json.dumps(data, ensure_ascii=False, indent=2), flush=True)
    if fail:
        raise SystemExit(1)


def cmd(*args, input=None, timeout=20, check=True):
    p = subprocess.run(args, input=input, text=True, capture_output=True,
                       timeout=timeout, check=False)
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
                config=BASE / f'task-{task}.json')


def allow_networks(raw):
    if not raw or len(raw) > 16:
        raise ValueError('Specify 1..16 allowed IPv4 networks')
    nets = []
    for value in raw:
        net = ipaddress.ip_network(value, strict=False)
        if net.version != 4 or net.prefixlen < 8:
            raise ValueError('IPv4 only; scope must be at least /8 specific')
        if net.overlaps(ipaddress.ip_network('127.0.0.0/8')):
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


# Docker's iptables-nft FORWARD chain may DROP traffic even after the
# earlier nftables NetGuard allow verdict. Bridge that single, scoped flow.
IPTABLES = '/usr/sbin/iptables'
HOSTS_BASE = Path('/etc/netns')


def docker_forward_rules(v, config, egress=None):
    allowed = config['allowed']
    egress = egress or config.get('current_egress', config['egress'])
    if egress == 'auto':
        raise ValueError('Docker forward integration needs explicit --egress, e.g. tun0')
    # No broad source/destination matches. The nftables early hook remains
    # the independent enforcement point for the entire root-owned task scope.
    if len(allowed) != 1 or not ipaddress.ip_network(allowed[0]).prefixlen == 32:
        raise ValueError('Docker forwarding currently requires one exact /32 target')
    destination = allowed[0]
    forward = ['-i', v['host'], '-o', egress,
               '-s', v['peerip'] + '/32', '-d', destination, '-j', 'ACCEPT']
    reverse = ['-i', egress, '-o', v['host'],
               '-s', destination, '-d', v['peerip'] + '/32',
               '-m', 'conntrack', '--ctstate', 'ESTABLISHED,RELATED', '-j', 'ACCEPT']
    return [forward, reverse]


def docker_chain_exists():
    return cmd(IPTABLES, '-w', '5', '-S', 'DOCKER-USER', check=False).returncode == 0


def docker_policy_drops_forward():
    result = cmd(IPTABLES, '-w', '5', '-S', 'FORWARD')
    return any(line.strip() == '-P FORWARD DROP' for line in result.stdout.splitlines())


def docker_rule_exists(rule):
    return cmd(IPTABLES, '-w', '5', '-C', 'DOCKER-USER', *rule, check=False).returncode == 0


def remove_docker_rules(rules):
    # Ignore already-absent rules, but never silently ignore a failed delete.
    for rule in reversed(rules):
        if docker_rule_exists(rule):
            cmd(IPTABLES, '-w', '5', '-D', 'DOCKER-USER', *rule)


def add_docker_rules(rules, adopt_existing=False):
    if not docker_chain_exists():
        raise RuntimeError('DOCKER-USER chain unavailable; refusing FORWARD DROP bypass')
    inserted = []
    try:
        for index, rule in enumerate(rules, start=1):
            if docker_rule_exists(rule):
                if not adopt_existing:
                    raise ValueError('Matching DOCKER-USER rule already exists; use sync-forward to adopt explicitly')
            else:
                cmd(IPTABLES, '-w', '5', '-I', 'DOCKER-USER', str(index), *rule)
                inserted.append(rule)
    except BaseException:
        remove_docker_rules(inserted)
        raise
    return inserted


def sync_forward(task):
    """Explicitly adopt existing scoped manual Docker rules (or insert them)."""
    ensure_root()
    v, config = owned_config(task)
    if not docker_policy_drops_forward():
        raise ValueError('FORWARD is not DROP; Docker bridge not required')
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
    if len(config['allowed']) != 1 or not config['allowed'][0].endswith('/32'):
        raise ValueError('Hostnames require an exact /32 scope')
    destination = str(ipaddress.ip_network(config['allowed'][0]).network_address)
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
    content = ('127.0.0.1 localhost\n::1 localhost\n' + destination + ' ' +
               ' '.join(names) + '\n')
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


def setup(task, owner, allowed, egress):
    ensure_root()
    v = task_values(task)
    networks = allow_networks(allowed)
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
    rules = filter_rules(v, networks, egress)
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
        sysctl_forward(True)
        config_data = {'task_id': task, 'name': v['name'], 'uid': account.pw_uid,
                       'gid': account.pw_gid, 'owner': owner, 'allowed': networks,
                       'egress': egress, 'approved_egress': egress,
                       'current_egress': egress,
                       'host_ip': v['hostip'], 'peer_ip': v['peerip']}
        # Docker's FORWARD DROP otherwise silently makes an authorized scan
        # return zero observations. Refuse unhandled DROP, never weaken it.
        if docker_policy_drops_forward():
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
        if created:
            cmd('/usr/sbin/ip', 'netns', 'delete', v['name'], check=False)
        if v['config'].exists():
            v['config'].unlink()
        sysctl_forward(False)
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
    # Sessions and the persistent workspace belong to the task lifetime.
    session_cleanup(task)
    v['config'].unlink()
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
    if ip.version != 4 or ip.is_loopback or ip.is_multicast or ip.is_unspecified:
        raise ValueError('Only concrete non-loopback IPv4 targets permitted')
    if any(ip in doc for doc in DOCS):
        raise ValueError('Documentation targets cannot be scanned')
    if not any(ip in ipaddress.ip_network(net) for net in allowed):
        raise ValueError('Destination denied by root-owned task scope')
    return str(ip)


def safe_http_path(path):
    """Strict read-only relative-to-origin URL path. No query, fragment or dot traversal."""
    if not isinstance(path, str) or not 1 <= len(path) <= 180 or not path.startswith('/'):
        raise ValueError('Expected an absolute HTTP path up to 180 bytes')
    if not re.fullmatch(r"/[A-Za-z0-9._~!$&'()+,;=:@%/\-]*", path):
        raise ValueError('Unsafe HTTP path characters (queries are not supported)')
    decoded = path
    for _ in range(3):
        decoded = unquote(decoded)
        if ('\\' in decoded or '//' in decoded or
                any(part == '..' for part in decoded.split('/')) or
                any(ord(char) < 32 or ord(char) == 127 for char in decoded)):
            raise ValueError('Unsafe HTTP path or encoded traversal')
    if '%' in decoded and re.search(r'%(?:2e|2f|5c|0[0-9a-f]|7f)', decoded, flags=re.I):
        raise ValueError('Encoded traversal or control denied')
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


def tool_args(profile, target, port, ports, scheme, path="/", hostname="", capture_limit=HTTP_CAPTURE_BODY_LIMIT):
    def valid_port(raw):
        if not re.fullmatch(r'[0-9]{1,5}', str(raw)) or not 1 <= int(raw) <= 65535:
            raise ValueError('Invalid TCP port')
        return str(int(raw))
    def valid_ports(raw):
        parts = raw.split(',')
        if not 1 <= len(parts) <= 32:
            raise ValueError('1..32 TCP ports required')
        values = [valid_port(part) for part in parts]
        if len(set(values)) != len(values):
            raise ValueError('Duplicate TCP port')
        return ','.join(values)
    if profile == 'tcp_full':
        # Operator-initiated one-off full TCP connect discovery (no exploits,
        # no UDP, no NSE scripts, no credential attacks). Exact target is still
        # enforced by the root-owned per-task /32 firewall and owner checks.
        return ['/usr/bin/nmap', '-sT', '-Pn', '-n', '--min-rate', '1000',
                '--open', '--max-retries', '1', '--host-timeout', '240s',
                '-p-', target]
    if profile in ('tcp_ports', 'service_versions'):
        selected = valid_ports(ports)
        if profile == 'tcp_ports':
            return ['/usr/bin/nmap', '-sT', '-Pn', '-n', '--open', '--max-retries', '1',
                    '--host-timeout', '25s', '-p', selected, target]
        return ['/usr/bin/nmap', '-sT', '-sV', '--version-light', '-Pn', '-n', '--open',
                '--max-retries', '1', '--host-timeout', '30s', '-p', selected, target]
    if profile not in ('http_headers', 'http_get', 'https_headers', 'http_path', 'http_document', 'http_capture'):
        raise ValueError('Unknown profile')
    selected = valid_port(port)
    if profile == 'http_headers': scheme = 'http'
    if profile == 'https_headers': scheme = 'https'
    if scheme not in ('http', 'https'):
        raise ValueError('Invalid HTTP scheme')
    result = ['/usr/bin/curl', '--silent', '--show-error', '--noproxy', '*',
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
        safe_http_path(path)
        if hostname:
            if hostname == target:
                hostname = ''
            elif not re.fullmatch(r'[a-z0-9.-]{1,253}', hostname):
                raise ValueError('Invalid HTTP host')
        if hostname:
            result += ['--resolve', f'{hostname}:{selected}:{target}']
        authority = hostname or target
        return result + ['--', f'{scheme}://{authority}:{selected}{path}']
    return result + ['--', f'{scheme}://{target}:{selected}/']


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
    p = cmd('/usr/sbin/ip', '-4', 'route', 'get', ip, check=False)
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
        if len(allowed) != 1 or ipaddress.ip_network(allowed[0]).prefixlen != 32:
            raise EgressError('Automatic egress repair requires one exact /32 target')
        old = current
        chain = cmd('/usr/sbin/nft', '-a', 'list', 'chain', 'inet', v['table'], 'forward').stdout
        old_rule = next((line for line in chain.splitlines()
                         if f'iifname "{v["host"]}"' in line
                         and f'oifname "{old}"' in line
                         and 'ip daddr' in line and 'accept' in line), None)
        handle = re.search(r'# handle (\d+)', old_rule or '')
        if not handle:
            raise EgressError('Scoped forwarding rule is missing; refusing repair')
        destination = allowed[0]
        new_docker = []
        if docker_policy_drops_forward():
            if not config.get('docker_forward_managed'):
                raise EgressError('Docker forwarding is not managed for this task')
            new_docker = add_docker_rules(docker_forward_rules(v, config, actual),
                                          adopt_existing=True)
        try:
            cmd('/usr/sbin/nft', 'replace', 'rule', 'inet', v['table'], 'forward',
                'handle', handle.group(1), 'iifname', v['host'], 'ip', 'saddr',
                v['peerip'], 'ip', 'daddr', destination, 'oifname', actual, 'accept')
            nat = cmd('/usr/sbin/nft', 'list', 'table', 'ip', v['nat']).stdout
            if f'oifname "{actual}" masquerade' not in nat:
                cmd('/usr/sbin/nft', 'add', 'rule', 'ip', v['nat'], 'postrouting',
                    'ip', 'saddr', v['peerip'], 'ip', 'daddr', destination,
                    'oifname', actual, 'masquerade')
            updated = dict(config, approved_egress=config.get('approved_egress',
                                                              config['egress']),
                           current_egress=actual)
            replace_config(v, updated)
        except BaseException:
            remove_docker_rules(new_docker)
            raise
        if docker_policy_drops_forward():
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


def run(task, profile, target, port, ports, scheme, path="/", hostname="",
        capture_limit=HTTP_CAPTURE_BODY_LIMIT, argv=None, poc_file=None,
        poc_interp='bash', research_host='', timeout=None):
    ensure_root()
    v, config = owned_config(task)
    sudo_uid = os.environ.get('SUDO_UID')
    if sudo_uid is not None and int(sudo_uid) != config['uid']:
        raise ValueError('Invoker is not the configured task owner')
    if isinstance(timeout, str) and timeout.isdigit():
        timeout = int(timeout)
    extra = ()
    workdir = None
    poc_details = None
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
                        'kind': 'broker', 'error': f'Executable unavailable: {args[0]}',
                        'exit_code': None, 'nonzero_exit': False})
                return
        else:
            built = poc_argv(poc_file, poc_interp, config['uid'], config['gid'], workdir)
            args = built['argv']
            poc_details = built
        profile_limit = EXEC_PROFILE_TIMEOUT_MAX if profile == 'exec' else POC_TIMEOUT_MAX
        run_timeout = EXEC_TIMEOUT if timeout is None else max(5, min(int(timeout), profile_limit, EXEC_TIMEOUT_MAX))
        stdout_limit = 120000
    else:
        target = check_target(target, config['allowed'])
        if profile in ('http_path', 'http_document', 'http_capture'):
            # Domain mapping is strictly per-task and points to the same /32 target.
            approved_hosts = config.get('hostnames', [])
            if hostname and hostname != target and hostname not in approved_hosts:
                raise ValueError('Hostname not approved for this NetGuard task')
        args = tool_args(profile, target, port, ports, scheme, path, hostname, capture_limit)
        run_timeout = 250 if profile == 'tcp_full' else 48
        stdout_limit = 270336 if profile == 'http_document' else 24000
    if check_egress:
        config = ensure_target_egress(v, config, target)
        verify_target_egress(config, target)
    # Require firewall tables still present, otherwise fail closed.
    if docker_policy_drops_forward():
        if not config.get('docker_forward_managed'):
            raise EgressError('Docker FORWARD DROP requires sync-forward --task-id N')
        rules = docker_forward_rules(v, config)
        if not docker_chain_exists() or not all(docker_rule_exists(rule) for rule in rules):
            raise EgressError('Task-specific Docker forwarding rules missing; refusing run')
    cmd('/usr/sbin/nft', 'list', 'table', 'inet', v['table'])
    cmd('/usr/sbin/nft', 'list', 'table', 'ip', v['nat'])
    if profile == 'http_capture':
        data = capture_process(isolated_command(v['name'], config['owner'], config['uid'], config['gid'], args),capture_limit)
        output({'operation': 'network_probe_isolated', 'capture_protocol': 1,
                'task_id': task, 'target': target, 'profile': profile,
                'port': int(port), 'scheme': scheme, 'path': path, 'hostname': hostname or target,
                'sandbox': 'netns+nft+bubblewrap', **data})
        return
    # Strictly bounded runtime and output (including potentially malicious service strings).
    started = time.monotonic()
    timed_out = False
    try:
        process = subprocess.Popen(
            isolated_command(v['name'], config['owner'], config['uid'], config['gid'],
                             args, extra, workdir=workdir),
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, errors='replace', start_new_session=True)
    except OSError as exc:
        output({'operation': 'network_probe_isolated', 'task_id': task,
                'profile': profile, 'target': target, 'status': 'error',
                'kind': 'broker', 'error': str(exc), 'exit_code': None,
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
    poc_result = {}
    if poc_details is not None:
        poc_result['network_isolated'] = True
        poc_result = {key: poc_details[key] for key in
                      ('poc_sha256', 'poc_bytes', 'poc_source_flag_literals')}
        poc_result['poc_path'] = args[1]
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
            'exit_code': code, 'nonzero_exit': code != 0,
            'stdout': stdout[:stdout_limit], 'stderr': stderr[:5000],
            'stdout_truncated': len(stdout) > stdout_limit,
            'stdout_limit': stdout_limit,
            'output_truncated': len(stdout) > stdout_limit or len(stderr) > 5000,
            'executable': Path(args[0]).name,
            'elapsed_seconds': round(time.monotonic() - started, 3),
            **poc_result})


def capture_process(argv, body_limit=None):
    """Drain binary pipes with hard byte/time caps; never buffer unbounded output."""
    started = time.monotonic()
    if body_limit is None:
        body_limit,wire_limit = HTTP_CAPTURE_BODY_LIMIT,HTTP_CAPTURE_WIRE_LIMIT
    else:
        if body_limit not in HTTP_CAPTURE_LIMITS:
            raise ValueError('Unsupported HTTP capture limit')
        wire_limit = body_limit + 65536
    try:
        process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, start_new_session=True)
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
    entry = dict(event, at=time.strftime('%Y-%m-%dT%H:%M:%S'))
    try:
        with (outdir / 'events.jsonl').open('a', encoding='utf-8') as handle:
            handle.write(json.dumps(entry, ensure_ascii=False) + '\n')
    except OSError:
        pass


def callback_listen(task, port, bind, timeout):
    """Detached worker: accepts connections only from the task's own scope."""
    ensure_root()
    v, config = owned_config(task)
    port = callback_port(port)
    outdir, piddir = callback_paths(task)
    outdir.mkdir(parents=True, exist_ok=True, mode=0o700)
    piddir.mkdir(parents=True, exist_ok=True, mode=0o700)
    deadline = time.monotonic() + max(10, min(int(timeout), 3600))
    accepted = rejected = 0
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((bind or '0.0.0.0', port))
        sock.listen(8)
        sock.settimeout(1.0)
        while time.monotonic() < deadline:
            try:
                conn, peer = sock.accept()
            except socket.timeout:
                continue
            with conn:
                ip = peer[0]
                if not ip_in_allowed(ip, config['allowed']):
                    rejected += 1
                    log_callback_event(outdir, {'peer': ip, 'port': port,
                                                'decision': 'rejected'})
                    continue
                accepted += 1
                log_callback_event(outdir, {'peer': ip, 'port': port,
                                            'decision': 'accepted'})
                data = read_stream(conn, deadline)
                name = f'{time.strftime("%Y%m%dT%H%M%S")}_{port}_{ip}.bin'
                (outdir / name).write_bytes(data)
                entry = {'file': name, 'peer': ip, 'port': port, 'bytes': len(data),
                         'at': time.strftime('%Y-%m-%dT%H:%M:%S'),
                         'preview': data[:2048].decode('utf-8', errors='replace')}
                with (outdir / 'index.jsonl').open('a', encoding='utf-8') as handle:
                    handle.write(json.dumps(entry, ensure_ascii=False) + '\n')
    finally:
        sock.close()
        try:
            (piddir / f'{port}.pid').unlink()
        except FileNotFoundError:
            pass
    return {'status': 'listener_exit', 'task_id': task, 'port': port,
            'accepted': accepted, 'rejected_peers': rejected}


def callback_open(task, port, bind, timeout):
    ensure_root()
    v, config = owned_config(task)
    port = callback_port(port)
    if bind:
        addr = ipaddress.ip_address(bind)
        if addr.version != 4 or addr.is_multicast or addr.is_unspecified:
            raise ValueError('Invalid bind address')
        local = cmd('/usr/sbin/ip', '-4', '-o', 'addr', 'show').stdout
        if not re.search(rf'\binet\s+{re.escape(str(addr))}/', local):
            raise ValueError('Bind address is not configured on this host')
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
            old = int(json.loads(pidfile.read_text()).get('pid'))
        except (ValueError, OSError, TypeError):
            old = 0
        if old and Path(f'/proc/{old}').exists():
            raise ValueError(f'Callback listener already running on port {port}')
        pidfile.unlink(missing_ok=True)
    argv = [self_path, 'callback', '--action', 'listen', '--task-id', str(task),
            '--port', str(port), '--timeout', str(int(timeout))]
    if bind:
        argv += ['--bind', bind]
    with (outdir / 'listener.log').open('ab') as log:
        process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=log,
                                  stderr=log, start_new_session=True,
                                  env={'PATH': '/usr/bin:/bin', 'HOME': '/root', 'LC_ALL': 'C'})
    pidfile.write_text(json.dumps({'pid': process.pid, 'port': port,
                                   'bind': bind or '0.0.0.0',
                                   'scope': config['allowed'],
                                   'expires': int(time.time() + int(timeout))}))
    return {'status': 'listening', 'task_id': task, 'port': port,
            'bind': bind or '0.0.0.0', 'pid': process.pid,
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
            if 'callback' in cmdline and str(task) in cmdline:
                try:
                    os.kill(pid, signal.SIGTERM)
                    killed.append(pid)
                except ProcessLookupError:
                    pass
        path.unlink(missing_ok=True)
    return {'status': 'closed', 'task_id': task, 'killed': killed}


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
    return meta


def session_alive(meta):
    pid = int(meta.get('pid') or 0)
    if pid <= 0 or not Path(f'/proc/{pid}').exists():
        return False
    try:
        cmdline = Path(f'/proc/{pid}/cmdline').read_bytes().decode('utf-8', 'replace')
    except OSError:
        return False
    return 'session-worker' in cmdline


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


def session_open(task, argv, idle):
    """Start a long-lived interactive session inside the task namespace."""
    ensure_root()
    v, config = owned_config(task)
    if not config['allowed']:
        raise ValueError('Task has no allowed scope')
    directory = session_dir(task)
    live = 0
    for path in sorted(directory.glob('*.json')):
        try:
            meta = json.loads(path.read_text())
        except (ValueError, OSError):
            path.unlink(missing_ok=True)
            continue
        if session_alive(meta):
            live += 1
        else:
            path.unlink(missing_ok=True)
    if live >= SESSION_MAX:
        raise ValueError(f'Too many open sessions (max {SESSION_MAX}); close one first')
    shell = [str(item) for item in (argv or ['/bin/bash', '--noprofile', '--norc', '-i'])]
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
    session_id = os.urandom(4).hex()
    socket_path = directory / f'{session_id}.sock'
    log_path = directory / f'{session_id}.log'
    idle = max(60, min(int(idle or SESSION_IDLE), SESSION_IDLE_MAX))
    meta = {'task_id': task, 'session_id': session_id, 'pid': 0,
            'socket': str(socket_path), 'log': str(log_path),
            'workdir': str(workdir), 'argv': shell, 'idle': idle,
            'created': int(time.time()), 'scope': config['allowed']}
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
    fd = os.open(meta_path, os.O_WRONLY | os.O_TRUNC)
    with os.fdopen(fd, 'w') as handle:
        json.dump(meta, handle)
    for _ in range(120):
        if socket_path.exists() or process.poll() is not None:
            break
        time.sleep(0.05)
    if not socket_path.exists():
        process.kill()
        meta_path.unlink(missing_ok=True)
        raise RuntimeError(f'Session did not start; see {log_path}')
    return {'status': 'opened', 'task_id': task, 'session_id': session_id,
            'pid': process.pid, 'argv': shell, 'workdir': str(workdir),
            'idle_timeout': idle, 'accepts_from': config['allowed'],
            'note': 'state persists: send input, then read output; /work keeps files'}


def session_worker(task, session_id):
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
    command = isolated_command(v['name'], config['owner'], config['uid'],
                               config['gid'], argv, workdir=workdir,
                               new_session=False)
    default_shell = argv == ['/bin/bash', '--noprofile', '--norc', '-i']
    if default_shell:
        separator = command.index('--')
        command[separator:separator] = ['--setenv', 'PS1', 'PM_SESSION> ']
    child, master = os.forkpty()
    if child == 0:
        try:
            os.execv(command[0], command)
        except OSError:
            os._exit(127)
    os.set_blocking(master, False)
    buffer = bytearray()
    cursor = 0
    last_request = time.monotonic()
    log = open(log_path, 'ab', buffering=0)

    def drain(seconds=0.0):
        """Move PTY output into the buffer; False means the child is gone."""
        nonlocal cursor
        deadline = time.monotonic() + max(0.0, seconds)
        while True:
            try:
                chunk = os.read(master, 65536)
            except BlockingIOError:
                chunk = b''
            except OSError:
                return False
            if chunk:
                buffer.extend(chunk)
                try:
                    log.write(chunk)
                except OSError:
                    pass
                overflow = len(buffer) - SESSION_OUTPUT_KEEP
                if overflow > 0:
                    del buffer[:overflow]
                    cursor = max(0, cursor - overflow)
                continue
            if time.monotonic() >= deadline:
                return True
            time.sleep(0.05)

    def take():
        nonlocal cursor
        text = bytes(buffer[cursor:]).decode('utf-8', 'replace')
        cursor = len(buffer)
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
            return {'status': 'running', 'pid': child, 'session_id': session_id,
                    'workdir': str(workdir),
                    'buffered': len(buffer) - cursor}, False
        if op == 'read':
            drain(wait)
            text = take()
            return {'status': 'ok', 'output': text, 'chars': len(text),
                    'prompt_seen': prompt_seen()}, False
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
                     'prompt_seen': prompt_seen()}
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
        try:
            os.killpg(child, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass
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


def session_send(task, session_id, data, wait):
    ensure_root()
    owned_config(task)
    if len(str(data).encode('utf-8')) > SESSION_DATA_MAX:
        raise ValueError('Session input is too large')
    meta = session_meta(task, session_id)
    if not session_alive(meta):
        raise ValueError('Session is not running')
    return session_request(meta, {'op': 'send', 'data': str(data),
                                  'wait': float(wait or 0)})


def session_interrupt(task, session_id, wait):
    ensure_root()
    owned_config(task)
    meta = session_meta(task, session_id)
    if not session_alive(meta):
        raise ValueError('Session is not running')
    return session_request(meta, {'op': 'interrupt', 'wait': float(wait or 0)})


def session_read(task, session_id, wait):
    ensure_root()
    owned_config(task)
    meta = session_meta(task, session_id)
    if not session_alive(meta):
        raise ValueError('Session is not running')
    return session_request(meta, {'op': 'read', 'wait': float(wait or 0)})


def session_close(task, session_id):
    ensure_root()
    owned_config(task)
    meta = session_meta(task, session_id)
    pid = int(meta.get('pid') or 0)
    if session_alive(meta):
        try:
            session_request(meta, {'op': 'close'}, timeout=10)
        except (OSError, ValueError, RuntimeError):
            pass
    killed = False
    for _ in range(40):
        if not pid or not Path(f'/proc/{pid}').exists():
            break
        time.sleep(0.05)
    if pid and Path(f'/proc/{pid}').exists():
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


def session_list(task):
    ensure_root()
    owned_config(task)
    directory = session_dir(task)
    sessions = []
    for path in sorted(directory.glob('*.json')):
        try:
            meta = json.loads(path.read_text())
        except (ValueError, OSError):
            path.unlink(missing_ok=True)
            continue
        alive = session_alive(meta)
        sessions.append({'session_id': meta.get('session_id'),
                         'pid': meta.get('pid'), 'running': alive,
                         'argv': meta.get('argv'),
                         'idle_timeout': meta.get('idle'),
                         'created': meta.get('created'),
                         'log': meta.get('log')})
        if not alive:
            path.unlink(missing_ok=True)
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
    s = sub.add_parser('setup')
    s.add_argument('--task-id', type=int, required=True)
    s.add_argument('--owner', required=True)
    s.add_argument('--allow', action='append', required=True)
    s.add_argument('--egress', default='auto')
    t = sub.add_parser('teardown')
    t.add_argument('--task-id', type=int, required=True)
    wi = sub.add_parser('workdir')
    wi.add_argument('--task-id', type=int, required=True)
    r = sub.add_parser('run')
    r.add_argument('--task-id', type=int, required=True)
    r.add_argument('--profile', required=True)
    r.add_argument('--target', required=True)
    r.add_argument('--port', default='80')
    r.add_argument('--ports', default='80,443')
    r.add_argument('--scheme', default='http')
    r.add_argument('--path', default='/')
    r.add_argument('--hostname', default='')
    r.add_argument('--capture-limit',type=int,choices=HTTP_CAPTURE_LIMITS,default=HTTP_CAPTURE_BODY_LIMIT)
    r.add_argument('--argv', action='append', default=None)
    r.add_argument('--poc-file', default='')
    r.add_argument('--poc-interp', default='bash', choices=POC_INTERPRETERS)
    r.add_argument('--research-host', default='')
    r.add_argument('--timeout', default='')
    hs = sub.add_parser('hosts')
    hs.add_argument('--task-id', type=int, required=True)
    hs.add_argument('--hostname', action='append', required=True)
    cb = sub.add_parser('callback')
    cb.add_argument('--action', required=True, choices=('open', 'read', 'close', 'listen'))
    cb.add_argument('--task-id', type=int, required=True)
    cb.add_argument('--port', default='')
    cb.add_argument('--bind', default='')
    cb.add_argument('--timeout', default='300')
    cb.add_argument('--since', default='')
    se = sub.add_parser('session')
    se.add_argument('--action', required=True,
                    choices=('open', 'send', 'read', 'interrupt', 'close', 'list'))
    se.add_argument('--task-id', type=int, required=True)
    se.add_argument('--session-id', default='')
    se.add_argument('--argv', action='append', default=None)
    se.add_argument('--data', default='')
    se.add_argument('--wait', default='0.8')
    se.add_argument('--idle', default=str(SESSION_IDLE))
    sw = sub.add_parser('session-worker')
    sw.add_argument('--task-id', type=int, required=True)
    sw.add_argument('--session-id', required=True)
    sf = sub.add_parser('sync-forward')
    sf.add_argument('--task-id', type=int, required=True)
    st = sub.add_parser('status')
    st.add_argument('--task-id', type=int, required=True)
    args = parser.parse_args()
    try:
        if args.command == 'capabilities':
            output({'capture_protocol': 1,
                    'profiles': ['http_capture', 'exec', 'poc_run', 'research', 'session'],
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
        elif args.command == 'setup': setup(args.task_id, args.owner, args.allow, args.egress)
        elif args.command == 'teardown': teardown(args.task_id)
        elif args.command == 'workdir': output(workdir_init(args.task_id))
        elif args.command == 'run': run(args.task_id, args.profile, args.target,
                                        args.port, args.ports, args.scheme, args.path, args.hostname,args.capture_limit,
                                        argv=args.argv, poc_file=args.poc_file, poc_interp=args.poc_interp,
                                        research_host=args.research_host, timeout=args.timeout or None)
        elif args.command == 'sync-forward': sync_forward(args.task_id)
        elif args.command == 'callback':
            action = args.action
            if action == 'open':
                output(callback_open(args.task_id, args.port or '4444', args.bind, args.timeout))
            elif action == 'read':
                output(callback_read(args.task_id, args.since or None))
            elif action == 'close':
                output(callback_close(args.task_id, args.port or None))
            else:
                output(callback_listen(args.task_id, args.port or '4444', args.bind, args.timeout))
        elif args.command == 'session-worker':
            session_worker(args.task_id, args.session_id)
        elif args.command == 'session':
            action = args.action
            if action == 'open':
                output(session_open(args.task_id, args.argv, args.idle))
            elif action == 'list':
                output(session_list(args.task_id))
            elif action == 'send':
                output(session_send(args.task_id, args.session_id, args.data, args.wait))
            elif action == 'read':
                output(session_read(args.task_id, args.session_id, args.wait))
            elif action == 'interrupt':
                output(session_interrupt(args.task_id, args.session_id, args.wait))
            else:
                output(session_close(args.task_id, args.session_id))
        elif args.command == 'hosts': set_hostnames(args.task_id, args.hostname)
        else:
            _, config = owned_config(args.task_id)
            output({'status': 'configured', 'task_id': args.task_id,
                    'allowed': config['allowed'], 'egress': config['egress'],
                    'approved_egress': config.get('approved_egress', config['egress']),
                    'current_egress': config.get('current_egress', config['egress']),
                    'host_veth_ip': config['host_ip'],
                    'docker_forward_managed': config.get('docker_forward_managed', False),
                    'hostnames': config.get('hostnames', [])})
    except EgressError as e:
        output({'status': 'blocked', 'kind': 'egress', 'error': str(e)}, fail=True)
    except TimeoutError as e:
        output({'status': 'timeout', 'kind': 'timeout', 'error': str(e)}, fail=True)
    except (ValueError, PermissionError, RuntimeError, OSError,
            subprocess.SubprocessError, KeyError) as e:
        output({'status': 'blocked', 'error': str(e)}, fail=True)


if __name__ == '__main__': main()
