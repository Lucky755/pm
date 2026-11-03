"""Private bounded HTTP body artifacts. No raw response headers in storage/evidence."""
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
import tempfile

ROOT = Path(__file__).resolve().parents[1] / 'artifacts' / 'http'
DEFAULT_BODY = 2 * 1024 * 1024
MAX_BODY = 8 * 1024 * 1024
MAX_TASK_BYTES = 64 * 1024 * 1024
MAX_HEADERS = 65536


def split_response(raw):
    """Parse final HTTP response after informational headers; preserve binary body."""
    offset = 0
    for _ in range(8):
        match = re.match(rb'HTTP/\d(?:\.\d)?[ \t]+(\d{3})[^\r\n]*\r?\n', raw[offset:offset+1024])
        if not match:
            raise ValueError('Capture has no valid HTTP status line')
        start = offset + match.end()
        separator = re.search(rb'\r?\n\r?\n', raw[start:start+MAX_HEADERS])
        # A response with no header fields has just one newline after status.
        if raw[start:start+2] == b'\r\n':
            header_end, body_start = start, start+2
        elif raw[start:start+1] == b'\n':
            header_end, body_start = start, start+1
        elif separator:
            header_end, body_start = start+separator.start(), start+separator.end()
        else:
            raise ValueError('Capture headers are incomplete or exceed the header limit')
        if body_start > MAX_HEADERS:
            raise ValueError('Capture headers exceed the header limit')
        code = int(match[1])
        if 100 <= code < 200 and code != 101:
            offset = body_start
            continue
        headers = {}
        for line in raw[start:header_end].splitlines():
            if b':' not in line:
                raise ValueError('Malformed HTTP header')
            key, value = line.split(b':', 1)
            name = key.decode('ascii', errors='replace').lower().strip()
            if name in ('content-type','content-length','content-encoding','location','server'):
                headers[name] = value.strip().decode('latin-1')[:1000]
        return code, headers, raw[body_start:]
    raise ValueError('Too many informational HTTP responses')


def decode_body(body, headers):
    """Bound decompression and decoding independently; binary content is not text."""
    encoding = headers.get('content-encoding','identity').lower().strip()
    expanded = body
    flags = {'decode_limit': False, 'decode_errors': False, 'text_skipped': None}
    if encoding in ('gzip','x-gzip'):
        try:
            with gzip.GzipFile(fileobj=io.BytesIO(body)) as stream:
                expanded = stream.read(MAX_BODY+1)
        except (OSError, EOFError) as exc:
            flags['text_skipped'] = 'invalid_or_incomplete_gzip'
            return '', flags
        flags['decode_limit'] = len(expanded) > MAX_BODY
        expanded = expanded[:MAX_BODY]
    elif encoding not in ('','identity'):
        flags['text_skipped'] = 'unsupported_content_encoding'
        return '', flags
    ctype = headers.get('content-type','').lower()
    textual = (ctype.startswith('text/') or any(x in ctype for x in
               ('javascript','ecmascript','json','xml','xhtml')))
    if not ctype:
        textual = body.lstrip().lower().startswith((b'<!doctype html',b'<html'))
    if not textual:
        flags['text_skipped'] = 'binary_or_unknown_content_type'
        return '', flags
    charset = re.search(r'charset\s*=\s*["\']?([a-zA-Z0-9_.-]{1,40})', ctype)
    codec = charset[1] if charset else 'utf-8-sig'
    if not charset and expanded.startswith((b'\xff\xfe',b'\xfe\xff')):
        codec = 'utf-16'
    try:
        text = expanded.decode(codec)
    except (LookupError, UnicodeError):
        text = expanded.decode('utf-8', errors='replace')
        flags['decode_errors'] = True
    flags['charset'] = codec
    return text, flags


def initialize(db):
    db.execute('CREATE TABLE IF NOT EXISTS pm_http_capture_policy ('
               'task_id INTEGER PRIMARY KEY,response_limit INTEGER NOT NULL,updated_at TEXT NOT NULL)')
    db.execute('''CREATE TABLE IF NOT EXISTS pm_http_artifacts (
        id INTEGER PRIMARY KEY, task_id INTEGER NOT NULL, target TEXT NOT NULL,
        scheme TEXT NOT NULL, hostname TEXT NOT NULL, port INTEGER NOT NULL, path TEXT NOT NULL,
        status_code INTEGER NOT NULL, sha256 TEXT NOT NULL, bytes_saved INTEGER NOT NULL,
        complete INTEGER NOT NULL, metadata_json TEXT NOT NULL, created_at TEXT NOT NULL)''')


def response_limit(db, task_id):
    row = db.execute('SELECT response_limit FROM pm_http_capture_policy WHERE task_id=?',(task_id,)).fetchone()
    limit = row[0] if row else DEFAULT_BODY
    if limit not in (DEFAULT_BODY,MAX_BODY):
        raise ValueError('Unsupported task HTTP capture limit')
    return limit


def set_response_limit(db, task_id, limit, stamp):
    if limit not in (DEFAULT_BODY,MAX_BODY):
        raise ValueError('Response limit must be 2 or 8 MiB')
    if not db.execute('SELECT 1 FROM tasks WHERE id=?',(task_id,)).fetchone():
        raise ValueError('Task not found')
    initialize(db)
    previous = response_limit(db,task_id)
    with db:
        db.execute('CREATE TABLE IF NOT EXISTS pm_http_capture_policy_history ('
                   'id INTEGER PRIMARY KEY,task_id INTEGER,previous_limit INTEGER,new_limit INTEGER,created_at TEXT)')
        if previous != limit:
            db.execute('INSERT INTO pm_http_capture_policy_history(task_id,previous_limit,new_limit,created_at) VALUES(?,?,?,?)',
                       (task_id,previous,limit,stamp))
        db.execute('INSERT INTO pm_http_capture_policy VALUES(?,?,?) ON CONFLICT(task_id) DO UPDATE '
                   'SET response_limit=excluded.response_limit,updated_at=excluded.updated_at',(task_id,limit,stamp))


def _directory(task_id):
    if type(task_id) is not int or task_id <= 0:
        raise ValueError('Invalid artifact task')
    # This writer is unprivileged. Reject links and unsafe existing artifact dirs.
    for directory in (ROOT, ROOT / f'task-{task_id}'):
        directory.mkdir(mode=0o700, parents=directory == ROOT, exist_ok=True)
        info = directory.lstat()
        if not stat.S_ISDIR(info.st_mode) or directory.is_symlink() or info.st_uid != os.getuid():
            raise ValueError('Unsafe HTTP artifact directory')
        directory.chmod(0o700)
    return ROOT / f'task-{task_id}'


def save(db, task_id, target, scheme, host, port, path, capture, stamp):
    initialize(db)
    body = capture['body']
    if len(body) > MAX_BODY:
        raise ValueError('Artifact exceeds body limit')
    digest = hashlib.sha256(body).hexdigest()
    present = db.execute('SELECT 1 FROM pm_http_artifacts WHERE task_id=? AND sha256=?', (task_id,digest)).fetchone()
    used = db.execute('SELECT COALESCE(SUM(bytes_saved),0) FROM '
                      '(SELECT MAX(bytes_saved) bytes_saved FROM pm_http_artifacts WHERE task_id=? GROUP BY sha256)',
                      (task_id,)).fetchone()[0]
    if not present and used+len(body) > MAX_TASK_BYTES:
        raise ValueError('Task HTTP artifact storage budget exceeded')
    directory = _directory(task_id)
    destination = directory / (digest+'.body')
    if destination.is_symlink():
        raise ValueError('Unsafe HTTP artifact file')
    handle, temporary = tempfile.mkstemp(prefix='.capture-',dir=directory)
    try:
        with os.fdopen(handle,'wb') as stream:
            stream.write(body)
        os.replace(temporary,destination)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    metadata = {k:v for k,v in capture['metadata'].items()}
    # Only these headers may be persisted; no cookies/auth/location query.
    metadata['headers'] = {k:v for k,v in capture['headers'].items()
                          if k in ('content-type','content-length','content-encoding','server')}
    with db:
        cursor = db.execute('INSERT INTO pm_http_artifacts '
            '(task_id,target,scheme,hostname,port,path,status_code,sha256,bytes_saved,complete,metadata_json,created_at) '
            'VALUES (?,?,?,?,?,?,?,?,?,?,?,?)',
            (task_id,target,scheme,host,port,path,capture['status'],digest,len(body),int(capture['complete']),json.dumps(metadata),stamp))
    return cursor.lastrowid


def info(db, artifact_id):
    row = db.execute('SELECT id,sha256,bytes_saved,complete,metadata_json,status_code FROM pm_http_artifacts WHERE id=?',
                     (artifact_id,)).fetchone()
    if not row:
        raise ValueError('HTTP artifact not found')
    return {'artifact_id':row[0],'sha256':row[1],'bytes_saved':row[2],
            'download_complete':bool(row[3]),'processing':json.loads(row[4]),'status_code':row[5]}


def load(db, task_id, artifact_id):
    row = db.execute('SELECT sha256,bytes_saved,metadata_json FROM pm_http_artifacts WHERE id=? AND task_id=?',
                     (artifact_id,task_id)).fetchone()
    if not row or not re.fullmatch(r'[0-9a-f]{64}',row[0]):
        raise ValueError('Artifact does not belong to this task')
    path = _directory(task_id) / (row[0]+'.body')
    descriptor = os.open(path,os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(descriptor,'rb') as stream:
        details = os.fstat(stream.fileno())
        if not stat.S_ISREG(details.st_mode) or details.st_uid != os.getuid() or details.st_mode & 0o077:
            raise ValueError('Unsafe HTTP artifact permissions')
        body = stream.read(MAX_BODY+1)
    if len(body) != row[1] or hashlib.sha256(body).hexdigest() != row[0]:
        raise ValueError('HTTP artifact checksum mismatch')
    return body,json.loads(row[2])


def diagnostic_text(text):
    """Best-effort terminal-only redaction. Raw artifacts stay private/local."""
    text = re.sub(r'(?is)(<input\b[^>]*\bvalue\s*=\s*)(["\']).*?\2',r'\1"[REDACTED]"',text)
    text = re.sub(r'''(?is)(<input\b[^>]*\bvalue\s*=\s*)(?!["'])([^\s>]+)''',r'\1[REDACTED]',text)
    text = re.sub(r'(?is)(<textarea\b[^>]*>).*?(</textarea>)',r'\1[REDACTED]\2',text)
    text = re.sub(r'''(?ix)((?:["']?)(?:password|passwd|token|secret|api[_-]?key|authorization|cookie|sessionid)(?:["']?)\s*[:=]\s*)(["'])(?:\\.|(?!\2).)*?\2''',r'\1"[REDACTED]"',text)
    return re.sub(r'[\x00-\x08\x0b-\x1f\x7f-\x9f]', '',text)
