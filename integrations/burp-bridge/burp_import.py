"""Pentest Master Burp History bridge client.

- Read-only, localhost only, shared token stored as mode 0600.
- Imports metadata only; no raw URLs, headers, cookies, bodies or auth tokens.
- Task Scope checked before requesting or saving any item.
- Does not trigger network requests against the target itself.
"""

import argparse
import ipaddress
import json
import re
import sqlite3
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from executor.task_scope import check_action

DB_PATH = ROOT / "storage/tasks.db"
TOKEN = Path.home() / ".config/pentest-master/burp-bridge.token"
API = "http://127.0.0.1:17779"
SHA256 = re.compile(r"^[0-9a-f]{64}$")
METHOD = re.compile(r"^[A-Z]{1,16}$")


def connect():
    db = sqlite3.connect(DB_PATH, timeout=10)
    db.execute("PRAGMA foreign_keys = ON")
    db.execute("PRAGMA busy_timeout = 5000")
    db.execute("""
        CREATE TABLE IF NOT EXISTS burp_history_observations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            task_id INTEGER NOT NULL,
            instance_id TEXT NOT NULL,
            burp_id INTEGER NOT NULL,
            host TEXT NOT NULL,
            port INTEGER NOT NULL,
            tls INTEGER NOT NULL,
            method TEXT NOT NULL,
            path_sha256 TEXT NOT NULL,
            has_response INTEGER NOT NULL,
            status_code INTEGER NOT NULL,
            observed_at TEXT NOT NULL,
            imported_at TEXT NOT NULL,
            UNIQUE(task_id, instance_id, burp_id)
        )
    """)
    db.execute("""
        CREATE INDEX IF NOT EXISTS idx_burp_history_task
        ON burp_history_observations(task_id, id)
    """)
    db.commit()
    return db


def authorized_target(db, task_id):
    if type(task_id) is not int or task_id <= 0:
        raise ValueError("Positive task_id required")
    row = db.execute("""
        SELECT t.target, s.initial_target
        FROM tasks AS t JOIN task_scope_settings AS s ON s.task_id = t.id
        WHERE t.id = ?
    """, (task_id,)).fetchone()
    if row is None or row[0] != row[1]:
        raise ValueError("Task has no valid initialized target")
    target = str(ipaddress.IPv4Address(row[0]))
    decision = check_action(db, task_id, "connect", target)
    if decision.get("decision") != "ALLOW":
        raise ValueError("Task Scope denied Burp target")
    return target


def request(path, params=None):
    if TOKEN.is_symlink():
        raise RuntimeError("Burp Bridge token must not be a symlink")
    if not TOKEN.is_file():
        raise RuntimeError("Burp Bridge token missing. Start Burp and load the extension.")
    if TOKEN.stat().st_mode & 0o077:
        raise RuntimeError("Insecure Burp Bridge token permissions (expected 0600)")
    key = TOKEN.read_text(encoding="ascii").strip()
    if len(key) < 32:
        raise RuntimeError("Invalid bridge token")
    url = API + path + ("?" + urllib.parse.urlencode(params) if params else "")
    call = urllib.request.Request(url, headers={"X-Pentest-Master-Token": key})
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(call, timeout=8) as reply:
            raw = reply.read(150_000 + 1)
    except (urllib.error.URLError, TimeoutError) as exc:
        raise RuntimeError("Burp Bridge unavailable or refused request") from exc
    if len(raw) > 150_000:
        raise RuntimeError("Burp Bridge response too large")
    obj = json.loads(raw)
    if not isinstance(obj, dict):
        raise RuntimeError("Invalid Burp Bridge response")
    return obj


def health():
    response = request("/health")
    if response.get("status") != "running":
        raise RuntimeError("Burp Bridge not ready")
    return response


def valid_record(record, host):
    if not isinstance(record, dict):
        return False
    try:
        if str(ipaddress.IPv4Address(record.get("host"))) != host:
            return False
    except (ValueError, ipaddress.AddressValueError):
        return False
    return (
        type(record.get("id")) is int and record["id"] >= 0
        and type(record.get("port")) is int and 1 <= record["port"] <= 65535
        and type(record.get("tls")) is bool
        and type(record.get("has_response")) is bool
        and type(record.get("status_code")) is int and 0 <= record["status_code"] <= 599
        and isinstance(record.get("method"), str) and bool(METHOD.fullmatch(record["method"]))
        and isinstance(record.get("path_sha256"), str)
        and bool(SHA256.fullmatch(record["path_sha256"]))
        and isinstance(record.get("observed_at"), str)
        and 0 < len(record["observed_at"]) <= 70
    )


def import_history(task_id, limit=50, after=None):
    if type(limit) is not int or not 1 <= limit <= 100:
        raise ValueError("limit must be 1..100")
    if after is not None and (type(after) is not int or after < 0):
        raise ValueError("after must be nonnegative")

    with connect() as db:
        host = authorized_target(db, task_id)
        session = health()
        instance = session.get("instance_id")
        if not isinstance(instance, str) or not re.fullmatch(r"[0-9a-f-]{36}", instance):
            raise RuntimeError("Invalid Burp Bridge instance_id")
        if after is None:
            after = db.execute("""
                SELECT COALESCE(MAX(burp_id), 0)
                FROM burp_history_observations
                WHERE task_id = ? AND instance_id = ?
            """, (task_id, instance)).fetchone()[0]
        payload = request("/history", {"host": host, "after": after, "limit": limit})
        if (payload.get("status") != "ok" or payload.get("host") != host
                or payload.get("instance_id") != instance
                or not isinstance(payload.get("entries"), list)
                or len(payload["entries"]) > limit):
            raise RuntimeError("Invalid history response or wrong host")

        inserted = 0
        ignored = 0
        for record in payload["entries"]:
            if not valid_record(record, host) or record["id"] <= after:
                raise RuntimeError("Burp Bridge returned malformed or out-of-scope data")
            decision = check_action(db, task_id, "connect", record["host"])
            if decision.get("decision") != "ALLOW":
                raise RuntimeError("Task Scope changed during import")
            cursor = db.execute("""
                INSERT OR IGNORE INTO burp_history_observations (
                    task_id, instance_id, burp_id, host, port, tls, method,
                    path_sha256, has_response, status_code, observed_at, imported_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                task_id, instance, record["id"], host, record["port"],
                int(record["tls"]), record["method"], record["path_sha256"],
                int(record["has_response"]), record["status_code"],
                record["observed_at"], datetime.now(timezone.utc).isoformat()
            ))
            if cursor.rowcount:
                inserted += 1
            else:
                ignored += 1
        return {"status": "completed", "task_id": task_id, "host": host,
                "instance_id": instance, "after": after, "received": len(payload["entries"]),
                "inserted": inserted, "duplicates": ignored}


def list_history(task_id, limit=50):
    if type(limit) is not int or not 1 <= limit <= 100:
        raise ValueError("limit must be 1..100")
    with connect() as db:
        host = authorized_target(db, task_id)
        rows = db.execute("""
            SELECT id, instance_id, burp_id, port, tls, method, path_sha256,
                   has_response, status_code, observed_at
            FROM burp_history_observations
            WHERE task_id = ? AND host = ?
            ORDER BY id DESC LIMIT ?
        """, (task_id, host, limit)).fetchall()
        return {"task_id": task_id, "host": host, "observations": [
            {"observation_id": r[0], "instance_id": r[1], "burp_id": r[2],
             "port": r[3], "scheme": "https" if r[4] else "http",
             "method": r[5], "path_sha256": r[6], "has_response": bool(r[7]),
             "status_code": r[8], "observed_at": r[9]} for r in rows
        ]}


def main():
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("health")
    for operation in ("import", "list"):
        cmd = sub.add_parser(operation)
        cmd.add_argument("--task-id", required=True, type=int)
        cmd.add_argument("--limit", type=int, default=50)
        if operation == "import":
            cmd.add_argument("--after", type=int)
    args = parser.parse_args()
    try:
        if args.command == "health":
            value = health()
        elif args.command == "import":
            value = import_history(args.task_id, args.limit, args.after)
        else:
            value = list_history(args.task_id, args.limit)
        print(json.dumps(value, indent=2, ensure_ascii=False))
    except (ValueError, RuntimeError, sqlite3.Error) as exc:
        print(json.dumps({"status": "blocked", "error": str(exc)}, ensure_ascii=False))
        raise SystemExit(1)


if __name__ == "__main__":
    main()
