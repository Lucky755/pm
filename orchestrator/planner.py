
import argparse
import getpass
import ipaddress
import json
import re
import sqlite3
import sys
import urllib.request
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path("/home/lucky/pentest-master")
DATABASE = ROOT / "storage" / "tasks.db"
API_URL = "https://api.experientiallabs.ai/v1/chat/completions"
MODEL = "glm-5.3-uncensored"
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from orchestrator import diagnostics
# A trailing sentence period is not part of the address: "10.1.1.1." must
# still be seen, otherwise a stale address survives in the plan text.
IPV4_RE = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?!\w|\.\d)")
# Same shape, but not the network part of a CIDR (10.0.0.0/8 stays as written):
# that address describes a range, not the lab machine we are following.
CONTEXT_ADDRESS_RE = re.compile(
    r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?!\w|\.\d|/\d{1,2}(?!\d))")


def version_label(value, index):
    """True when the match is announced as a version, not as a host address.

    Four-part product versions (1.2.3.4) are indistinguishable from IPv4 by
    shape alone, so the label in front of them is the only cheap signal.
    """
    prefix = value[max(0, index - 20):index]
    return re.search(r'(?:version|версия)\s*[:=]?\s*\Z', prefix, re.I) is not None

SYSTEM_PROMPT = """
You are a planning component for an authorized cybersecurity lab.

Convert the operator's natural-language task into a structured plan.
Only the explicitly supplied target is authorized.

Do not execute commands or claim that tests have been performed.
Do not expand the target scope based on the operator's description.

Return a JSON object with:
- summary: string
- target: string
- objectives: array of strings
- tasks: array of objects with:
  - agent: recon, vuln, access, or verify
  - instruction: string
  - asset_kind, asset_key: optional typed asset targeted by this step
  - new_evidence_id: optional result ID justifying a repeated probe
  - depends_on: array of integer task indexes
  - depends_on содержит индексы ТОЛЬКО предыдущих шагов (нумерация с 0); шаг не может ссылаться на себя
- checkpoints: array of strings

Use concise, concrete task descriptions. Each instruction should be a testable
yes/no question answerable with one decisive probe. The first recon pass may
stay broad when no service map exists; later instructions must be narrow.
Prior evidence context is a hint, never an expansion of authorized scope.
Do not plan a repeated check of a closed asset without a new result ID.
Return JSON only, without Markdown.
"""

RAW_DIR = ROOT / "storage" / "planner_raw"


def parse_json_response(content):
    """Parse the plan even when the model wraps it in prose.

    A single stray character used to abort task creation with a bare
    JSONDecodeError, and nothing recorded what the model returned, so the cause
    could not be inspected afterwards. Strict parsing is tried first, then the
    first complete JSON object is located inside the text.
    """
    text = (content or "").strip()
    if not text:
        raise ValueError("Planner returned an empty response")

    candidates = [text]
    candidates += [
        match.strip()
        for match in re.findall(r"```(?:json)?\s*\n(.*?)\n?```", text, re.I | re.S)
    ]
    decoder = json.JSONDecoder()

    seen_object = False
    for candidate in candidates:
        try:
            parsed = json.loads(candidate)
        except ValueError:
            parsed = None
        if isinstance(parsed, dict):
            if "tasks" in parsed:
                return parsed
            seen_object = True
        for match in re.finditer(r"\{", candidate):
            try:
                parsed, _ = decoder.raw_decode(candidate, match.start())
            except ValueError:
                continue
            if isinstance(parsed, dict) and "tasks" in parsed:
                return parsed

    if seen_object:
        raise ValueError("Planner JSON has no \"tasks\" list")
    raise ValueError("Planner did not return a parsable JSON plan")


def save_raw_plan(target, content, finish_reason):
    """Keep the exact reply so a parse failure can be explained later."""
    RAW_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    path = RAW_DIR / f"plan-{stamp}.json"
    path.write_text(
        json.dumps({"target": target, "finish_reason": finish_reason,
                    "content": content}, ensure_ascii=False),
        encoding="utf-8",
    )
    path.chmod(0o600)
    return path


def request_plan(api_key, target, description, attempts=2, context=None):
    """Ask for the plan, and survive one malformed or truncated reply.

    max_tokens was fixed at 4000 and finish_reason was never inspected, so a
    plan for a larger room could be cut off mid-string and the resulting
    "Expecting ',' delimiter" killed the whole task creation.
    """
    diagnostics.register_secret(api_key)
    last_error = None
    for attempt in range(1, attempts + 1):
        request_text = description
        if attempt > 1:
            request_text = description + (
                "\n\nReturn ONLY one compact JSON object: no markdown, no prose, "
                "every instruction under 200 characters. The previous reply was "
                "not valid JSON."
            )

        payload = {
        "model": MODEL,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {
                "role": "user",
                "content": json.dumps({
                    "authorized_target": target,
                    "operator_request": request_text,
                    "prior_evidence_context": context or {},
                    "autonomy": "automatic_with_checkpoints",
                    "notify_without_pausing": [
                        "credentials_found",
                        "initial_access",
                        "flag_found"
                    ],
                    "approval_required": [
                        "privilege_escalation",
                        "destructive_operation",
                        "system_wide_changes"
                    ]
                }, ensure_ascii=False)
            }
        ],
        "max_tokens": 8000 if attempt > 1 else 4000,
        "stream": False
    }

        request = urllib.request.Request(
            API_URL,
            data=json.dumps(payload).encode("utf-8"),
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json"
            },
            method="POST"
        )

        if attempt > 1:
            diagnostics.emit('model.retry', reason='planner_format')
        with diagnostics.Action('model', 'planner_request'):
            with urllib.request.urlopen(request, timeout=120) as response:
                result = json.load(response)

        choice = result["choices"][0]
        content = choice["message"]["content"]
        finish_reason = choice.get("finish_reason")
        raw_path = save_raw_plan(target, content, finish_reason)

        try:
            return parse_json_response(content)
        except ValueError as exc:
            last_error = exc
            print(f"[!] Ответ планировщика не разобран: {exc}", flush=True)
            print(f"[!] Сырой ответ сохранён: {raw_path}", flush=True)
            if finish_reason == "length":
                print("[!] Ответ обрезан по лимиту вывода — повторяю с большим лимитом",
                      flush=True)
            elif attempt < attempts:
                print("[!] Повторяю запрос с требованием компактного JSON", flush=True)

    raise ValueError(
        f"Planner did not return a parsable JSON plan after {attempts} attempts: "
        f"{last_error}"
    )


def stale_addresses(context, target):
    """Inherited addresses that are not the authorized target."""
    found = set()

    def walk(node):
        if isinstance(node, dict):
            # Keys are context too: an address used as a dict key would
            # otherwise pass unnoticed.
            for key, value in node.items():
                walk(key)
                walk(value)
        elif isinstance(node, (list, tuple)):
            for entry in node:
                walk(entry)
        elif isinstance(node, str):
            for hit in CONTEXT_ADDRESS_RE.finditer(node):
                if not version_label(node, hit.start()):
                    found.add(hit.group(0))

    walk(context or {})
    return found - {target}


def scrub_addresses(value, addresses, target):
    """Replace inherited addresses in place: the plan may name only the target.

    A rebooted lab machine keeps its evidence but changes its address. A stale
    literal in that evidence is a pointer to update, not a scope expansion, and
    letting the planner copy it produces a plan the validator rejects whole.
    """
    if isinstance(value, dict):
        cleaned = {}
        for key, item in list(value.items()):
            new_key = (scrub_addresses(key, addresses, target)
                       if isinstance(key, str) else key)
            if new_key in cleaned:
                # Two keys must not collapse into one: keep both entries, the
                # later one under a suffixed name, so no evidence is dropped.
                suffix = 2
                while f'{new_key}#{suffix}' in cleaned:
                    suffix += 1
                new_key = f'{new_key}#{suffix}'
            cleaned[new_key] = scrub_addresses(item, addresses, target)
        value.clear()
        value.update(cleaned)
        return value
    if isinstance(value, list):
        for position, entry in enumerate(value):
            value[position] = scrub_addresses(entry, addresses, target)
        return value
    if isinstance(value, str) and addresses:
        def replace(hit):
            if hit.group(0) not in addresses:
                return hit.group(0)
            if version_label(value, hit.start()):
                return hit.group(0)
            return target
        return CONTEXT_ADDRESS_RE.sub(replace, value)
    return value


def validate_plan(plan, target, stale=()):
    if not isinstance(plan, dict):
        raise ValueError("Expected a JSON object")

    if plan.get("target") != target:
        raise ValueError("Model returned a different target")

    tasks = plan.get("tasks")
    if not isinstance(tasks, list) or not tasks:
        raise ValueError("Plan must contain tasks")

    allowed_agents = {"recon", "vuln", "access", "verify"}

    for index, task in enumerate(tasks):
        if task.get("agent") not in allowed_agents:
            raise ValueError(f"Invalid agent in task {index}")
        if not isinstance(task.get("instruction"), str):
            raise ValueError(f"Invalid instruction in task {index}")

        dependencies = task.get("depends_on", [])
        if not isinstance(dependencies, list):
            raise ValueError("Invalid task dependencies")
        if any(
            not isinstance(d, int) or d < 0 or d > index
            for d in dependencies
        ):
            raise ValueError("Invalid or forward task dependency")
        task["depends_on"] = [d for d in dependencies if d != index]

    # A stale address that came from inherited evidence is corrected, never
    # accepted: the plan may name the authorized target and nothing else.
    inherited = {address for address in stale if address != target}
    if inherited:
        scrub_addresses(plan, inherited, target)

    # Verify target references throughout the generated plan.
    plan_text = json.dumps(plan, ensure_ascii=False)

    for hit in IPV4_RE.finditer(plan_text):
        candidate = hit.group(0)
        if candidate == target:
            continue
        # A loopback literal cannot name another machine: it refers to the
        # loopback stack of whatever host the instruction is about. Real
        # egress is enforced by the task netns, not by plan text.
        try:
            if ipaddress.ip_address(candidate).is_loopback or candidate == '0.0.0.0':
                continue
        except ValueError:
            pass
        if version_label(plan_text, hit.start()):
            # "version: 1.2.3.4" is a product version, not a target reference.
            continue
        raise ValueError(
            f"Unexpected or malformed target in plan: {candidate}. "
            f"Authorized target: {target}"
        )


def filter_closed_steps(plan, context):
    """Keep indexes stable; mark redundant steps so dependencies still resolve."""
    closed = context.get('closed') or []
    current_ids = set(context.get('current_result_ids') or [])
    skipped = 0
    for task in plan.get('tasks') or []:
        instruction = str(task.get('instruction') or '')
        explicit = (str(task.get('asset_kind') or ''), str(task.get('asset_key') or ''))
        matched = None
        for item in closed:
            kind, key = str(item.get('kind') or ''), str(item.get('key') or '')
            if explicit == (kind, key):
                matched = item
                break
        if matched is None and re.search(r'\b(?:check|inspect|enumerate|scan|probe|'
                                         r'провер|осмотр|перебор|скан)\w*',
                                         instruction, re.I):
            aliases = []
            for item in closed:
                alias = str(item.get('key') or '').rstrip('/').rsplit('/', 1)[-1]
                variants = (alias, alias[:-1]) if alias.endswith('s') and len(alias) >= 4 else (alias,)
                if len(alias) >= 4 and any(re.search(
                        r'(?<!\w)' + re.escape(value) + r'(?!\w)', instruction, re.I)
                        for value in variants):
                    aliases.append(item)
            # Free text is ambiguous: require two closed references before skipping.
            if len(aliases) >= 2:
                matched = aliases[0]
        if matched and str(task.get('new_evidence_id') or '') not in current_ids:
            task['status'] = 'skipped'
            task['skip_reason'] = ('Повтор закрытого актива без нового свидетельства: '
                                   f"{matched.get('kind')} {matched.get('key')}")
            skipped += 1
    steps = plan.get('tasks') or []
    for index, task in enumerate(steps):
        if task.get('status') == 'skipped':
            continue
        expanded = set()
        pending = list(task.get('depends_on') or [])
        while pending:
            dep = pending.pop()
            if dep >= index or dep < 0:
                continue
            if steps[dep].get('status') == 'skipped':
                pending.extend(steps[dep].get('depends_on') or [])
            else:
                expanded.add(dep)
        task['depends_on'] = sorted(expanded)
    return skipped


def plan_with_context(api_key, target, description, context=None, planner_call=None):
    """One bounded retry only when useful open work exists and filtering is severe."""
    context = context or {}
    inherited = stale_addresses(context, target)
    if inherited:
        # Same box, previous address: update the pointers instead of paying for
        # a plan that the target validator must reject whole.
        print("[!] В контексте переноса найден прежний адрес "
              f"({', '.join(sorted(inherited))}) — заменён на {target}.",
              flush=True)
        # Deep copy: scrub_addresses mutates nested dicts in place, and a
        # shallow copy would rewrite the caller's own context as a side effect.
        context = scrub_addresses(deepcopy(context), inherited, target)
        description = scrub_addresses(description, inherited, target)
    caller = planner_call or request_plan
    plan = caller(api_key, target, description, context=context)
    validate_plan(plan, target, inherited)
    filter_closed_steps(plan, context)
    active = sum(task.get('status') != 'skipped' for task in plan['tasks'])
    if active < 3 and context.get('open'):
        second = dict(context)
        second['instruction'] = 'Предложи работу по ОТКРЫТО; закрытые активы не повторяй.'
        retry = caller(api_key, target, description, context=second)
        validate_plan(retry, target, inherited)
        filter_closed_steps(retry, context)
        if sum(task.get('status') != 'skipped' for task in retry['tasks']) > active:
            plan = retry
    return plan

def save_plan(target, description, plan):
    DATABASE.parent.mkdir(parents=True, exist_ok=True)

    with sqlite3.connect(DATABASE) as db:
        db.execute("""
            CREATE TABLE IF NOT EXISTS tasks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at TEXT NOT NULL,
                target TEXT NOT NULL,
                description TEXT NOT NULL,
                plan_json TEXT NOT NULL,
                status TEXT NOT NULL
            )
        """)

        cursor = db.execute("""
            INSERT INTO tasks
            (created_at, target, description, plan_json, status)
            VALUES (?, ?, ?, ?, ?)
        """, (
            datetime.now(timezone.utc).isoformat(),
            target,
            description,
            json.dumps(plan, ensure_ascii=False),
            "pending_review"
        ))

        return cursor.lastrowid


@diagnostics.entrypoint
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", required=True)
    parser.add_argument("--task", required=True)
    parser.add_argument("--context-file")
    args = parser.parse_args()

    target = str(ipaddress.ip_address(args.target))

    api_key = getpass.getpass("Experiential API key: ").strip()
    if not api_key:
        raise SystemExit("API key is required")

    context = {}
    if args.context_file:
        source = Path(args.context_file)
        if source.is_symlink() or source.stat().st_size > 65536:
            raise SystemExit('Unsafe planner context file')
        context = json.loads(source.read_text(encoding='utf-8'))
        if not isinstance(context, dict):
            raise SystemExit('Planner context must be an object')

    print("[1] Requesting plan from GLM...")
    plan = plan_with_context(api_key, target, args.task, context)

    print("[2] Validating plan...")
    try:
        validate_plan(plan, target)
    except ValueError as exc:
        print(f"PM_PLAN_VALIDATION_ERROR: {exc}", file=sys.stderr, flush=True)
        raise SystemExit(2) from exc

    task_id = save_plan(target, args.task, plan)
    diagnostics.emit('state.change', task_id=task_id, table='tasks',
                     identifiers={'id': task_id}, status='pending_review')

    print("[3] Plan saved to SQLite.")
    print("Task ID:", task_id)
    print("Status: pending_review")
    print(json.dumps(plan, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
