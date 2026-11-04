"""Explicit machine reply over the planner PTY, separate from progress text."""
import base64
import json

RESULT_PREFIX = 'PM_PLANNER_RESULT_V1:'


def encode_result(task_id, plan):
    payload = json.dumps({'task_id': task_id, 'plan': plan}, ensure_ascii=False).encode('utf-8')
    return RESULT_PREFIX + base64.b64encode(payload).decode('ascii')


def decode_result(transcript, expected_task_id):
    frames = [line[len(RESULT_PREFIX):] for line in transcript.splitlines()
              if line.startswith(RESULT_PREFIX)]
    if len(frames) != 1:
        raise ValueError('Planner must return exactly one machine reply')
    try:
        reply = json.loads(base64.b64decode(frames[0], validate=True).decode('utf-8'))
    except (ValueError, UnicodeError) as exc:
        raise ValueError('Invalid planner machine reply encoding') from exc
    if (not isinstance(reply, dict) or set(reply) != {'task_id', 'plan'}
            or type(reply['task_id']) is not int or reply['task_id'] <= 0
            or reply['task_id'] != expected_task_id):
        raise ValueError('Planner machine reply task ID mismatch')
    plan = reply['plan']
    if not isinstance(plan, dict) or not isinstance(plan.get('tasks'), list):
        raise ValueError('Invalid planner machine reply structure')
    return plan
