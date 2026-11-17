"""Explicit byte storage bounds, never silent operator-task truncation."""
MAX_OPERATOR_BYTES = 16 * 1024 * 1024
# Compatibility names describe resource limits, not a 6000-character policy.
INTENT_MAX = MAX_OPERATOR_BYTES
HINTS_MAX = MAX_OPERATOR_BYTES


def read_utf8_file(path):
    from pathlib import Path
    with Path(path).open('rb') as stream:data=stream.read(MAX_OPERATOR_BYTES+1)
    if len(data)>MAX_OPERATOR_BYTES:raise ValueError('UTF-8 input exceeds explicit 16 MiB storage limit; supply referenced materials')
    try:return data.decode('utf-8')
    except UnicodeError as exc:raise ValueError('Input must be a valid UTF-8 file') from exc


def clip_intent(text):
    text = str(text or '')
    if len(text.encode('utf-8')) > MAX_OPERATOR_BYTES:
        raise ValueError('Operator task exceeds explicit 16 MiB storage limit; supply referenced materials')
    return text
