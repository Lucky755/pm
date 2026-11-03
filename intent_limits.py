"""Shared character limits for operator intent and agent context."""

INTENT_MAX = 6000
HINTS_MAX = 6000


def clip_intent(text):
    text = str(text or '')
    if len(text) <= INTENT_MAX:
        return text
    omitted = len(text) - INTENT_MAX
    return text[:INTENT_MAX] + f'…[обрезано {omitted} символов]'
