"""Extract bounded public application hints; never execute scripts or issue requests."""
import re


def extract(body, content_type):
    """Return explicit product/version claims, not verified installed versions."""
    if not isinstance(body, str):
        raise ValueError('Expected text body')
    if not any(kind in (content_type or '').lower() for kind in ('html', 'javascript', 'ecmascript', 'text/css')):
        return []
    hints = []
    # Require the product name adjacent to a version. Generic `version` fields
    # in library scripts must never be attributed to the application.
    pattern = r'\b(MagnusBilling)[ \t]*(?:version[ \t]*[:=]?[ \t]*|v[ \t]*|[:=-][ \t]*)?["\']?([0-9]{1,3}(?:\.[0-9]{1,3}){1,3})(?![\w.])'
    for match in re.finditer(pattern, body[:8 * 1024 * 1024], re.I):
        hint = {'product': 'MagnusBilling', 'version_claim': match.group(2),
                'verified_product': False, 'source': 'public_response_text'}
        if hint not in hints:
            hints.append(hint)
        if len(hints) == 4:
            break
    return hints
