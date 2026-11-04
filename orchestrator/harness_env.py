"""Environment the bundled Harness runtime needs to reach the model gateway.

Measured problem (this host, 2026-11-01): every role turn stopped at the first
model call with ``TRANSPORT: Connection error.`` after six fast retries. The
bundled runtime (``deepseek-harness-sdk-runtime-linux-x64``, Node 24.22) keeps
Node's AddressFamily auto-selection enabled: each candidate address is attempted
with a short per-attempt timeout, so on a slow uplink every attempt is aborted
and ``fetch`` rejects with ``AggregateError``/``ETIMEDOUT``. The OpenAI SDK then
reports ``Connection error.`` and the harness classifies it as TRANSPORT, even
though the gateway itself is healthy:

* ``curl`` to ``/v1/models``: HTTP 401 in 10/10 tries;
* bundled runtime without the fix: 48/48 requests rejected in ~775 ms;
* bundled runtime with the fix: HTTP 401 in ~2 s, every time.

NODE_OPTIONS is inherited by every runtime child, so merging the flags once in
the process environment covers every harness launch, including the MCP child
and any nested node process. The flags are idempotent.
"""

from __future__ import annotations

import os
import shlex
from orchestrator import diagnostics

# --no-network-family-autoselection: one attempt at a time, like curl, so a
#   slow-but-working TCP handshake is never aborted after a few hundred ms.
# --dns-result-order=ipv4first: this host has no IPv6 default route, so trying
#   an AAAA address first only wastes an attempt on ENETUNREACH.
REQUIRED_NODE_FLAGS: tuple[str, ...] = (
    '--no-network-family-autoselection',
    '--dns-result-order=ipv4first',
)


def merge_node_options(current: str | None,
                       required: tuple[str, ...] = REQUIRED_NODE_FLAGS) -> str:
    """Return NODE_OPTIONS with every required flag present exactly once."""
    tokens = shlex.split(current or '')
    for flag in required:
        if flag not in tokens:
            tokens.append(flag)
    return shlex.join(tokens)


def ensure_process_env(environ: dict | None = None) -> str:
    """Merge the flags into NODE_OPTIONS for this process and its children."""
    env = os.environ if environ is None else environ
    merged = merge_node_options(env.get('NODE_OPTIONS'))
    env['NODE_OPTIONS'] = merged
    return merged


def harness_env(extra: dict | None = None) -> dict:
    """Child environment for DeepSeekHarness(env=...) call sites."""
    env = {'NODE_OPTIONS': ensure_process_env(), **diagnostics.child_env()}
    if extra:
        env.update(extra)
        for key, value in extra.items():
            if 'KEY' in key or 'TOKEN' in key:
                diagnostics.register_secret(value)
    return env
