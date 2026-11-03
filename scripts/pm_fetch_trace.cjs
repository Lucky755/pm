'use strict';
/**
 * Pentest Master - outbound fetch tracer (diagnostic preload).
 *
 * Load it without touching any package:
 *
 *   NODE_OPTIONS="--require /home/lucky/pentest-master/scripts/pm_fetch_trace.cjs" \
 *   PM_FETCH_LOG=/home/lucky/pentest-master/storage/diagnostics/fetch-trace.jsonl \
 *   .venv/bin/python pm.py
 *
 * Why: the OpenAI SDK collapses every socket-level failure into the opaque
 * "Connection error." message, so the harness can only report TRANSPORT
 * without saying whether the TLS handshake failed, the gateway reset the
 * connection, or the SSE body died mid-stream. This hook records the URL,
 * status, timing and the full error `cause` chain for every request the
 * harness child makes. Credentials are never written: only their length.
 *
 * It is a passive observer - responses are re-wrapped unchanged - and it is
 * active only while NODE_OPTIONS points at it.
 */

const fs = require('node:fs');
const path = require('node:path');

const LOG_PATH = process.env.PM_FETCH_LOG ||
  path.join(process.cwd(), 'storage', 'diagnostics', 'fetch-trace.jsonl');

function write(entry) {
  try {
    fs.mkdirSync(path.dirname(LOG_PATH), { recursive: true });
    fs.appendFileSync(LOG_PATH, JSON.stringify(entry) + '\n');
  } catch (_) {
    /* tracing must never break the request it observes */
  }
}

function describeError(error) {
  const chain = [];
  let current = error;
  for (let depth = 0; current && depth < 6; depth += 1) {
    const item = {
      name: current.name,
      message: String(current.message === undefined ? current : current.message).slice(0, 400),
    };
    for (const field of ['code', 'errno', 'syscall', 'address', 'port', 'status']) {
      if (current[field] !== undefined) item[field] = current[field];
    }
    chain.push(item);
    current = current.cause;
  }
  return chain;
}

function headerSummary(headers) {
  const summary = { names: [], authorizationLength: null };
  if (!headers) return summary;
  let entries;
  if (typeof headers.forEach === 'function' && !Array.isArray(headers)) {
    entries = [];
    headers.forEach((value, name) => entries.push([name, value]));
  } else if (Array.isArray(headers)) {
    entries = headers;
  } else {
    entries = Object.entries(headers);
  }
  for (const [name, value] of entries) {
    const lower = String(name).toLowerCase();
    summary.names.push(lower);
    if (lower === 'authorization') summary.authorizationLength = String(value).length;
  }
  return summary;
}

function bodyBytes(init) {
  if (!init || init.body === undefined || init.body === null) return null;
  const body = init.body;
  if (typeof body === 'string') return Buffer.byteLength(body);
  if (body instanceof Uint8Array) return body.byteLength;
  return -1; // streamed or exotic body
}

function requestUrl(input) {
  if (typeof input === 'string') return input;
  if (input && typeof input.url === 'string') return input.url;
  return String(input);
}

function wrapBody(response, info) {
  const body = response.body;
  if (!body || typeof body.tee !== 'function') return response;
  if (response.status === 204 || response.status === 304) return response;
  let branchA;
  let branchB;
  try {
    [branchA, branchB] = body.tee();
  } catch (_) {
    return response;
  }
  (async () => {
    let bytes = 0;
    try {
      for await (const chunk of branchB) bytes += chunk.length;
      write({ ...info, event: 'body-end', bodyBytes: bytes });
    } catch (error) {
      write({ ...info, event: 'body-error', bodyBytes: bytes, error: describeError(error) });
    }
  })();
  const wrapped = new Response(branchA, {
    status: response.status,
    statusText: response.statusText,
    headers: response.headers,
  });
  try {
    Object.defineProperty(wrapped, 'url', { value: response.url, configurable: true });
  } catch (_) { /* cosmetic only */ }
  return wrapped;
}

if (typeof globalThis.fetch !== 'function') {
  write({ event: 'trace-disabled', reason: 'globalThis.fetch is not a function' });
} else if (!globalThis.__pmFetchTraceInstalled) {
  globalThis.__pmFetchTraceInstalled = true;
  const original = globalThis.fetch;
  globalThis.fetch = function pmTracedFetch(input, init) {
    const info = {
      at: new Date().toISOString(),
      pid: process.pid,
      event: 'request',
      url: requestUrl(input),
      method: (init && init.method) || (input && input.method) || 'GET',
      bodyBytes: bodyBytes(init),
      headers: headerSummary((init && init.headers) || (input && input.headers)),
    };
    const started = Date.now();
    let pending;
    try {
      pending = original.call(this, input, init);
    } catch (error) {
      write({ ...info, event: 'fetch-threw', ms: Date.now() - started, error: describeError(error) });
      throw error;
    }
    return pending.then(
      (response) => {
        const responseInfo = {
          at: info.at,
          pid: info.pid,
          url: info.url,
          method: info.method,
          bodyBytes: info.bodyBytes,
          status: response.status,
          contentType: response.headers.get('content-type'),
          requestId: response.headers.get('x-request-id') || response.headers.get('cf-ray') || null,
          ms: Date.now() - started,
        };
        write({ ...responseInfo, event: 'response' });
        return wrapBody(response, responseInfo);
      },
      (error) => {
        write({
          ...info,
          event: 'fetch-rejected',
          ms: Date.now() - started,
          error: describeError(error),
        });
        throw error;
      },
    );
  };
  write({ event: 'trace-installed', pid: process.pid, node: process.version, log: LOG_PATH });
}
