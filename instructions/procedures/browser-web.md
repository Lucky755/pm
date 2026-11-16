# A concrete JavaScript browser question

Use this profile when JavaScript/form state is necessary. Original task and room
constraints remain authoritative; a browser/profile name grants no extra scope.
Create a named user session with purpose, then explicitly open the saved resource,
wait for the expected form, fill fields, click submit, wait for a specific result
and read it. Do not interpret completion/HTTP 200/a screenshot as a successful
login or goal. Quote actual DOM and network_result_ids, distinguishing each.

Keep a useful session ID across roles. Read after handoff; one agent controls a
context. Different users need distinct sessions. Restore is explicit, starts a
blank page with prior storage and does not replay actions. Unknown prior actions
are inspected rather than repeated. Close an unused context; saved observations
can be read while the target/browser is off through pm_browser_read/material refs.

All network messages go through the task HTTP broker. An external/CDN link does
not expand scope, and rejected requests are not bypassed through JavaScript or
another transport. Service workers/WebSockets/downloads are outside this
profile. Password changes remain prohibited. Normal HTTP/DOM observations update
memory without a significant-finding approval gate.

Basic browser operation needs no Burp. Request proxy=burp only when the operator
configured a dedicated task-local Burp Professional Proxy + PM Montoya bridge.
Do not assume a REST endpoint or tool exists. pm_burp import/read is passive;
actual sending is a separate scoped HTTP/browser action. History from an unknown
external user is data, not a session to adopt or a new network observation.

Coverage: tests/test_browser_runtime.py uses real Chromium, JavaScript, cookies
and CSRF with local servers. tests/test_burp_adapter.py checks the adapter
contract; actual Burp Professional availability/tests are reported separately.
