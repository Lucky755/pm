# Current-level access triage

Use saved access_state and saved categories for its current level. If pending,
the concrete assignment must start with ТРИАЖ: and cannot request escalation.
Fill only missing categories: who, where, boundary, reachable, credentials,
next_level. Record a short summary, original result_id and exact quote for each.
Identify the actual user/context, accessible boundaries and already authorized
reachability. An observed additional host or a proposed next level is not
permission to contact it or escalate. Do not change passwords or collect data
beyond the assignment. Preserve previously saved categories and uncertainty;
a narrative or repeated result cannot replace fresh evidence for new access.

Validation coverage: tests/test_agent_prompt_context.py and
tests/test_coordinated_attack.py cover current-level state, evidence links and
the pending-triage gate. They do not certify every possible SSH/shell command.
