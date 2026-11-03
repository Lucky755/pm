/**
 * Tool policy for action agents.
 *
 * Unlike evidence_readonly.mjs this policy keeps every registered tool enabled.
 * Agents may do real work (scans, PoCs, research, scoped callbacks), but the
 * turn is bounded: after STEP_LIMIT executed tool calls the gate denies every
 * further call, so the agent must stop acting and return its JSON report.
 *
 * The budget belongs to one agent instance (one Harness session = one stage),
 * so the orchestrator resets it by starting a new session for the next stage.
 */
export const name = 'pm-agent-actions';
export const inject = ['tools'];
import { readFileSync, writeFileSync } from 'node:fs';

const STEP_LIMIT = Number(process.env.PM_AGENT_STEP_LIMIT || 15);
const POC_BUDGET = Number(process.env.PM_AGENT_POC_BUDGET || 7);

const spent = new WeakMap();
const reads = new WeakMap();
const pocs = new WeakMap();
const sessions = new WeakMap();
const denied = new WeakMap();
const events = new WeakMap();
const recentTools = new WeakMap();
const READ_LIMIT = 64;

export function apply(ctx) {
  ctx.on('tools/pre-execute', (exec) => {
    const agent = exec && exec.agent;

    // Not an agent-driven call: leave policy untouched.
    if (!agent) {
      return { kind: 'allow' };
    }

    const tool = String(exec.name || exec.toolName || exec.tool?.name ||
      exec.tool?.id || exec.call?.name || exec.invocation?.name ||
      exec.tool?.definition?.name ||
      (typeof exec.tool === 'string' ? exec.tool : '') || '');
    if (!spent.has(agent) && process.env.PM_AGENT_STATS_FILE) {
      try {
        const prior = JSON.parse(readFileSync(process.env.PM_AGENT_STATS_FILE, 'utf8'));
        spent.set(agent, Number(prior.calls) || 0);
        reads.set(agent, Number(prior.reads) || 0);
        pocs.set(agent, Number(prior.pocs) || 0);
        sessions.set(agent, Number(prior.sessions) || 0);
        denied.set(agent, Number(prior.denied) || 0);
        events.set(agent, Number(prior.tool_events) || 0);
        recentTools.set(agent, Array.isArray(prior.recent_tools) ?
          prior.recent_tools.slice(-10).map(String) : []);
      } catch { /* A new stage starts with empty counters. */ }
    }
    events.set(agent, (events.get(agent) || 0) + 1);
    const writeStats = () => {
      if (!process.env.PM_AGENT_STATS_FILE) return;
      try {
        writeFileSync(process.env.PM_AGENT_STATS_FILE, JSON.stringify({
          calls: spent.get(agent) || 0,
          steps_used: spent.get(agent) || 0,
          sessions: sessions.get(agent) || 0,
          reads: reads.get(agent) || 0,
          denied: denied.get(agent) || 0,
          pocs: pocs.get(agent) || 0,
          tool_events: events.get(agent) || 0,
          recent_tools: recentTools.get(agent) || [],
          remaining: STEP_LIMIT - (spent.get(agent) || 0),
        }));
      } catch { /* The hard gate still applies if stats cannot be written. */ }
    };
    const reject = (reason) => {
      denied.set(agent, (denied.get(agent) || 0) + 1);
      writeStats();
      return { kind: 'deny', reason };
    };
    if (tool.endsWith('pm_capability_read') || tool.endsWith('pm_evidence_index')) {
      const usedReads = reads.get(agent) || 0;
      if (usedReads >= READ_LIMIT) {
        return reject('PM_READ_LIMIT: return the final JSON report now.');
      }
      reads.set(agent, usedReads + 1);
      writeStats();
      return { kind: 'allow' };
    }

    const used = spent.get(agent) || 0;
    const pocUsed = pocs.get(agent) || 0;

    if (tool.endsWith('pm_poc_run') && pocUsed >= POC_BUDGET) {
      return reject(
        `PM_POC_LIMIT: this stage already used ${POC_BUDGET} PoC runs. ` +
        'Return the final JSON report or use other evidence.');
    }

    if (used >= STEP_LIMIT) {
      return reject(
          `PM_STEP_LIMIT: this stage already used its ${STEP_LIMIT} tool steps ` +
          '(the next stage gets a fresh budget). Do not call any more tools. ' +
          'Return the final JSON report now with what you did, what you ' +
          'observed and what remains unverified.');
    }

    // Rule 7 of the stage prompt asks for a pm_worknote before the report, so
    // the gate must allow it on the final step; otherwise the agent follows the
    // prompt, gets rejected and loses the step it needs to report.
    if (used >= STEP_LIMIT - 1 &&
        !tool.endsWith('pm_write_poc') && !tool.endsWith('pm_worknote')) {
      return reject(
        'PM_FINAL_STEP: Остался один шаг. Разрешены только pm_worknote и ' +
        'pm_write_poc; завершите стадию итоговым JSON-отчётом.');
    }

    // Counting here means a call that later fails or is cancelled still costs
    // a step, so a looping agent cannot refill its budget through errors.
    spent.set(agent, used + 1);
    if (tool.endsWith('pm_poc_run')) pocs.set(agent, pocUsed + 1);
    if (tool.endsWith('pm_session')) sessions.set(agent, (sessions.get(agent) || 0) + 1);
    const recent = recentTools.get(agent) || [];
    recent.push(tool.endsWith('pm_session') ? 'session' : 'other');
    recentTools.set(agent, recent.slice(-10));
    writeStats();

    return { kind: 'allow' };
  });
}

export default { name, inject, apply };
