/** Tool policy for evidence analysis only. Does not affect scheduler executors. */
export const name = 'pm-evidence-readonly';
export const inject = ['tools'];

export function apply(ctx) {
  const reason = 'PM_EVIDENCE_READ_ONLY: analyze supplied observations; tools are disabled';
  // Hide inherited tools before the first model turn, including late registrations.
  ctx.on('agent/created', ({ agent }) => {
    if (typeof agent.ctx.tools.restrict !== 'function') {
      throw new Error('PM_EVIDENCE_READ_ONLY: this Harness version lacks tools.restrict');
    }
    agent.ctx.tools.restrict({ allow: [] });
  });
  // Deny dispatch as well, including an unsolicited call absent from the schemas.
  ctx.on('tools/pre-execute', () => ({ kind: 'deny', reason }));
  // Newer runtimes provide an additional monotonic guard.
  if (typeof ctx.tools.guard === 'function') {
    ctx.tools.guard(() => reason);
  }
}

export default { name, inject, apply };
