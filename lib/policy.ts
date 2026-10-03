import type { ExecutionInput, FindingInput, Gate, Policy } from './types';
export function evaluateGate(policy: Policy, executions: ExecutionInput[], findings: {finding: FindingInput; isNew: boolean; suppressed: boolean}[]): Gate {
  const checks = new Map(executions.map(e => [e.engine,e]));
  let incomplete = false;
  for (const required of policy.checks) {
    const e = checks.get(required);
    if (!e || e.status !== 'completed' || e.limitations.some(x => x.startsWith('PARTIAL:'))) incomplete = true;
    if (required === 'trivy' && (!e?.database_updated_at || Date.now()-new Date(e.database_updated_at).getTime() > 48*3600*1000)) incomplete = true;
  }
  const violating = findings.some(({finding,isNew,suppressed}) => !suppressed && (!policy.gate.new_only || isNew) &&
    (policy.gate.severities.includes(finding.severity) || policy.gate.rules.includes(finding.rule)));
  if (policy.mode === 'enforce' && violating) return 'fail';
  return incomplete ? 'incomplete' : 'pass';
}
