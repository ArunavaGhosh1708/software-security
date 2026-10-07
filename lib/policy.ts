import type { ExecutionInput, FindingInput, Gate, Policy } from './types';
export function evaluateGate(policy: Policy, executions: ExecutionInput[], findings: {finding: FindingInput; isNew: boolean; suppressed: boolean}[],metrics:Record<string,unknown>={}): Gate {
  const checks = new Map(executions.map(e => [e.engine,e]));
  let incomplete = false;
  for (const required of policy.checks) {
    const e = checks.get(required);
    if (!e || e.status !== 'completed' || e.limitations.some(x => x.startsWith('PARTIAL:'))) incomplete = true;
    if(required==='trivy') {
      const age=e?.database_updated_at?Date.now()-new Date(e.database_updated_at).getTime():NaN;
      if(!Number.isFinite(age)||age<0||age>48*3600*1000)incomplete=true;
    }
  }
  let metricViolation=false;
  if(policy.gate.min_imported_coverage!==undefined) {
    const reports=Object.values((metrics.imported_coverage??{}) as Record<string,{percent:number}>);
    if(!reports.length||reports.some(r=>typeof r.percent!=='number'||!Number.isFinite(r.percent)||r.percent<0||r.percent>100)||metrics.coverage_invalid===true)incomplete=true;
    else metricViolation=reports.some(r=>r.percent<policy.gate.min_imported_coverage!);
  }
  if(policy.gate.max_python_function_complexity!==undefined) {
    const functions=metrics.python_functions as {complexity:number}[]|undefined;
    if(!Array.isArray(functions)||!functions.length||metrics.python_parse_errors===true)incomplete=true;
    else if(functions.some(f=>!Number.isInteger(f.complexity)||f.complexity<1))incomplete=true;
    else metricViolation ||= functions.some(f=>f.complexity>policy.gate.max_python_function_complexity!);
  }
  if((policy.gate.min_imported_coverage!==undefined||policy.gate.max_python_function_complexity!==undefined)&&checks.get('quality')?.status!=='completed')incomplete=true;
  const violating = metricViolation||findings.some(({finding,isNew,suppressed}) => !suppressed && (!policy.gate.new_only || isNew) &&
    (policy.gate.severities.includes(finding.severity) || policy.gate.rules.includes(finding.rule)));
  if (policy.mode === 'enforce' && violating) return 'fail';
  return incomplete ? 'incomplete' : 'pass';
}
