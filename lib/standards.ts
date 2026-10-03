import catalog from '../data/asvs-5.0.json';
export const RULE_REQUIREMENTS:Record<string,string[]>={
  'sentinel.express-command-taint':['1.2.5'],'sentinel.flask-command-taint':['1.2.5'],
  'sentinel.python-tls-disabled':['12.3.2'],'sentinel.node-tls-disabled':['12.3.2'],
  'sentinel.express-sql-taint':['1.2.4'],'sentinel.flask-django-sql-taint':['1.2.4'],
  'python.dynamic-eval':['1.3.2'],'javascript.dynamic-eval':['1.3.2'],'sentinel.javascript-eval':['1.3.2'],
  'python.unsafe-pickle':['1.5.2'],'java.native-deserialization':['1.5.2'],'csharp.binary-formatter':['1.5.2'],
  'sentinel.python-pickle':['1.5.2'],'sentinel.java-object-input':['1.5.2'],'sentinel.csharp-binaryformatter':['1.5.2'],
  'python.shell-true':['1.2.5'],'java.process-execution':['1.2.5'],'go.shell-execution':['1.2.5'],
  'javascript.raw-html':['1.3.1'],'go.tls-bypass':['12.3.2'],'csharp.tls-bypass':['12.3.2'],'sentinel.go-insecure-tls':['12.3.2']
};
export function requirementsFor(rule:string){
  const match=Object.keys(RULE_REQUIREMENTS).find(k=>rule===k||rule.endsWith('.'+k));
  return match?RULE_REQUIREMENTS[match].map(id=>`ASVS-5.0.0:${id}`):[];
}
export function standardsCoverage(findings:Record<string,any>[],executions:Record<string,any>[]) {
  const mapped=new Map<string,string[]>();
  for(const finding of findings)for(const ref of requirementsFor(finding.rule)){
    const id=ref.split(':')[1];mapped.set(id,[...(mapped.get(id)??[]),finding.id]);
  }
  const enginesRan=executions.some(e=>e.status==='completed'&&['guardrails','opengrep'].includes(e.engine));
  return {version:catalog.version,attribution:catalog.attribution,license:catalog.license,license_url:catalog.license_url,source:catalog.source,
    requirements:catalog.requirements.map(r=>({...r,status:mapped.has(r.id)?'automated_evidence':
      Object.values(RULE_REQUIREMENTS).some(ids=>ids.includes(r.id))?(enginesRan?'manual_review':'not_run'):'unsupported',
      finding_ids:mapped.get(r.id)??[],limitation:'Automated findings are partial evidence; absence of findings does not verify this requirement.'}))};
}
