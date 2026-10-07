import catalog from '../rules/remediation.json';

type Finding = {engine:string;rule:string;path?:string;line?:number;source_revision?:string;source_context?:string;endpoint?:string;remediation:string;limitation?:string;dependency?:{name:string;version:string;fixed_version?:string;ecosystem?:string}};
export type RemediationGuide = {summary:string;steps:string[];verification:string;limitation?:string;basis:string};
const patternDefault='Pattern-based evidence. Verify input provenance and relevant controls; no exploit is proven.';

export function remediationGuide(f:Finding):RemediationGuide {
  const location=f.path?`${f.path}${f.line?`:${f.line}`:''}`:f.endpoint??'the reported location';
  if(f.engine==='gitleaks') {
    const key=f.rule.startsWith('github-pat')?'github-pat':f.rule;
    const entry=catalog.secrets[key as keyof typeof catalog.secrets]??catalog.secrets.default;
    return {...entry,steps:[`Review ${location}${f.source_revision?` in detected commit ${f.source_revision.slice(0,12)}`:''}. The secret value is intentionally hidden.`,...entry.steps,
      f.source_revision?'This finding comes from Git history. Removing the current literal or adding a Git ignore entry does not remove the old commit. Assess history cleanup with repository owners after retiring a real credential.':'Remove the source literal and check whether it was committed or copied into logs, build artifacts, or example files. Only consider history rewriting after coordinating with repository owners.'],
      limitation:'Secret-pattern match only. Sentinel has not contacted the credential issuer, tested validity, or determined its permissions. Public identifiers and inert fixtures require review.',basis:'Curated secret-type guidance'};
  }
  if(f.engine==='trivy'&&f.dependency) {
    const d=f.dependency;
    return {summary:f.remediation,steps:[`Locate ${d.name}@${d.version} in ${location} (${d.ecosystem??'dependency manifest'}). Determine whether it is direct or transitive.`,
      d.fixed_version?`Select a compatible release from the scanner's reported fixed versions: ${d.fixed_version}. Update the direct dependency or the parent dependency introducing it, and regenerate the lockfile with the project's package manager.`:'The scanner lists no fixed release. Review the advisory and assess removal, a maintained replacement, or a documented compensating control; do not invent a safe version.'],
      verification:'Run the affected application tests and repeat dependency analysis using a fresh advisory database. Confirm the affected installed package version changed.',limitation:f.limitation===patternDefault?'Advisory matching identifies a potentially affected package; application reachability and successful exploitation have not been established.':f.limitation,basis:'Scanner remediation and package metadata'};
  }
  if(f.engine==='lint') {
    const rule=f.rule.split('.').at(-1)??f.rule,fix=catalog.lint[rule as keyof typeof catalog.lint];
    return {summary:fix??f.remediation,steps:[`Review ${location} against analyzer rule ${f.rule}.`,...(fix?[fix]:['Use the diagnostic message and the analyzer rule documentation to identify the exact required change. A safe automatic edit is not available from the retained evidence.'])],verification:`Rerun coding-standard checks and relevant application tests. Confirm rule ${f.rule} no longer reports this location.`,limitation:f.limitation===patternDefault?'Analyzer diagnostic; this does not demonstrate a security exploit.':f.limitation,basis:fix?'Curated analyzer-rule guidance':'Scanner guidance'};
  }
  const limitations:Record<string,string>={dast:'Runtime scanner observation; review the affected endpoint and authentication context. Successful exploitation has not been established.',trivy:'Scanner configuration evidence. Review the affected deployment settings; successful exploitation has not been established.'};
  return {summary:f.remediation,steps:[`Review ${location} for rule ${f.rule}.`],verification:`Apply the recommended change, run relevant regression tests, and repeat ${f.engine} analysis. Confirm this finding is no longer detected with comparable coverage.`,limitation:f.limitation===patternDefault?(limitations[f.engine]??f.limitation):f.limitation,basis:'Scanner guidance'};
}
