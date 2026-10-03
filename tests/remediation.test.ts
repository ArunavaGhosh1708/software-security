import {test} from 'node:test';
import assert from 'node:assert/strict';
import {remediationGuide} from '../lib/remediation';

const old={engine:'gitleaks',rule:'generic-api-key',path:'src/config.ts',line:12,remediation:'Revoke or rotate the credential, remove it from source/history, and store replacements in a secrets manager.',limitation:'Pattern-based evidence. Verify input provenance and relevant controls; no exploit is proven.'};
test('stored secret reports receive type-specific guidance without validity guesses or secret disclosure',()=>{
  const generic=remediationGuide({...old,evidence:'secret-fixture-never-display'} as typeof old);
  const privateKey=remediationGuide({...old,rule:'private-key',source_revision:'a'.repeat(40)});
  assert.notEqual(generic.summary,privateKey.summary);
  assert(generic.steps.some(s=>s.includes('public client identifier')));
  assert(privateKey.steps.some(s=>s.includes('Git history')));
  assert(generic.steps.some(s=>s.includes('src/config.ts:12')));
  assert(generic.limitation?.includes('has not contacted'));
  assert(!JSON.stringify(generic).includes('secret-fixture-never-display'));
  assert(!privateKey.steps.some(s=>s.includes('force push')));
});
test('package guidance uses reported installed and fixed versions and preserves missing-fix uncertainty',()=>{
  const base={...old,engine:'trivy',rule:'CVE-2024-12345',remediation:'Upgrade example to 2',dependency:{name:'example',version:'1',fixed_version:'2',ecosystem:'npm'}};
  const known=remediationGuide(base);assert(known.steps.some(s=>s.includes('example@1')));assert(known.steps.some(s=>s.includes('versions: 2')));
  const unknown=remediationGuide({...base,dependency:{...base.dependency,fixed_version:undefined},remediation:'No fix listed'});
  assert(unknown.steps.some(s=>s.includes('do not invent a safe version')));
});
test('coding guidance distinguishes unused imports and locals while preserving scanner advice for unknown rules',()=>{
  const imports=remediationGuide({...old,engine:'lint',rule:'F401'}),locals=remediationGuide({...old,engine:'lint',rule:'F841'});
  assert.notEqual(imports.summary,locals.summary);
  assert(imports.summary.includes('re-exports'));assert(locals.summary.includes('side effects'));
  const unknown=remediationGuide({...old,engine:'lint',rule:'UNKNOWN',remediation:'Specific scanner instruction'});
  assert.equal(unknown.summary,'Specific scanner instruction');assert(unknown.steps.some(s=>s.includes('not available')));
});
test('stored infrastructure and runtime findings receive their own evidence limitations',()=>{
  assert(remediationGuide({...old,engine:'trivy',rule:'DS-0002',remediation:'Use a non-root user'}).limitation?.includes('deployment settings'));
  assert(remediationGuide({...old,engine:'dast',rule:'10020',endpoint:'/login',path:undefined}).limitation?.includes('authentication context'));
});
