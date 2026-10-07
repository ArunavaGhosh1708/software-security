import { createHmac, randomUUID } from 'node:crypto';
import { importPKCS8, SignJWT } from 'jose';
import { db, transaction } from './db';
import { check, equal } from './security';
import {rawBody} from './validation';
import {sourceSnapshot} from './scans';

async function appJwt() {
  const id=process.env.GITHUB_APP_ID,key=process.env.GITHUB_APP_PRIVATE_KEY?.replace(/\\n/g,'\n');
  check(id && key,503,'GitHub App is not configured.');
  return new SignJWT({}).setProtectedHeader({alg:'RS256'}).setIssuer(id).setIssuedAt(Math.floor(Date.now()/1000)-30).setExpirationTime('8m').sign(await importPKCS8(key,'RS256'));
}
const apiHeaders=(token:string)=>({authorization:`Bearer ${token}`,accept:'application/vnd.github+json','X-GitHub-Api-Version':'2022-11-28'});
export async function installationToken(id: number, repository: string, checks=false) {
  check(/^[\w.-]+\/[\w.-]+$/.test(repository),400,'Invalid repository identifier.');
  const response=await fetch(`https://api.github.com/app/installations/${id}/access_tokens`,{method:'POST',headers:{...apiHeaders(await appJwt()),'Content-Type':'application/json'},body:JSON.stringify({repositories:[repository.split('/')[1]],permissions:checks?{checks:'write'}:{contents:'read'}}),signal:AbortSignal.timeout(10000)});
  check(response.ok,502,'GitHub installation token request failed.');return (await response.json()).token as string;
}
export async function installationAllowed(organization: string, installationId: number,repository?:string,t=db) {
  const rows=await t.query('SELECT repositories FROM github_installations WHERE organization_id=$1 AND installation_id=$2 AND revoked_at IS NULL',[organization,installationId]);
  check(rows.length,403,'Connect this GitHub installation in Integrations first.');
  if(repository)check(rows[0].repositories.some((r:{full_name:string})=>r.full_name.toLowerCase()===repository.toLowerCase()),403,'This repository is not authorized for your workspace. Reconnect GitHub to update access.');
}
export async function installationRepositories(id:number) {
  const response=await fetch(`https://api.github.com/app/installations/${id}/access_tokens`,{method:'POST',redirect:'error',headers:{...apiHeaders(await appJwt()),'Content-Type':'application/json'},body:JSON.stringify({permissions:{contents:'read'}}),signal:AbortSignal.timeout(10000)});
  check(response.ok,502,'GitHub installation access is unavailable. Reconnect GitHub.');const token=(await response.json()).token;
  const repositories:Record<string,any>[]=[];
  for(let page=1;page<=5;page++) {
    const result=await fetch(`https://api.github.com/installation/repositories?per_page=100&page=${page}`,{headers:apiHeaders(token),redirect:'error',signal:AbortSignal.timeout(10000)});
    check(result.ok,502,'GitHub repositories are unavailable.');const data=await result.json();
    check(Array.isArray(data.repositories),502,'Invalid GitHub repository response.');repositories.push(...data.repositories);
    if(data.repositories.length<100)break;
  }
  return repositories;
}
export async function verifyRepository(repository: string, installationId: number, organization: string) {
  await installationAllowed(organization,installationId,repository);
  const response=await fetch(`https://api.github.com/repos/${repository}`,{headers:apiHeaders(await installationToken(installationId,repository)),signal:AbortSignal.timeout(10000)});
  check(response.ok,400,'Repository is not accessible to this GitHub App installation.');
}
export async function publishCheck(scan: Record<string,any>) {
  const projects=await db.query('SELECT * FROM projects WHERE id=$1',[scan.project_id]);const p=projects[0]&&{...projects[0],...scan.source_snapshot};
  if(!p || p.source_type!=='github' || !/^[a-f0-9]{40}$/.test(scan.revision ?? ''))return;
  await installationAllowed(p.organization_id,Number(p.github_installation_id),p.source_ref);
  const response=await fetch(`https://api.github.com/repos/${p.source_ref}/check-runs`,{method:'POST',headers:{...apiHeaders(await installationToken(Number(p.github_installation_id),p.source_ref,true)),'Content-Type':'application/json'},
    body:JSON.stringify({name:'Sentinel security guardrails',head_sha:scan.revision,status:'completed',conclusion:scan.gate==='pass'?'success':scan.gate==='fail'?'failure':'action_required',
      output:{title:`Security gate: ${scan.gate}`,summary:scan.gate==='incomplete'?'Required checks did not complete. Review scanner coverage.':'Review findings and the policy in Sentinel.'}}),signal:AbortSignal.timeout(10000)});
  check(response.ok,502,'GitHub check publishing failed; repository requires checks:write permission.');
}
export async function githubWebhook(request: Request) {
  const secret=process.env.GITHUB_WEBHOOK_SECRET;check(secret,503,'GitHub webhook is not configured.');
  const payload=await rawBody(request,1_000_000);
  const expected=`sha256=${createHmac('sha256',secret).update(payload).digest('hex')}`;
  check(equal(expected,request.headers.get('x-hub-signature-256')??''),401,'Webhook signature rejected.');
  const delivery=request.headers.get('x-github-delivery');check(delivery && delivery.length<200,400,'Delivery ID required.');
  const event=JSON.parse(payload.toString('utf8'));
  return transaction(async t=>{
  const seen=await t.query('INSERT INTO github_deliveries(id) VALUES($1) ON CONFLICT DO NOTHING RETURNING id',[delivery]);
  if(!seen.length)return {duplicate:true};
  if(request.headers.get('x-github-event')==='installation'&&['deleted','suspend'].includes(event.action)) {
    await t.query('UPDATE github_installations SET revoked_at=now() WHERE installation_id=$1',[event.installation?.id]);return {accepted:true};
  }
  if(request.headers.get('x-github-event')!=='pull_request' || !['opened','synchronize','reopened'].includes(event.action))return {accepted:true};
  // Fork pull requests require a different clone/permission policy. Never run their code implicitly.
  if(event.pull_request?.head?.repo?.full_name!==event.repository?.full_name)return {accepted:true,skipped:'Fork pull requests require explicit scan submission.'};
  const sha=event.pull_request?.head?.sha;check(typeof sha==='string'&&/^[a-f0-9]{40}$/.test(sha),400,'Invalid revision.');
  const projects=await t.query('SELECT * FROM projects WHERE source_type=$1 AND source_ref=$2 AND github_installation_id=$3',['github',event.repository.full_name,event.installation?.id]);
  let queued=0;
  for(const p of projects){
    const connections=await t.query('SELECT repositories FROM github_installations WHERE organization_id=$1 AND installation_id=$2 AND revoked_at IS NULL',[p.organization_id,p.github_installation_id]);
    if(!connections.some(c=>c.repositories.some((r:{full_name:string})=>r.full_name.toLowerCase()===p.source_ref.toLowerCase())))continue;
    const branch=event.pull_request.head.ref;
    const scope=typeof branch==='string'&&/^[A-Za-z0-9_./-]{1,120}$/.test(branch)&&!branch.includes('..')?(branch===p.default_branch?'default':`branch:${branch}`):`commit:${sha}`;
    await t.query('INSERT INTO scans(id,organization_id,project_id,requested_revision,policy,source_snapshot,baseline_scope) VALUES($1,$2,$3,$4,$5,$6,$7)',[randomUUID(),p.organization_id,p.id,sha,JSON.stringify(p.policy),JSON.stringify(sourceSnapshot(p)),scope]);queued++;
  }
  return {queued};
  });
}
