import {createHash,randomBytes} from 'node:crypto';
import {z} from 'zod';
import {db,transaction} from './db';
import {audit,canOwn,check,hashToken,type Session} from './security';
import {oauthCallbackUrl} from './oauth';
import {installationRepositories} from './github';

export const GITHUB_CALLBACK_PATH='/integrations/github/callback';
export function githubConnectConfigured() {
  return !!(process.env.GITHUB_APP_ID&&process.env.GITHUB_APP_PRIVATE_KEY&&process.env.GITHUB_WEBHOOK_SECRET&&process.env.GITHUB_APP_SLUG&&process.env.GITHUB_CLIENT_ID&&process.env.GITHUB_CLIENT_SECRET);
}
function configuration() {
  check(githubConnectConfigured(),503,'The host has not configured GitHub connections yet. Contact your administrator.');
  check(/^[a-z0-9-]+$/.test(process.env.GITHUB_APP_SLUG!),503,'Invalid GitHub App slug.');
  const origin=new URL(oauthCallbackUrl(process.env.APP_ORIGIN??'' )).origin;
  return {callback:new URL(GITHUB_CALLBACK_PATH,origin).href,slug:process.env.GITHUB_APP_SLUG!,client:process.env.GITHUB_CLIENT_ID!,secret:process.env.GITHUB_CLIENT_SECRET!};
}
const headers=(token:string)=>({authorization:`Bearer ${token}`,accept:'application/vnd.github+json','X-GitHub-Api-Version':'2022-11-28'});
async function githubJson(path:string,token:string) {
  const response=await fetch(`https://api.github.com${path}`,{headers:headers(token),redirect:'error',signal:AbortSignal.timeout(10000)});
  check(response.ok,502,'GitHub could not verify access. Start Connect GitHub again.');return response.json();
}
export async function startGithubConnect(s:Session) {
  canOwn(s);const config=configuration(),state=randomBytes(32).toString('base64url');
  await db.query('DELETE FROM github_connect_states WHERE expires_at<now()');
  await db.query(`INSERT INTO github_connect_states(state_hash,organization_id,user_id,expires_at) VALUES($1,$2,$3,now()+interval '15 minutes')`,[hashToken(state),s.org,s.user]);
  const url=new URL(`https://github.com/apps/${config.slug}/installations/new`);url.searchParams.set('state',state);
  return {url:url.href};
}
export const githubCompleteSchema=z.object({state:z.string().regex(/^[A-Za-z0-9_-]{43}$/),installation_id:z.coerce.number().int().positive().max(Number.MAX_SAFE_INTEGER).optional(),code:z.string().min(1).max(2048).optional()}).strict();
export async function completeGithubConnect(s:Session,input:unknown) {
  canOwn(s);const b=githubCompleteSchema.parse(input),config=configuration(),stateHash=hashToken(b.state);
  if(!b.code) {
    check(b.installation_id,400,'Installation was not completed. Start Connect GitHub again.');
    const verifier=randomBytes(32).toString('base64url');
    const pending=await db.query(`UPDATE github_connect_states SET installation_id=$1,code_verifier=$2
      WHERE state_hash=$3 AND organization_id=$4 AND user_id=$5 AND expires_at>now() AND code_verifier IS NULL RETURNING state_hash`,[b.installation_id,verifier,stateHash,s.org,s.user]);
    check(pending.length,400,'Connection expired or already used. Start Connect GitHub again.');
    const url=new URL('https://github.com/login/oauth/authorize');
    for(const [key,value] of Object.entries({client_id:config.client,redirect_uri:config.callback,state:b.state,code_challenge:createHash('sha256').update(verifier).digest('base64url'),code_challenge_method:'S256'}))url.searchParams.set(key,value);
    return {url:url.href};
  }
  // Consume the nonce atomically before exchanging the code. It is bound to the
  // authenticated Sentinel owner and workspace, and cannot be reused or transferred.
  const pending=await db.query(`DELETE FROM github_connect_states WHERE state_hash=$1 AND organization_id=$2 AND user_id=$3
    AND expires_at>now() AND code_verifier IS NOT NULL RETURNING installation_id,code_verifier`,[stateHash,s.org,s.user]);
  check(pending.length,400,'Connection expired or already used. Start Connect GitHub again.');
  const installationId=Number(pending[0].installation_id);
  check(!b.installation_id||b.installation_id===installationId,400,'Installation does not match this connection.');
  const response=await fetch('https://github.com/login/oauth/access_token',{method:'POST',redirect:'error',headers:{accept:'application/json','Content-Type':'application/json'},
    body:JSON.stringify({client_id:config.client,client_secret:config.secret,code:b.code,redirect_uri:config.callback,code_verifier:pending[0].code_verifier}),signal:AbortSignal.timeout(10000)});
  check(response.ok,502,'GitHub authorization failed. Start Connect GitHub again.');const tokenData=await response.json();
  check(typeof tokenData.access_token==='string'&&!tokenData.error,400,'GitHub authorization was cancelled or expired. Start Connect GitHub again.');
  const token=tokenData.access_token;let installation:Record<string,any>|undefined;
  for(let page=1;page<=10;page++) {
    const data=await githubJson(`/user/installations?per_page=100&page=${page}`,token);
    check(Array.isArray(data.installations),502,'Invalid GitHub installation response.');
    installation=data.installations.find((item:Record<string,any>)=>item.id===installationId&&String(item.app_id)===process.env.GITHUB_APP_ID);
    if(installation||data.installations.length<100)break;
  }
  check(installation&&!installation.suspended_at,403,'This GitHub account cannot access the selected installation.');
  const repositories:Record<string,any>[]=[];
  for(let page=1;page<=5;page++) {
    const data=await githubJson(`/user/installations/${installationId}/repositories?per_page=100&page=${page}`,token);
    check(Array.isArray(data.repositories),502,'Invalid GitHub repository response.');
    repositories.push(...data.repositories.map((r:Record<string,any>)=>({id:r.id,full_name:r.full_name,default_branch:r.default_branch??'main'})));
    check(Number(data.total_count)<=500,400,'Connect an installation with at most 500 repositories. Choose selected repositories in GitHub.');
    if(data.repositories.length<100)break;
  }
  check(repositories.length,403,'No authorized repositories are available. Select repositories in GitHub and reconnect.');
  check(repositories.every(r=>Number.isSafeInteger(r.id)&&r.id>0&&/^[\w.-]+\/[\w.-]+$/.test(r.full_name)),502,'Invalid GitHub repository data.');
  // Keep only the intersection of user access and app access. A user with access
  // to one repository must not gain all repositories granted to the installation.
  await transaction(async t=>{
    await t.query(`INSERT INTO github_installations(organization_id,installation_id,account_login,connected_by,repositories,revoked_at)
      VALUES($1,$2,$3,$4,$5,NULL) ON CONFLICT(organization_id,installation_id) DO UPDATE SET
      account_login=excluded.account_login,connected_by=excluded.connected_by,repositories=excluded.repositories,revoked_at=NULL,connected_at=now()`,[s.org,installationId,installation.account.login,s.user,JSON.stringify(repositories)]);
    await audit(s,'github.connected',String(installationId),t);
  });
  // User OAuth tokens are used only for verification and never stored or returned.
  return {connected:true,account:installation.account.login};
}
export async function githubConnections(org:string) {
  return db.query('SELECT installation_id,account_login,connected_at FROM github_installations WHERE organization_id=$1 AND revoked_at IS NULL ORDER BY account_login',[org]);
}
export async function githubRepositories(s:Session) {
  canOwn(s);const connections=await db.query('SELECT installation_id,repositories FROM github_installations WHERE organization_id=$1 AND revoked_at IS NULL',[s.org]);
  const repositories:Record<string,any>[]=[];
  for(const connection of connections) {
    for(const current of await installationRepositories(Number(connection.installation_id))) {
      if(!connection.repositories.some((r:{id:number})=>r.id===current.id))continue;
      repositories.push({installation_id:Number(connection.installation_id),full_name:current.full_name,default_branch:current.default_branch??'main'});
    }
  }
  return {repositories};
}
