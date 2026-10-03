import {test,after} from 'node:test';
import assert from 'node:assert/strict';
import {createHash,createHmac,generateKeyPairSync,randomUUID} from 'node:crypto';
import {startGithubConnect,completeGithubConnect,githubRepositories,githubConnections} from '../lib/github-connect';
import {githubWebhook,installationAllowed,verifyRepository} from '../lib/github';
import {db,closeDatabase} from '../lib/db';
import {hashToken,signSession,type Session} from '../lib/security';
import {POST} from '../app/api/[...path]/route';

process.env.DATABASE_MODE='embedded';process.env.TEST_DATABASE='true';process.env.LOCAL_AUTH='true';
process.env.SESSION_SECRET='test-only-secret-with-at-least-32-characters';process.env.APP_ORIGIN='http://127.0.0.1:3000';
process.env.GITHUB_APP_ID='99';process.env.GITHUB_APP_SLUG='sentinel-fixture';
process.env.GITHUB_CLIENT_ID='fixture-client';process.env.GITHUB_CLIENT_SECRET='fixture-client-secret';
process.env.GITHUB_WEBHOOK_SECRET='fixture-webhook-secret';
process.env.GITHUB_APP_PRIVATE_KEY=generateKeyPairSync('rsa',{modulusLength:2048}).privateKey.export({type:'pkcs8',format:'pem'}).toString();
after(closeDatabase);

async function owner():Promise<Session> {
  const s:Session={user:randomUUID(),org:randomUUID(),role:'owner'};
  await db.query('INSERT INTO organizations(id,name) VALUES($1,$2)',[s.org,'Connection test']);
  await db.query('INSERT INTO memberships(organization_id,user_id,role) VALUES($1,$2,$3)',[s.org,s.user,s.role]);return s;
}
async function begin(s:Session) {
  const started=await startGithubConnect(s),url=new URL(started.url);
  assert.equal(url.origin,'https://github.com');assert.equal(url.pathname,'/apps/sentinel-fixture/installations/new');
  const state=url.searchParams.get('state')!;
  const authorization=await completeGithubConnect(s,{state,installation_id:123});
  assert(authorization.url);const authUrl=new URL(authorization.url);
  assert.equal(authUrl.pathname,'/login/oauth/authorize');assert.equal(authUrl.searchParams.get('code_challenge_method'),'S256');
  return {state,authUrl};
}

test('GitHub connection binds OAuth state to owner, user and workspace and rejects expiry',async()=>{
  const s=await owner(),started=await startGithubConnect(s),state=new URL(started.url).searchParams.get('state')!;
  await assert.rejects(()=>startGithubConnect({...s,role:'viewer'}));
  await assert.rejects(()=>completeGithubConnect({...s,user:randomUUID()},{state,installation_id:123}));
  const other=await owner();
  await assert.rejects(()=>completeGithubConnect(other,{state,installation_id:123}));
  const rows=await db.query('SELECT * FROM github_connect_states WHERE state_hash=$1',[hashToken(state)]);
  assert.equal(rows.length,1);assert(!JSON.stringify(rows).includes(state));
  await db.query("UPDATE github_connect_states SET expires_at=now()-interval '1 second' WHERE state_hash=$1",[hashToken(state)]);
  await assert.rejects(()=>completeGithubConnect(s,{state,installation_id:123}));
  assert.equal((await githubConnections(s.org)).length,0);
});

test('GitHub owner APIs reject viewers and cross-origin requests',async()=>{
  const s=await owner();await db.query("UPDATE memberships SET role='viewer' WHERE user_id=$1",[s.user]);
  const request=new Request('http://127.0.0.1:3000/api/github/connect',{method:'POST',headers:{Origin:process.env.APP_ORIGIN!,cookie:`sentinel-session=${await signSession(s.user)}`,'Content-Type':'application/json'},body:'{}'});
  assert.equal((await POST(request,{params:Promise.resolve({path:['github','connect']})})).status,403);
  const badOrigin=new Request(request.url,{method:'POST',headers:{Origin:'https://evil.example',cookie:`sentinel-session=${await signSession(s.user)}`,'Content-Type':'application/json'},body:'{}'});
  assert.equal((await POST(badOrigin,{params:Promise.resolve({path:['github','connect']})})).status,403);
});

test('GitHub verifies user installation access, limits repositories and consumes codes once',async(t)=>{
  const s=await owner(),{state,authUrl}=await begin(s);let exchanges=0;
  t.mock.method(globalThis,'fetch',async(input:string|URL|Request,options?:RequestInit)=>{
    const url=String(input);
    if(url==='https://github.com/login/oauth/access_token') {
      exchanges++;const body=JSON.parse(String(options?.body));
      assert.equal(body.client_secret,'fixture-client-secret');
      assert.equal(createHash('sha256').update(body.code_verifier).digest('base64url'),authUrl.searchParams.get('code_challenge'));
      assert.equal(body.redirect_uri,'http://127.0.0.1:3000/integrations/github/callback');
      return Response.json({access_token:'fixture-user-token',refresh_token:'fixture-refresh-token'});
    }
    if(url.includes('/user/installations?'))return Response.json({installations:[{id:123,app_id:99,account:{login:'fixture-org'},suspended_at:null}]});
    if(url.includes('/user/installations/123/repositories'))return Response.json({total_count:1,repositories:[{id:1,full_name:'fixture-org/allowed',default_branch:'develop'}]});
    if(url.includes('/app/installations/123/access_tokens'))return Response.json({token:'fixture-installation-token'});
    if(url.includes('/installation/repositories?'))return Response.json({repositories:[{id:1,full_name:'fixture-org/allowed',default_branch:'develop'},{id:2,full_name:'fixture-org/not-authorized',default_branch:'main'}]});
    throw new Error('Unexpected request '+url);
  });
  assert.deepEqual(await completeGithubConnect(s,{state,code:'fixture-code'}),{connected:true,account:'fixture-org'});
  await assert.rejects(()=>completeGithubConnect(s,{state,code:'fixture-code'}));assert.equal(exchanges,1);
  await installationAllowed(s.org,123,'fixture-org/allowed');
  await assert.rejects(()=>installationAllowed(s.org,123,'fixture-org/not-authorized'));
  await assert.rejects(()=>verifyRepository('fixture-org/not-authorized',123,s.org));
  const rows=await db.query('SELECT * FROM github_installations WHERE organization_id=$1',[s.org]);
  assert(!JSON.stringify(rows).includes('fixture-user-token'));assert(!JSON.stringify(rows).includes('fixture-refresh-token'));
  assert.deepEqual((await githubRepositories(s)).repositories,[{installation_id:123,full_name:'fixture-org/allowed',default_branch:'develop'}]);
  assert.equal((await githubConnections(randomUUID())).length,0);
  const payload=JSON.stringify({action:'deleted',installation:{id:123}});
  await githubWebhook(new Request('http://127.0.0.1:3000/api/github/webhook',{method:'POST',headers:{'x-github-event':'installation','x-github-delivery':randomUUID(),'x-hub-signature-256':'sha256='+createHmac('sha256',process.env.GITHUB_WEBHOOK_SECRET!).update(payload).digest('hex')},body:payload}));
  await assert.rejects(()=>installationAllowed(s.org,123));assert.deepEqual((await githubRepositories(s)).repositories,[]);
});

test('spoofed or unapproved installations never become workspace connections',async(t)=>{
  const s=await owner(),{state}=await begin(s);
  t.mock.method(globalThis,'fetch',async(input:string|URL|Request)=>String(input).includes('/access_token')?Response.json({access_token:'fixture-user-token'}):Response.json({installations:[{id:999,app_id:99,account:{login:'other-org'}}]}));
  await assert.rejects(()=>completeGithubConnect(s,{state,code:'fixture-code'}));
  assert.equal((await githubConnections(s.org)).length,0);
});
