import {test,after} from 'node:test';
import assert from 'node:assert/strict';
import {randomUUID} from 'node:crypto';
import {GET,POST,PATCH,DELETE} from '../app/api/[...path]/route';
import {signSession,hashToken,runnerAuth} from '../lib/security';
import {db,closeDatabase} from '../lib/db';
process.env.DATABASE_MODE='embedded';process.env.TEST_DATABASE='true';process.env.LOCAL_AUTH='true';process.env.SESSION_SECRET='test-only-secret-with-at-least-32-characters';process.env.APP_ORIGIN='http://127.0.0.1:3000';
after(closeDatabase);

test('AI suggestions default to Gemini and redact request and response credentials',async(t)=>{
  const previous={key:process.env.AI_API_KEY,model:process.env.AI_MODEL,url:process.env.AI_BASE_URL};
  process.env.AI_API_KEY='test-only-provider-key';process.env.AI_MODEL='gemini-3.8-flash';delete process.env.AI_BASE_URL;
  try {
    const owner=randomUUID(),org=(await call('overview','GET',owner)).data.session.org;
    const project=(await call('projects','POST',owner,{name:'Gemini test',source_type:'local',source_ref:'gemini-test'})).data;
    await call(`projects/${project.id}`,'PATCH',owner,{ai_enabled:true,metadata_only:false});
    const finding=randomUUID();
    await db.query(`INSERT INTO findings(id,organization_id,project_id,fingerprint,rule,engine,severity,category,title,data,revision)
      VALUES($1,$2,$3,$4,'test','guardrails','high','security','Test',$5,'test')`,[finding,org,project.id,'g'.repeat(64),JSON.stringify({evidence:'api_key="private-fixture-value"'})]);
    let requests=0;
    t.mock.method(globalThis,'fetch',async(input:string|URL|Request,options?:RequestInit)=>{
      requests++;
      assert.equal(String(input),'https://generativelanguage.googleapis.com/v1beta/openai/chat/completions');
      assert.equal(new Headers(options?.headers).get('authorization'),'Bearer test-only-provider-key');
      assert.equal(options?.redirect,'error');
      const payload=JSON.parse(String(options?.body));
      assert.equal(payload.model,'gemini-3.8-flash');assert.equal(payload.max_completion_tokens,2000);
      assert(!JSON.stringify(payload).includes('private-fixture-value'));assert(!('tools' in payload));
      return Response.json({choices:[{message:{content:'Review suggestion api_key="response-fixture-value"'}}]});
    });
    const response=await call(`findings/${finding}/ai`,'POST',owner,{});
    assert.equal(response.status,200);assert.equal(requests,1);
    assert.equal(response.data.validation,'unvalidated');assert(!response.data.text.includes('response-fixture-value'));
  } finally {
    for(const [name,value] of Object.entries({AI_API_KEY:previous.key,AI_MODEL:previous.model,AI_BASE_URL:previous.url})) {
      if(value===undefined)delete process.env[name];else process.env[name]=value;
    }
  }
});

async function call(path:string,method:string,user:string|undefined,data?:unknown,extra:Record<string,string>={}) {
  const headers={'Content-Type':'application/json',Origin:'http://127.0.0.1:3000',...extra} as Record<string,string>;
  if(user)headers.cookie=`sentinel-session=${await signSession(user)}`;
  const request=new Request(`http://127.0.0.1:3000/api/${path}`,{method,headers,body:data?JSON.stringify(data):undefined});
  const handler=({GET,POST,PATCH,DELETE} as Record<string,typeof GET>)[method];
  const response=await handler(request,{params:Promise.resolve({path:path.split('/')})});
  return {status:response.status,data:await response.json()};
}
test('authenticated endpoints enforce cross-tenant, role, origin, scope, and metadata retention',async()=>{
  const owner=randomUUID(),other=randomUUID(),viewer=randomUUID();
  assert.equal((await call('overview','GET',undefined)).status,401);
  const org=(await call('overview','GET',owner)).data.session.org;
  await call('overview','GET',other);
  const project=(await call('projects','POST',owner,{name:'Private project',source_type:'local',source_ref:'private'})).data;
  assert(project.id);
  assert.equal((await call(`projects/${project.id}`,'GET',other)).status,404);
  assert.equal((await call(`projects/${project.id}/scans`,'POST',other,{})).status,404);
  assert.equal((await call(`projects/${project.id}`,'DELETE',other)).status,404);
  await call('members','POST',owner,{user_id:viewer,role:'viewer'});
  assert.equal((await call('projects','POST',viewer,{name:'Denied',source_type:'local',source_ref:'denied'})).status,403);
  assert.equal((await call('runners','POST',viewer,{name:'Denied',project_ids:[project.id]})).status,403);
  assert.equal((await call(`projects/${project.id}/scans`,'POST',owner,{}, {Origin:'https://evil.example'})).status,403);
  const runner=(await call('runners','POST',owner,{name:'Scoped runner',project_ids:[project.id]})).data;
  assert(runner.token.startsWith('sgr_'));
  const row=(await db.query('SELECT * FROM runners WHERE id=$1',[runner.id]))[0];assert.equal(row.token_hash,hashToken(runner.token));assert(!JSON.stringify(row).includes(runner.token));
  const unrelated=(await call('projects','POST',owner,{name:'Other project',source_type:'local',source_ref:'other'})).data;
  const event={event_key:'test',timestamp:new Date().toISOString(),path:'/login',environment:'local'};
  assert.equal((await call('runner/events','POST',undefined,{project_id:unrelated.id,events:[event]},{Authorization:`Bearer ${runner.token}`})).status,403);
  // Metadata-only mode purges snippets from existing findings and historical snapshots.
  const finding=randomUUID();
  await db.query(`INSERT INTO findings(id,organization_id,project_id,fingerprint,rule,engine,severity,category,title,data,revision)
    VALUES($1,$2,$3,$4,'test','guardrails','high','security','Test',$5,'test')`,[finding,org,project.id,'f'.repeat(64),JSON.stringify({evidence:'private source',patch:'private patch'})]);
  assert.equal((await call(`projects/${project.id}`,'PATCH',owner,{metadata_only:true})).status,200);
  const stored=(await db.query('SELECT data FROM findings WHERE id=$1',[finding]))[0].data;assert(!('evidence' in stored));assert(!('patch' in stored));
  assert.equal((await call(`findings/${finding}`,'PATCH',owner,{status:'accepted'})).status,400);
  assert.equal((await call(`findings/${finding}`,'PATCH',owner,{status:'accepted',reason:'Temporary exception for test fixture',expires_at:new Date(Date.now()+86400000).toISOString()})).status,200);
  assert.equal((await call(`findings/${finding}/ai`,'POST',owner,{})).status,403);
  assert.equal((await call('runners/'+runner.id,'DELETE',owner)).status,200);
  assert.equal((await call('runner/claim','POST',undefined,{}, {Authorization:`Bearer ${runner.token}`})).status,401);
});
