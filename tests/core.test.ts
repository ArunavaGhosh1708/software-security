import {test,after} from 'node:test';
import assert from 'node:assert/strict';
import {randomUUID,createHmac} from 'node:crypto';
import {DEFAULT_POLICY,type ScanReport,type FindingInput} from '../lib/types';
import {parsePolicy,projectSchema,reportSchema} from '../lib/validation';
import {evaluateGate} from '../lib/policy';
import {redact,signSession,session,hashToken,HttpError} from '../lib/security';
import {claim,enqueue,finish,heartbeat} from '../lib/scans';
import {ingest,eventsSchema} from '../lib/telemetry';
import {stringify} from 'yaml';
import {githubWebhook,installationAllowed} from '../lib/github';

process.env.DATABASE_MODE='embedded';process.env.TEST_DATABASE='true';process.env.LOCAL_AUTH='true';process.env.SESSION_SECRET='test-only-secret-with-at-least-32-characters';process.env.APP_ORIGIN='http://127.0.0.1:3000';
const {db,closeDatabase}=await import('../lib/db');
after(async()=>closeDatabase());
const finding:FindingInput={fingerprint:'a'.repeat(64),rule:'test.tls',engine:'guardrails',engine_version:'0.1.0',severity:'high',confidence:'medium',category:'security',title:'TLS bypass',path:'app.go',line:2,evidence:'api_key="secret-value"',impact:'Unsafe connection',remediation:'Restore verification'};
const report:ScanReport={schema_version:1,revision:'snapshot:test',inventory:{languages:{Go:1}},metrics:{},findings:[finding],executions:[{engine:'guardrails',version:'0.1.0',status:'completed',duration_ms:3,coverage:['Go'],limitations:[]}]};
function policy(){return {...structuredClone(DEFAULT_POLICY),checks:['guardrails'],mode:'enforce' as const};}

test('strict declarative policy rejects commands, aliases, duplicate keys, and unknown checks',()=>{
  assert.deepEqual(parsePolicy(stringify(DEFAULT_POLICY)),DEFAULT_POLICY);
  assert.throws(()=>parsePolicy(stringify({...DEFAULT_POLICY,command:'rm -rf /'})));
  assert.throws(()=>parsePolicy('version: 1\nversion: 1'));
  assert.throws(()=>parsePolicy(stringify({...DEFAULT_POLICY,checks:['shell']})));
  assert.throws(()=>parsePolicy('version: &x 1\nmode: *x'));
});
test('project input rejects arbitrary paths, traversal, production DAST, and URL credentials',()=>{
  const p={name:'App',source_type:'local',source_ref:'my-app'};
  assert(projectSchema.safeParse(p).success);
  assert(!projectSchema.safeParse({...p,source_ref:'C:/secrets'}).success);
  assert(!projectSchema.safeParse({...p,components:[{name:'escape',root:'../outside'}]}).success);
  assert(!projectSchema.safeParse({...p,target:{url:'https://user:pass@example.com',environment:'staging',authorized:true}}).success);
  assert(!projectSchema.safeParse({...p,target:{url:'https://example.com',environment:'production',authorized:true}}).success);
});
test('gate distinguishes new vulnerabilities, baseline, advisory, and missing engines',()=>{
  const p=policy(),e=report.executions,entries=[{finding,isNew:true,suppressed:false}];
  assert.equal(evaluateGate(p,e,entries),'fail');
  assert.equal(evaluateGate(p,e,[{...entries[0],isNew:false}]),'pass');
  assert.equal(evaluateGate(p,e,[{...entries[0],suppressed:true}]),'pass');
  assert.equal(evaluateGate({...p,mode:'advisory'},e,entries),'pass');
  assert.equal(evaluateGate({...p,checks:['guardrails','trivy']},e,[]),'incomplete');
});
test('stale vulnerability databases cannot pass required checks',()=>{
  assert.equal(evaluateGate({...policy(),checks:['trivy']},[{...report.executions[0],engine:'trivy',database_updated_at:'2020-01-01T00:00:00Z'}],[]),'incomplete');
});
test('quality thresholds fail low metrics and keep absent or invalid evidence incomplete',()=>{
  const p={...policy(),checks:['quality'],gate:{...policy().gate,min_imported_coverage:80,max_python_function_complexity:5}};
  const executions=[{...report.executions[0],engine:'quality'}];
  assert.equal(evaluateGate(p,executions,[],{}),'incomplete');
  assert.equal(evaluateGate(p,executions,[],{imported_coverage:{lcov:{percent:90}},python_functions:[{complexity:3}]}),'pass');
  assert.equal(evaluateGate(p,executions,[],{imported_coverage:{lcov:{percent:70}},python_functions:[{complexity:3}]}),'fail');
  assert.equal(evaluateGate(p,executions,[],{imported_coverage:{lcov:{percent:101}},python_functions:[{complexity:3}]}),'incomplete');
});
test('redaction removes credentials without exposing secret material',()=>{
  assert(!redact('api_key="hidden-value" authorization=Bearer abc').includes('hidden-value'));
  assert(!redact('AKIAABCDEFGHIJKLMNOP').includes('AKIA'));
  assert(!redact('{"api_key":"hidden-value"}').includes('hidden-value'));
  assert(!redact('https://user:hidden-value@example.test').includes('hidden-value'));
  assert(!redact('Authorization: Basic dXNlcjpwYXNzd29yZA==').includes('dXNlcjpwYXNzd29yZA=='));
  assert.equal(redact('safe ordinary code'),'safe ordinary code');
});
test('report schema rejects malformed and oversized findings',()=>{
  assert(reportSchema.safeParse(report).success);
  assert(!reportSchema.safeParse({...report,findings:[{...finding,severity:'nuclear'}]}).success);
});

test('GitHub organization binding, signed webhook, and atomic duplicate delivery',async()=>{
  const org=randomUUID(),project=randomUUID();
  process.env.GITHUB_WEBHOOK_SECRET='test-webhook-secret';
  await db.query('INSERT INTO organizations(id,name) VALUES($1,$2)',[org,'GitHub fixture']);
  await db.query('INSERT INTO github_installations(organization_id,installation_id,account_login,connected_by,repositories) VALUES($1,12345,$2,$3,$4)',[org,'fixture',randomUUID(),JSON.stringify([{id:1,full_name:'fixture/project'}])]);
  await installationAllowed(org,12345,'fixture/project');
  await assert.rejects(()=>installationAllowed(randomUUID(),12345));
  await assert.rejects(()=>installationAllowed(org,12345,'fixture/other'));
  await db.query('INSERT INTO projects(id,organization_id,name,source_type,source_ref,github_installation_id,policy) VALUES($1,$2,$3,$4,$5,$6,$7)',[project,org,'Webhook fixture','github','fixture/project',12345,JSON.stringify(DEFAULT_POLICY)]);
  const payload=JSON.stringify({action:'synchronize',installation:{id:12345},repository:{full_name:'fixture/project'},pull_request:{head:{repo:{full_name:'fixture/project'},sha:'a'.repeat(40)}}});
  const headers={'x-github-delivery':randomUUID(),'x-github-event':'pull_request','x-hub-signature-256':'sha256='+createHmac('sha256',process.env.GITHUB_WEBHOOK_SECRET).update(payload).digest('hex')};
  const request=()=>new Request('http://127.0.0.1:3000/api/github/webhook',{method:'POST',headers,body:payload});
  assert.deepEqual(await githubWebhook(request()),{queued:1});
  assert.deepEqual(await githubWebhook(request()),{duplicate:true});
  assert.equal((await db.query('SELECT * FROM scans WHERE project_id=$1',[project])).length,1);
  await assert.rejects(()=>githubWebhook(new Request(request().url,{method:'POST',headers:{...headers,'x-hub-signature-256':'sha256=invalid'},body:payload})));
});

test('tenant isolation, runner leases, retry-safe completion, baseline, partial results, and suppression expiry',async()=>{
  const user=randomUUID(),cookie=await signSession(user);
  const request=new Request('http://127.0.0.1:3000/api/overview',{headers:{cookie:`sentinel-session=${cookie}`}});
  const s=await session(request);const project=randomUUID(),runnerId=randomUUID();
  await db.query('INSERT INTO projects(id,organization_id,name,source_type,source_ref,policy) VALUES($1,$2,$3,$4,$5,$6)',[project,s.org,'Fixture','local','fixture',JSON.stringify(policy())]);
  await db.query('INSERT INTO runners(id,organization_id,name,token_hash,project_ids) VALUES($1,$2,$3,$4,$5)',[runnerId,s.org,'Test',hashToken('sgr_test'),JSON.stringify([project])]);
  const runner=(await db.query('SELECT * FROM runners WHERE id=$1',[runnerId]))[0];
  await assert.rejects(()=>session(new Request(request.url,{headers:{cookie:`sentinel-session=${cookie}`,'x-organization-id':randomUUID()}})),(e:unknown)=>e instanceof HttpError&&e.status===403);
  const queued=await enqueue(s,project);const job=await claim(runner);assert.equal(job!.id,queued.id);assert.equal(await claim(runner),null);
  await assert.rejects(()=>heartbeat(runner,job!.id,randomUUID()));
  assert.equal((await finish(runner,job!.id,job!.lease_token,report)).gate,'fail');
  assert.equal((await finish(runner,job!.id,job!.lease_token,report)).gate,'fail');
  const f=(await db.query('SELECT * FROM findings WHERE project_id=$1',[project]))[0];assert(!f.data.evidence.includes('secret-value'));
  await enqueue(s,project);const second=(await claim(runner))!;assert.equal((await finish(runner,second.id,second.lease_token,report)).gate,'pass');
  await db.query("INSERT INTO suppressions(id,organization_id,finding_id,reason,expires_at,created_by) VALUES($1,$2,$3,$4,now()-interval '1 second',$5)",[randomUUID(),s.org,f.id,'Expired test exception',s.user]);
  await db.query("UPDATE findings SET status='accepted' WHERE id=$1",[f.id]);
  await enqueue(s,project);const expiryJob=(await claim(runner))!;assert.equal((await finish(runner,expiryJob.id,expiryJob.lease_token,report)).gate,'fail');
  assert.equal((await db.query('SELECT status FROM findings WHERE id=$1',[f.id]))[0].status,'open');
  await db.query('DELETE FROM suppressions WHERE finding_id=$1',[f.id]);
  await enqueue(s,project);const third=(await claim(runner))!;await finish(runner,third.id,third.lease_token,{...report,findings:[],executions:[{...report.executions[0],status:'failed'}]});
  assert.equal((await db.query('SELECT status FROM findings WHERE id=$1',[f.id]))[0].status,'open');
  await enqueue(s,project);const fourth=(await claim(runner))!;await finish(runner,fourth.id,fourth.lease_token,{...report,findings:[]});
  assert.equal((await db.query('SELECT status FROM findings WHERE id=$1',[f.id]))[0].status,'resolved');
  // A vulnerability that reappears is new again, even with a stable fingerprint.
  await enqueue(s,project);const fifth=(await claim(runner))!;assert.equal((await finish(runner,fifth.id,fifth.lease_token,report)).gate,'fail');
  // Expired leases can be reclaimed; the old worker may not finalize the new attempt.
  await enqueue(s,project);const stale=(await claim(runner))!;await db.query("UPDATE scans SET lease_until=now()-interval '1 second' WHERE id=$1",[stale.id]);
  const fresh=(await claim(runner))!;assert.equal(fresh.id,stale.id);assert.notEqual(fresh.lease_token,stale.lease_token);
  await assert.rejects(()=>finish(runner,stale.id,stale.lease_token,report));
  await db.query('UPDATE scans SET cancel_requested=true WHERE id=$1',[fresh.id]);
  assert.equal((await finish(runner,fresh.id,fresh.lease_token,report)).status,'cancelled');
  // Telemetry is allowlisted, pseudonymized, and idempotent.
  const events=eventsSchema.parse(Array.from({length:10},(_,i)=>({event_key:`failure-${i}`,timestamp:new Date().toISOString(),environment:'local',actor:'10.0.0.1',path:'/login?token=hidden',status:401,auth_outcome:'failure',password:'must-not-store'})));
  assert.equal((await ingest(runner,project,events)).inserted,10);
  assert.equal((await ingest(runner,project,events)).inserted,0);
  const stored=(await db.query('SELECT * FROM runtime_events WHERE project_id=$1',[project]))[0];assert.notEqual(stored.actor_hash,'10.0.0.1');assert.equal(stored.path,'/login');assert(!('password' in stored));
  assert.equal((await db.query('SELECT * FROM alerts WHERE project_id=$1',[project])).length,1);
  const normal=eventsSchema.parse(Array.from({length:20},(_,i)=>({event_key:`normal-${i}`,timestamp:new Date().toISOString(),environment:'local',actor:'normal-client',path:'/home',status:200})));
  await ingest(runner,project,normal);
  assert.equal((await db.query('SELECT * FROM alerts WHERE project_id=$1',[project])).length,1);
  await assert.rejects(()=>ingest({...runner,project_ids:[]},project,events));
  await assert.rejects(()=>ingest(runner,project,[{...events[0],event_key:'future',timestamp:'2099-01-01T00:00:00Z'}]));
  // Endpoint, environment, and revision must match the same event, not different events.
  await enqueue(s,project);const runtimeJob=(await claim(runner))!;
  const runtimeFinding={...finding,fingerprint:'b'.repeat(64),engine:'dast',rule:'runtime-fixture',endpoint:'http://fixture.test/login',environment:'local' as const};
  await finish(runner,runtimeJob.id,runtimeJob.lease_token,{...report,revision:'b'.repeat(40),findings:[runtimeFinding],executions:[{...report.executions[0],engine:'dast'}]});
  const runtimeEvent={timestamp:new Date().toISOString(),environment:'local' as const,actor:'pair-control',path:'/login',status:403,security_event:'authorization_failure' as const};
  await ingest(runner,project,[{...runtimeEvent,event_key:'mismatched-revision',endpoint:'http://fixture.test/login',revision:'c'.repeat(40)},{...runtimeEvent,event_key:'mismatched-endpoint',endpoint:'http://fixture.test/other',revision:'b'.repeat(40)}]);
  const unrelated=(await db.query("SELECT evidence FROM alerts WHERE project_id=$1 AND kind='authorization_failure'",[project]))[0];
  assert.deepEqual(unrelated.evidence.linked_findings,[]);
  await ingest(runner,project,[{...runtimeEvent,event_key:'matching-pair',endpoint:'http://fixture.test/login',revision:'b'.repeat(40)}]);
  const linked=(await db.query("SELECT evidence FROM alerts WHERE project_id=$1 AND kind='authorization_failure'",[project]))[0];
  assert.equal(linked.evidence.linked_findings.length,1);
});
