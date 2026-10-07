import {test,after} from 'node:test';
import assert from 'node:assert/strict';
import {randomUUID} from 'node:crypto';
import {db,closeDatabase} from '../lib/db';
import {DEFAULT_POLICY,type ScanReport} from '../lib/types';
import {enqueue,claim,finish} from '../lib/scans';
import {history,operationalHealth,operationsApi} from '../lib/operations';
import {standardsCoverage} from '../lib/standards';
process.env.DATABASE_MODE='embedded';process.env.TEST_DATABASE='true';
after(closeDatabase);
async function fixture(source='local') {
  const org=randomUUID(),project=randomUUID(),user=randomUUID(),rid=randomUUID();
  await db.query('INSERT INTO organizations(id,name) VALUES($1,$2)',[org,'Operations fixture']);
  const policy={...structuredClone(DEFAULT_POLICY),checks:['guardrails'],mode:'enforce'};
  await db.query('INSERT INTO projects(id,organization_id,name,source_type,source_ref,policy) VALUES($1,$2,$3,$4,$5,$6)',[project,org,'Fixture',source,'fixture',JSON.stringify(policy)]);
  await db.query('INSERT INTO runners(id,organization_id,name,token_hash,project_ids) VALUES($1,$2,$3,$4,$5)',[rid,org,'Runner',randomUUID(),JSON.stringify([project])]);
  return {s:{org,user,role:'owner' as const},project,runner:(await db.query('SELECT * FROM runners WHERE id=$1',[rid]))[0]};
}
const report:ScanReport={schema_version:1,revision:'a'.repeat(40),inventory:{},metrics:{},executions:[{engine:'guardrails',version:'test',status:'completed',duration_ms:1,coverage:['Python'],limitations:[]}],findings:[{fingerprint:'x'.repeat(64),engine:'guardrails',engine_version:'test',rule:'test',severity:'high',confidence:'high',category:'security',title:'Test',impact:'Test',remediation:'Test'}]};
test('queued source, target, components, and privacy scope stay immutable',async()=>{
  const {s,project,runner}=await fixture();await enqueue(s,project);
  await db.query("UPDATE projects SET source_ref='changed',components='[{\"name\":\"new\",\"root\":\"new\"}]',metadata_only=true WHERE id=$1",[project]);
  const job=(await claim(runner))!;assert.equal(job.source_ref,'fixture');assert.deepEqual(job.components,[]);assert.equal(job.metadata_only,false);
  await finish(runner,job.id,job.lease_token,{...report,findings:[{...report.findings[0],evidence:'private snippet'}]});
  assert(!('evidence' in (await db.query('SELECT data FROM findings WHERE project_id=$1',[project]))[0].data));
});
test('branch gates distinguish existing default findings, regressions, and partial coverage',async()=>{
  const {s,project,runner}=await fixture('github');
  const run=async(findings=report.findings,branch?:string,partial=false)=>{
    await enqueue(s,project,branch?report.revision:undefined,branch);
    const job=(await claim(runner))!;
    return finish(runner,job.id,job.lease_token,{...report,findings,executions:partial?[{...report.executions[0],limitations:['PARTIAL: unsupported files']}]:report.executions});
  };
  assert.equal((await run()).gate,'fail');
  assert.equal((await run(report.findings,'feature')).gate,'pass');
  await run([],'feature',true);
  assert.equal((await run(report.findings,'feature')).gate,'pass');
  await run([],'feature');
  assert.equal((await run(report.findings,'feature')).gate,'fail');
  const f=(await db.query('SELECT * FROM findings WHERE project_id=$1',[project]))[0];
  assert.equal((await db.query("SELECT status FROM finding_scopes WHERE finding_id=$1 AND scope='default'",[f.id]))[0].status,'open');
  await run([]); // A finding still present on feature must remain visible.
  assert.equal((await db.query('SELECT status FROM findings WHERE id=$1',[f.id]))[0].status,'open');
});
test('branch-only findings cannot silently enter the default baseline',async()=>{
  const {s,project,runner}=await fixture('github');
  await enqueue(s,project,report.revision,'feature');let job=(await claim(runner))!;await finish(runner,job.id,job.lease_token,report);
  await enqueue(s,project);job=(await claim(runner))!;assert.equal((await finish(runner,job.id,job.lease_token,report)).gate,'fail');
});
test('history pagination covers every record without cross-tenant leakage',async()=>{
  const {s,project}=await fixture();for(let i=0;i<5;i++)await enqueue(s,project);
  const first=await history(s.org,'scans',new URLSearchParams({limit:'2'}));assert.equal(first.items.length,2);assert(first.next_cursor);
  const second=await history(s.org,'scans',new URLSearchParams({limit:'2',cursor:first.next_cursor!}));
  assert(!first.items.some(a=>second.items.some(b=>a.id===b.id)));
  assert.equal((await history(randomUUID(),'scans',new URLSearchParams())).items.length,0);
  assert.equal((await history(s.org,'audit',new URLSearchParams())).items.length,5);
  await assert.rejects(()=>history(s.org,'scans',new URLSearchParams({cursor:'garbage'})));
  const health=(await operationalHealth(s.org))[0];assert.equal(health.online_runners,0);assert.equal(health.queued_scans,5);assert.deepEqual(health.collectors,[]);
});
test('scan submission idempotency is atomic, tenant-scoped, and detects changed revisions',async()=>{
  const {s,project}=await fixture('github');
  const [first,second]=await Promise.all([enqueue(s,project,report.revision,'feature','fixture-key-1'),enqueue(s,project,report.revision,'feature','fixture-key-1')]);
  assert.equal(first.id,second.id);assert.equal((await db.query('SELECT 1 FROM scans WHERE project_id=$1',[project])).length,1);
  await assert.rejects(()=>enqueue(s,project,'b'.repeat(40),'feature','fixture-key-1'));
  await assert.rejects(()=>enqueue({...s,org:randomUUID()},project,report.revision,'feature','fixture-key-1'));
});
test('manual reviews require tenant and writer access; expired evidence never overrides automated status',async()=>{
  const {s,project}=await fixture();
  const payload={requirement_id:'1.2.4',status:'met',evidence:'Reviewed parameterized SQL queries.',expires_at:new Date(Date.now()+86400000).toISOString()};
  const request=()=>new Request('http://localhost/api',{method:'PUT',body:JSON.stringify(payload)});
  await assert.rejects(()=>operationsApi(request(),['projects',project,'controls'],{...s,role:'viewer'}));
  await assert.rejects(()=>operationsApi(request(),['projects',project,'controls'],{...s,org:randomUUID()}));
  assert.equal((await operationsApi(request(),['projects',project,'controls'],s))!.status,200);
  const review=(await db.query('SELECT * FROM control_reviews WHERE project_id=$1',[project]))[0];
  const result=standardsCoverage([{id:'evidence',rule:'sentinel.express-sql-taint'}],[],[{...review,expires_at:'2020-01-01T00:00:00Z'}]);
  const requirement=result.requirements.find(r=>r.id==='1.2.4')!;assert.equal(requirement.status,'automated_evidence');assert.equal(requirement.manual_reviews[0].current,false);
});
