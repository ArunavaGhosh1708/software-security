import {test,after} from 'node:test';
import assert from 'node:assert/strict';
import {randomUUID} from 'node:crypto';
import {db,closeDatabase} from '../lib/db';
import {listFindings,assignFindings,addNote,summary} from '../lib/workbench';
import {sarif,sourceUri,compareReports} from '../lib/exports';
import {DEFAULT_POLICY,type FindingInput} from '../lib/types';
import {workbenchApi} from '../lib/workbench-api';
import {refreshIntelligence} from '../lib/intelligence';
import {enqueue,claim,finish} from '../lib/scans';
import {priorityFromScore} from '../lib/priority';
process.env.DATABASE_MODE='embedded';process.env.TEST_DATABASE='true';
after(closeDatabase);
const finding:FindingInput={fingerprint:'f'.repeat(64),engine:'opengrep',engine_version:'1.16.0',rule:'test',title:'Example',severity:'high',confidence:'high',category:'security',path:'src/file name.ts',line:4,impact:'Example impact',remediation:'Use parameters'};
const execution={engine:'opengrep',version:'1.16.0',status:'completed' as const,duration_ms:1,coverage:['TypeScript'],limitations:[]};

test('priority tiers preserve all severity levels and escalation boundaries',()=>{
  for(const [score,tier] of [[100,'P0'],[75,'P0'],[74,'P1'],[55,'P1'],[50,'P1'],[49,'P2'],[30,'P2'],[25,'P2'],[24,'P3'],[10,'P3'],[9,'P4'],[0,'P4']] as const)
    assert.equal(priorityFromScore(score),tier);
});

test('SARIF preserves stable identity, engine provenance, severity and failed execution without source snippets',()=>{
  const output=sarif([{...finding,evidence:'do not export this source'}],[execution,{...execution,engine:'trivy',status:'failed',error:'No database'}],'abc','incomplete');
  assert.equal(output.version,'2.1.0');assert.equal(output.runs.length,2);
  assert.equal(output.runs[0].results[0].partialFingerprints['sentinel/v1'],finding.fingerprint);
  assert.equal(output.runs[0].results[0].locations?.[0].physicalLocation.artifactLocation.uri,'src/file%20name.ts');
  assert.equal(output.runs[1].invocations[0].executionSuccessful,false);
  assert(!JSON.stringify(output).includes('do not export this source'));
  for(const p of ['/etc/passwd','C:\\private\\file','../secret','https://example.test'])assert.equal(sourceUri(p),undefined);
});
test('comparison never reports a missing or partial engine as a candidate fix',()=>{
  const before={findings:[{data:finding}],policy:DEFAULT_POLICY,inventory:{languages:['TypeScript']}};
  const after={...before,findings:[],executions:[{...execution,status:'failed'}]};
  assert.equal(compareReports(before,after).not_rechecked.length,1);
  assert.equal(compareReports(before,{...after,executions:[execution]}).no_longer_detected.length,1);
  assert.equal(compareReports(before,{...after,executions:[{...execution,limitations:['PARTIAL: skipped files']}]}).no_longer_detected.length,0);
  assert.equal(compareReports(before,{...after,executions:[execution],policy:{...DEFAULT_POLICY,exclusions:['src/**']}}).not_rechecked.length,1);
});
test('workbench enforces tenant isolation, full pagination, expiry, SLAs, ownership and atomic bulk writes',async()=>{
  const org=randomUUID(),other=randomUUID(),project=randomUUID(),ids=Array.from({length:31},()=>randomUUID()),s={org,user:randomUUID(),role:'owner' as const};
  for(const id of [org,other])await db.query('INSERT INTO organizations(id,name) VALUES($1,$2)',[id,'Test org']);
  await db.query('INSERT INTO projects(id,organization_id,name,source_type,source_ref,policy) VALUES($1,$2,$3,$4,$5,$6)',[project,org,'Test app','local','test',JSON.stringify(DEFAULT_POLICY)]);
  for(let i=0;i<ids.length;i++)await db.query(`INSERT INTO findings(id,organization_id,project_id,fingerprint,rule,engine,severity,category,title,data,revision,first_seen)
    VALUES($1,$2,$3,$4,$5,'opengrep','high','security',$6,$7,'abc',now()-interval '40 days')`,[ids[i],org,project,String(i),'CVE-2021-44228',`Finding ${i}`,JSON.stringify({...finding,fingerprint:String(i)})]);
  await db.query("UPDATE findings SET status='accepted' WHERE id=$1",[ids[0]]);
  await db.query("INSERT INTO suppressions(id,organization_id,finding_id,reason,expires_at,created_by) VALUES($1,$2,$3,'Expired test',now()-interval '1 day',$4)",[randomUUID(),org,ids[0],s.user]);
  const first=await listFindings(org,{}),second=await listFindings(org,{page:2});
  assert.equal(first.total,31);assert.equal(first.items.length,25);assert.equal(second.items.length,6);
  assert(first.items.every(r=>r.priority==='P1'&&!('priority_score' in r)));
  assert.equal(new Set([...first.items,...second.items].map(r=>r.id)).size,31);
  assert.equal((await listFindings(org,{overdue:'yes'})).total,31);
  assert.equal((await listFindings(other,{project})).total,0);
  await assert.rejects(assignFindings({...s,org:other},{ids:[ids[0]],assignee:'x',due_at:null}));
  await assert.rejects(assignFindings(s,{ids:[ids[0],randomUUID()],assignee:'x',due_at:null}));
  assert.equal((await db.query('SELECT assignee FROM findings WHERE id=$1',[ids[0]]))[0].assignee,null);
  await assignFindings(s,{ids:[ids[0],ids[1]],assignee:'platform',due_at:'2030-01-01T00:00:00Z'});
  assert.equal((await listFindings(org,{assignee:'platform'})).total,2);
  assert.equal((await listFindings(org,{overdue:'yes'})).total,29);
  await addNote(s,ids[0],{body:'Investigated api_key="private-test-secret"'});
  const note=(await db.query('SELECT body FROM finding_notes WHERE finding_id=$1',[ids[0]]))[0];assert(!note.body.includes('private-test-secret'));
  assert.equal((await summary(org)).reduce((a,r)=>a+r.count,0),31);
  assert.equal((await listFindings(org,{q:"' OR 1=1 --"})).total,0);
  const request=new Request('http://127.0.0.1/api/findings/assign',{method:'POST',body:JSON.stringify({ids:[ids[0]],assignee:'x',due_at:null})});
  await assert.rejects(workbenchApi(request,['findings','assign'],{...s,role:'viewer'}));
  const response=await workbenchApi(new Request('http://127.0.0.1/api/views',{method:'POST',body:JSON.stringify({name:'My triage',filters:{severity:'high'}})}),['views'],s);
  assert.equal(response?.status,201);
  const hidden=await workbenchApi(new Request('http://127.0.0.1/api/views'),['views'],{...s,user:randomUUID()});assert.deepEqual(await hidden!.json(),[]);
  // Public-feed failure preserves known data; unknown CVEs never become zero EPSS.
  const original=global.fetch;
  global.fetch=async input=>String(input).includes('cisa.gov')?Response.json({vulnerabilities:[{cveID:'CVE-2021-44228'}]}):Response.json({data:[{cve:'CVE-2021-44228',epss:'0.9',percentile:'0.99',date:new Date().toISOString().slice(0,10)}]});
  try{
    const refreshed=await refreshIntelligence(s);assert.equal(refreshed.results.length,2);
    const enriched=await listFindings(org,{});assert.equal(enriched.items[0].priority,'P0');assert(!('priority_score' in enriched.items[0]));assert(enriched.items[0].kev);
    global.fetch=async()=>{throw new Error('offline');};await refreshIntelligence(s);
    assert.equal((await listFindings(org,{})).items[0].epss,0.9);
  }finally{global.fetch=original;}
  // Concurrent scanners must not evaluate one project's baseline at the same time.
  const rid=randomUUID();await db.query('INSERT INTO runners(id,organization_id,name,token_hash,project_ids) VALUES($1,$2,$3,$4,$5)',[rid,org,'test runner',rid,JSON.stringify([project])]);
  const runner={id:rid,organization_id:org,project_ids:[project]};
  await enqueue(s,project);await enqueue(s,project);
  const firstJob=await claim(runner);assert(firstJob);assert.equal(await claim(runner),null);
  await finish(runner,firstJob.id,firstJob.lease_token,null,'Synthetic test completion');assert(await claim(runner));
});

test('explicit GitHub revisions do not close baseline findings or silently reuse their new-only gate baseline',async()=>{
  const org=randomUUID(),project=randomUUID(),rid=randomUUID(),fid=randomUUID(),user=randomUUID();
  await db.query('INSERT INTO organizations(id,name) VALUES($1,$2)',[org,'Revision test']);
  const policy={...DEFAULT_POLICY,mode:'enforce',checks:['opengrep']};
  await db.query('INSERT INTO projects(id,organization_id,name,source_type,source_ref,policy) VALUES($1,$2,$3,$4,$5,$6)',[project,org,'Revision app','github','example/test',JSON.stringify(policy)]);
  await db.query('INSERT INTO runners(id,organization_id,name,token_hash,project_ids) VALUES($1,$2,$3,$4,$5)',[rid,org,'Revision runner',rid,JSON.stringify([project])]);
  await db.query(`INSERT INTO findings(id,organization_id,project_id,fingerprint,rule,engine,severity,category,title,data,revision)
    VALUES($1,$2,$3,$4,'test','opengrep','high','security','Baseline',$5,'default-revision')`,[fid,org,project,finding.fingerprint,JSON.stringify(finding)]);
  const s={org,user,role:'owner' as const},runner={id:rid,organization_id:org,project_ids:[project]},revision='a'.repeat(40);
  await enqueue(s,project,revision);let job=await claim(runner);assert(job);
  await finish(runner,job.id,job.lease_token,{schema_version:1,revision,findings:[],executions:[execution],inventory:{},metrics:{}});
  assert.equal((await db.query('SELECT status FROM findings WHERE id=$1',[fid]))[0].status,'open');
  await enqueue(s,project,revision);job=await claim(runner);assert(job);
  const result=await finish(runner,job.id,job.lease_token,{schema_version:1,revision,findings:[finding],executions:[execution],inventory:{},metrics:{}});
  assert.equal(result.gate,'fail');
});
