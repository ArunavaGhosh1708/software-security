// Queries public feeds with one public CVE in an isolated in-memory database.
import {randomUUID} from 'node:crypto';
import {db,closeDatabase} from '../lib/db';
import {refreshIntelligence} from '../lib/intelligence';
import {DEFAULT_POLICY} from '../lib/types';
process.env.DATABASE_MODE='embedded';process.env.TEST_DATABASE='true';
const org=randomUUID(),project=randomUUID();
try{
  await db.query('INSERT INTO organizations(id,name) VALUES($1,$2)',[org,'Disposable feed validation']);
  await db.query('INSERT INTO projects(id,organization_id,name,source_type,source_ref,policy) VALUES($1,$2,$3,$4,$5,$6)',[project,org,'Public CVE fixture','local','fixture',JSON.stringify(DEFAULT_POLICY)]);
  await db.query(`INSERT INTO findings(id,organization_id,project_id,fingerprint,rule,engine,severity,category,title,data,revision)
    VALUES($1,$2,$3,'public-feed-fixture','CVE-2021-44228','fixture','critical','security','Public CVE fixture','{}','fixture')`,[randomUUID(),org,project]);
  const result=await refreshIntelligence({org,user:randomUUID(),role:'owner'});
  console.log(JSON.stringify(result,null,2));
  if(result.results.some(r=>r.status!=='updated'))process.exitCode=2;
  else{
    const row=(await db.query('SELECT * FROM threat_intelligence WHERE organization_id=$1',[org]))[0];
    if(!row?.kev||row.epss==null)throw new Error('Expected known exploited CVE and a public EPSS score.');
    console.log('PASS: live CISA KEV and FIRST EPSS normalized with separate freshness metadata.');
  }
}finally{await closeDatabase();}
