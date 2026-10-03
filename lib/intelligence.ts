import {z} from 'zod';
import {db,transaction} from './db';
import {audit,type Session} from './security';

const cve=z.string().regex(/^CVE-\d{4}-\d{4,}$/);
const kevSchema=z.object({vulnerabilities:z.array(z.object({cveID:cve})).max(30000)});
const epssSchema=z.object({data:z.array(z.object({cve,epss:z.coerce.number().min(0).max(1),percentile:z.coerce.number().min(0).max(1),date:z.string().regex(/^\d{4}-\d{2}-\d{2}$/)})).max(100)});
export const INTELLIGENCE_SOURCES={kev:'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',epss:'https://api.first.org/data/v1/epss'};
async function fetchJson(url:string) {
  const r=await fetch(url,{signal:AbortSignal.timeout(15000),redirect:'error',headers:{Accept:'application/json'}});
  if(!r.ok)throw new Error('Public feed unavailable');
  const reader=r.body?.getReader();if(!reader)throw new Error('Empty feed');
  const chunks:Uint8Array[]=[];let length=0;
  while(true){const {done,value}=await reader.read();if(done)break;length+=value.length;if(length>12_000_000){await reader.cancel();throw new Error('Feed exceeds size limit');}chunks.push(value);}
  return JSON.parse(Buffer.concat(chunks).toString('utf8'));
}
export async function refreshIntelligence(s:Session) {
  const rows=await db.query(`SELECT DISTINCT coalesce(data->>'vulnerability_id',rule) AS cve FROM findings
    WHERE organization_id=$1 AND coalesce(data->>'vulnerability_id',rule) ~ '^CVE-[0-9]{4}-[0-9]{4,}$' ORDER BY cve LIMIT 101`,[s.org]);
  const ids=rows.slice(0,100).map(r=>r.cve),results:{source:string;status:string;count:number}[]=[];
  if(!ids.length)return {results,checked:0,limited:false,message:'No CVE findings to enrich.'};
  // Only public CVE identifiers leave the server. Source, project names, and credentials never do.
  try{
    const kev=new Set(kevSchema.parse(await fetchJson(INTELLIGENCE_SOURCES.kev)).vulnerabilities.map(v=>v.cveID));
    await transaction(async t=>{for(const id of ids)await t.query(`INSERT INTO threat_intelligence(organization_id,cve,kev,kev_checked_at) VALUES($1,$2,$3,now())
      ON CONFLICT(organization_id,cve) DO UPDATE SET kev=excluded.kev,kev_checked_at=excluded.kev_checked_at`,[s.org,id,kev.has(id)]);});
    results.push({source:'CISA KEV',status:'updated',count:ids.length});
  }catch{results.push({source:'CISA KEV',status:'unavailable; previous data retained',count:0});}
  try{
    const all:z.infer<typeof epssSchema>['data']=[];
    for(let i=0;i<ids.length;i+=50)all.push(...epssSchema.parse(await fetchJson(`${INTELLIGENCE_SOURCES.epss}?cve=${ids.slice(i,i+50).join(',')}&limit=100`)).data);
    const allowed=new Set(ids);
    await transaction(async t=>{for(const row of all){if(!allowed.has(row.cve))continue;await t.query(`INSERT INTO threat_intelligence(organization_id,cve,epss,percentile,epss_date,epss_checked_at) VALUES($1,$2,$3,$4,$5,now())
      ON CONFLICT(organization_id,cve) DO UPDATE SET epss=excluded.epss,percentile=excluded.percentile,epss_date=excluded.epss_date,epss_checked_at=excluded.epss_checked_at`,[s.org,row.cve,row.epss,row.percentile,row.date]);}});
    results.push({source:'FIRST EPSS',status:'updated',count:all.filter(x=>allowed.has(x.cve)).length});
  }catch{results.push({source:'FIRST EPSS',status:'unavailable; previous data retained',count:0});}
  await audit(s,'intelligence.refreshed');return {results,checked:ids.length,limited:rows.length>100,limitation:'On-demand enrichment is limited to the first 100 distinct CVEs. Missing or stale scores are unknown, not zero risk.'};
}
