import {z} from 'zod';
import {randomUUID} from 'node:crypto';
import {db,transaction} from './db';
import {audit,check,redact,type Session} from './security';
import {priorityFromScore} from './priority';

export const contextSchema=z.object({
  criticality:z.enum(['standard','important','critical']),exposure:z.enum(['unknown','internal','internet']),
  owner:z.string().trim().max(100),
  sla_days:z.object({critical:z.number().int().min(1).max(365),high:z.number().int().min(1).max(365),medium:z.number().int().min(1).max(365),low:z.number().int().min(1).max(730),info:z.number().int().min(1).max(730)}).strict()
}).strict();
export const filterSchema=z.object({
  project:z.string().uuid().optional(),q:z.string().max(200).default(''),
  severity:z.enum(['all','critical','high','medium','low','info']).default('all'),
  status:z.enum(['all','actionable','open','confirmed','accepted','false_positive','resolved']).default('actionable'),
  category:z.enum(['all','security','quality','architecture','suspicious']).default('all'),
  engine:z.string().max(80).default(''),assignee:z.string().max(100).default(''),
  overdue:z.enum(['all','yes']).default('all'),sort:z.enum(['priority','newest','oldest','due']).default('priority'),
  page:z.coerce.number().int().min(1).max(100000).default(1),limit:z.coerce.number().int().min(1).max(100).default(25)
}).strict();

const effectiveStatus=`CASE WHEN f.status IN ('accepted','false_positive') AND (s.expires_at IS NULL OR s.expires_at<=now()) THEN 'open' ELSE f.status END`;
const due=`coalesce(f.due_at,f.first_seen + coalesce((p.security_context->'sla_days'->>f.severity)::integer,30)*interval '1 day')`;
// Transparent triage ordering, not an exploitation probability or a replacement for CVSS.
const score=`LEAST(100,(CASE f.severity WHEN 'critical' THEN 75 WHEN 'high' THEN 55 WHEN 'medium' THEN 30 WHEN 'low' THEN 10 ELSE 0 END)
  + CASE p.security_context->>'criticality' WHEN 'critical' THEN 10 WHEN 'important' THEN 5 ELSE 0 END
  + CASE WHEN p.security_context->>'exposure'='internet' THEN 10 ELSE 0 END
  + CASE WHEN i.kev=true THEN 25 ELSE 0 END
  + CASE WHEN i.epss_date>=current_date-7 AND i.epss>=0.1 THEN 10 ELSE 0 END)`;
const joins=`FROM findings f JOIN projects p ON p.id=f.project_id
 LEFT JOIN suppressions s ON s.finding_id=f.id
 LEFT JOIN threat_intelligence i ON i.organization_id=f.organization_id AND i.cve=coalesce(f.data->>'vulnerability_id',f.rule)`;
export function priorityReasons(row:Record<string,any>) {
  const reasons=[`${row.severity} severity`];
  if(row.security_context?.criticality!=='standard')reasons.push(`${row.security_context?.criticality??'unknown'} business criticality`);
  if(row.security_context?.exposure==='internet')reasons.push('Internet-facing asset (owner supplied)');
  if(row.kev)reasons.push('CISA known exploited vulnerability');
  if(row.epss!==null&&row.epss!==undefined&&new Date(row.epss_date).getTime()>=Date.now()-7*86400000&&row.epss>=0.1)reasons.push('EPSS probability ≥10%');
  return reasons;
}
export async function listFindings(org:string,input:unknown):Promise<{items:Record<string,any>[];total:number;page:number;limit:number;pages:number}> {
  const f=filterSchema.parse(input),params:unknown[]=[org],where=['f.organization_id=$1'];
  const add=(sql:string,v:unknown)=>{params.push(v);where.push(sql.replace('?',`$${params.length}`));};
  if(f.project)add('f.project_id=?',f.project);
  if(f.q)add("(f.title||' '||f.rule||' '||coalesce(f.data->>'path','')||' '||coalesce(f.data->'dependency'->>'name','')) ILIKE ?",`%${f.q.replace(/[\\%_]/g,'\\$&')}%`);
  for(const key of ['severity','category'] as const)if(f[key]!=='all')add(`f.${key}=?`,f[key]);
  if(f.status==='actionable')where.push(`${effectiveStatus} IN ('open','confirmed')`);else if(f.status!=='all')add(`${effectiveStatus}=?`,f.status);
  if(f.engine)add('f.engine=?',f.engine);
  if(f.assignee==='unassigned')where.push("coalesce(f.assignee,p.security_context->>'owner','')=''");else if(f.assignee)add("coalesce(f.assignee,p.security_context->>'owner','')=?",f.assignee);
  if(f.overdue==='yes')where.push(`${due}<now() AND ${effectiveStatus} IN ('open','confirmed')`);
  const predicate=where.join(' AND '),order={priority:'priority_score DESC,f.first_seen ASC,f.id',newest:'f.first_seen DESC,f.id',oldest:'f.first_seen ASC,f.id',due:'effective_due_at ASC,f.id'}[f.sort];
  return transaction(async t=>{
    const total=Number((await t.query(`SELECT count(*) AS total ${joins} WHERE ${predicate}`,params))[0].total);
    const rows=await t.query(`SELECT f.*,p.name AS project_name,p.security_context,${effectiveStatus} AS effective_status,
      s.expires_at AS suppression_expires,s.reason AS suppression_reason,${due} AS effective_due_at,
      coalesce(f.assignee,p.security_context->>'owner','') AS effective_assignee,${score} AS priority_score,
      i.kev,i.epss,i.epss_date,i.kev_checked_at,i.epss_checked_at ${joins} WHERE ${predicate}
      ORDER BY ${order} LIMIT $${params.length+1} OFFSET $${params.length+2}`,[...params,f.limit,(f.page-1)*f.limit]);
    return {items:rows.map(({priority_score,...r})=>({...r,priority:priorityFromScore(Number(priority_score)),priority_reasons:priorityReasons(r)})),total,page:f.page,limit:f.limit,pages:Math.ceil(total/f.limit)};
  });
}
export async function summary(org:string,project?:string) {
  return db.query(`SELECT f.severity,f.category,${effectiveStatus} AS status,count(*)::integer AS count,
    count(*) FILTER (WHERE ${due}<now() AND ${effectiveStatus} IN ('open','confirmed'))::integer AS overdue
    ${joins} WHERE f.organization_id=$1 AND ($2::uuid IS NULL OR f.project_id=$2)
    GROUP BY f.severity,f.category,${effectiveStatus}`,[org,project??null]);
}
export const assignmentSchema=z.object({ids:z.array(z.string().uuid()).min(1).max(100),assignee:z.string().trim().max(100).nullable(),due_at:z.string().datetime({offset:true}).nullable()}).strict();
export async function assignFindings(s:Session,input:unknown) {
  const b=assignmentSchema.parse(input),ids=[...new Set(b.ids)];
  return transaction(async t=>{
    const rows=await t.query('SELECT id FROM findings WHERE organization_id=$1 AND id=ANY($2::uuid[]) FOR UPDATE',[s.org,ids]);
    check(rows.length===ids.length,404,'One or more findings are unavailable.');
    await t.query('UPDATE findings SET assignee=$1,due_at=$2 WHERE organization_id=$3 AND id=ANY($4::uuid[])',[b.assignee===null?null:redact(b.assignee),b.due_at,s.org,ids]);
    for(const id of ids)await audit(s,'finding.assigned',id,t);
    return {updated:rows.length};
  });
}
export async function addNote(s:Session,id:string,input:unknown) {
  const b=z.object({body:z.string().trim().min(1).max(4000)}).strict().parse(input);
  return transaction(async t=>{
    check((await t.query('SELECT 1 FROM findings WHERE id=$1 AND organization_id=$2',[id,s.org])).length,404,'Finding not found.');
    const note={id:randomUUID(),body:redact(b.body)};
    await t.query('INSERT INTO finding_notes(id,organization_id,finding_id,author,body) VALUES($1,$2,$3,$4,$5)',[note.id,s.org,id,s.user,note.body]);
    await audit(s,'finding.note_added',id,t);return note;
  });
}
