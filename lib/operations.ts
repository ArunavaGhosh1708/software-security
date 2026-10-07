import {z} from 'zod';
import {db} from './db';
import {audit,canWrite,check,redact,type Session} from './security';
import {body} from './validation';
import {projectFor} from './scans';
import catalog from '../data/asvs-5.0.json';
import {analytics} from './analytics';

const uuid=z.string().uuid();
const json=(data:unknown)=>Response.json(data,{headers:{'Cache-Control':'no-store'}});
const cursorSchema=z.object({time:z.string().datetime({offset:true}),id:uuid}).strict();
export async function history(org:string,kind:'scans'|'alerts'|'audit',params:URLSearchParams) {
  const limit=z.coerce.number().int().min(1).max(100).parse(params.get('limit')??50);
  const project=params.has('project')?uuid.parse(params.get('project')):null;
  const cursor=params.get('cursor');let after:z.infer<typeof cursorSchema>|null=null;
  if(cursor){check(cursor.length<300,400,'Invalid cursor.');try{after=cursorSchema.parse(JSON.parse(Buffer.from(cursor,'base64url').toString()));}catch{check(false,400,'Invalid cursor.');}}
  const table={scans:'scans',alerts:'alerts',audit:'audit_events'}[kind];
  const time=kind==='alerts'?'last_seen':'created_at';
  const rows=await db.query(`SELECT r.*${kind==='audit'?'':',p.name AS project_name'} FROM ${table} r
    ${kind==='audit'?'':'JOIN projects p ON p.id=r.project_id'} WHERE r.organization_id=$1
    ${kind==='audit'?'AND $2::uuid IS NULL':'AND ($2::uuid IS NULL OR r.project_id=$2)'}
    AND ($3::timestamptz IS NULL OR (r.${time},r.id)<($3::timestamptz,$4::uuid))
    ORDER BY r.${time} DESC,r.id DESC LIMIT $5`,[org,project,after?.time??null,after?.id??null,limit+1]);
  const items=rows.slice(0,limit),last=items.at(-1);
  return {items,next_cursor:rows.length>limit&&last?Buffer.from(JSON.stringify({time:new Date(last[time]).toISOString(),id:last.id})).toString('base64url'):null};
}
export async function operationalHealth(org:string) {
  return db.query(`SELECT p.id,p.name,p.target IS NOT NULL AS dast_configured,
    p.policy->'checks' ? 'dast' AS dast_enabled,
    (SELECT count(*)::integer FROM runners r WHERE r.organization_id=p.organization_id AND r.revoked_at IS NULL
      AND r.project_ids @> to_jsonb(ARRAY[p.id::text])) AS assigned_runners,
    (SELECT count(*)::integer FROM runners r WHERE r.organization_id=p.organization_id AND r.revoked_at IS NULL
      AND r.last_seen>now()-interval '2 minutes' AND r.project_ids @> to_jsonb(ARRAY[p.id::text])) AS online_runners,
    (SELECT count(*)::integer FROM scans s WHERE s.project_id=p.id AND s.status='queued') AS queued_scans,
    (SELECT count(*)::integer FROM scans s WHERE s.project_id=p.id AND s.status='running' AND s.lease_until<now()) AS expired_leases,
    (SELECT max(occurred_at) FROM runtime_events e WHERE e.project_id=p.id) AS last_event,
    (SELECT coalesce(jsonb_agg(jsonb_build_object('source',c.source,'environment',c.environment,'last_seen',c.last_seen,
      'events',c.events,'unparsed',c.unparsed,'unparsed_total',c.unparsed_total,'status',CASE WHEN c.last_seen<now()-interval '2 minutes' THEN 'offline' ELSE c.status END)),'[]')
      FROM collector_sources c WHERE c.project_id=p.id) AS collectors
    FROM projects p WHERE p.organization_id=$1 ORDER BY p.name`,[org]);
}
export async function operationsApi(request:Request,path:string[],s:Session):Promise<Response|null> {
  const key=path.join('/'),method=request.method,url=new URL(request.url);
  if(method==='GET'&&['scans','alerts','audit'].includes(key))return json(await history(s.org,key as 'scans'|'alerts'|'audit',url.searchParams));
  if(key==='operations'&&method==='GET')return json({projects:await operationalHealth(s.org)});
  if(key==='analytics'&&method==='GET')return json(await analytics(s.org,url.searchParams.has('project')?uuid.parse(url.searchParams.get('project')):null));
  if(key==='organizations'&&method==='GET')return json(await db.query(`SELECT o.id,o.name,m.role FROM organizations o JOIN memberships m ON m.organization_id=o.id WHERE m.user_id=$1 ORDER BY o.name`,[s.user]));
  if(path[0]==='projects'&&path[2]==='controls'&&path.length===3) {
    const id=uuid.parse(path[1]);await projectFor(s.org,id);
    if(method==='GET')return json(await db.query('SELECT *,expires_at>now() AS current FROM control_reviews WHERE project_id=$1 ORDER BY requirement_id',[id]));
    if(method==='PUT') {
      canWrite(s);const b=z.object({requirement_id:z.string().max(30),status:z.enum(['met','not_met','not_applicable','needs_review']),evidence:z.string().trim().min(15).max(5000),expires_at:z.string().datetime({offset:true})}).strict().parse(await body(request,8000));
      check(catalog.requirements.some(r=>r.id===b.requirement_id),400,'Unknown ASVS requirement.');
      check(new Date(b.expires_at).getTime()>Date.now()&&new Date(b.expires_at).getTime()<=Date.now()+366*86400000,400,'Review expiry must be within one year.');
      await db.query(`INSERT INTO control_reviews(project_id,requirement_id,status,evidence,reviewer,expires_at) VALUES($1,$2,$3,$4,$5,$6)
        ON CONFLICT(project_id,requirement_id) DO UPDATE SET status=excluded.status,evidence=excluded.evidence,reviewer=excluded.reviewer,reviewed_at=now(),expires_at=excluded.expires_at`,[id,b.requirement_id,b.status,redact(b.evidence),s.user,b.expires_at]);
      await audit(s,'control.reviewed',`${id}:${b.requirement_id}`);return json({saved:true});
    }
  }
  return null;
}
