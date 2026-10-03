import { randomUUID, createHash } from 'node:crypto';
import { z } from 'zod';
import { transaction } from './db';
import { actorHash, check, redact } from './security';

const eventSchema = z.object({
  event_key:z.string().min(1).max(200),timestamp:z.string().datetime({offset:true}),environment:z.enum(['local','staging','production']),
  actor:z.string().max(300).default('unknown'),path:z.string().max(1000),status:z.number().int().min(100).max(599).optional(),
  auth_outcome:z.enum(['success','failure']).optional(), security_event:z.enum(['authorization_failure','integrity_failure']).optional(),
  revision:z.string().max(200).optional()
  ,endpoint:z.string().url().max(1000).refine(value=>{const u=new URL(value);return ['http:','https:'].includes(u.protocol)&&!u.username&&!u.password&&!u.search&&!u.hash;}).transform(value=>new URL(value).href).optional()
}).strip();
export const eventsSchema = z.array(eventSchema).min(1).max(500);
function indicators(path: string) {
  let text = path; for(let i=0;i<2;i++) {try {text=decodeURIComponent(text);} catch {break;}}
  const list: string[]=[];
  if (/(?:\.\.\/|\.\.\\|\/etc\/passwd)/i.test(text)) list.push('traversal');
  if (/(?:union\s+select|['"]\s*or\s+\d+=\d+|<script\b)/i.test(text)) list.push('injection');
  if (/\/(?:\.env|\.git|wp-admin|actuator\/env)(?:\/|\?|$)/i.test(text)) list.push('sensitive_path');
  return list;
}
export async function ingest(runner: Record<string,any>, projectId: string, events: z.infer<typeof eventsSchema>) {
  check(runner.project_ids.includes(projectId),403,'Runner is not assigned to this project.');
  return transaction(async t => {
    const projects = await t.query('SELECT * FROM projects WHERE id=$1 AND organization_id=$2 FOR UPDATE',[projectId,runner.organization_id]);
    check(projects.length,404,'Project not found.'); const project=projects[0]; let inserted=0;
    for(const e of events) {
      const when = new Date(e.timestamp).getTime();
      check(when<=Date.now()+60000 && when>=Date.now()-7*86400000,400,'Event timestamp outside accepted retention window.');
      const result=await t.query(`INSERT INTO runtime_events(id,organization_id,project_id,event_key,occurred_at,environment,actor_hash,path,status,auth_outcome,security_event,revision,indicators,endpoint)
        VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14) ON CONFLICT(project_id,event_key) DO NOTHING RETURNING id`,
      [randomUUID(),runner.organization_id,projectId,e.event_key,e.timestamp,e.environment,actorHash(e.actor,runner.organization_id),redact(e.path.split('?')[0]),e.status ?? null,e.auth_outcome ?? null,e.security_event ?? null,e.revision ?? null,JSON.stringify(indicators(e.path)),e.endpoint??null]);
      inserted+=result.length;
    }
    const config=project.policy.monitoring;
    const recent=await t.query(`SELECT * FROM runtime_events WHERE project_id=$1 AND occurred_at>now()-$2*interval '1 second' ORDER BY occurred_at`,[projectId,config.window_seconds]);
    const groups=new Map<string,Record<string,any>[]>();
    for(const e of recent) {const k=`${e.actor_hash}:${e.environment}`; groups.set(k,[...(groups.get(k)??[]),e]);}
    const triggered: string[]=[];
    for(const [key,group] of groups) {
      const failures=group.filter(e=>e.auth_outcome==='failure'); const denied=group.filter(e=>[401,403].includes(e.status));
      const candidates: [string,string,string,Record<string,any>[]][]=[];
      if(failures.length>=config.auth_failure_threshold) candidates.push(['authentication_burst','high','Repeated authentication failures',failures]);
      if(denied.length>=config.denied_threshold) candidates.push(['denied_burst','medium','Burst of denied requests',denied]);
      for(const kind of ['injection','traversal','sensitive_path']) {const evidence=group.filter(e=>e.indicators.includes(kind)); if(evidence.length) candidates.push([kind,'medium',`Suspicious ${kind.replace('_',' ')} activity`,evidence]);}
      for(const kind of ['authorization_failure','integrity_failure']) {const evidence=group.filter(e=>e.security_event===kind);if(evidence.length) candidates.push([kind,'high',`Application reported ${kind.replace('_',' ')}`,evidence]);}
      for(const [kind,severity,title,evidence] of candidates) {
        const bucket=Math.floor(new Date(evidence.at(-1)!.occurred_at).getTime()/(config.window_seconds*1000));
        const fp=createHash('sha256').update(`${kind}:${key}:${bucket}`).digest('hex');
        const pairs=evidence.filter(e=>e.endpoint&&e.revision).map(e=>({endpoint:e.endpoint,revision:e.revision,environment:e.environment}));
        const links=await t.query(`SELECT DISTINCT f.id FROM findings f JOIN scan_findings sf ON sf.finding_id=f.id JOIN scans s ON s.id=sf.scan_id
          JOIN jsonb_to_recordset($2::jsonb) AS supplied(endpoint text,revision text,environment text)
          ON sf.data->>'endpoint'=supplied.endpoint AND sf.data->>'environment'=supplied.environment AND s.revision=supplied.revision
          WHERE f.project_id=$1 AND f.status<>'resolved' AND s.status='completed'`,[projectId,JSON.stringify(pairs)]);
        const details={count:evidence.length,window_seconds:config.window_seconds,rule_version:1,configuration:config,events:evidence.slice(-20).map(e=>({id:e.id,path:e.path,status:e.status,timestamp:e.occurred_at})),
          linked_findings:[...new Set(links.map(f=>f.id))],limitation:'Attack indicators do not establish successful exploitation. Detection depends on supplied telemetry.'};
        await t.query(`INSERT INTO alerts(id,organization_id,project_id,fingerprint,kind,severity,title,evidence)
          VALUES($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT(project_id,fingerprint) DO UPDATE SET last_seen=now(),evidence=excluded.evidence`,[randomUUID(),runner.organization_id,projectId,fp,kind,severity,title,JSON.stringify(details)]);
        triggered.push(kind);
      }
    }
    return {inserted,alerts:[...new Set(triggered)]};
  });
}
