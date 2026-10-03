import { randomUUID } from 'node:crypto';
import { db, transaction } from './db';
import { audit, check, redact, type Session } from './security';
import { evaluateGate } from './policy';
import type { ScanReport } from './types';
import {requirementsFor} from './standards';

export async function projectFor(org: string, id: string) {
  const rows = await db.query('SELECT * FROM projects WHERE id=$1 AND organization_id=$2', [id,org]);
  check(rows.length,404,'Project not found.'); return rows[0];
}
export async function enqueue(s: Session, projectId: string, revision?: string) {
  const p = await projectFor(s.org,projectId); const id = randomUUID();
  if (revision) check(/^[a-f0-9]{40}$/i.test(revision),400,'Requested revision must be a complete commit SHA.');
  await db.query('INSERT INTO scans(id,organization_id,project_id,policy,requested_revision) VALUES($1,$2,$3,$4,$5)', [id,s.org,p.id,JSON.stringify(p.policy),revision ?? null]);
  await audit(s,'scan.queued',id); return {id,status:'queued'};
}
export async function claim(runner: Record<string,any>): Promise<Record<string,any> | null> {
  return transaction(async t => {
    // Exhausted jobs become terminal. Never revive cancelled work.
    await t.query(`UPDATE scans SET status=CASE WHEN cancel_requested THEN 'cancelled' ELSE 'failed' END,
      error='Runner lease expired; retries exhausted.',finished_at=now(),gate='incomplete'
      WHERE organization_id=$1 AND status='running' AND lease_until<now() AND (attempts>=3 OR cancel_requested)`,[runner.organization_id]);
    const rows = await t.query(`SELECT s.*,p.source_type,p.source_ref,p.components,p.target,p.metadata_only,p.github_installation_id,p.default_branch
      FROM scans s JOIN projects p ON p.id=s.project_id
      WHERE s.organization_id=$1 AND p.id IN (SELECT value::uuid FROM jsonb_array_elements_text($2::jsonb))
      AND NOT s.cancel_requested AND s.attempts<3 AND
      NOT EXISTS (SELECT 1 FROM scans other WHERE other.project_id=s.project_id AND other.id<>s.id AND other.status='running' AND other.lease_until>now()) AND
      (s.status='queued' OR (s.status='running' AND s.lease_until<now()))
      ORDER BY s.created_at FOR UPDATE OF p,s SKIP LOCKED LIMIT 1`,[runner.organization_id,JSON.stringify(runner.project_ids)]);
    if (!rows.length) return null;
    const job = rows[0], lease = randomUUID();
    await t.query(`UPDATE scans SET status='running',runner_id=$1,lease_token=$2,lease_until=now()+interval '90 seconds',
      attempts=attempts+1,started_at=coalesce(started_at,now()) WHERE id=$3`,[runner.id,lease,job.id]);
    return {...job,lease_token:lease,attempts:job.attempts+1};
  });
}
export async function heartbeat(runner: Record<string,any>, id: string, lease: string) {
  const rows = await db.query(`UPDATE scans SET lease_until=now()+interval '90 seconds' WHERE id=$1 AND organization_id=$2
    AND runner_id=$3 AND lease_token=$4 AND status='running' AND lease_until>now() RETURNING cancel_requested`,[id,runner.organization_id,runner.id,lease]);
  check(rows.length,409,'Lease lost or scan already finished.'); return rows[0];
}
export async function finish(runner: Record<string,any>, id: string, lease: string, report: ScanReport | null, error?: string) {
  return transaction(async t => {
    const scans = await t.query(`SELECT * FROM scans WHERE id=$1 AND organization_id=$2 AND runner_id=$3
      AND lease_token=$4 FOR UPDATE`,[id,runner.organization_id,runner.id,lease]);
    check(scans.length,409,'Lease does not belong to this runner.'); const scan = scans[0];
    // Same lease may retry a delivery after losing the HTTP response.
    if (['completed','failed','cancelled'].includes(scan.status)) return {status:scan.status,gate:scan.gate};
    check(new Date(scan.lease_until).getTime()>Date.now(),409,'Lease expired.');
    if (scan.cancel_requested || !report) {
      const status = scan.cancel_requested ? 'cancelled' : 'failed';
      await t.query('UPDATE scans SET status=$1,error=$2,gate=$3,finished_at=now(),lease_until=NULL WHERE id=$4',[status,redact(error ?? 'Cancelled.'),'incomplete',id]);
      return {status,gate:'incomplete'};
    }
    check(!scan.requested_revision || report.revision === scan.requested_revision,409,'Report revision differs from requested commit.');
    const project = (await t.query('SELECT * FROM projects WHERE id=$1 AND organization_id=$2',[scan.project_id,scan.organization_id]))[0];
    // A PR/explicit commit is not evidence that a default-branch finding was fixed.
    // Until branch baselines are modeled, enforce all findings on these assessments.
    const revisionScoped=project.source_type==='github'&&!!scan.requested_revision;
    const entries: {finding: any; isNew: boolean; suppressed: boolean}[] = [];
    const observed: string[] = [];
    const keys=(f:ScanReport['findings'][number])=>f.category==='security'&&f.path&&f.line ? (f.cwe??[]).map(c=>JSON.stringify([f.path,f.line,c,f.source_revision])) : [];
    const groups=new Map<string,ScanReport['findings']>();
    for(const finding of report.findings)for(const key of keys(finding)){
      const group=groups.get(key)??[];if(group.length<20)group.push(finding);groups.set(key,group);
    }
    for (const raw of report.findings) {
      const related=Array.from(new Map([raw,...keys(raw).flatMap(key=>groups.get(key)??[])].map(other=>[other.fingerprint,other])).values()).slice(0,20);
      const f = {...raw, standards:requirementsFor(raw.rule), evidence: project.metadata_only ? undefined : redact(raw.evidence ?? ''),
        related_reports:related.map(other=>({fingerprint:other.fingerprint,engine:other.engine,rule:other.rule})),
        patch:project.metadata_only ? undefined : raw.patch ? redact(raw.patch) : undefined,
        title:redact(raw.title),impact:redact(raw.impact),remediation:redact(raw.remediation)};
      const existing = await t.query('SELECT f.id,f.status,s.expires_at FROM findings f LEFT JOIN suppressions s ON s.finding_id=f.id WHERE f.project_id=$1 AND f.fingerprint=$2',[scan.project_id,f.fingerprint]);
      const expired=existing[0]?.expires_at && new Date(existing[0].expires_at).getTime()<=Date.now();
      const isNew = revisionScoped || !existing.length || existing[0].status === 'resolved' || !!expired, findingId = existing[0]?.id ?? randomUUID(); observed.push(f.fingerprint);
      if(expired)await t.query("UPDATE findings SET status='open' WHERE id=$1",[findingId]);
      await t.query(`INSERT INTO findings(id,organization_id,project_id,fingerprint,rule,engine,severity,category,title,data,revision)
        VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) ON CONFLICT(project_id,fingerprint) DO UPDATE
        SET last_seen=now(),revision=excluded.revision,data=excluded.data,severity=excluded.severity,title=excluded.title,
        resolved_at=NULL,status=CASE WHEN findings.status='resolved' THEN 'open' ELSE findings.status END`,
      [findingId,scan.organization_id,scan.project_id,f.fingerprint,f.rule,f.engine,f.severity,f.category,f.title,JSON.stringify(f),report.revision]);
      await t.query('INSERT INTO scan_findings(scan_id,finding_id,data,is_new) VALUES($1,$2,$3,$4)',[id,findingId,JSON.stringify(f),isNew]);
      const suppressed = await t.query('SELECT 1 FROM suppressions WHERE finding_id=$1 AND expires_at>now()',[findingId]);
      entries.push({finding:f,isNew,suppressed:suppressed.length>0});
    }
    for (const e of report.executions) await t.query(`INSERT INTO executions(id,scan_id,engine,version,status,duration_ms,coverage,limitations,error,database_updated_at)
      VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,[randomUUID(),id,e.engine,e.version,e.status,e.duration_ms,JSON.stringify(e.coverage),JSON.stringify(e.limitations),e.error ? redact(e.error) : null,e.database_updated_at ?? null]);
    // A partial/failed engine may not resolve prior findings. Empty coverage is not a successful assessment.
    const completed = report.executions.filter(e=>e.status==='completed' && e.coverage.length>0 && !e.limitations.some(x=>x.startsWith('PARTIAL:'))).map(e=>e.engine);
    if (completed.length&&!revisionScoped) await t.query(`UPDATE findings SET status='resolved',resolved_at=now() WHERE project_id=$1
      AND engine=ANY($2::text[]) AND NOT(fingerprint=ANY($3::text[])) AND status IN ('open','confirmed')`,[scan.project_id,completed,observed]);
    const gate = evaluateGate(scan.policy,report.executions,entries);
    await t.query(`UPDATE scans SET status='completed',revision=$1,gate=$2,inventory=$3,metrics=$4,finished_at=now(),lease_until=NULL WHERE id=$5`,[report.revision,gate,JSON.stringify(report.inventory),JSON.stringify(report.metrics),id]);
    await audit({org:scan.organization_id,user:runner.id},'scan.completed',id,t);
    return {status:'completed',gate};
  });
}
