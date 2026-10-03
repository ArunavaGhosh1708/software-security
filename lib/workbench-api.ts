import {randomUUID} from 'node:crypto';
import {z} from 'zod';
import {db} from './db';
import {audit,canOwn,canWrite,check,rateLimit,type Session} from './security';
import {body} from './validation';
import {addNote,assignFindings,contextSchema,filterSchema,listFindings,summary} from './workbench';
import {compareReports,sarif} from './exports';
import {projectFor} from './scans';
import {refreshIntelligence,INTELLIGENCE_SOURCES} from './intelligence';

const uuid=z.string().uuid();
const json=(data:unknown,status=200)=>Response.json(data,{status,headers:{'Cache-Control':'no-store'}});
async function report(org:string,id:string):Promise<Record<string,any>&{findings:Record<string,any>[];executions:Record<string,any>[]}> {
  const rows=await db.query('SELECT * FROM scans WHERE id=$1 AND organization_id=$2',[uuid.parse(id),org]);check(rows.length,404,'Scan not found.');
  return {...rows[0],executions:await db.query('SELECT * FROM executions WHERE scan_id=$1',[id]),findings:await db.query('SELECT data FROM scan_findings WHERE scan_id=$1',[id])};
}
export async function workbenchApi(request:Request,path:string[],s:Session):Promise<Response|null> {
  const key=path.join('/'),method=request.method,url=new URL(request.url);
  if(key==='findings'&&method==='GET')return json(await listFindings(s.org,Object.fromEntries(url.searchParams)));
  if(key==='findings/summary'&&method==='GET')return json(await summary(s.org,url.searchParams.has('project')?uuid.parse(url.searchParams.get('project')):undefined));
  if(key==='findings/assign'&&method==='POST'){canWrite(s);return json(await assignFindings(s,await body(request,20000)));}
  if(path[0]==='findings'&&path[2]==='notes'&&path.length===3) {
    const id=uuid.parse(path[1]);check((await db.query('SELECT 1 FROM findings WHERE id=$1 AND organization_id=$2',[id,s.org])).length,404,'Finding not found.');
    if(method==='GET')return json(await db.query('SELECT id,author,body,created_at FROM finding_notes WHERE finding_id=$1 AND organization_id=$2 ORDER BY created_at DESC LIMIT 100',[id,s.org]));
    if(method==='POST'){canWrite(s);return json(await addNote(s,id,await body(request,5000)),201);}
  }
  if(key==='views'&&method==='GET')return json(await db.query('SELECT id,name,filters FROM saved_views WHERE organization_id=$1 AND user_id=$2 ORDER BY name',[s.org,s.user]));
  if(key==='views'&&method==='POST') {
    const b=z.object({name:z.string().trim().min(1).max(80),filters:filterSchema}).strict().parse(await body(request,3000));
    const count=Number((await db.query('SELECT count(*) AS n FROM saved_views WHERE organization_id=$1 AND user_id=$2',[s.org,s.user]))[0].n);check(count<30,400,'Limit of 30 personal views reached.');
    await db.query('INSERT INTO saved_views(id,organization_id,user_id,name,filters) VALUES($1,$2,$3,$4,$5) ON CONFLICT(organization_id,user_id,name) DO UPDATE SET filters=excluded.filters',[randomUUID(),s.org,s.user,b.name,JSON.stringify(b.filters)]);return json({saved:true},201);
  }
  if(path[0]==='views'&&path.length===2&&method==='DELETE'){await db.query('DELETE FROM saved_views WHERE id=$1 AND organization_id=$2 AND user_id=$3',[uuid.parse(path[1]),s.org,s.user]);return json({deleted:true});}
  if(path[0]==='projects'&&path[2]==='context'&&path.length===3&&method==='PUT') {
    canWrite(s);const id=uuid.parse(path[1]);await projectFor(s.org,id);const context=contextSchema.parse(await body(request,2000));
    await db.query('UPDATE projects SET security_context=$1 WHERE id=$2 AND organization_id=$3',[JSON.stringify(context),id,s.org]);await audit(s,'project.context_updated',id);return json(context);
  }
  if(path[0]==='scans'&&path.length===3&&path[2]==='compare'&&method==='GET') {
    const after=await report(s.org,path[1]),before=await report(s.org,uuid.parse(url.searchParams.get('base')));
    check(after.project_id===before.project_id,400,'Compare assessments from the same project.');
    check(after.status==='completed'&&before.status==='completed',409,'Both assessments must be completed.');
    return json({...compareReports(before,after),base:before.id,current:after.id});
  }
  if(path[0]==='scans'&&path.length===3&&['sarif','sbom'].includes(path[2])&&method==='GET') {
    const r=await report(s.org,path[1]);check(r.status==='completed',409,'Assessment has not completed.');
    if(path[2]==='sarif')return json(sarif(r.findings.map(f=>f.data),r.executions as any,r.revision,r.gate));
    check(r.metrics?.sbom?.bomFormat==='CycloneDX',404,'No CycloneDX SBOM was produced. Enable Trivy and review execution coverage.');
    return json(r.metrics.sbom);
  }
  if(key==='intelligence/refresh'&&method==='POST'){canOwn(s);await rateLimit(`intel:${s.org}`,2,3600);return json(await refreshIntelligence(s));}
  if(key==='integrations'&&method==='GET') {
    const stats=await db.query(`SELECT
      (SELECT count(*)::integer FROM projects WHERE organization_id=$1) AS projects,
      (SELECT count(*)::integer FROM runners WHERE organization_id=$1 AND revoked_at IS NULL AND last_seen>now()-interval '2 minutes') AS online_runners,
      (SELECT count(*)::integer FROM scans WHERE organization_id=$1 AND status='queued') AS queued_scans,
      (SELECT count(*)::integer FROM scans WHERE organization_id=$1 AND status='running' AND lease_until<now()) AS expired_leases,
      (SELECT max(kev_checked_at) FROM threat_intelligence WHERE organization_id=$1) AS kev_checked_at,
      (SELECT max(epss_checked_at) FROM threat_intelligence WHERE organization_id=$1) AS epss_checked_at`,[s.org]);
    return json({...stats[0],github_configured:!!(process.env.GITHUB_APP_ID&&process.env.GITHUB_APP_PRIVATE_KEY&&process.env.GITHUB_WEBHOOK_SECRET),ai_configured:!!(process.env.AI_API_KEY&&process.env.AI_MODEL),sources:INTELLIGENCE_SOURCES});
  }
  return null;
}
