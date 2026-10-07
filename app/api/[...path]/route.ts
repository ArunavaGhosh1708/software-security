import { NextResponse } from 'next/server';
import { randomBytes, randomUUID } from 'node:crypto';
import { z, ZodError } from 'zod';
import { db, transaction } from '@/lib/db';
import { audit, canOwn, canWrite, check, equal, hashToken, HttpError, localAuthAllowed, rateLimit, redact, runnerAuth, session, signSession, verifyOrigin } from '@/lib/security';
import { body, defaultPolicy, parsePolicy, projectSchema, reportSchema, targetSchema } from '@/lib/validation';
import { claim, enqueue, finish, heartbeat, projectFor } from '@/lib/scans';
import { eventsSchema, ingest } from '@/lib/telemetry';
import { githubWebhook, installationToken, installationAllowed, publishCheck, verifyRepository } from '@/lib/github';
import {standardsCoverage} from '@/lib/standards';
import {cleanup} from '@/lib/retention';
import {workbenchApi} from '@/lib/workbench-api';
import {summary} from '@/lib/workbench';
import {authOptions} from '@/lib/auth-config';
import {aiFallbackModels,aiSuggestion} from '@/lib/ai';
import {operationsApi} from '@/lib/operations';
import {openApi} from '@/lib/openapi';
import {invitationsApi} from '@/lib/invitations';

export const runtime='nodejs';
export const dynamic='force-dynamic';
const uuid=z.string().uuid();
const ok=(data:unknown,status=200)=>NextResponse.json(data,{status,headers:{'Cache-Control':'no-store'}});
async function route(request:Request, context:{params:Promise<{path:string[]}>}) {
  try {
    const params=await context.params;const path=params.path[0]==='v1'?params.path.slice(1):params.path; const key=path.join('/'), method=request.method;
    if(method!=='GET')verifyOrigin(request);
    if(key==='health')return ok({status:'ok',version:'0.1.0',database:process.env.DATABASE_MODE??'postgres',local_auth:localAuthAllowed(),google_auth:authOptions().google,github:!!process.env.GITHUB_APP_ID,ai:!!process.env.AI_API_KEY});
    if(key==='maintenance/cleanup'&&['GET','POST'].includes(method)) {
      check(process.env.CRON_SECRET&&process.env.CRON_SECRET.length>=32,503,'Scheduled maintenance is not configured.');
      check(equal(request.headers.get('authorization')??'',`Bearer ${process.env.CRON_SECRET}`),401,'Maintenance credential rejected.');
      return ok({cleaned:await cleanup()});
    }
    if(key==='auth/login'&&method==='POST') {
      check(localAuthAllowed(),403,'Local login is disabled. Use Supabase authentication.');
      await rateLimit('local-login',10,300);
      const {password}=z.object({password:z.string().max(200)}).parse(await body(request,1000));
      check(process.env.LOCAL_PASSWORD && process.env.LOCAL_PASSWORD.length>=16,503,'Run npm run setup to configure a strong local password.');
      check(equal(password,process.env.LOCAL_PASSWORD),401,'Incorrect password.');
      const response=ok({authenticated:true});
      response.cookies.set('sentinel-session',await signSession('00000000-0000-4000-8000-000000000001'),{httpOnly:true,sameSite:'strict',secure:new URL(request.url).protocol==='https:',path:'/',maxAge:28800});return response;
    }
    if(key==='auth/logout'&&method==='POST') {const response=ok({authenticated:false});response.cookies.set('sentinel-session','',{httpOnly:true,path:'/',maxAge:0});return response;}
    if(key==='github/webhook'&&method==='POST')return ok(await githubWebhook(request));
    if(path[0]==='runner') {
      const runner=await runnerAuth(request);
      await rateLimit(`runner:${runner.id}`,300);
      if(key==='runner/claim'&&method==='POST') {
        await cleanup();
        const job=await claim(runner);
        if(job?.source_type==='github') {
          try {await installationAllowed(runner.organization_id,Number(job.github_installation_id),job.source_ref);job.github_token=await installationToken(Number(job.github_installation_id),job.source_ref);}
          catch {await finish(runner,job.id,job.lease_token,null,'GitHub installation authentication failed.');throw new HttpError(502,'GitHub installation authentication failed.');}
        }
        return ok({job});
      }
      if(key==='runner/heartbeat'&&method==='POST') {
        const b=z.object({scan_id:uuid,lease_token:uuid}).parse(await body(request,1000));return ok(await heartbeat(runner,b.scan_id,b.lease_token));
      }
      if(key==='runner/finish'&&method==='POST') {
        const b=z.object({scan_id:uuid,lease_token:uuid,report:reportSchema.nullable(),error:z.string().max(2000).optional()}).parse(await body(request,3_000_000));
        const result=await finish(runner,b.scan_id,b.lease_token,b.report,b.error);
        try {const scan=(await db.query('SELECT * FROM scans WHERE id=$1 AND organization_id=$2',[b.scan_id,runner.organization_id]))[0];if(scan.status==='completed')await publishCheck(scan);}
        catch {await audit({org:runner.organization_id,user:runner.id},'github.check_publish_failed',b.scan_id);}
        return ok(result);
      }
      if(key==='runner/events'&&method==='POST') {
        const b=z.object({project_id:uuid,events:eventsSchema}).parse(await body(request));return ok(await ingest(runner,b.project_id,b.events));
      }
      if(key==='runner/collector-status'&&method==='POST') {
        const b=z.object({project_id:uuid,source:z.string().regex(/^[a-f0-9]{24}$/),environment:z.enum(['local','staging','production']),events:z.number().int().min(0).max(500),unparsed:z.number().int().min(0).max(250),unparsed_total:z.number().int().min(0).max(1000000000).default(0),status:z.enum(['healthy','partial','error'])}).strict().parse(await body(request,2000));
        check(runner.project_ids.includes(b.project_id),403,'Runner is not assigned to this project.');await projectFor(runner.organization_id,b.project_id);
        await db.query(`INSERT INTO collector_sources(project_id,source,environment,runner_id,events,unparsed,status,unparsed_total) VALUES($1,$2,$3,$4,$5,$6,$7,$8)
          ON CONFLICT(project_id,source,environment) DO UPDATE SET runner_id=excluded.runner_id,last_seen=now(),events=excluded.events,unparsed=excluded.unparsed,status=excluded.status,unparsed_total=excluded.unparsed_total`,[b.project_id,b.source,b.environment,runner.id,b.events,b.unparsed,b.status,b.unparsed_total]);
        return ok({received:true});
      }
      throw new HttpError(404,'Runner endpoint not found.');
    }
    const s=await session(request);
    await rateLimit(`user:${s.user}`,300);
    if(key==='openapi'&&method==='GET')return ok(openApi());
    const invitation=await invitationsApi(request,path,s);if(invitation)return invitation;
    const operation=await operationsApi(request,path,s);if(operation)return operation;
    const extended=await workbenchApi(request,path,s);if(extended)return extended;
    if(key==='standards'&&method==='GET') {
      const project=new URL(request.url).searchParams.get('project');if(project)await projectFor(s.org,uuid.parse(project));
      const findings=await db.query('SELECT id,rule FROM findings WHERE organization_id=$1 AND status<>$2 AND ($3::uuid IS NULL OR project_id=$3) AND category=$4',[s.org,'resolved',project,'security']);
      const executions=await db.query(`SELECT e.* FROM executions e JOIN scans s ON s.id=e.scan_id
        WHERE s.id IN (SELECT DISTINCT ON (project_id) id FROM scans WHERE organization_id=$1
          AND ($2::uuid IS NULL OR project_id=$2) ORDER BY project_id,created_at DESC)`,[s.org,project]);
      const reviews=await db.query(`SELECT c.* FROM control_reviews c JOIN projects p ON p.id=c.project_id WHERE p.organization_id=$1 AND ($2::uuid IS NULL OR c.project_id=$2)`,[s.org,project]);
      return ok(standardsCoverage(findings,executions,reviews));
    }
    if(key==='overview'&&method==='GET') {
      const projects=await db.query(`SELECT p.*,(SELECT max(occurred_at) FROM runtime_events e WHERE e.project_id=p.id) AS last_telemetry FROM projects p WHERE p.organization_id=$1 ORDER BY p.created_at DESC`,[s.org]);
      const scans=await db.query('SELECT s.*,p.name AS project_name FROM scans s JOIN projects p ON p.id=s.project_id WHERE s.organization_id=$1 ORDER BY s.created_at DESC LIMIT 100',[s.org]);
      const findings=await db.query(`SELECT f.*,p.name AS project_name,s.reason AS suppression_reason,s.expires_at AS suppression_expires FROM findings f
        JOIN projects p ON p.id=f.project_id LEFT JOIN suppressions s ON s.finding_id=f.id WHERE f.organization_id=$1 ORDER BY f.last_seen DESC LIMIT 1000`,[s.org]);
      const alerts=await db.query('SELECT a.*,p.name AS project_name FROM alerts a JOIN projects p ON p.id=a.project_id WHERE a.organization_id=$1 ORDER BY a.last_seen DESC LIMIT 200',[s.org]);
      const runners=await db.query('SELECT id,name,project_ids,last_seen,revoked_at,created_at FROM runners WHERE organization_id=$1 ORDER BY created_at DESC',[s.org]);
      const auditEvents=await db.query('SELECT action,resource,created_at FROM audit_events WHERE organization_id=$1 ORDER BY created_at DESC LIMIT 50',[s.org]);
      return ok({session:s,projects,scans,findings,alerts,runners,audit:auditEvents,finding_summary:await summary(s.org),
        limits:{findings:1000,scans:100,alerts:200},sampled:findings.length===1000||scans.length===100||alerts.length===200});
    }
    if(key==='projects'&&method==='POST') {
      canWrite(s);const p=projectSchema.parse(await body(request,30000));
      if(p.source_type==='github') {canOwn(s);await verifyRepository(p.source_ref,p.github_installation_id!,s.org);}
      const id=randomUUID();
      await db.query(`INSERT INTO projects(id,organization_id,name,source_type,source_ref,github_installation_id,default_branch,components,target,metadata_only,ai_enabled,policy)
        VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,[id,s.org,p.name,p.source_type,p.source_ref,p.github_installation_id??null,p.default_branch,JSON.stringify(p.components),p.target?JSON.stringify(p.target):null,p.metadata_only,p.ai_enabled,JSON.stringify(defaultPolicy())]);
      await audit(s,'project.created',id);return ok({id,...p},201);
    }
    if(path[0]==='projects'&&path.length>=2) {
      const id=uuid.parse(path[1]);const p=await projectFor(s.org,id);
      if(path.length===2&&method==='GET')return ok(p);
      if(path.length===2&&method==='PATCH') {
        canWrite(s);const b=z.object({name:z.string().min(2).max(100).optional(),target:targetSchema.nullable().optional(),metadata_only:z.boolean().optional(),ai_enabled:z.boolean().optional()}).strict().parse(await body(request,10000));
        await transaction(async t=>{
          const target=b.target===undefined?p.target:b.target;
          await t.query('UPDATE projects SET name=$1,target=$2,metadata_only=$3,ai_enabled=$4 WHERE id=$5 AND organization_id=$6', [b.name??p.name,target?JSON.stringify(target):null,b.metadata_only??p.metadata_only,b.ai_enabled??p.ai_enabled,id,s.org]);
          if(b.metadata_only) {
            await t.query("UPDATE findings SET data=data-'evidence'-'patch'-'source_context' WHERE project_id=$1 AND organization_id=$2",[id,s.org]);
            await t.query("UPDATE scan_findings SET data=data-'evidence'-'patch'-'source_context' WHERE scan_id IN (SELECT id FROM scans WHERE project_id=$1 AND organization_id=$2)",[id,s.org]);
          }
        });
        await audit(s,'project.updated',id);return ok({updated:true});
      }
      if(path.length===2&&method==='DELETE') {canOwn(s);await db.query('DELETE FROM projects WHERE id=$1 AND organization_id=$2',[id,s.org]);await audit(s,'project.deleted',id);return ok({deleted:true});}
      if(path[2]==='scans'&&method==='POST') {canWrite(s);const b=z.object({revision:z.string().optional(),branch:z.string().optional()}).strict().parse(await body(request,1000));return ok(await enqueue(s,id,b.revision,b.branch,request.headers.get('idempotency-key')??undefined),201);}
      if(path[2]==='policy'&&method==='PUT') {
        canWrite(s);const b=z.object({yaml:z.string()}).parse(await body(request,40000));const policy=parsePolicy(b.yaml);
        await db.query('UPDATE projects SET policy=$1 WHERE id=$2 AND organization_id=$3',[JSON.stringify(policy),id,s.org]);await audit(s,'policy.updated',id);return ok(policy);
      }
    }
    if(path[0]==='scans'&&path.length>=2) {
      const id=uuid.parse(path[1]);const scans=await db.query('SELECT * FROM scans WHERE id=$1 AND organization_id=$2',[id,s.org]);check(scans.length,404,'Scan not found.');
      if(path.length===2&&method==='GET')return ok({...scans[0],executions:await db.query('SELECT * FROM executions WHERE scan_id=$1',[id]),findings:await db.query('SELECT finding_id,data,is_new FROM scan_findings WHERE scan_id=$1',[id])});
      if(path[2]==='cancel'&&method==='POST') {canWrite(s);await db.query(`UPDATE scans SET cancel_requested=true,status=CASE WHEN status='queued' THEN 'cancelled' ELSE status END WHERE id=$1 AND organization_id=$2 AND status IN ('queued','running')`,[id,s.org]);await audit(s,'scan.cancelled',id);return ok({cancel_requested:true});}
      if(path[2]==='export'&&method==='GET') {
        const findings=await db.query('SELECT data FROM scan_findings WHERE scan_id=$1',[id]);return ok({schema_version:1,scan:scans[0],findings:findings.map(x=>x.data),executions:await db.query('SELECT * FROM executions WHERE scan_id=$1',[id])});
      }
    }
    if(path[0]==='findings'&&path.length>=2) {
      const id=uuid.parse(path[1]);const rows=await db.query('SELECT * FROM findings WHERE id=$1 AND organization_id=$2',[id,s.org]);check(rows.length,404,'Finding not found.');const f=rows[0];
      if(path.length===2&&method==='PATCH') {
        canWrite(s);const b=z.object({status:z.enum(['open','confirmed','false_positive','accepted']),reason:z.string().trim().min(8).max(1000).optional(),expires_at:z.string().datetime().optional()}).parse(await body(request,2000));
        if(['false_positive','accepted'].includes(b.status))check(b.reason&&b.expires_at&&new Date(b.expires_at).getTime()>Date.now()&&new Date(b.expires_at).getTime()<Date.now()+366*86400000,400,'Suppression requires a reason and future expiry within one year.');
        await transaction(async t=>{
          await t.query('UPDATE findings SET status=$1 WHERE id=$2 AND organization_id=$3',[b.status,id,s.org]);
          if(b.reason&&b.expires_at) await t.query(`INSERT INTO suppressions(id,organization_id,finding_id,reason,expires_at,created_by) VALUES($1,$2,$3,$4,$5,$6)
            ON CONFLICT(finding_id) DO UPDATE SET reason=excluded.reason,expires_at=excluded.expires_at,created_by=excluded.created_by`,[randomUUID(),s.org,id,redact(b.reason),b.expires_at,s.user]);
          else await t.query('DELETE FROM suppressions WHERE finding_id=$1 AND organization_id=$2',[id,s.org]);
          await audit(s,'finding.triaged',id,t);
        });return ok({updated:true});
      }
      if(path[2]==='ai'&&method==='POST') {
        canWrite(s);const p=await projectFor(s.org,f.project_id);
        check(p.ai_enabled&&!p.metadata_only,403,'Enable AI and snippet retention in project settings first.');
        check(process.env.AI_API_KEY&&process.env.AI_MODEL,503,'Configure AI_API_KEY and AI_MODEL; cloud usage can incur charges.');
        const provider=new URL(process.env.AI_BASE_URL??'https://generativelanguage.googleapis.com/v1beta/openai');
        check(provider.protocol==='https:'&&!provider.username&&!provider.password&&!provider.search&&!provider.hash,503,'AI provider must use an HTTPS base URL without credentials, query, or fragment.');
        await rateLimit(`ai:${s.org}`,10,3600);
        const fallbacks=aiFallbackModels(provider,process.env.AI_MODEL);
        const result=await aiSuggestion(provider,process.env.AI_API_KEY,process.env.AI_MODEL,f.data,fallbacks);
        await audit(s,'ai.suggestion_requested',id);
        if(result.fallback_used)await audit(s,'ai.fallback_used',`${id}:${result.model}`);
        return ok({...result,validation:'unvalidated'});
      }
    }
    if(path[0]==='alerts'&&path.length===2&&method==='PATCH') {
      canWrite(s);const id=uuid.parse(path[1]);const b=z.object({status:z.enum(['open','investigating','dismissed','resolved'])}).parse(await body(request,1000));
      const rows=await db.query('UPDATE alerts SET status=$1 WHERE id=$2 AND organization_id=$3 RETURNING id',[b.status,id,s.org]);check(rows.length,404,'Alert not found.');await audit(s,'alert.triaged',id);return ok({updated:true});
    }
    if(key==='runners'&&method==='POST') {
      canOwn(s);const b=z.object({name:z.string().trim().min(2).max(100),project_ids:z.array(uuid).min(1).max(100)}).parse(await body(request,20000));
      for(const id of b.project_ids)await projectFor(s.org,id);
      const id=randomUUID(),token=`sgr_${randomBytes(32).toString('base64url')}`;
      await db.query('INSERT INTO runners(id,organization_id,name,token_hash,project_ids) VALUES($1,$2,$3,$4,$5)',[id,s.org,b.name,hashToken(token),JSON.stringify(b.project_ids)]);
      await audit(s,'runner.enrolled',id);return ok({id,token,message:'Shown once. Save this in your local runner settings.'},201);
    }
    if(path[0]==='runners'&&path.length===2&&method==='DELETE') {canOwn(s);const id=uuid.parse(path[1]);const r=await db.query('UPDATE runners SET revoked_at=now() WHERE id=$1 AND organization_id=$2 RETURNING id',[id,s.org]);check(r.length,404,'Runner not found.');await audit(s,'runner.revoked',id);return ok({revoked:true});}
    if(key==='members'&&method==='GET')return ok(await db.query('SELECT user_id,role FROM memberships WHERE organization_id=$1',[s.org]));
    if(key==='members'&&method==='POST') {
      canOwn(s);const b=z.object({user_id:uuid,role:z.enum(['maintainer','viewer'])}).parse(await body(request,1000));check(b.user_id!==s.user,400,'Cannot change your own owner role.');
      await db.query('INSERT INTO memberships VALUES($1,$2,$3) ON CONFLICT(organization_id,user_id) DO UPDATE SET role=excluded.role',[s.org,b.user_id,b.role]);await audit(s,'member.updated',b.user_id);return ok({updated:true});
    }
    throw new HttpError(404,'Endpoint not found.');
  } catch(error) {
    if(error instanceof HttpError)return ok({error:error.message},error.status);
    if(error instanceof ZodError)return ok({error:error.issues.map(x=>`${x.path.join('.')}: ${x.message}`).join('; ')},400);
    console.error('API request failed:',error instanceof Error ? redact(error.message):'Unknown error');
    return ok({error:'Request failed. Check the server log and local configuration.'},500);
  }
}
export const GET=route;export const POST=route;export const PUT=route;export const PATCH=route;export const DELETE=route;
