import {z} from 'zod';
import {projectSchema,policySchema,reportSchema} from './validation';
export function openApi() {
  const routes:Record<string,Record<string,string>>={
    '/projects':{post:'Connect a local alias or an authorized GitHub repository'},
    '/projects/{id}':{get:'Read project settings',patch:'Update project settings',delete:'Delete project and assessment data'},
    '/projects/{id}/scans':{post:'Queue an assessment; optional Idempotency-Key header, revision SHA and branch'},
    '/projects/{id}/policy':{put:'Save declarative guardrails YAML for future scans'},
    '/projects/{id}/context':{put:'Save asset criticality, exposure, owner and SLAs'},
    '/projects/{id}/controls':{get:'List manual ASVS reviews',put:'Save expiring manual evidence'},
    '/scans':{get:'Paginated assessment history: project, cursor, limit'},
    '/scans/{id}':{get:'Assessment details and execution coverage'},
    '/scans/{id}/cancel':{post:'Request cancellation'},
    '/scans/{id}/export':{get:'Export normalized report'},
    '/scans/{id}/sarif':{get:'Export SARIF'},'/scans/{id}/sbom':{get:'Export CycloneDX'},
    '/scans/{id}/dependency-paths':{get:'Bounded SBOM relationship paths; package query; no reachability inference'},
    '/scans/{id}/compare':{get:'Compare with base scan ID'},
    '/findings':{get:'Filtered paginated findings'},'/findings/summary':{get:'Full finding counts'},
    '/findings/assign':{post:'Atomic bulk assignment'},'/findings/{id}':{patch:'Triage with required suppression reason and expiry'},
    '/findings/{id}/notes':{get:'Investigation notes',post:'Add redacted note'},'/findings/{id}/ai':{post:'Request selected redacted evidence explanation; no execution'},
    '/alerts':{get:'Paginated runtime alerts'},'/alerts/{id}':{patch:'Triage runtime alert'},
    '/audit':{get:'Paginated organization audit history'},'/operations':{get:'Per-project runner, DAST and collector health'},
    '/standards':{get:'ASVS catalog with automated coverage and manual evidence'},
    '/analytics':{get:'Thirty-day assessment and observed resolution trends'},
    '/invitations':{get:'Owner lists workspace invitations',post:'Owner creates seven-day email-bound invitation'},'/invitations/accept':{post:'Redeem invitation with verified Supabase email'},'/invitations/{id}':{delete:'Owner revokes pending invitation'},
    '/overview':{get:'Bounded dashboard preview'},'/integrations':{get:'Connection diagnostics'},
    '/organizations':{get:'List the authenticated user’s workspaces'},'/members':{get:'List workspace roles',post:'Owner adds a known user ID'},
    '/runners':{post:'Enroll scoped private runner; credential shown once'},'/runners/{id}':{delete:'Revoke runner'},
    '/views':{get:'List personal and shared workspace views',post:'Save personal or maintainer-published shared view'},'/views/{id}':{delete:'Delete own view'},
    '/github/connect':{post:'Begin GitHub workspace binding'},'/github/connect/complete':{post:'Complete verified GitHub binding'},'/github/repositories':{get:'Authorized repository choices'},
    '/intelligence/refresh':{post:'Refresh public CVE intelligence'},
    '/runner/claim':{post:'Claim scoped queued assessment'},'/runner/heartbeat':{post:'Renew live lease'},'/runner/finish':{post:'Idempotent report delivery'},'/runner/events':{post:'Ingest allowlisted events'},'/runner/collector-status':{post:'Report source health without local paths'}
  };
  const paths=Object.fromEntries(Object.entries(routes).map(([path,methods])=>[path,Object.fromEntries(Object.entries(methods).map(([method,summary])=>[method,{summary,
    security:[{[path.startsWith('/runner/')?'runnerBearer':'supabaseBearer']:[]}],
    parameters:[...(path.includes('{id}')?[{name:'id',in:'path',required:true,schema:{type:'string',format:'uuid'}}]:[]),{name:'X-Organization-Id',in:'header',schema:{type:'string',format:'uuid'},description:'Must be an existing membership; never grants access.'}],
    responses:{'200':{description:'Successful response; JSON'},'400':{description:'Invalid input'},'401':{description:'Authentication required'},'403':{description:'Insufficient role or scope'},'409':{description:'Lease, revision or idempotency conflict'}}}]))]));
  return {openapi:'3.1.0',info:{title:'Sentinel API',version:'1.0.0',description:'Versioned API transport. Request schemas below cover core records; endpoint-specific mutation and response schemas are still being expanded. Runtime validation remains authoritative.'},servers:[{url:'/api/v1'}],paths,
    components:{securitySchemes:{supabaseBearer:{type:'http',scheme:'bearer',description:'Supabase user access token'},runnerBearer:{type:'http',scheme:'bearer',description:'Organization/project-scoped runner credential'}},schemas:{Project:z.toJSONSchema(projectSchema,{unrepresentable:'any'}),Policy:z.toJSONSchema(policySchema,{unrepresentable:'any'}),Report:z.toJSONSchema(reportSchema,{unrepresentable:'any'})}}};
}
