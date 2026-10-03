import {readFileSync} from 'node:fs';
import {randomUUID} from 'node:crypto';
for(const line of readFileSync('.env.supabase.local','utf8').split(/\r?\n/)){const i=line.indexOf('=');if(i>0)process.env[line.slice(0,i)]=line.slice(i+1);}
const base=process.env.SUPABASE_URL!,key=process.env.SUPABASE_ANON_KEY!;
const headers={'Content-Type':'application/json',apikey:key};
const response=await fetch(`${base}/auth/v1/signup`,{method:'POST',headers,body:JSON.stringify({email:`sentinel-test-${randomUUID()}@example.test`,password:randomUUID()+randomUUID()})});
if(!response.ok)throw new Error(`Local Supabase signup failed: ${response.status}`);
const auth=await response.json();
if(!auth.access_token||!auth.user?.id)throw new Error('Autoconfirm test did not obtain a session.');
const {db,closeDatabase}=await import('../lib/db');
const {session}=await import('../lib/security');
let organization:string|undefined;
try{
  const s=await session(new Request('http://127.0.0.1:3000/api/overview',{headers:{authorization:`Bearer ${auth.access_token}`}}));
  organization=s.org;
  if(s.user!==auth.user.id||s.role!=='owner')throw new Error('Supabase identity did not match the organization session.');
  const rows=await db.query("SELECT relname,relrowsecurity FROM pg_class WHERE relnamespace='public'::regnamespace AND relname IN ('projects','findings','scans')");
  if(rows.length!==3||rows.some(r=>!r.relrowsecurity))throw new Error('Assessment RLS is missing.');
  const grants=await db.query("SELECT has_table_privilege('authenticated','public.projects','SELECT') AS allowed");
  if(grants[0].allowed)throw new Error('Direct assessment-table access was unexpectedly granted.');
  console.log('PASS: real PostgreSQL schema, Supabase signup/token verification, organization bootstrap, RLS, and restricted direct grants.');
}finally{
  if(organization)await db.query('DELETE FROM organizations WHERE id=$1',[organization]);
  await db.query('DELETE FROM auth.users WHERE id=$1',[auth.user.id]);
  await closeDatabase();
}
