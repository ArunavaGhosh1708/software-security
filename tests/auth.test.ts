import {test,after} from 'node:test';
import assert from 'node:assert/strict';
import {randomUUID} from 'node:crypto';
import {authOptions} from '../lib/auth-config';
import {oauthCallbackCode,oauthCallbackUrl,AUTHENTICATED_PATH} from '../lib/oauth';
import {session,signSession} from '../lib/security';
import {db,closeDatabase} from '../lib/db';
process.env.DATABASE_MODE='embedded';process.env.TEST_DATABASE='true';
after(closeDatabase);

test('Google availability requires explicit enablement and both client/server Supabase configuration',()=>{
  const keys=['LOCAL_AUTH','VERCEL','NODE_ENV','GOOGLE_AUTH_ENABLED','SUPABASE_URL','SUPABASE_ANON_KEY','NEXT_PUBLIC_SUPABASE_URL','NEXT_PUBLIC_SUPABASE_ANON_KEY'];
  const previous=Object.fromEntries(keys.map(k=>[k,process.env[k]]));
  try {
    keys.forEach(k=>delete process.env[k]);process.env.LOCAL_AUTH='true';assert(authOptions().local);assert(!authOptions().google);
    process.env.GOOGLE_AUTH_ENABLED='true';assert(!authOptions().google);
    process.env.SUPABASE_URL=process.env.NEXT_PUBLIC_SUPABASE_URL='https://auth.example.test';
    process.env.SUPABASE_ANON_KEY=process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY='public-test-key';assert(authOptions().google);
    delete process.env.SUPABASE_URL;assert(!authOptions().google);
    (process.env as Record<string,string|undefined>).NODE_ENV='production';assert(!authOptions().local);
  }finally{for(const k of keys){if(previous[k]===undefined)delete process.env[k];else process.env[k]=previous[k];}}
});

test('OAuth uses a fixed same-origin callback and fixed workspace destination',()=>{
  assert.equal(oauthCallbackUrl('http://127.0.0.1:3000'),'http://127.0.0.1:3000/auth/callback');
  assert.equal(oauthCallbackUrl('https://sentinel.example'),'https://sentinel.example/auth/callback');
  for(const origin of ['http://public.example','https://user:password@example.test','https://example.test/?next=https://evil.test','javascript:alert(1)'])assert.throws(()=>oauthCallbackUrl(origin));
  assert.equal(oauthCallbackCode('https://example.test/auth/callback?code=one-use-code&next=https://evil.test'),'one-use-code');
  assert.equal(AUTHENTICATED_PATH,'/dashboard');
  for(const query of ['', '?error=access_denied&error_description=private-test-detail','?code=','?code=a&code=b'])assert.throws(()=>oauthCallbackCode('https://example.test/auth/callback'+query),error=>error instanceof Error&&!error.message.includes('private-test-detail'));
});

test('a verified Google identity cannot inherit a local-cookie workspace and invalid OAuth tokens do not fall back',async()=>{
  const old={local:process.env.LOCAL_AUTH,secret:process.env.SESSION_SECRET,url:process.env.SUPABASE_URL,key:process.env.SUPABASE_ANON_KEY};
  const fetchOriginal=global.fetch;
  try {
    process.env.LOCAL_AUTH='true';process.env.SESSION_SECRET='test-only-secret-at-least-32-characters';
    process.env.SUPABASE_URL='https://auth.example.test';process.env.SUPABASE_ANON_KEY='public-test-key';
    const localUser=randomUUID(),googleUser=randomUUID(),cookie=`sentinel-session=${await signSession(localUser)}`;
    const local=await session(new Request('http://127.0.0.1:3000/api/overview',{headers:{cookie}}));
    global.fetch=async(input,options)=>{
      assert.equal(String(input),'https://auth.example.test/auth/v1/user');
      return new Headers(options?.headers).get('authorization')==='Bearer valid-test-token'?Response.json({id:googleUser}):new Response('{}',{status:401});
    };
    const google=await session(new Request('http://127.0.0.1:3000/api/overview',{headers:{cookie,authorization:'Bearer valid-test-token'}}));
    assert.equal(google.user,googleUser);assert.notEqual(google.org,local.org);
    assert.equal((await db.query('SELECT * FROM memberships WHERE user_id=$1 AND organization_id=$2',[googleUser,local.org])).length,0);
    await assert.rejects(session(new Request('http://127.0.0.1:3000/api/overview',{headers:{cookie,authorization:'Bearer invalid-test-token'}})),/Invalid or expired/);
    await assert.rejects(session(new Request('http://127.0.0.1:3000/api/overview',{headers:{authorization:'Bearer valid-test-token','x-organization-id':local.org}})),/Organization access denied/);
  }finally{
    global.fetch=fetchOriginal;
    for(const [key,value] of Object.entries({LOCAL_AUTH:old.local,SESSION_SECRET:old.secret,SUPABASE_URL:old.url,SUPABASE_ANON_KEY:old.key})){if(value===undefined)delete process.env[key];else process.env[key]=value;}
  }
});
