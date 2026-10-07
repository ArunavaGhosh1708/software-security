import {test} from 'node:test';
import assert from 'node:assert/strict';
import {SentinelClient} from '../lib/sdk';
import {openApi} from '../lib/openapi';
test('SDK uses versioned authenticated transport, tenant scope and idempotency without redirects',async t=>{
  const client=new SentinelClient('https://sentinel.example','user-token','org');
  t.mock.method(globalThis,'fetch',async(input:unknown,options?:RequestInit)=>{
    assert.equal(String(input),'https://sentinel.example/api/v1/projects/aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa/scans');
    const headers=new Headers(options?.headers);assert.equal(headers.get('authorization'),'Bearer user-token');assert.equal(headers.get('x-organization-id'),'org');assert.equal(headers.get('idempotency-key'),'unique-key-1');assert.equal(options?.redirect,'error');
    return Response.json({id:'scan',status:'queued'});
  });
  assert.equal((await client.queueScan('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa',{},'unique-key-1')).status,'queued');
  await assert.rejects(()=>client.request('../outside'));await assert.rejects(()=>client.request('%2e%2e/outside'));
  assert.throws(()=>new SentinelClient('http://public.example','token'));
  assert.throws(()=>new SentinelClient('https://user:pass@example.com','token'));
});
test('OpenAPI describes the versioned transport and scoped core schemas',()=>{
  const document=openApi();assert.equal(document.openapi,'3.1.0');assert.equal(document.servers[0].url,'/api/v1');
  assert(document.paths['/projects/{id}/scans']);assert(document.components.schemas.Project);assert(document.components.schemas.Report);
});
