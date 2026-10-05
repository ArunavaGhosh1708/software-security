import {test} from 'node:test';
import assert from 'node:assert/strict';
import {aiSuggestion} from '../lib/ai';

const provider=new URL('https://generativelanguage.googleapis.com/v1beta/openai');
test('temporary provider failures retry the same redacted request and recover',async(t)=>{
  let calls=0;
  t.mock.method(globalThis,'fetch',async(_input:unknown,options?:RequestInit)=>{
    calls++;
    assert(!String(options?.body).includes('private-fixture-value'));
    assert(!JSON.parse(String(options?.body)).tools);
    return calls<3?new Response('busy',{status:503}):Response.json({choices:[{message:{content:'Reviewable proposal'}}]});
  });
  assert.equal(await aiSuggestion(provider,'test-key','test-model',{impact:'api_key="private-fixture-value"'}),'Reviewable proposal');
  assert.equal(calls,3);
});
test('provider overload retries are bounded and explain the failure without exposing its body',async(t)=>{
  let calls=0;
  t.mock.method(globalThis,'fetch',async()=>{calls++;return new Response('private-provider-detail',{status:503});});
  await assert.rejects(aiSuggestion(provider,'test-key','test-model',{}),/busy or temporarily unavailable after retries/);
  assert.equal(calls,3);
});
for(const [status,message] of [[429,'quota or rate limit'],[401,'credentials or permissions'],[404,'configured AI model']] as const) {
  test(`provider ${status} returns actionable guidance without retries`,async(t)=>{
    let calls=0;t.mock.method(globalThis,'fetch',async()=>{calls++;return new Response('private-provider-detail',{status});});
    await assert.rejects(aiSuggestion(provider,'test-key','test-model',{}),new RegExp(message));assert.equal(calls,1);
  });
}
test('empty and malformed successes are errors rather than fake suggestions',async(t)=>{
  t.mock.method(globalThis,'fetch',async()=>Response.json({choices:[{message:{content:' '}}]}));
  await assert.rejects(aiSuggestion(provider,'test-key','test-model',{}),/returned no suggestion/);
  t.mock.method(globalThis,'fetch',async()=>new Response('not json'));
  await assert.rejects(aiSuggestion(provider,'test-key','test-model',{}),/invalid response/);
});
test('network errors hide internal details',async(t)=>{
  t.mock.method(globalThis,'fetch',async()=>{throw new Error('private-provider-detail');});
  await assert.rejects(aiSuggestion(provider,'test-key','test-model',{}),/Could not reach the AI provider/);
});
