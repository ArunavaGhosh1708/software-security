import {test} from 'node:test';
import assert from 'node:assert/strict';
import {aiFallbackModels,aiSuggestion} from '../lib/ai';

const provider=new URL('https://generativelanguage.googleapis.com/v1beta/openai');
test('temporary provider failures retry the same redacted request and recover',async(t)=>{
  let calls=0;
  t.mock.method(globalThis,'fetch',async(_input:unknown,options?:RequestInit)=>{
    calls++;
    assert(!String(options?.body).includes('private-fixture-value'));
    assert(!JSON.parse(String(options?.body)).tools);
    return calls<3?new Response('busy',{status:503}):Response.json({choices:[{message:{content:'Reviewable proposal'}}]});
  });
  assert.equal((await aiSuggestion(provider,'test-key','test-model',{impact:'api_key="private-fixture-value"'})).text,'Reviewable proposal');
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

test('Gemini fallback recovers overload with identical redacted input and model provenance',async(t)=>{
  const calls:{url:string;payload:any}[]=[];
  t.mock.method(globalThis,'fetch',async(input:unknown,options?:RequestInit)=>{
    const payload=JSON.parse(String(options?.body));calls.push({url:String(input),payload});
    assert(!JSON.stringify(payload).includes('private-fixture-value'));
    return payload.model==='gemini-primary'?new Response('busy',{status:503}):Response.json({choices:[{message:{content:'Proposal api_key="response-fixture-value"'}}]});
  });
  const result=await aiSuggestion(provider,'test-key','gemini-primary',{evidence:'api_key="private-fixture-value"'},['gemini-secondary']);
  assert.deepEqual(calls.map(c=>c.payload.model),['gemini-primary','gemini-primary','gemini-secondary']);
  assert(calls.every(c=>c.url===provider.href+'/chat/completions'));
  assert.deepEqual(calls[0].payload.messages,calls[2].payload.messages);
  assert.equal(result.model,'gemini-secondary');assert.equal(result.requested_model,'gemini-primary');assert(result.fallback_used);
  assert(!result.text.includes('response-fixture-value'));
});
test('Gemini fallback configuration is bounded, deduplicated and restricted to the Google endpoint',()=>{
  assert.deepEqual(aiFallbackModels(provider,'gemini-primary','gemini-secondary,gemini-secondary,gemini-primary'),['gemini-secondary']);
  assert.deepEqual(aiFallbackModels(provider,'gemini-primary',''),[]);
  assert.deepEqual(aiFallbackModels(new URL('https://other.example/v1/chat'),'gemini-primary','gemini-secondary'),[]);
  assert.deepEqual(aiFallbackModels(new URL('https://generativelanguage.googleapis.com/other'),'gemini-primary','gemini-secondary'),[]);
  assert.throws(()=>aiFallbackModels(provider,'gemini-primary','gemini-one,gemini-two,gemini-three'),/at most two/);
  assert.throws(()=>aiFallbackModels(provider,'gemini-primary','https://other.example'),/Gemini model IDs/);
});
test('an inaccessible fallback is skipped and the chain remains bounded',async(t)=>{
  const models:string[]=[];
  t.mock.method(globalThis,'fetch',async(_input:unknown,options?:RequestInit)=>{
    const model=JSON.parse(String(options?.body)).model;models.push(model);
    return new Response('private-detail',{status:model==='gemini-stale'?404:503});
  });
  await assert.rejects(aiSuggestion(provider,'test-key','gemini-primary',{},['gemini-stale','gemini-secondary']),/after retries and any configured fallbacks/);
  assert.deepEqual(models,['gemini-primary','gemini-primary','gemini-stale','gemini-secondary']);
});
for(const status of [400,401,403,404,429]) {
  test(`provider ${status} never switches models`,async(t)=>{
    let calls=0;t.mock.method(globalThis,'fetch',async()=>{calls++;return new Response('private-detail',{status});});
    await assert.rejects(aiSuggestion(provider,'test-key','gemini-primary',{},['gemini-secondary']));assert.equal(calls,1);
  });
}
test('a primary timeout leaves an attempt for the fallback',async(t)=>{
  const models:string[]=[];
  t.mock.method(globalThis,'fetch',async(_input:unknown,options?:RequestInit)=>{
    const model=JSON.parse(String(options?.body)).model;models.push(model);
    if(model==='gemini-primary')throw new DOMException('private-detail','TimeoutError');
    return Response.json({choices:[{message:{content:'Reviewable proposal'}}]});
  });
  const result=await aiSuggestion(provider,'test-key','gemini-primary',{},['gemini-secondary']);
  assert.equal(result.model,'gemini-secondary');assert(result.fallback_used);assert.equal(models.length,3);
});
test('empty or safety-blocked content does not trigger a model switch',async(t)=>{
  let calls=0;
  t.mock.method(globalThis,'fetch',async()=>{calls++;return Response.json({choices:[{finish_reason:'content_filter',message:{content:''}}]});});
  await assert.rejects(aiSuggestion(provider,'test-key','gemini-primary',{},['gemini-secondary']),/returned no suggestion/);
  assert.equal(calls,1);
});
