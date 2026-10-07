/** Lightweight client. Use a user token or scoped runner token; never a Supabase admin key. */
export class SentinelClient {
  constructor(private base:string,private token:string,private organization?:string) {
    const url=new URL(base);
    if(url.username||url.password||url.search||url.hash||(url.protocol!=='https:'&&!(url.protocol==='http:'&&['localhost','127.0.0.1','[::1]'].includes(url.hostname))))throw new Error('Use HTTPS or a loopback development URL without credentials.');
    this.base=base.replace(/\/$/,'');
  }
  async request<T=unknown>(path:string,method='GET',data?:unknown,idempotencyKey?:string):Promise<T> {
    if(!/^[A-Za-z0-9_/?=&%.:-]+$/.test(path)||path.startsWith('/')||path.includes('..')||path.includes('://')||/%(?:2e|2f|5c)/i.test(path))throw new Error('Invalid API path.');
    const response=await fetch(`${this.base}/api/v1/${path}`,{method,redirect:'error',signal:AbortSignal.timeout(30000),
      headers:{authorization:`Bearer ${this.token}`,'Content-Type':'application/json',...(this.organization?{'X-Organization-Id':this.organization}:{}),...(idempotencyKey?{'Idempotency-Key':idempotencyKey}:{})},body:data===undefined?undefined:JSON.stringify(data)});
    const result=await response.json();
    if(!response.ok)throw Object.assign(new Error(result.error??'Sentinel request failed.'),{status:response.status});
    return result as T;
  }
  queueScan(project:string,options:{revision?:string;branch?:string}={},key?:string){if(!/^[a-f0-9-]{36}$/i.test(project))throw new Error('Invalid project ID.');return this.request<{id:string;status:string}>(`projects/${project}/scans`,'POST',options,key);}
}
