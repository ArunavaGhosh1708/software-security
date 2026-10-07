'use client';
import {createClient} from '@supabase/supabase-js';
const url=process.env.NEXT_PUBLIC_SUPABASE_URL,key=process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY;
export const supabase=url&&key?createClient(url,key,{auth:{flowType:'pkce',detectSessionInUrl:false}}):null;
export async function api(path:string,method='GET',data?:unknown) {
  const headers:Record<string,string>={'Content-Type':'application/json'};
  const organization=typeof window!=='undefined'?window.localStorage.getItem('sentinel.organization'):null;
  if(organization)headers['x-organization-id']=organization;
  const session=supabase?(await supabase.auth.getSession()).data.session:null;
  if(session)headers.authorization=`Bearer ${session.access_token}`;
  const response=await fetch(`/api/${path}`,{method,headers,credentials:'same-origin',body:data===undefined?undefined:JSON.stringify(data)});
  const result=await response.json();
  if(!response.ok)throw Object.assign(new Error(result.error??'Request failed.'),{status:response.status});
  return result;
}
export function download(name:string,text:string,type='text/plain') {
  const url=URL.createObjectURL(new Blob([text],{type}));const a=document.createElement('a');a.href=url;a.download=name;a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);
}
