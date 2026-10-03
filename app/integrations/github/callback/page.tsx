'use client';
import {useEffect,useRef,useState} from 'react';
import Link from 'next/link';
import {api} from '@/lib/client';

export default function GithubCallback() {
  const started=useRef(false),[message,setMessage]=useState('Verifying your GitHub connection…'),[failed,setFailed]=useState(false);
  useEffect(()=>{
    if(started.current)return;started.current=true;
    const params=new URL(window.location.href).searchParams;
    window.history.replaceState(null,'',window.location.pathname);
    if(params.has('error')){setFailed(true);setMessage('GitHub authorization was cancelled. Return to Integrations to try again.');return;}
    const values:Record<string,string>={};
    for(const key of ['state','installation_id','code']) {
      const entries=params.getAll(key);
      if(entries.length>1){setFailed(true);setMessage('Invalid GitHub callback. Start Connect GitHub again.');return;}
      if(entries[0])values[key]=entries[0];
    }
    api('github/connect/complete','POST',values).then(result=>{
      if(result.url){window.location.assign(result.url);return;}
      setMessage(`GitHub account ${result.account} is connected. You can now select its authorized repositories.`);
    }).catch(error=>{setFailed(true);setMessage(error.status===401?'Sign in to Sentinel, then restart Connect GitHub from Integrations.':error.message);});
  },[]);
  return <main className="auth-page"><section className="panel"><div className="integration-body">
    <h1>{failed?'GitHub connection needs attention':'Connect GitHub'}</h1><p role="status">{message}</p>
    <Link className="button" href="/dashboard?tab=integrations">Return to Integrations</Link>
  </div></section></main>;
}
