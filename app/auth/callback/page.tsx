'use client';
import {useEffect,useRef,useState} from 'react';
import {useRouter} from 'next/navigation';
import Link from 'next/link';
import {LoaderCircle,ShieldCheck} from 'lucide-react';
import {api,supabase} from '@/lib/client';
import {AUTHENTICATED_PATH,oauthCallbackCode} from '@/lib/oauth';

export default function AuthCallback() {
  const router=useRouter(),exchange=useRef<Promise<void>|null>(null),[error,setError]=useState('');
  useEffect(()=>{
    let active=true;
    if(!exchange.current)exchange.current=(async()=>{
      const callback=window.location.href;
      // Remove authorization codes and provider error parameters from browser history.
      window.history.replaceState(null,'','/auth/callback');
      const code=oauthCallbackCode(callback);
      if(!supabase)throw new Error('Google sign-in is not configured for this workspace.');
      const result=await supabase.auth.exchangeCodeForSession(code);
      if(result.error||!result.data.session)throw new Error('Your sign-in link expired or could not be verified. Start Google sign-in again.');
      await api('auth/logout','POST',{}); // Retire a previous local development identity.
      await api('overview'); // Server verifies the token and resolves organization membership.
    })();
    exchange.current.then(()=>{if(active)router.replace(AUTHENTICATED_PATH);}).catch(e=>{if(active)setError((e as Error).message);});
    return()=>{active=false;};
  },[router]);
  return <main className="oauth-screen"><section><ShieldCheck size={34}/><h1>{error?'Sign-in could not be completed':'Completing your sign-in'}</h1>{error?<><p role="alert">{error}</p><Link className="button primary" href="/signin">Return to sign in</Link></>:<p role="status"><LoaderCircle size={18} className="spin"/>Verifying your session and opening your workspace…</p>}</section></main>;
}
