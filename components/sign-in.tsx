'use client';
import {useState,type FormEvent} from 'react';
import {useRouter} from 'next/navigation';
import {ArrowRight,LoaderCircle,LockKeyhole,ShieldCheck} from 'lucide-react';
import {api,supabase} from '@/lib/client';
import {AUTHENTICATED_PATH,oauthCallbackUrl} from '@/lib/oauth';

export type SignInOptions={local:boolean;password:boolean;google:boolean};
export default function SignIn({options}:{options:SignInOptions}) {
  const router=useRouter(),[error,setError]=useState(''),[busy,setBusy]=useState<'password'|'google'|null>(null);
  const submit=async(e:FormEvent<HTMLFormElement>)=>{
    e.preventDefault();setBusy('password');setError('');const form=new FormData(e.currentTarget);
    try {
      if(options.local){await api('auth/login','POST',{password:form.get('password')});await supabase?.auth.signOut({scope:'local'});}
      else {
        if(!supabase||!options.password)throw new Error('Password sign-in is not enabled for this workspace yet.');
        const result=await supabase.auth.signInWithPassword({email:String(form.get('email')),password:String(form.get('password'))});
        if(result.error)throw new Error('Sign-in failed. Check your email and password, then try again.');
        await api('auth/logout','POST',{});
      }
      router.push(AUTHENTICATED_PATH);router.refresh();
    }catch(e){setError((e as Error).message);}finally{setBusy(null);}
  };
  const google=async()=>{
    setBusy('google');setError('');
    try {
      if(!supabase||!options.google)throw new Error('Google sign-in is not enabled for this workspace yet.');
      const {error}=await supabase.auth.signInWithOAuth({provider:'google',options:{redirectTo:oauthCallbackUrl(window.location.origin),queryParams:{prompt:'select_account'}}});
      if(error)throw new Error('Google sign-in could not be started. Please try again.');
    }catch(e){setError((e as Error).message);setBusy(null);}
  };
  return <div className="signin-card" id="sign-in"><span className="signin-emblem"><ShieldCheck size={24}/></span><div className="eyebrow">YOUR SECURITY WORKSPACE</div><h2>Welcome to Sentinel</h2><p>Sign in to connect your projects and turn findings into action.</p>
    <button type="button" className="google-signin" onClick={google} disabled={!!busy||!options.google}>{busy==='google'?<LoaderCircle size={18} className="spin"/>:<span className="google-letter" aria-hidden="true">G</span>}Continue with Google</button>
    {!options.google&&<p className="signin-provider-note">Google sign-in is not enabled for this workspace yet.</p>}
    <div className="signin-divider"><span>or use your password</span></div>
    <form onSubmit={submit}>{!options.local&&<label>Email address<input name="email" type="email" autoComplete="username" required disabled={!!busy||!options.password}/></label>}<label>{options.local?'Workspace password':'Password'}<input name="password" type="password" autoComplete="current-password" required disabled={!!busy||(!options.local&&!options.password)}/></label>
      {error&&<div className="banner error" role="alert">{error}</div>}<button className="button primary" disabled={!!busy||(!options.local&&!options.password)}>{busy==='password'?<LoaderCircle size={17} className="spin"/>:<>Sign in<ArrowRight size={17}/></>}</button>
    </form><p className="signin-trust"><LockKeyhole size={14}/>Private runners. Scoped access. Your control.</p>
  </div>;
}
