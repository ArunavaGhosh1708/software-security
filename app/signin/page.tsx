import Link from 'next/link';
import {ArrowLeft,ShieldCheck} from 'lucide-react';
import SignIn from '@/components/sign-in';
import {PublicBrand} from '@/components/landing';
import {authOptions} from '@/lib/auth-config';
export default function SignInPage(){return <main className="public-signin-page"><header><PublicBrand/><Link href="/"><ArrowLeft size={15}/>Back to home</Link></header><div className="public-signin-layout"><section><span className="eyebrow">BUILD WITH CONFIDENCE</span><h1>Your next step toward<br/>safer software.</h1><p>Connect your projects, understand the risks and bring your team a clear path forward.</p><span className="signin-promise"><ShieldCheck size={18}/>Evidence-backed findings. Private scan execution.</span></section><SignIn options={authOptions()}/></div></main>;}
