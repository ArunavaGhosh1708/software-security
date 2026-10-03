'use client';
import {useEffect,useState} from 'react';
import {api} from '@/lib/client';

export function ConnectGithubButton({disabled=false,onError}:{disabled?:boolean;onError:(message:string)=>void}) {
  const [busy,setBusy]=useState(false);
  return <button type="button" className="button primary" disabled={disabled||busy} onClick={async()=>{
    setBusy(true);try {const result=await api('github/connect','POST',{});window.location.assign(result.url);}
    catch(error){onError((error as Error).message);setBusy(false);}
  }}>{busy?'Opening GitHub…':'Connect GitHub'}</button>;
}
type Repository={installation_id:number;full_name:string;default_branch:string};
export function GithubRepositoryPicker() {
  const [repositories,setRepositories]=useState<Repository[]>([]),[selected,setSelected]=useState(''),[loading,setLoading]=useState(true),[error,setError]=useState('');
  const refresh=async()=>{setLoading(true);setError('');try{const result=await api('github/repositories');setRepositories(result.repositories);}
    catch(error){setError((error as Error).message);}finally{setLoading(false);}};
  useEffect(()=>{refresh();},[]);
  const repository=repositories.find(r=>`${r.installation_id}:${r.full_name}`===selected);
  return <>
    <label>GitHub repository<select required value={selected} onChange={e=>setSelected(e.target.value)} aria-busy={loading}>
      <option value="">{loading?'Loading repositories…':'Choose an authorized repository'}</option>
      {repositories.map(r=><option key={`${r.installation_id}:${r.full_name}`} value={`${r.installation_id}:${r.full_name}`}>{r.full_name}</option>)}
    </select></label>
    <input type="hidden" name="source" value={repository?.full_name??''}/>
    <input type="hidden" name="installation" value={repository?.installation_id??''}/>
    <input type="hidden" name="branch" value={repository?.default_branch??'main'}/>
    <p className="form-help">Choose repositories on GitHub, then select one here. A workspace owner can connect or update access.</p>
    <div className="inline-actions"><ConnectGithubButton onError={setError}/><button type="button" className="button" disabled={loading} onClick={refresh}>Refresh repositories</button></div>
    {error&&<p className="danger" role="alert">{error}</p>}
  </>;
}
