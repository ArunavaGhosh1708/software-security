'use client';
import {useEffect,useState} from 'react';
import {ArrowDownToLine,Search} from 'lucide-react';
import {api,download} from '@/lib/client';
export default function Standards({project}:{project:string}) {
  const [catalog,setCatalog]=useState<Record<string,any>|null>(null),[search,setSearch]=useState(''),[error,setError]=useState('');
  useEffect(()=>{let active=true;api('standards'+(project==='all'?'':`?project=${project}`)).then(x=>{if(active)setCatalog(x);}).catch(e=>setError(e.message));return()=>{active=false;};},[project]);
  if(error)return <div className="banner error">{error}</div>;
  if(!catalog)return <p className="muted" style={{padding:20}}>Loading requirements…</p>;
  const visible=catalog.requirements.filter((r:Record<string,any>)=>`${r.id} ${r.chapter} ${r.description} ${r.status}`.toLowerCase().includes(search.toLowerCase()));
  return <><div className="table-toolbar"><label className="search"><Search size={15}/><input aria-label="Search ASVS requirements" placeholder="Search requirements or coverage status…" value={search} onChange={e=>setSearch(e.target.value)}/></label><span>{visible.length} of {catalog.requirements.length} requirements</span><button className="button" onClick={()=>download('asvs-coverage.json',JSON.stringify(catalog,null,2),'application/json')}><ArrowDownToLine size={14}/>Export</button></div><div className="asvs-list">{visible.map((r:Record<string,any>)=><div key={r.id} className="asvs-row"><div><code>v5.0.0-{r.id}</code><span className={`badge ${r.status}`}>{r.status.replaceAll('_',' ')}</span></div><p>{r.description}</p><small>{r.chapter} · Level {r.level}{r.finding_ids.length?` · ${r.finding_ids.length} evidence items`:''}</small></div>)}</div><p className="coverage-disclaimer">{catalog.attribution}. <a href={catalog.source} target="_blank" rel="noreferrer">Official source</a> · <a href={catalog.license_url} target="_blank" rel="noreferrer">{catalog.license}</a>. Unsupported means automated verification is not implemented; manual review is still required. Evidence does not certify compliance.</p></>;
}
