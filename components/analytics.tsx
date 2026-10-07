'use client';
import {useEffect,useState} from 'react';
import {api,download} from '@/lib/client';
export default function Analytics({project}:{project:string}) {
  const [data,setData]=useState<Record<string,any>|null>(null),[error,setError]=useState('');
  useEffect(()=>{let active=true;setData(null);setError('');api(`analytics${project==='all'?'':`?project=${project}`}`).then(x=>{if(active)setData(x);}).catch(e=>{if(active)setError(e.message);});return()=>{active=false;};},[project]);
  return <section className="panel"><div className="panel-heading"><div><h2>Assessment trends</h2><p>Last 30 days · all records, rather than the overview preview</p></div><button className="button" disabled={!data} onClick={()=>download('assessment-trends.json',JSON.stringify(data,null,2),'application/json')}>Export</button></div>{error&&<p className="banner error">{error}</p>}{data&&<><div className="integration-body"><p>{data.resolutions.resolved} currently resolved findings · mean resolution time {data.resolutions.mean_resolution_days==null?'not available':`${Number(data.resolutions.mean_resolution_days).toFixed(1)} days`}</p><p className="form-help">{data.limitation}</p></div><div className="table-wrap"><table><thead><tr><th>Day (UTC)</th><th>Assessments</th><th>Pass</th><th>Fail</th><th>Incomplete</th></tr></thead><tbody>{data.scans.map((r:Record<string,any>)=><tr key={r.day}><td>{r.day}</td><td>{r.scans}</td><td>{r.passed}</td><td>{r.failed}</td><td>{r.incomplete}</td></tr>)}</tbody></table></div></>}</section>;
}
