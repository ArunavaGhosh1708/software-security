'use client';
import {useState} from 'react';
import {LoaderCircle,TriangleAlert} from 'lucide-react';
import {api,download} from '@/lib/client';

type Project={ai_enabled:boolean;metadata_only:boolean};
export default function AiSuggestion({findingId,project,providerConfigured,canWrite,onConfigure}:{
  findingId:string;project?:Project;providerConfigured?:boolean;canWrite:boolean;onConfigure:()=>void;
}) {
  const [pending,setPending]=useState(false),[error,setError]=useState(''),[text,setText]=useState('');
  const [model,setModel]=useState(''),[requestedModel,setRequestedModel]=useState('');
  const needsSettings=!!project&&(!project.ai_enabled||project.metadata_only);
  const reason=!canWrite?'Maintainer access is required to request an AI suggestion.':
    !project?'Project settings are unavailable. Refresh the workspace.':
    needsSettings?[
      !project.ai_enabled?'Optional cloud AI is disabled for this project.':'',
      project.metadata_only?'This project retains metadata only. Enable redacted snippet retention and rescan to collect evidence.':''
    ].filter(Boolean).join(' '):
    providerConfigured===undefined?'Checking AI provider configuration…':
    !providerConfigured?'The AI provider is not configured. Set AI_API_KEY and AI_MODEL on the server.':'';
  async function suggest() {
    if(reason||pending)return;
    setPending(true);setError('');setText('');setModel('');setRequestedModel('');
    try {
      const result=await api(`findings/${findingId}/ai`,'POST',{});
      if(typeof result.text!=='string'||!result.text.trim())throw new Error('The provider returned no suggestion. Try again.');
      setText(result.text);
      setModel(result.model??'');setRequestedModel(result.requested_model??'');
    } catch(e) {setError(e instanceof Error?e.message:'AI request failed. Try again.');}
    finally {setPending(false);}
  }
  return <section aria-label="Optional AI suggestion">
    <h3>Optional AI suggestion</h3>
    {reason?<p>{reason}</p>:<p>Send only this selected finding and its redacted evidence to the configured cloud provider. Provider charges may apply. Suggestions remain unvalidated.</p>}
    <div className="finding-actions">
      <button className="button" disabled={!!reason||pending} onClick={suggest}>
        {pending&&<LoaderCircle className="spin" size={14}/>} {pending?'Generating suggestion…':'Optional AI suggestion'}
      </button>
      {canWrite&&needsSettings&&<button className="button" onClick={onConfigure}>Open project settings</button>}
    </div>
    {pending&&<p role="status">Waiting for the AI provider…</p>}
    {error&&<div className="banner error" role="alert"><TriangleAlert size={17}/>{error}</div>}
    {text&&<><h3>AI proposal · unvalidated</h3>{model&&<p>Generated with {model}{requestedModel&&model!==requestedModel?` · fallback from ${requestedModel}`:''}.</p>}<pre className="ai-output">{text}</pre><button className="button" onClick={()=>download('ai-suggestion.txt',`${model?`Model: ${model}\nRequested model: ${requestedModel}\nValidation: unvalidated\n\n`:''}${text}`)}>Download suggestion</button></>}
  </section>;
}
