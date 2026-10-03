import {remediationGuide} from '@/lib/remediation';

export default function Remediation({finding}:{finding:Parameters<typeof remediationGuide>[0]}) {
  const guide=remediationGuide(finding);
  return <section className="remediation-guide"><h3>How to fix it</h3><p>{guide.summary}</p><ol>{guide.steps.map((step,i)=><li key={i}>{step}</li>)}</ol><h3>How to verify</h3><p>{guide.verification}</p><p className="form-help">{guide.basis} · Recommended actions have not been executed or validated.</p>{guide.limitation&&<div className="banner">{guide.limitation}</div>}</section>;
}
