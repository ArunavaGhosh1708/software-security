"""Real engine acceptance for original SSRF rules; no outbound fixture requests."""
import json
from pathlib import Path
import sys
import tempfile
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from runner.adapters import Executor,scan_external

cases={
 'vulnerable':('import requests\ndef handler(request):\n    url = request.args.get("url")\n    requests.get(url)\n','async function handler(req) { const url = req.query.url; await fetch(url); }'),
 'corrected':('import requests\ndef handler(request):\n    requests.get("https://approved.example/api")\n','async function handler(req) { await fetch("https://approved.example/api"); }')}
expected={'sentinel.express-ssrf-taint','sentinel.python-ssrf-taint'}
results={}
with tempfile.TemporaryDirectory(prefix='sentinel-ssrf-') as tmp:
 for label,(py,ts) in cases.items():
    root=Path(tmp)/label;root.mkdir();(root/'app.py').write_text(py);(root/'app.ts').write_text(ts)
    findings,execution,_=scan_external('opengrep',root,{'languages':['Python','TypeScript']},Executor(),{})
    assert execution['status']=='completed',execution
    found={rule for rule in expected if any(f['rule'].endswith(rule) for f in findings)}
    assert found==(expected if label=='vulnerable' else set()),(label,found)
    results[label]={'rules':sorted(found),'execution':execution}
Path('artifacts').mkdir(exist_ok=True);Path('artifacts/ssrf-rules.json').write_text(json.dumps(results,indent=2))
print('PASS: both original SSRF rules detect vulnerable URL flow and clear fixed-destination controls.')
