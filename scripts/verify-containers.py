"""Real scanner checks using disposable synthetic input, never repository hooks."""
import json
import tempfile
import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from runner.core import DEFAULT_POLICY
from runner.service import assess,gate
root=Path(__file__).resolve().parents[1]
policy={**DEFAULT_POLICY,'checks':['guardrails','quality','opengrep','gitleaks'],'mode':'enforce'}
bad=assess(root/'fixtures/vulnerable',{},policy)
good=assess(root/'fixtures/corrected',{},policy)
assert all(e['status']=='completed' for e in bad['executions']),bad['executions']
assert gate(bad)=='fail' and gate(good)=='pass'
assert len([f for f in bad['findings'] if f['engine']=='opengrep'])>=5
with tempfile.TemporaryDirectory(prefix='sentinel-integration-') as temp:
    source=Path(temp)
    (source/'requirements.txt').write_text('flask==1.0\n')
    (source/'Dockerfile').write_text('FROM python:3.12\nRUN pip install flask\nCMD ["python", "app.py"]\n')
    (source/'app.py').write_text('import os\nprint("safe fixture")\n')
    (source/'app.ts').write_text('const value: any = 1;\nconsole.log(value);\n')
    (source/'App.java').write_text('public class App { public static void main(String[] args) { } }\n')
    report=assess(source,{}, {**DEFAULT_POLICY,'checks':['trivy','lint']})
    assert all(e['status']=='completed' for e in report['executions']),report['executions']
    assert any(f['engine']=='trivy' and f['path']=='requirements.txt' for f in report['findings'])
    assert report['metrics'].get('sbom')
    (root/'artifacts').mkdir(exist_ok=True)
    (root/'artifacts/container-integration.json').write_text(json.dumps(report,indent=2))
(root/'artifacts/container-vulnerable.json').write_text(json.dumps(bad,indent=2))
(root/'artifacts/container-corrected.json').write_text(json.dumps(good,indent=2))
print('PASS: real Opengrep vulnerable/corrected pairs in five languages; Gitleaks; Trivy dependency/IaC/SBOM; JS/Python/Java lint adapters.')
