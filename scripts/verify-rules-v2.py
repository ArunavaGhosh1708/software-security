"""Validate new original rules against vulnerable cases and safe controls."""
import json
import sys
import tempfile
import threading
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from runner.adapters import Executor,scan_external

bad_py='''import os, requests
def handle(request, app):
    command = request.args.get("command")
    os.system(command)
    requests.get("https://example.test", verify=False)
    app.run(debug=True)
'''
good_py='''import subprocess, requests
def handle(request, app):
    subprocess.run(["echo", request.args.get("value")], shell=False)
    requests.get("https://example.test", verify=True)
    app.run(debug=False)
'''
bad_ts='''import https from "https";
import cp from "child_process";
function handler(req) { cp.exec(req.query.command); }
new https.Agent({ rejectUnauthorized: false });
'''
good_ts='''import https from "https";
import cp from "child_process";
function handler(req) { cp.execFile("echo", [req.query.value]); }
new https.Agent({ rejectUnauthorized: true });
'''
expected={'sentinel.express-command-taint','sentinel.flask-command-taint','sentinel.python-tls-disabled','sentinel.node-tls-disabled','sentinel.flask-debug'}
results={}
with tempfile.TemporaryDirectory(prefix='sentinel-rules-v2-') as tmp:
    for label,python,typescript in [('vulnerable',bad_py,bad_ts),('corrected',good_py,good_ts)]:
        root=Path(tmp)/label;root.mkdir();(root/'app.py').write_text(python);(root/'app.ts').write_text(typescript)
        findings,execution,_=scan_external('opengrep',root,{'languages':['Python','TypeScript']},Executor('container',threading.Event()),{})
        assert execution['status']=='completed',execution
        found={r for r in expected if any(f['rule'].endswith(r) for f in findings)}
        if label=='vulnerable':assert found==expected,(found,execution)
        else:assert not found,found
        results[label]={'rules':sorted(found),'execution':execution}
Path('artifacts').mkdir(exist_ok=True);Path('artifacts/rules-v2.json').write_text(json.dumps(results,indent=2))
print('PASS: all five added AST/taint rules detect vulnerable inputs and clear safe controls in the real engine.')
