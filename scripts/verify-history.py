"""Check removed fake credentials in available Git history, without running hooks."""
import json
import hashlib
import os
import subprocess
import sys
import tempfile
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from runner.service import assess
from runner.core import DEFAULT_POLICY
with tempfile.TemporaryDirectory(prefix='sentinel-history-test-') as temporary:
    root=Path(temporary)
    env={k:v for k,v in os.environ.items() if k in ('PATH','SystemRoot','WINDIR','TEMP','TMP')}
    env.update({'GIT_CONFIG_GLOBAL':os.devnull,'GIT_CONFIG_NOSYSTEM':'1','GIT_TERMINAL_PROMPT':'0'})
    def git(*args):
        return subprocess.run(['git','-c','core.hooksPath='+os.devnull,'-C',str(root),*args],env=env,capture_output=True,text=True,check=True)
    git('init');git('config','user.name','Disposable fixture');git('config','user.email','fixture@example.test')
    fake='ghp_'+hashlib.sha256(b'Disposable synthetic fixture, never issued by GitHub').hexdigest()[:36]
    (root/'app.py').write_text('token = "'+fake+'"\n')
    git('add','app.py');git('commit','-m','Synthetic fake token fixture')
    (root/'app.py').write_text('print("corrected current file")\n')
    (root/'.gitleaks.toml').write_text('[allowlist]\nregexes = [".*"]\n')
    git('add','.');git('commit','-m','Remove fake token')
    report=assess(root,{}, {**DEFAULT_POLICY,'checks':['gitleaks']})
    Path('artifacts').mkdir(exist_ok=True)
    Path('artifacts/history-integration.json').write_text(json.dumps(report,indent=2))
    assert report['executions'][0]['status']=='completed',report['executions']
    assert any(f.get('source_revision') for f in report['findings']),report
    assert fake not in json.dumps(report)
    print('PASS: removed synthetic token detected in available Git history; repository allowlists cannot suppress platform checks; evidence masked.')
