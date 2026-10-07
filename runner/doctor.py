"""Read-only prerequisite checks. Never loads or executes target repository code."""
import datetime as dt
import json
import shutil
import subprocess
from pathlib import Path
from .adapters import IMAGES,image_ref

def diagnose(settings):
    checks=[];docker=shutil.which('docker')
    def add(name,ready,detail):checks.append({'name':name,'status':'ready' if ready else 'needs_attention','detail':detail})
    available=False
    if docker:
        try:available=subprocess.run([docker,'info','--format','{{.ServerVersion}}'],capture_output=True,timeout=15).returncode==0
        except (OSError,subprocess.TimeoutExpired):pass
    add('Docker',available,'Engine reachable' if available else 'Start Docker Desktop with Linux containers, or install Docker Engine.')
    for engine in IMAGES:
        ready=False
        if available:
            try:ready=subprocess.run([docker,'image','inspect',image_ref(engine)],capture_output=True,timeout=10).returncode==0
            except (OSError,ValueError,subprocess.TimeoutExpired):pass
        add(engine,ready,'Prepared image available' if ready else 'Cannot inspect images until Docker is reachable.' if not available else 'Run python -m runner.cli prepare --build-linters')
    fresh=False
    try:
        stamp=json.loads((Path(settings.get('cache_dir','.data/trivy-cache'))/'db/metadata.json').read_text()).get('UpdatedAt')
        age=(dt.datetime.now(dt.timezone.utc)-dt.datetime.fromisoformat(stamp.replace('Z','+00:00'))).total_seconds();fresh=0<=age<=172800
    except (OSError,ValueError,TypeError,AttributeError):pass
    add('Advisory database',fresh,'Updated within 48 hours' if fresh else 'Refresh scanner preparation; missing/stale advisories make required checks incomplete.')
    for alias,root in settings.get('roots',{}).items():add('Source alias '+alias,Path(root).is_dir(),'Directory available' if Path(root).is_dir() else 'Register an existing source directory.')
    return {'ready':all(c['status']=='ready' for c in checks),'checks':checks,'limitation':'Checks local prerequisites only; this does not validate target credentials, repository access, or application coverage.'}
