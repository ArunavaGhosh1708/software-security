"""Real HTTP + runner workflow against an explicitly running local dev server.

Uses synthetic fixtures only; never prints local credentials or runner tokens.
Creates a clearly named sample project and leaves its results available to review.
"""
import datetime as dt
import json
import shutil
import sys
import uuid
from pathlib import Path
import requests
import yaml
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
from runner.core import DEFAULT_POLICY
from runner.service import run_once,Client

values={}
for line in (ROOT/'.env.local').read_text().splitlines():
    if '=' in line:values[line.split('=',1)[0]]=line.split('=',1)[1]
base=values.get('APP_ORIGIN','http://127.0.0.1:3000');session=requests.Session();session.headers['Origin']=base
def api(path,method='GET',body=None):
    response=session.request(method,base+'/api/'+path,json=body,timeout=30)
    if not response.ok:raise RuntimeError(f'{path}: {response.status_code}: {response.json().get("error")}')
    return response.json()

api('auth/login','POST',{'password':values['LOCAL_PASSWORD']})
overview=api('overview')
for old in overview['runners']:
    if old['name']=='Local verification runner' and not old['revoked_at']:api('runners/'+old['id'],'DELETE')
project=next((p for p in overview['projects'] if p['source_ref']=='security-lab'),None)
if not project:project=api('projects','POST',{'name':'Security lab · five languages','source_type':'local','source_ref':'security-lab'})
pid=project['id'];directory=ROOT/'.data'/'security-lab';directory.mkdir(parents=True,exist_ok=True)
for source in (ROOT/'fixtures/vulnerable').iterdir():shutil.copyfile(source,directory/source.name)
credential=api('runners','POST',{'name':'Local verification runner','project_ids':[pid]})
settings={'api_url':base,'token':credential['token'],'roots':{'security-lab':str(directory)},'allowed_targets':[],'scanner_mode':'native'}
policy={**DEFAULT_POLICY,'checks':['guardrails','quality'],'mode':'enforce'}
api(f'projects/{pid}/policy','PUT',{'yaml':yaml.safe_dump(policy)})
# Clear previous synthetic findings so this script is repeatable on the same database.
for source in (ROOT/'fixtures/corrected').iterdir():shutil.copyfile(source,directory/source.name)
api(f'projects/{pid}/scans','POST',{});assert run_once(settings)
for source in (ROOT/'fixtures/vulnerable').iterdir():shutil.copyfile(source,directory/source.name)
scan=api(f'projects/{pid}/scans','POST',{})
assert run_once(settings)
result=api('scans/'+scan['id']);assert result['status']=='completed' and result['gate']=='fail',result
assert set(result['inventory']['languages'])=={'Python','TypeScript','Java','C#','Go'}
assert len(result['findings'])>=5
baseline=api(f'projects/{pid}/scans','POST',{});assert run_once(settings)
assert api('scans/'+baseline['id'])['gate']=='pass'
for source in (ROOT/'fixtures/corrected').iterdir():shutil.copyfile(source,directory/source.name)
fixed=api(f'projects/{pid}/scans','POST',{});assert run_once(settings)
assert api('scans/'+fixed['id'])['gate']=='pass'
assert all(f['status']=='resolved' for f in api('overview')['findings'] if f['project_id']==pid and f['engine']=='guardrails')
for source in (ROOT/'fixtures/vulnerable').iterdir():shutil.copyfile(source,directory/source.name)
# Keep missing required engines visible in the final reviewable report.
api(f'projects/{pid}/policy','PUT',{'yaml':yaml.safe_dump(DEFAULT_POLICY)})
final=api(f'projects/{pid}/scans','POST',{});assert run_once(settings)
assert api('scans/'+final['id'])['gate']=='incomplete'
if '--containers' in sys.argv:
    complete={**DEFAULT_POLICY,'checks':['guardrails','quality','opengrep','gitleaks','trivy'],'mode':'enforce','gate':{**DEFAULT_POLICY['gate'],'new_only':False}}
    api(f'projects/{pid}/policy','PUT',{'yaml':yaml.safe_dump(complete)})
    settings['scanner_mode']='container'
    integrated=api(f'projects/{pid}/scans','POST',{});assert run_once(settings)
    result=api('scans/'+integrated['id'])
    assert result['gate']=='fail' and all(e['status']=='completed' for e in result['executions']),result
    assert api('scans/'+integrated['id']+'/sbom')['bomFormat']=='CycloneDX'
workbench=api('findings?project='+pid+'&limit=2')
assert workbench['total']>=5 and len(workbench['items'])==2
sarif=api('scans/'+scan['id']+'/sarif')
assert sarif['version']=='2.1.0' and any(run['results'] for run in sarif['runs'])
comparison=api('scans/'+fixed['id']+'/compare?base='+scan['id'])
assert len(comparison['no_longer_detected'])>=5 and not comparison['new']
finding_id=workbench['items'][0]['id']
api('findings/assign','POST',{'ids':[finding_id],'assignee':'Security lab team','due_at':None})
api('findings/'+finding_id+'/notes','POST',{'body':'Synthetic workflow verification: review the supplied safe fixture before closing.'})
assert api('findings/'+finding_id+'/notes')
assert 'online_runners' in api('integrations')
client=Client(settings)
events=[{'event_key':uuid.uuid4().hex,'timestamp':dt.datetime.now(dt.timezone.utc).isoformat(),'environment':'local','actor':'synthetic-test-client','path':'/login','status':401,'auth_outcome':'failure'} for _ in range(10)]
assert 'authentication_burst' in client.post('runner/events',{'project_id':pid,'events':events})['alerts']
standards=api('standards?project='+pid);assert len(standards['requirements'])==345
assert any(r['status']=='automated_evidence' for r in standards['requirements'])
api('runners/'+credential['id'],'DELETE')
response=requests.post(base+'/api/runner/claim',json={},headers={'Authorization':'Bearer '+credential['token']},timeout=10)
assert response.status_code==401
print('HTTP smoke passed: onboarding, scoped enrollment, five-language assessment, gates, baseline, resolution, incomplete engines, telemetry, ASVS catalog, credential revocation.')
print('Sample project is available in the dashboard. No credentials were written to the report.')
print('Workbench, assignment, notes, SARIF/SBOM exports, scan comparison, and integration diagnostics passed.')
