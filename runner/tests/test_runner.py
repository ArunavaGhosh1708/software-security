import json
import threading
from pathlib import Path
import pytest
from runner.core import DEFAULT_POLICY,guardrails,inventory,load_policy,redact,snapshot
from runner.service import assess,gate
from runner.collector import normalize,collect_once
from runner.adapters import Executor,parse_gitleaks,parse_trivy,Cancelled
from runner.dast_guard import Scope,verify_target

PAIRS=[
 ('app.py','eval(user_input)','json.loads(user_input)','python.dynamic-eval'),
 ('app.ts','eval(userInput)','JSON.parse(userInput)','javascript.dynamic-eval'),
 ('App.java','new ObjectInputStream(input);','new DataInputStream(input);','java.native-deserialization'),
 ('App.cs','new BinaryFormatter();','JsonSerializer.Deserialize<Model>(input);','csharp.binary-formatter'),
 ('app.go','cfg := tls.Config{InsecureSkipVerify: true}','cfg := tls.Config{MinVersion: tls.VersionTLS12}','go.tls-bypass')]

@pytest.mark.parametrize('filename,bad,good,rule',PAIRS)
def test_vulnerable_corrected_pairs(tmp_path,filename,bad,good,rule):
    p=tmp_path/filename;p.write_text(bad)
    policy={**DEFAULT_POLICY,'checks':['guardrails','quality'],'mode':'enforce'}
    report=assess(tmp_path,{},policy)
    assert any(f['rule']==rule for f in report['findings']);assert gate(report)=='fail'
    p.write_text(good);corrected=assess(tmp_path,{},policy)
    assert not any(f['rule']==rule for f in corrected['findings']);assert gate(corrected)=='pass'

def test_fingerprint_survives_line_insertion(tmp_path):
    p=tmp_path/'app.py';p.write_text('eval(user_input)')
    policy={**DEFAULT_POLICY,'checks':['guardrails']}
    before=assess(tmp_path,{},policy);p.write_text('# harmless comment\n\neval(user_input)')
    after=assess(tmp_path,{},policy)
    assert before['findings'][0]['fingerprint']==after['findings'][0]['fingerprint']

def test_snapshots_skip_dependencies_and_large_files(tmp_path):
    root=tmp_path/'source';root.mkdir();(root/'app.py').write_text('print(1)');(root/'node_modules').mkdir();(root/'node_modules'/'bad.py').write_text('eval(x)')
    (root/'large.py').write_bytes(b'x'*2000001);out=tmp_path/'copy';out.mkdir()
    result=snapshot(root,out,[])
    assert result['files']==['app.py'];assert result['excluded_or_oversized']==['large.py']

def test_component_traversal_is_rejected(tmp_path):
    output=tmp_path/'output';output.mkdir()
    with pytest.raises(ValueError):snapshot(tmp_path,output,[],[{'root':'../outside'}])

def test_unavailable_scanner_produces_incomplete_not_pass(tmp_path):
    (tmp_path/'app.py').write_text('print(1)')
    report=assess(tmp_path,{'scanner_mode':'native'},{**DEFAULT_POLICY,'checks':['trivy']})
    assert report['executions'][0]['status']=='unavailable';assert gate(report)=='incomplete'

def test_no_repository_hooks_are_executed(tmp_path):
    marker=tmp_path/'executed';(tmp_path/'package.json').write_text(json.dumps({'scripts':{'postinstall':f'touch {marker}'}}))
    assess(tmp_path,{}, {**DEFAULT_POLICY,'checks':['guardrails','quality']})
    assert not marker.exists()

def test_repository_policy_cannot_enable_cli_compilation(tmp_path,monkeypatch):
    import sys
    import yaml
    from runner.cli import main
    (tmp_path/'App.cs').write_text('public class App {}')
    (tmp_path/'security-guardrails.yml').write_text(yaml.safe_dump({**DEFAULT_POLICY,'checks':['lint'],'compiler_analysis':True}))
    output=tmp_path/'report.json'
    monkeypatch.setattr(sys,'argv',['sentinel','scan','--path',str(tmp_path),'--output',str(output)])
    assert main()==2
    assert json.loads(output.read_text())['policy']['compiler_analysis'] is False

def test_policy_rejects_commands_and_duplicate_keys(tmp_path):
    import yaml
    p=tmp_path/'security-guardrails.yml';p.write_text(yaml.safe_dump({**DEFAULT_POLICY,'command':'execute'}))
    with pytest.raises(ValueError):load_policy(p)
    p.write_text('version: 1\nversion: 1\n')
    with pytest.raises(ValueError):load_policy(p)

def test_boundary_and_unsafe_api_rules(tmp_path):
    (tmp_path/'ui.py').write_text('from database import admin\nunsafe_api(x)')
    policy={**DEFAULT_POLICY,'checks':['guardrails'],'architecture':[{'from':'ui.py','forbidden':['database']}],'unsafe_apis':['unsafe_api']}
    rules={f['rule'] for f in assess(tmp_path,{},policy)['findings']}
    assert {'policy.layer-boundary','policy.unsafe-api'}<=rules

def test_gitleaks_report_never_retains_secret():
    output=parse_gitleaks([{'RuleID':'test','File':'app.py','StartLine':4,'Secret':'do-not-retain','Match':'api_key=do-not-retain'}])
    assert 'do-not-retain' not in json.dumps(output)

def test_secret_remediation_distinguishes_key_types_and_evidence():
    output=parse_gitleaks([{'RuleID':rule,'File':'config.ts','StartLine':7,'Secret':'never-retain'} for rule in ['private-key','generic-api-key']])
    assert output[0]['remediation']!=output[1]['remediation']
    assert 'public client identifier' in output[1]['remediation']
    assert all('config.ts:7' in f['remediation'] and 'validity' in f['limitation'] for f in output)
    assert 'never-retain' not in json.dumps(output)

def test_json_and_url_credentials_are_redacted():
    assert 'hidden-value' not in redact('{"api_key":"hidden-value"}')
    assert 'hidden-value' not in redact('https://user:hidden-value@example.test')
    assert 'dXNlcjpwYXNzd29yZA==' not in redact('Authorization: Basic dXNlcjpwYXNzd29yZA==')

def test_trivy_normalization_has_upgrade_and_advisory_identity():
    result=parse_trivy({'Results':[{'Target':'package-lock.json','Vulnerabilities':[{'VulnerabilityID':'CVE-test','PkgName':'test-package','InstalledVersion':'1.0','FixedVersion':'2.0','Severity':'HIGH'}]}]})
    assert result[0]['severity']=='high';assert '2.0' in result[0]['remediation']

def test_collector_allowlists_sensitive_fields():
    payload={'timestamp':'2026-09-30T20:00:00Z','path':'/login','password':'secret','authorization':'Bearer secret','body':{'secret':1},'actor':'1.2.3.4'}
    event=normalize(json.dumps(payload),'key','local')
    assert 'password' not in event and 'authorization' not in event and 'body' not in event
    event=normalize(json.dumps({**payload,'path':'/search?token=hidden-value&q=union%20select%20users'}),'key','local')
    assert 'hidden-value' not in event['path'] and 'union%20select' in event['path']
    assert normalize(json.dumps({**payload,'timestamp':'2026-09-30T20:00:00'}),'key','local') is None

def test_collector_retry_does_not_advance_checkpoint(tmp_path):
    log=tmp_path/'app.log';checkpoint=tmp_path/'checkpoint.json'
    log.write_text(json.dumps({'timestamp':'2026-09-30T20:00:00Z','path':'/login'})+'\n')
    class Failing:
        def post(self,*a,**k):raise RuntimeError('offline')
    with pytest.raises(RuntimeError):collect_once(Failing(),'project',log,checkpoint,'local')
    assert not checkpoint.exists()
    class Working:
        def post(self,*a,**k):return {}
    assert collect_once(Working(),'project',log,checkpoint,'local')['events']==1
    assert collect_once(Working(),'project',log,checkpoint,'local')['events']==0

def test_dast_scope_rejects_redirects_traversal_and_exclusions(monkeypatch):
    monkeypatch.setattr('runner.dast_guard.resolve',lambda *a:{'127.0.0.1'})
    scope=Scope({'url':'http://127.0.0.1:8080','exclusions':['/logout','/admin/*']})
    assert scope.validate('/login')=='127.0.0.1'
    for path in ['/logout','/admin/delete','/%252e%252e/etc/passwd','http://evil.example/']:
        with pytest.raises(ValueError):scope.validate(path)
    with pytest.raises(ValueError):scope.redirect('https://evil.example/','/login')
    monkeypatch.setattr('runner.dast_guard.resolve',lambda *a:{'169.254.169.254'})
    with pytest.raises(ValueError):scope.validate('/login')

def test_hosted_dast_rejects_private_addresses(monkeypatch):
    monkeypatch.setattr('runner.dast_guard.resolve',lambda *a:{'10.0.0.1'})
    with pytest.raises(ValueError):Scope({'url':'http://example.test','hosted':True})

def test_dast_rejects_invalid_credentials_and_bounds_request_rate(monkeypatch):
    from types import SimpleNamespace
    monkeypatch.setattr('runner.dast_guard.resolve',lambda *a:{'127.0.0.1'})
    scope=Scope({'url':'http://127.0.0.1:8080','credential':'Bearer synthetic-test-value'})
    class Rejected:
        def __init__(self,*a,**k):pass
        def request(self,*a,**k):assert k['headers']['Authorization']=='Bearer synthetic-test-value'
        def getresponse(self):return SimpleNamespace(status=401,getheader=lambda name:None)
        def close(self):pass
    monkeypatch.setattr('runner.dast_guard.http.client.HTTPConnection',Rejected)
    with pytest.raises(ValueError,match='credentials'):verify_target(scope)
    ticks=iter([1.,1.,1.1,1.5]);delays=[]
    monkeypatch.setattr('runner.dast_guard.time.monotonic',lambda:next(ticks))
    monkeypatch.setattr('runner.dast_guard.time.sleep',delays.append)
    scope.last=0;scope.throttle();scope.throttle()
    assert delays==pytest.approx([.4])
    scope.requests=3600
    with pytest.raises(ValueError,match='budget'):scope.throttle()

def test_cancelled_scan_never_runs_engine(tmp_path):
    cancel=threading.Event();cancel.set()
    with pytest.raises(Cancelled):assess(tmp_path,{}, {**DEFAULT_POLICY,'checks':['guardrails']},cancel=cancel)
