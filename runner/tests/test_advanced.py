import json
import sys
from types import SimpleNamespace
import pytest
from runner.core import DEFAULT_POLICY,quality,inventory,load_policy,redact
from runner.service import assess,gate
from runner.quality_metrics import python_functions
from runner.patches import validate_patch
from runner.dast_guard import Scope,verify_target

def test_python_metrics_exclude_nested_functions_and_cover_boolean_branches():
    functions=python_functions('def outer(a,b):\n    def inner(x):\n        if x: return 1\n    if a and b: return inner(a)\n','app.py')
    assert {f['name']:f['complexity'] for f in functions}=={'outer':3,'inner':2}

def test_metric_gates_fail_and_missing_or_invalid_evidence_is_incomplete(tmp_path):
    (tmp_path/'app.py').write_text('def f(x):\n    if x: return 1\n    return 0\n')
    (tmp_path/'lcov.info').write_text('LF:10\nLH:8\n')
    policy=json.loads(json.dumps(DEFAULT_POLICY));policy['checks']=['quality'];policy['mode']='enforce'
    policy['gate']['min_imported_coverage']=90
    report=assess(tmp_path,{},policy);assert gate(report)=='fail'
    policy['gate']['min_imported_coverage']=70;assert gate(assess(tmp_path,{},policy))=='pass'
    (tmp_path/'lcov.info').write_text('LF:10\nLH:11\n');assert gate(assess(tmp_path,{},policy))=='incomplete'
    del policy['gate']['min_imported_coverage'];policy['gate']['max_python_function_complexity']=1
    assert gate(assess(tmp_path,{},policy))=='fail'
    (tmp_path/'app.py').write_text('def broken(:');assert gate(assess(tmp_path,{},policy))=='incomplete'

def test_curated_source_context_is_bounded_redacted_and_never_reads_outside_snapshot(tmp_path):
    (tmp_path/'app.py').write_text('api_key="fixture-private-value"\neval(user_input)\n')
    report=assess(tmp_path,{},dict(DEFAULT_POLICY,checks=['guardrails']))
    context=report['findings'][0]['source_context'];assert 'fixture-private-value' not in context and 'eval' in context
    (tmp_path/'app.py').write_text('eval(user_input)\n# -----BEGIN PRIVATE KEY-----\nprivate-material\n# -----END PRIVATE KEY-----')
    report=assess(tmp_path,{},dict(DEFAULT_POLICY,checks=['guardrails']))
    assert 'source_context' not in report['findings'][0]
    assert 'private-material' not in redact('-----BEGIN PRIVATE KEY-----\nprivate-material\n-----END PRIVATE KEY-----')

def test_patch_applicability_does_not_edit_source_or_execute_hooks(tmp_path):
    root=tmp_path/'project';root.mkdir();file=root/'app.py';file.write_text('eval(user_input)\n')
    patch=tmp_path/'proposal.diff';patch.write_text('--- a/app.py\n+++ b/app.py\n@@ -1 +1 @@\n-eval(user_input)\n+json.loads(user_input)\n')
    result=validate_patch(root,patch);assert result['applies_to_snapshot'];assert not result['security_checks_run'];assert file.read_text()=='eval(user_input)\n'
    patch.write_text('--- a/../escape\n+++ b/../escape\n@@ -1 +1 @@\n-a\n+b\n')
    with pytest.raises(ValueError,match='Unsafe'):validate_patch(root,patch)

def test_cookie_authentication_verification_does_not_accept_public_login_or_missing_marker(monkeypatch):
    monkeypatch.setattr('runner.dast_guard.resolve',lambda *args:{'127.0.0.1'})
    scope=Scope({'url':'http://127.0.0.1:8080','credential':'session=synthetic','credential_type':'cookie','verify_path':'/me','success_marker':'signed-in'})
    response=SimpleNamespace(status=200,getheader=lambda _:None,read=lambda _:b'public login')
    class Connection:
        def __init__(self,*args,**kwargs):pass
        def request(self,method,path,headers):assert path=='/me';assert headers['Cookie']=='session=synthetic';assert 'Authorization' not in headers
        def getresponse(self):return response
        def close(self):pass
    monkeypatch.setattr('runner.dast_guard.http.client.HTTPConnection',Connection)
    with pytest.raises(ValueError,match='success marker'):verify_target(scope)
    response.read=lambda _:b'signed-in';verify_target(scope)
    response.status=302;response.getheader=lambda _: '/login'
    with pytest.raises(ValueError,match='HTTP 200'):verify_target(scope)

def test_supervisor_drain_marker_exits_before_claiming(tmp_path,monkeypatch):
    from runner.cli import main
    config=tmp_path/'settings.json';config.write_text('{}');drain=tmp_path/'drain';drain.touch()
    monkeypatch.setattr(sys,'argv',['runner','run','--config',str(config),'--drain-file',str(drain)])
    monkeypatch.setattr('runner.cli.run_once',lambda _:pytest.fail('Draining worker must not claim'))
    assert main()==0
