from runner.reporting import sarif,source_uri
from runner.adapters import parse_trivy

def test_sarif_locations_and_stable_fingerprints():
    report={'revision':'snapshot:test','gate':'fail','executions':[{'engine':'example','version':'1','status':'completed','coverage':['Python'],'limitations':[]}],
      'findings':[{'engine':'example','rule':'unsafe','fingerprint':'a'*64,'title':'Unsafe API','severity':'high','category':'security','confidence':'high','impact':'impact','remediation':'fix','path':'src/file name.py','line':2,'evidence':'never export this snippet'}]}
    output=sarif(report);result=output['runs'][0]['results'][0]
    assert output['version']=='2.1.0'
    assert result['partialFingerprints']['sentinel/v1']=='a'*64
    assert result['locations'][0]['physicalLocation']['artifactLocation']['uri']=='src/file%20name.py'
    assert 'never export this snippet' not in str(output)
    for path in ('../secret','C:\\private','/etc/passwd','https://example.test'):assert source_uri(path) is None

def test_dependency_evidence_retains_upgrade_and_cvss_metadata():
    finding=parse_trivy({'Results':[{'Target':'requirements.txt','Type':'pip','Vulnerabilities':[{'PkgName':'example','VulnerabilityID':'CVE-2024-12345','InstalledVersion':'1','FixedVersion':'2','Severity':'HIGH','CVSS':{'nvd':{'V3Score':8.1}},'PkgIdentifier':{'PURL':'pkg:pypi/example@1'}}]}]})[0]
    assert finding['dependency']['fixed_version']=='2'
    assert finding['dependency']['purl']=='pkg:pypi/example@1'
    assert finding['vulnerability_id']=='CVE-2024-12345'
    assert finding['cvss']==8.1
