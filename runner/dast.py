from __future__ import annotations
import json
import os
import re
import subprocess
import tempfile
import threading
import time
import uuid
from pathlib import Path
from urllib.parse import urlsplit
from .adapters import Cancelled, Executor, IMAGES, image_ref
from .core import execution, make_finding, redact, safe_relative

def docker(args: list[str],check=True):
    result=subprocess.run(['docker',*args],capture_output=True,text=True,timeout=30)
    if check and result.returncode:raise RuntimeError('Docker DAST setup failed: '+redact(result.stderr)[:500])
    return result

def scan_dast(root: Path,target: dict | None,settings: dict,cancel: threading.Event) -> tuple[list[dict],dict]:
    start=time.monotonic();version=IMAGES['zap'].split(':')[-1]
    if not target:return [],execution('dast','skipped',start,[],['No authorized runtime target attached.'],version)
    network='sentinel-dast-'+uuid.uuid4().hex;guard=network+'-guard';scanner=network+'-zap'
    try:
        if target.get('environment') not in ('local','staging') or not target.get('authorized'):raise ValueError('Only authorized local/staging targets may be tested')
        url=target['url'];u=urlsplit(url)
        if u.scheme not in ('http','https') or u.username or u.password or u.query or u.fragment:raise ValueError('Invalid DAST target')
        if url not in settings.get('allowed_targets',[]):raise ValueError('Exact target URL is not registered in runner allowed_targets')
        if settings.get('scanner_mode','container')!='container':raise ValueError('DAST requires Docker network isolation')
        import yaml
        with tempfile.TemporaryDirectory(prefix='sentinel-dast-') as tmp:
            folder=Path(tmp);config=folder/'config';guard_config=folder/'guard';output=folder/'output';config.mkdir();guard_config.mkdir();output.mkdir()
            credential=os.environ.get(target.get('credential_ref','')) if target.get('credential_ref') else None
            if target.get('credential_ref') and not credential:raise ValueError('Target credential reference could not be resolved on the runner')
            proxy_target={**target,'credential':credential,'hosted':settings.get('hosted',False)}
            if u.hostname in ('localhost','127.0.0.1','::1'):proxy_target['connect_host']='host.docker.internal'
            (guard_config/'target.json').write_text(json.dumps(proxy_target))
            base='http://guard:8080'+(u.path.rstrip('/') or '/')
            jobs=[]
            if target.get('openapi'):
                schema=safe_relative(root,target['openapi']);(config/'openapi.yaml').write_bytes(schema.read_bytes())
                jobs.append({'type':'openapi','parameters':{'apiFile':'/config/openapi.yaml','targetUrl':base,'context':'sentinel'}})
            jobs += [{'type':'spider','parameters':{'context':'sentinel','url':base,'maxDuration':2}},
              {'type':'passiveScan-wait','parameters':{'maxDuration':2}}]
            if target.get('active'):jobs.append({'type':'activeScan','parameters':{'context':'sentinel','maxScanDurationInMins':30}})
            jobs.append({'type':'report','parameters':{'template':'traditional-json','reportDir':'/out','reportFile':'zap-report'}})
            plan={'env':{'contexts':[{'name':'sentinel','urls':[base],'includePaths':['http://guard:8080/.*'],
                  'excludePaths':['http://guard:8080'+re.escape(p) for p in target.get('exclusions',[])]}],
                  'parameters':{'failOnError':True,'failOnWarning':False,'continueOnFailure':False}},'jobs':jobs}
            (config/'plan.yaml').write_text(yaml.safe_dump(plan))
            # Only the trusted guard has an external network. ZAP cannot bypass it.
            docker(['network','create','--internal',network])
            docker(['run','-d','--pull=never','--name',guard,'--network','bridge','--add-host','host.docker.internal:host-gateway',
              '--read-only','--cap-drop=ALL','--security-opt=no-new-privileges','--pids-limit=64','--memory=256m','--cpus=1',
              '--mount',f'type=bind,source={guard_config.resolve()},target=/config,readonly',image_ref('dast-guard')])
            docker(['network','connect','--alias','guard',network,guard])
            command=['docker','run','--rm','--pull=never','--name',scanner,'--network',network,'--read-only','--cap-drop=ALL',
              '--security-opt=no-new-privileges','--pids-limit=256','--memory=2g','--cpus=2','--user','0',
              '--tmpfs','/tmp:rw,nosuid,nodev,size=536870912','--tmpfs','/root/.ZAP:rw,nosuid,nodev,size=536870912',
              '--mount',f'type=bind,source={config.resolve()},target=/config,readonly',
              '--mount',f'type=bind,source={output.resolve()},target=/out',image_ref('zap'),
              'zap.sh','-cmd','-autorun','/config/plan.yaml']
            with (folder/'zap.log').open('wb') as log:
                process=subprocess.Popen(command,stdout=log,stderr=subprocess.STDOUT,shell=False)
                try:
                    while process.poll() is None:
                        if cancel.wait(.2):raise Cancelled('DAST cancelled')
                        if time.monotonic()-start>2100:raise TimeoutError('DAST job exceeded 35-minute total limit')
                        if (folder/'zap.log').stat().st_size>8_000_000:raise ValueError('DAST output limit reached')
                    if process.returncode:raise RuntimeError('ZAP did not complete. Inspect scanner readiness and authorized target connectivity.')
                finally:
                    if process.poll() is None:process.kill();process.wait(timeout=10)
            report=output/'zap-report.json'
            if not report.exists():raise RuntimeError('ZAP report not produced')
            result=json.loads(report.read_text());findings=[]
            for site in result.get('site',[]):
                for alert in site.get('alerts',[]):
                    for instance in alert.get('instances',[])[:100]:
                        address=urlsplit(instance.get('uri',base));endpoint=f'{u.scheme}://{u.netloc}{address.path}'
                        strip=lambda s:re.sub('<[^>]+>','',s)
                        f=make_finding(str(alert.get('pluginid','zap')),alert.get('name','Runtime security finding'),'',1,instance.get('evidence',''),
                          {'0':'info','1':'low','2':'medium','3':'high'}.get(str(alert.get('riskcode')),'medium'),impact=strip(alert.get('desc','')),
                          remediation=strip(alert.get('solution','Review the runtime control.')),engine='dast',cwe=[f"CWE-{alert.get('cweid')}"] if alert.get('cweid') else [])
                        import hashlib
                        f['endpoint']=endpoint;f['environment']=target['environment'];f['engine_version']=version;f['fingerprint']=hashlib.sha256(f"dast:{target['environment']}:{f['rule']}:{endpoint}:{instance.get('param','')}".encode()).hexdigest();findings.append(f)
            limitations=['Only discovered routes and supplied API definitions were tested.',
              'The guarded bridge strips cookies and rewrites redirects. Cookie/session controls and multi-step browser authentication require manual review.',
              'Header-based authentication is supported through local credential references; browser login workflows are not yet supported.']
            return findings,execution('dast','completed',start,[url],limitations,version)
    except Cancelled:raise
    except Exception as error:return [],execution('dast','failed',start,[],[],version,str(error))
    finally:
        for name in (scanner,guard):
            try:docker(['rm','-f',name],False)
            except Exception:pass
        try:docker(['network','rm',network],False)
        except Exception:pass
