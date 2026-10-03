from __future__ import annotations
import base64
import hashlib
import json
import os
import subprocess
import tempfile
import threading
import time
from pathlib import Path
import requests
from .adapters import Cancelled, Executor, lint, scan_external
from .core import DEFAULT_POLICY, execution, guardrails, inventory, load_policy, quality, revision_hash, snapshot,snapshot_history
from .dast import scan_dast

def assess(root: Path,settings: dict,policy: dict | None=None,components: list | None=None,target: dict | None=None,
           cancel: threading.Event | None=None,revision: str | None=None) -> dict:
    cancel=cancel or threading.Event()
    if policy is None:
        file=root/'security-guardrails.yml';policy=load_policy(file) if file.exists() else json.loads(json.dumps(DEFAULT_POLICY))
    # Server policy is immutable for enrolled jobs. Repository YAML cannot weaken it.
    with tempfile.TemporaryDirectory(prefix='sentinel-snapshot-') as tmp:
        copied=Path(tmp)/'source';copied.mkdir()
        info=snapshot(root,copied,policy['exclusions'],components);inv=inventory(copied,info)
        local_revision=revision or revision_hash(copied,info['files'])
        history=Path(tmp)/'history';history_limitations=[]
        if 'gitleaks' in policy['checks']:
            history_limitations=snapshot_history(root,history)
        executor=Executor(settings.get('scanner_mode','container'),cancel,Path(settings.get('cache_dir','.data/trivy-cache')).resolve())
        findings=[];executions=[];metrics={}
        for check in policy['checks']:
            if cancel.is_set():raise Cancelled('Scan cancelled')
            if check=='guardrails':result,e=guardrails(copied,inv,policy)
            elif check=='quality':result,m,e=quality(copied,inv);metrics.update(m)
            elif check=='lint':result,e=lint(copied,inv,executor,policy)
            elif check=='dast':result,e=scan_dast(copied,target,settings,cancel)
            else:result,e,m=scan_external(check,copied,inv,executor,policy,history if (history/'.git').exists() else None,history_limitations);metrics.update(m)
            if info['excluded_or_oversized'] and e['status']=='completed':
                if not any(x.startswith('PARTIAL:') for x in e['limitations']):e['limitations'].append('PARTIAL: Snapshot omitted oversized or unsafe files.')
            findings.extend(result);executions.append(e)
        if len(findings)>10000:raise RuntimeError('Assessment exceeds 10,000-finding limit; split project into components')
        # Preserve separate engine reports. Identical fingerprints within one engine collapse.
        findings=list({f['fingerprint']:f for f in findings}.values())
        return {'schema_version':1,'revision':local_revision,'inventory':inv,'findings':findings,
                'executions':executions,'metrics':metrics,'policy':policy}

def gate(report: dict,baseline: set[str] | None=None) -> str:
    policy=report['policy'];baseline=baseline or set();required={e['engine']:e for e in report['executions']};incomplete=False
    for check in policy['checks']:
        e=required.get(check)
        if not e or e['status']!='completed' or any(x.startswith('PARTIAL:') for x in e['limitations']):incomplete=True
        if check=='trivy':
            import datetime as dt
            stamp=e.get('database_updated_at') if e else None
            if not stamp or (dt.datetime.now(dt.timezone.utc)-dt.datetime.fromisoformat(stamp.replace('Z','+00:00'))).total_seconds()>172800:incomplete=True
    violations=[f for f in report['findings'] if (not policy['gate']['new_only'] or f['fingerprint'] not in baseline)
      and (f['severity'] in policy['gate']['severities'] or f['rule'] in policy['gate']['rules'])]
    if policy['mode']=='enforce' and violations:return 'fail'
    return 'incomplete' if incomplete else 'pass'

class Client:
    def __init__(self,settings: dict):
        self.settings=settings;self.base=settings['api_url'].rstrip('/')
        from urllib.parse import urlsplit
        u=urlsplit(self.base)
        if u.scheme!='https' and not (u.scheme=='http' and u.hostname in ('localhost','127.0.0.1','::1')):
            raise ValueError('Runner API must use HTTPS except for loopback development')
        if u.username or u.password:raise ValueError('API URL cannot contain credentials')
        self.headers={'Authorization':'Bearer '+settings['token'],'Content-Type':'application/json'}
    def post(self,path: str,data: dict,retries=0):
        for attempt in range(retries+1):
            try:
                response=requests.post(self.base+'/api/'+path,json=data,headers=self.headers,timeout=30,allow_redirects=False)
                if response.status_code>=500 and attempt<retries:time.sleep(min(2**attempt,10));continue
                if not response.ok:raise RuntimeError(f'API {path} returned {response.status_code}')
                return response.json()
            except requests.RequestException:
                if attempt==retries:raise
                time.sleep(min(2**attempt,10))

def clone_github(job: dict,destination: Path) -> Path:
    repository=job['source_ref']
    import re
    if not re.fullmatch(r'[\w.-]+/[\w.-]+',repository):raise ValueError('Invalid repository identifier')
    token=job.get('github_token')
    if not token:raise ValueError('Installation credential missing')
    credential=base64.b64encode(('x-access-token:'+token).encode()).decode()
    env={**os.environ,'GIT_TERMINAL_PROMPT':'0','GIT_CONFIG_NOSYSTEM':'1','GIT_CONFIG_GLOBAL':os.devnull,
      'GIT_CONFIG_COUNT':'4','GIT_CONFIG_KEY_0':'http.https://github.com/.extraheader','GIT_CONFIG_VALUE_0':'Authorization: Basic '+credential,
      'GIT_CONFIG_KEY_1':'core.hooksPath','GIT_CONFIG_VALUE_1':os.devnull,
      'GIT_CONFIG_KEY_2':'protocol.file.allow','GIT_CONFIG_VALUE_2':'never',
      'GIT_CONFIG_KEY_3':'http.followRedirects','GIT_CONFIG_VALUE_3':'false'}
    commands=[['git','clone','--no-checkout','--depth=1','--branch',job.get('default_branch','main'),f'https://github.com/{repository}.git',str(destination)]]
    revision=job.get('requested_revision')
    if revision:
        if not re.fullmatch(r'[a-fA-F0-9]{40}',revision):raise ValueError('Requested revision is invalid')
        commands.append(['git','-C',str(destination),'fetch','--depth=1','origin',revision])
    commands.append(['git','-C',str(destination),'checkout','--detach',revision or 'HEAD'])
    for command in commands:
        result=subprocess.run(command,env=env,capture_output=True,timeout=120,shell=False)
        if result.returncode:raise RuntimeError('GitHub snapshot failed; check installation permissions and revision accessibility')
    result=subprocess.run(['git','-C',str(destination),'rev-parse','HEAD'],env=env,capture_output=True,text=True,timeout=10,check=True)
    job['verified_revision']=result.stdout.strip();return destination

def run_once(settings: dict) -> bool:
    client=Client(settings);job=client.post('runner/claim',{})['job']
    if not job:return False
    cancel=threading.Event();stop=threading.Event();lease={'scan_id':job['id'],'lease_token':job['lease_token']}
    def heartbeat_loop():
        while not stop.wait(20):
            try:
                if client.post('runner/heartbeat',lease).get('cancel_requested'):cancel.set()
            except Exception:cancel.set();return
    thread=threading.Thread(target=heartbeat_loop,daemon=True);thread.start()
    try:
        with tempfile.TemporaryDirectory(prefix='sentinel-checkout-') as tmp:
            if job['source_type']=='local':
                alias=job['source_ref'];registered=settings.get('roots',{}).get(alias)
                if not registered:raise ValueError('Source alias is not registered on this runner')
                root=Path(registered).resolve(strict=True)
            elif job['source_type']=='github':root=clone_github(job,Path(tmp)/'repository')
            else:raise ValueError('Unsupported project source type')
            report=assess(root,settings,job['policy'],job['components'],job['target'],cancel,job.get('verified_revision'))
            # Metadata-only jobs must not transmit source snippets or patches.
            if job.get('metadata_only'):
                for finding in report['findings']:finding.pop('evidence',None);finding.pop('patch',None)
            client.post('runner/finish',{**lease,'report':report},retries=3)
    except Exception as error:
        from .core import redact
        try:client.post('runner/finish',{**lease,'report':None,'error':redact(str(error))[:2000]},retries=2)
        except Exception:print('Could not deliver final status. Lease expiry will handle recovery.')
    finally:stop.set();thread.join(timeout=3)
    return True
