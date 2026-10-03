from __future__ import annotations
import datetime as dt
import json
import os
import shutil
import subprocess
import tempfile
import threading
import time
import uuid
from pathlib import Path
from typing import Any
from .core import VERSION, execution, make_finding, redact
from .remediation import secret_remediation

IMAGES = {
 'opengrep':'sentinel-opengrep:1.16.0',
 'gitleaks':'ghcr.io/gitleaks/gitleaks:v8.28.0',
 'trivy':'aquasec/trivy:0.74.0',
 'eslint':'sentinel-eslint:0.1.0',
 'ruff':'ghcr.io/astral-sh/ruff:0.14.0',
 'checkstyle':'sentinel-checkstyle:0.1.0',
 'roslyn':'sentinel-roslyn:0.1.0',
 'staticcheck':'sentinel-staticcheck:0.1.0',
 'zap':'ghcr.io/zaproxy/zaproxy:2.16.1',
 'dast-guard':'sentinel-dast-guard:0.1.0',
}
RULES_ROOT = Path(__file__).resolve().parents[1]/'rules'
IMAGE_LOCK=RULES_ROOT.parent/'.data/scanner-images.json'

def image_ref(engine: str) -> str:
    if IMAGE_LOCK.exists():
        locked=json.loads(IMAGE_LOCK.read_text()).get(engine)
        import re
        if locked:
            if not re.fullmatch(r'sha256:[a-f0-9]{64}',locked):raise ValueError('Invalid scanner image lock')
            return locked
    return IMAGES[engine]

def pin_prepared_images():
    locked={}
    for engine,reference in IMAGES.items():
        result=subprocess.run(['docker','image','inspect','--format','{{.Id}}',reference],capture_output=True,text=True,timeout=30)
        if result.returncode==0:locked[engine]=result.stdout.strip()
    IMAGE_LOCK.parent.mkdir(parents=True,exist_ok=True)
    IMAGE_LOCK.write_text(json.dumps(locked,indent=2))
    return len(locked)

class Cancelled(RuntimeError): pass
class EngineUnavailable(RuntimeError): pass

class Executor:
    def __init__(self, mode='container', cancel: threading.Event | None=None, cache: Path | None=None):
        if mode not in ('container','native'):raise ValueError('scanner_mode must be container or native')
        self.mode=mode;self.cancel=cancel or threading.Event();self.cache=cache

    def command(self, engine: str, args: list[str], root: Path, timeout=300, extra_mounts: list[tuple[Path,str,bool]] | None=None) -> tuple[str,int]:
        if self.cancel.is_set():raise Cancelled('Scan cancelled')
        container_name='sentinel-'+uuid.uuid4().hex
        if self.mode=='container':
            docker_binary=shutil.which('docker')
            if not docker_binary:raise EngineUnavailable('Docker CLI unavailable')
            command=[docker_binary,'run','--rm','--pull=never','--name',container_name,'--read-only','--cap-drop=ALL',
              '--security-opt=no-new-privileges','--pids-limit=128','--memory=2g','--cpus=2','--network=none',
              '--tmpfs','/tmp:rw,exec,nosuid,nodev,size=536870912','--mount',f'type=bind,source={root.resolve()},target=/src,readonly',
              '--mount',f'type=bind,source={RULES_ROOT.resolve()},target=/rules,readonly','--workdir','/src',
              '--env','HOME=/tmp','--env','SEMGREP_SEND_METRICS=off']
            for source,target,readonly in extra_mounts or []:
                command+=['--mount',f'type=bind,source={source.resolve()},target={target}'+(',readonly' if readonly else '')]
            command+=[image_ref(engine)]+args
        else:
            if engine not in ('opengrep','gitleaks','trivy','ruff','eslint','staticcheck'):raise EngineUnavailable(f'{engine} requires its pinned container image')
            binary=shutil.which(engine)
            if not binary:raise EngineUnavailable(f'{engine} executable not installed')
            translations=[('/src',str(root.resolve())),('/rules',str(RULES_ROOT.resolve())),('/cache',str(self.cache or ''))]+[(target,str(source.resolve())) for source,target,_ in extra_mounts or []]
            def translate(argument):
                for before,after in translations:argument=argument.replace(before,after)
                return argument
            command=[binary]+[translate(a) for a in args]
        # Capture bounded output in files, never risk blocking on full stderr/stdout pipes.
        with tempfile.TemporaryDirectory(prefix='sentinel-output-') as temporary:
            stdout_path=Path(temporary)/'stdout';stderr_path=Path(temporary)/'stderr'
            env={k:v for k,v in os.environ.items() if k in ('PATH','SystemRoot','WINDIR','TEMP','TMP','USERPROFILE')}
            env.update({'HOME':temporary,'SEMGREP_SEND_METRICS':'off','NO_COLOR':'1','GIT_CONFIG_NOSYSTEM':'1','GIT_CONFIG_GLOBAL':os.devnull})
            start=time.monotonic()
            with stdout_path.open('wb') as stdout,stderr_path.open('wb') as stderr:
                process=subprocess.Popen(command,cwd=root,env=env,stdout=stdout,stderr=stderr,shell=False)
                try:
                    while process.poll() is None:
                        if self.cancel.wait(.15):raise Cancelled('Scan cancelled')
                        if time.monotonic()-start>timeout:raise TimeoutError(f'{engine} exceeded {timeout}s execution limit')
                        if stdout_path.stat().st_size+stderr_path.stat().st_size>8_000_000:raise RuntimeError('Scanner output exceeded 8 MB')
                finally:
                    if process.poll() is None:
                        process.kill();process.wait(timeout=10)
                        if self.mode=='container':
                            subprocess.run([command[0],'rm','-f',container_name],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=20)
            raw=stdout_path.read_text(errors='replace')
            if process.returncode not in (0,1):
                error=redact(stderr_path.read_text(errors='replace'))
                if self.mode=='container' and ('No such image' in error or 'Cannot connect' in error or 'error during connect' in error or 'not found' in error):raise EngineUnavailable(error)
                raise RuntimeError(f'{engine} exited {process.returncode}: {error[:1000]}')
            return raw,process.returncode

def parse_opengrep(output: dict) -> list[dict]:
    findings=[]
    for r in output.get('results',[]):
        extra=r.get('extra',{});meta=extra.get('metadata',{});path=r.get('path','').removeprefix('/src/');text=extra.get('lines','')
        severity={'ERROR':'high','WARNING':'medium','INFO':'info'}.get(extra.get('severity'),'medium')
        f=make_finding(r['check_id'],extra.get('message',r['check_id']),path,r.get('start',{}).get('line',1),text,severity,
          impact=meta.get('impact','A security-sensitive code pattern was detected. Verify input provenance and controls.'),
          remediation=meta.get('remediation','Inspect the reported boundary and use an approved safe alternative.'),engine='opengrep',cwe=meta.get('cwe',[]))
        f['engine_version']=IMAGES['opengrep'].split(':')[-1];findings.append(f)
    return findings

def parse_gitleaks(output: list[dict]) -> list[dict]:
    result=[]
    for r in output:
        f=make_finding(r.get('RuleID','secret'),r.get('Description','Potential exposed secret'),r.get('File','').removeprefix('/src/'),r.get('StartLine',1),'[REDACTED SECRET]','high',
          impact='A potential credential is present in source. If real, it may grant unauthorized access.',
          remediation=secret_remediation(r.get('RuleID','secret'),r.get('File','').removeprefix('/src/'),r.get('StartLine',1)),engine='gitleaks',cwe=['CWE-798'],confidence='medium')
        # Preserve engine identity without hashing/storing the actual secret.
        import hashlib
        f['fingerprint']=hashlib.sha256(f"gitleaks:{r.get('RuleID')}:{f['path']}:{r.get('Fingerprint',r.get('StartLine'))}".encode()).hexdigest()
        f['engine_version']=IMAGES['gitleaks'].split(':')[-1];result.append(f)
        commit=r.get('Commit','')
        import re
        if re.fullmatch(r'[a-f0-9]{40}',commit):f['source_revision']=commit
    return result

def parse_trivy(output: dict) -> list[dict]:
    findings=[]
    for result in output.get('Results',[]):
        target=result.get('Target','').removeprefix('/src/')
        for vuln in result.get('Vulnerabilities',[]):
            package=vuln.get('PkgName','unknown');id=vuln.get('VulnerabilityID','unknown');version=vuln.get('InstalledVersion','unknown');fixed=vuln.get('FixedVersion')
            f=make_finding(id,f'{id} in {package}',target,1,f'{package}@{version}',vuln.get('Severity','UNKNOWN').lower() if vuln.get('Severity','UNKNOWN')!='UNKNOWN' else 'info',
              impact=vuln.get('Description','Known vulnerable dependency. Applicability depends on how the package is used.')[:5000],
              remediation=f'Upgrade {package} to {fixed}; verify compatibility and rescan.' if fixed else 'No fixed version is listed. Evaluate removal, compensating controls, and upstream advisories.',engine='trivy',confidence='high')
            # Package path + advisory identity remains stable across vulnerable upgrades.
            import re
            f['dependency']={'name':package[:300],'version':version[:200],'ecosystem':result.get('Type','unknown')[:100]}
            if fixed:f['dependency']['fixed_version']=fixed[:500]
            purl=vuln.get('PkgIdentifier',{}).get('PURL')
            if purl:f['dependency']['purl']=purl[:1000]
            if re.fullmatch(r'(CVE-\d{4}-\d{4,}|GHSA-[\w-]+)',id):f['vulnerability_id']=id
            scores=[v.get('V3Score') for v in vuln.get('CVSS',{}).values() if isinstance(v,dict) and isinstance(v.get('V3Score'),(int,float)) and 0<=v['V3Score']<=10]
            if scores:f['cvss']=max(scores)
            import hashlib
            f['fingerprint']=hashlib.sha256(f'trivy:{target}:{package}:{id}'.encode()).hexdigest();f['engine_version']=IMAGES['trivy'].split(':')[-1];findings.append(f)
        for mis in result.get('Misconfigurations',[]):
            f=make_finding(mis.get('ID','misconfiguration'),mis.get('Title','Insecure infrastructure configuration'),target,
              mis.get('CauseMetadata',{}).get('StartLine',1) or 1,'',mis.get('Severity','MEDIUM').lower(),
              impact=mis.get('Description','Infrastructure configuration may weaken a security boundary.'),remediation=mis.get('Resolution','Review the indicated configuration.'),engine='trivy')
            f['engine_version']=IMAGES['trivy'].split(':')[-1];findings.append(f)
    return findings

def scan_external(engine: str,root: Path,inv: dict,executor: Executor,policy: dict,history: Path | None=None,history_limitations: list[str] | None=None) -> tuple[list[dict],dict,dict]:
    start=time.monotonic();findings=[];metrics={};version=IMAGES.get(engine,VERSION).split(':')[-1];limitations=[]
    try:
        if engine=='opengrep':
            raw,_=executor.command(engine,['scan','--json','--disable-version-check','--disable-nosem','--no-git-ignore','--x-ignore-semgrepignore-files','--config','/rules/opengrep.yml','/src'],root)
            output=json.loads(raw);findings=parse_opengrep(output)
            if output.get('errors'):limitations.append('PARTIAL: Opengrep diagnostics: '+redact(json.dumps(output['errors'][:3]))[:1500])
            coverage=list(inv['languages']);limitations.append('Coverage is limited to the bundled original rules and engine-supported syntax.')
        elif engine=='gitleaks':
            with tempfile.TemporaryDirectory(prefix='sentinel-gitleaks-') as tmp:
                folder=Path(tmp)
                executor.command(engine,['dir','/src','--config','/rules/gitleaks.toml','--ignore-gitleaks-allow','--gitleaks-ignore-path','/rules/gitleaks.ignore','--redact=100','--no-banner','--report-format','json','--report-path','/out/report.json'],root,extra_mounts=[(folder,'/out',False)])
                file=folder/'report.json';output=json.loads(file.read_text()) if file.exists() else [];findings=parse_gitleaks(output)
                if history:
                    executor.command(engine,['git','/history','--log-opts=--all','--config','/rules/gitleaks.toml','--ignore-gitleaks-allow','--gitleaks-ignore-path','/rules/gitleaks.ignore','--redact=100','--no-banner','--report-format','json','--report-path','/out/history.json'],root,extra_mounts=[(folder,'/out',False),(history,'/history',True)])
                    history_file=folder/'history.json'
                    if history_file.exists():findings.extend(parse_gitleaks(json.loads(history_file.read_text())))
            coverage=['snapshotted files']+(['available Git history'] if history else [])
            limitations.extend(history_limitations or [])
        elif engine=='trivy':
            if not executor.cache or not (executor.cache/'db'/'metadata.json').exists():raise EngineUnavailable('Trivy database cache missing. Run runner prepare before assessment.')
            metadata=json.loads((executor.cache/'db'/'metadata.json').read_text());updated=metadata.get('UpdatedAt')
            if not updated:raise EngineUnavailable('Trivy database freshness cannot be established')
            raw,_=executor.command(engine,['fs','--config','/rules/trivy.yml','--ignorefile','/rules/trivy.ignore','--quiet','--format','json','--scanners','vuln,misconfig','--skip-db-update','--skip-java-db-update','--cache-dir','/cache','/src'],root,timeout=600,extra_mounts=[(executor.cache,'/cache',True)])
            output=json.loads(raw);findings=parse_trivy(output)
            sbom,_=executor.command(engine,['fs','--config','/rules/trivy.yml','--quiet','--format','cyclonedx','--skip-db-update','--skip-java-db-update','--cache-dir','/cache','/src'],root,extra_mounts=[(executor.cache,'/cache',True)])
            metrics['sbom']=json.loads(sbom);coverage=[r.get('Target','filesystem') for r in output.get('Results',[])] or ['filesystem inventory']
            limitations.append('Known-advisory matching does not establish reachability or detect all malicious packages.')
        else:raise ValueError('Unknown engine')
        if inv.get('excluded_or_oversized'):limitations.append('PARTIAL: Snapshot excluded oversized or unsafe files.')
        e=execution(engine,'completed',start,coverage,limitations,version)
        if engine=='trivy':e['database_updated_at']=updated
        return findings,e,metrics
    except Cancelled:raise
    except (EngineUnavailable,FileNotFoundError) as error:return [],execution(engine,'unavailable',start,[],[],version,str(error)),{}
    except Exception as error:return [],execution(engine,'failed',start,[],[],version,str(error)),{}

def lint(root: Path,inv: dict,executor: Executor,policy: dict) -> tuple[list[dict],dict]:
    start=time.monotonic();findings=[];coverage=[];limitations=[];failed=False
    languages=inv['languages']
    for engine,lang in [('eslint','JavaScript'),('eslint','TypeScript'),('ruff','Python'),('checkstyle','Java'),('roslyn','C#'),('staticcheck','Go')]:
        if lang not in languages:continue
        if engine in ('roslyn','staticcheck') and not policy.get('compiler_analysis'):
            limitations.append(f'PARTIAL: {engine} requires compiler_analysis opt-in; no project build was executed.');failed=True;continue
        try:
            if engine=='ruff':
                raw,_=executor.command(engine,['check','--isolated','--no-cache','--output-format','json','/src'],root)
                for r in json.loads(raw):findings.append(make_finding(r.get('code','ruff'),r.get('message','Python coding violation'),r.get('filename','').removeprefix('/src/'),r.get('location',{}).get('row',1),'','low','quality',
                  'A coding-standard violation may reduce correctness or reviewability.','Apply the documented Ruff rule guidance.',engine='lint'))
            elif engine=='eslint':
                if lang=='TypeScript' and 'JavaScript' in languages:continue # Combined JS/TS run.
                raw,_=executor.command(engine,['--no-config-lookup','--config','/rules/eslint.config.mjs','--format','json','/src'],root)
                for r in json.loads(raw):
                    for m in r.get('messages',[]):findings.append(make_finding(m.get('ruleId') or 'eslint.parse',m.get('message','JavaScript coding violation'),r.get('filePath','').removeprefix('/src/'),m.get('line',1),'','medium' if m.get('severity')==2 else 'low','quality',
                      'A coding-standard violation may hide an unsafe or incorrect behavior.','Apply the bundled ESLint rule guidance.',engine='lint'))
                if 'TypeScript' in languages:coverage.append('TypeScript')
            elif engine=='checkstyle':
                raw,_=executor.command(engine,['-c','/rules/checkstyle.xml','-f','xml','/src'],root)
                # Do not process external XML entities.
                if '<!DOCTYPE' in raw or '<!ENTITY' in raw:raise ValueError('Unexpected XML entities in scanner output')
                import xml.etree.ElementTree as ET
                for file in ET.fromstring(raw).findall('file'):
                    for m in file.findall('error'):findings.append(make_finding(m.attrib.get('source','checkstyle'),m.attrib.get('message','Java coding violation'),file.attrib['name'].removeprefix('/src/'),int(m.attrib.get('line',1)) or 1,'','low','quality',impact='Coding standards aid reviewability.',remediation='Apply the bundled Checkstyle rule.',engine='lint'))
            elif engine=='staticcheck':
                raw,_=executor.command(engine,['-f','json','./...'],root,timeout=600)
                for line in raw.splitlines():
                    if not line.strip():continue
                    r=json.loads(line);location=r.get('location',{})
                    findings.append(make_finding(r.get('code','staticcheck'),r.get('message','Go coding violation'),location.get('file','').removeprefix('/src/'),location.get('line',1),'','medium','quality',impact='The analyzer detected a possible correctness issue.',remediation='Review and apply Staticcheck guidance.',engine='lint'))
            elif engine=='roslyn':
                raw,_=executor.command(engine,[],root,timeout=600)
                output=json.loads(raw)
                for run in output.get('runs',[]):
                    for r in run.get('results',[]):
                        first=r.get('locations',[{}])[0]
                        location=first.get('physicalLocation') or first.get('resultFile',{})
                        uri=location.get('artifactLocation',{}).get('uri') or location.get('uri','')
                        uri=uri.removeprefix('file://').removeprefix('/tmp/work/').removeprefix('/src/')
                        message=r.get('message','C# analyzer finding')
                        title=message.get('text','C# analyzer finding') if isinstance(message,dict) else str(message)
                        findings.append(make_finding(r.get('ruleId','roslyn'),title,uri,location.get('region',{}).get('startLine',1),'','medium','quality',impact='A .NET analyzer detected a correctness or coding issue.',remediation='Review the analyzer rule and update the affected code.',engine='lint'))
            coverage.append(lang)
        except Cancelled:raise
        except Exception as error:failed=True;limitations.append(f'PARTIAL: {engine}: {redact(str(error))[:500]}')
    if inv.get('excluded_or_oversized'):failed=True;limitations.append('PARTIAL: Snapshot omitted unsafe or oversized files.')
    if not languages:failed=True;limitations.append('No supported source language found.')
    return findings,execution('lint','failed' if failed else 'completed',start,sorted(set(coverage)),limitations)
