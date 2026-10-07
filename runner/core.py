from __future__ import annotations
import fnmatch
import hashlib
import json
import re
import shutil
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from .remediation import evidence_limitation

VERSION = '0.1.0'
LANGUAGES = {'.js':'JavaScript', '.jsx':'JavaScript', '.ts':'TypeScript', '.tsx':'TypeScript',
             '.py':'Python', '.java':'Java', '.cs':'C#', '.go':'Go'}
SKIP = {'.git', 'node_modules', 'vendor', '.venv', 'venv', '__pycache__', '.next', 'dist', 'build', '.data'}
MANIFESTS = {'package.json','package-lock.json','yarn.lock','pnpm-lock.yaml','requirements.txt','poetry.lock',
             'pyproject.toml','pom.xml','build.gradle','go.mod','go.sum','packages.lock.json'}
DEFAULT_POLICY = {'version':1,'mode':'advisory','checks':['guardrails','quality','opengrep','gitleaks','trivy','lint'],
 'exclusions':['node_modules/**','.git/**','dist/**','vendor/**','.next/**'],
 'gate':{'severities':['critical','high'],'new_only':True,'rules':[]},'architecture':[], 'unsafe_apis':[],
 'compiler_analysis':False,'monitoring':{'window_seconds':300,'auth_failure_threshold':10,'denied_threshold':30}}

def redact(text: str) -> str:
    text=re.sub(r'-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----[\s\S]*?-----END (?:[A-Z ]+ )?PRIVATE KEY-----','[REDACTED PRIVATE KEY]',text)
    text = re.sub(r'(?:gh[pousr]_[A-Za-z0-9]{15,}|AKIA[A-Z0-9]{16}|sk-[A-Za-z0-9_-]{16,})', '[REDACTED]', text)
    text = re.sub(r'''((?:authorization|proxy-authorization)["']?\s*[=:]\s*)(?:"[^"]*"|'[^']*'|[^\r\n]+)''', r'\1[REDACTED]', text, flags=re.I)
    text = re.sub(r'eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{8,}', '[REDACTED JWT]', text)
    text = re.sub(r'''((?:password|passwd|secret|credential|api[_-]?key|token|authorization|cookie)["']?\s*[=:]\s*)(?:"[^"]*"|'[^']*'|[^\s,;}]+)''', r'\1[REDACTED]', text, flags=re.I)
    text = re.sub(r'([a-z][a-z0-9+.-]{1,20}://)[^\s/@:]+:[^\s/@]+@', r'\1[REDACTED]@', text, flags=re.I)
    return re.sub(r'Bearer\s+[\w.\-]+', 'Bearer [REDACTED]', text, flags=re.I)[:12000]

def excluded(relative: str, patterns: list[str]) -> bool:
    return any(fnmatch.fnmatch(relative, p) or (p.endswith('/**') and relative.startswith(p[:-3] + '/')) for p in patterns)

def safe_relative(root: Path, relative: str) -> Path:
    candidate = root / relative
    if not relative or Path(relative).is_absolute() or '..' in Path(relative).parts or ':' in relative or '\\' in relative:
        raise ValueError('Invalid relative component path')
    resolved = candidate.resolve()
    if not resolved.is_relative_to(root.resolve()):
        raise ValueError('Component escapes registered source directory')
    return resolved

def snapshot(root: Path, destination: Path, exclusions: list[str], components: list[dict] | None = None) -> dict:
    """Copy regular files only. Never follow symlinks or run code from the project."""
    root = root.resolve(strict=True)
    if not root.is_dir(): raise ValueError('Registered root must be a directory')
    component_roots = [safe_relative(root, c['root']) if c['root'] not in ('','.') else root for c in (components or [])]
    for c in component_roots:
        if not c.is_dir(): raise ValueError('Component directory does not exist')
    ignored: list[str] = []; copied: list[str] = []; total = 0
    import os
    for current, directories, files in os.walk(root, followlinks=False):
        directories[:] = sorted(d for d in directories if d not in SKIP and not (Path(current)/d).is_symlink()
          and not excluded((Path(current)/d).relative_to(root).as_posix()+'/', exclusions))
        for name in sorted(files):
            source = Path(current)/name; relative = source.relative_to(root).as_posix()
            if excluded(relative, exclusions): continue
            if component_roots and not any(source.is_relative_to(c) for c in component_roots) and name != 'security-guardrails.yml': continue
            if source.is_symlink() or not source.is_file(): ignored.append(relative); continue
            size = source.stat().st_size
            if size > 2_000_000 or total + size > 100_000_000 or len(copied) >= 20000:
                ignored.append(relative); continue
            # Resolve immediately before opening; avoid following a symlink introduced since traversal.
            if not source.resolve().is_relative_to(root) or source.is_symlink(): ignored.append(relative); continue
            target = destination/relative; target.parent.mkdir(parents=True,exist_ok=True)
            with source.open('rb') as f:
                payload=f.read(2_000_001)
            if len(payload)>2_000_000: ignored.append(relative); continue
            target.write_bytes(payload); copied.append(relative); total+=len(payload)
    return {'files':copied,'bytes':total,'excluded_or_oversized':ignored,'limits':{'files':20000,'file_bytes':2000000,'total_bytes':100000000}}

def inventory(root: Path, snapshot_info: dict) -> dict:
    languages: dict[str,int] = {}; frameworks: set[str] = set(); manifests: list[str] = []; unsupported: list[str]=[]
    for relative in snapshot_info['files']:
        file=root/relative; language=LANGUAGES.get(file.suffix)
        if language: languages[language]=languages.get(language,0)+1
        elif file.suffix not in {'.json','.yaml','.yml','.xml','.md','.txt','.lock','.toml','.tf','.html','.css','.sql',''}: unsupported.append(relative)
        if file.name in MANIFESTS or file.suffix=='.csproj': manifests.append(relative)
        if file.name=='package.json':
            try:
                package=json.loads(file.read_text()); dependencies={**package.get('dependencies',{}),**package.get('devDependencies',{})}
                frameworks.update(k for k in ['next','react','express','@nestjs/core','vue','angular'] if k in dependencies)
            except (ValueError,UnicodeError): pass
        if file.suffix=='.py':
            text=file.read_text(errors='replace')
            frameworks.update(k for k in ['django','flask','fastapi'] if re.search(rf'\b{re.escape(k)}\b',text))
        if file.name=='pom.xml' and 'spring' in file.read_text(errors='replace'):frameworks.add('Spring')
        if file.suffix=='.csproj' and 'Microsoft.NET.Sdk.Web' in file.read_text(errors='replace'):frameworks.add('ASP.NET')
    return {**snapshot_info,'languages':languages,'frameworks':sorted(frameworks),'manifests':manifests,'unsupported_files':unsupported}

def revision_hash(root: Path, files: list[str]) -> str:
    digest=hashlib.sha256()
    for file in sorted(files): digest.update(file.encode()+b'\0'+(root/file).read_bytes()+b'\0')
    return 'snapshot:'+digest.hexdigest()

def snapshot_history(root: Path,destination: Path) -> list[str]:
    """Bounded Git objects/refs snapshot without hooks, config, or external object stores."""
    import os
    git=root/'.git';limitations=[]
    if not git.is_dir() or git.is_symlink():return ['Git history is unavailable; only current files were checked.']
    out=destination/'.git';out.mkdir(parents=True)
    total=0;count=0;omitted=False
    for current,directories,files in os.walk(git,followlinks=False):
        directories[:]=[d for d in directories if d not in ('hooks','lfs') and not (Path(current)/d).is_symlink()]
        for name in files:
            source=Path(current)/name;relative=source.relative_to(git)
            if name in ('config','index','commondir','gitdir','alternates','http-alternates','grafts') or name.endswith('.lock'):continue
            if source.is_symlink() or not source.is_file() or not source.resolve().is_relative_to(git.resolve()):omitted=True;continue
            size=source.stat().st_size
            if total+size>50_000_000 or count>=10000:omitted=True;continue
            target=out/relative;target.parent.mkdir(parents=True,exist_ok=True)
            with source.open('rb') as stream:
                content=stream.read(min(size+1,50_000_001))
            if len(content)!=size:omitted=True;continue
            target.write_bytes(content);total+=size;count+=1
    (out/'config').write_text('[core]\nrepositoryformatversion = 0\nbare = false\nhooksPath = /dev/null\n')
    if omitted:limitations.append('PARTIAL: Git history exceeded the 50 MB/10,000-file snapshot limit or contained unsafe links.')
    if (out/'shallow').exists():limitations.append('History covers available shallow-clone commits; earlier revisions were not fetched.')
    return limitations

@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    languages: tuple[str,...]
    pattern: str
    severity: str
    cwe: str
    impact: str
    remediation: str
    category: str = 'security'
    confidence: str = 'medium'

# Original detection rules. Pattern findings are indicators, not a substitute for taint analysis.
RULES = [
 Rule('python.dynamic-eval','Dynamic Python evaluation',('Python',),r'\b(?:eval|exec)\s*\(', 'high','CWE-95',
      'Dynamic evaluation can execute code if untrusted input reaches it.','Replace dynamic evaluation with explicit parsing and allowlisted operations.'),
 Rule('python.unsafe-pickle','Unsafe Python deserialization',('Python',),r'\bpickle\.(?:load|loads)\s*\(', 'high','CWE-502',
      'Pickle input can execute code during deserialization.','Use a data-only format such as JSON; never unpickle untrusted input.'),
 Rule('python.shell-true','Shell execution enabled',('Python',),r'\bshell\s*=\s*True\b','high','CWE-78',
      'Shell metacharacters may turn input into additional commands.','Pass an argument list with shell=False and validate command arguments.'),
 Rule('javascript.dynamic-eval','Dynamic JavaScript evaluation',('JavaScript','TypeScript'),r'\beval\s*\(','high','CWE-95',
      'Untrusted input evaluated as code may run attacker-controlled instructions.','Use JSON.parse for data and explicit allowlisted operations for behavior.'),
 Rule('javascript.raw-html','Raw HTML rendering boundary',('JavaScript','TypeScript'),r'\b(?:dangerouslySetInnerHTML|innerHTML\s*=)','medium','CWE-79',
      'Raw HTML can expose a cross-site scripting sink if content is attacker controlled.','Use escaped rendering; when HTML is necessary use a maintained sanitizer and verify its configuration.'),
 Rule('java.native-deserialization','Native Java deserialization',('Java',),r'\b(?:new\s+ObjectInputStream|\.readObject\s*\()','high','CWE-502',
      'Native deserialization may instantiate dangerous classes from untrusted streams.','Use schema-validated data formats; avoid native deserialization at trust boundaries.'),
 Rule('java.process-execution','Java process execution boundary',('Java',),r'\bRuntime\.getRuntime\s*\(\)\s*\.exec\s*\(','high','CWE-78',
      'Process execution needs validation to prevent unsafe command or argument construction.','Use fixed executables and validated argument lists; verify input cannot select arbitrary commands.'),
 Rule('csharp.binary-formatter','Unsafe .NET BinaryFormatter',('C#',),r'\b(?:new\s+BinaryFormatter|BinaryFormatter\s*\()','high','CWE-502',
      'BinaryFormatter deserialization is unsafe at untrusted input boundaries.','Replace BinaryFormatter with a supported data-only serialization format and validate inputs.'),
 Rule('csharp.tls-bypass','TLS certificate verification bypass',('C#',),r'\bDangerousAcceptAnyServerCertificateValidator\b','high','CWE-295',
      'Accepting arbitrary certificates enables interception of encrypted connections.','Restore platform certificate validation and configure a trusted certificate authority.'),
 Rule('go.tls-bypass','Go TLS verification disabled',('Go',),r'\bInsecureSkipVerify\s*:\s*true\b','high','CWE-295',
      'Skipping certificate verification enables interception of TLS connections.','Remove InsecureSkipVerify and configure RootCAs if a private authority is required.'),
 Rule('go.shell-execution','Go shell execution boundary',('Go',),r'\bexec\.Command\s*\(\s*"(?:sh|bash)"\s*,\s*"-c"','high','CWE-78',
      'Invoking a shell with constructed input can permit command injection.','Call the fixed executable directly with validated arguments rather than sh -c.'),
 Rule('install.remote-script','Remote script execution indicator',tuple(LANGUAGES.values()),r'(?:curl|wget)[^\n]{0,200}\|\s*(?:sh|bash)|(?:powershell|pwsh)[^\n]{0,100}\b(?:iex|Invoke-Expression)\b',
      'medium','CWE-494','Downloading and executing code can bypass dependency provenance checks.','Pin and verify downloaded artifacts; inspect scripts before execution.','suspicious','low'),
]

def make_finding(rule: str, title: str, path: str, line: int, text: str, severity='medium',category='security',
                 impact='',remediation='',engine='guardrails',cwe: list[str] | None=None,confidence='medium',occurrence=0,limitation='') -> dict:
    # Normalize redacted text, exclude line numbers, and preserve repeated occurrence identities.
    normalized=re.sub(r'\s+',' ',redact(text).strip())
    fingerprint=hashlib.sha256(f'{engine}:{rule}:{path}:{normalized}:{occurrence}'.encode()).hexdigest()
    return {'fingerprint':fingerprint,'rule':rule,'engine':engine,'engine_version':VERSION,'severity':severity,
      'confidence':confidence,'category':category,'title':title,'path':path,'line':line,'evidence':redact(text),
      'impact':impact,'remediation':remediation,'cwe':cwe or [],'standards':[],
      'limitation':limitation or evidence_limitation(engine,category)}

def guardrails(root: Path, inv: dict, policy: dict) -> tuple[list[dict],dict]:
    start=time.monotonic();findings=[]
    for relative in inv['files']:
        file=root/relative;language=LANGUAGES.get(file.suffix)
        if not language and file.name!='package.json' and file.name!='Dockerfile':continue
        text=file.read_text(errors='replace');occurrences: dict[str,int]={}
        for number,line in enumerate(text.splitlines(),1):
            stripped=line.strip()
            if stripped.startswith(('#','//','/*','*')):continue
            for rule in RULES:
                if (language in rule.languages or (file.name=='package.json' and rule.id=='install.remote-script')) and re.search(rule.pattern,line):
                    key=rule.id+redact(line);count=occurrences.get(key,0);occurrences[key]=count+1
                    finding=make_finding(rule.id,rule.title,relative,number,line,rule.severity,rule.category,
                      rule.impact,rule.remediation,cwe=[rule.cwe],confidence=rule.confidence,occurrence=count)
                    if rule.id=='go.tls-bypass':
                        import difflib
                        fixed=re.sub(r'\bInsecureSkipVerify\s*:\s*true\b','InsecureSkipVerify: false',text)
                        finding['patch']=redact(''.join(difflib.unified_diff(text.splitlines(keepends=True),fixed.splitlines(keepends=True),fromfile='a/'+relative,tofile='b/'+relative,n=0)))
                        finding['remediation']+=' The suggested diff is unvalidated; verify private-CA configuration and application behavior before applying.'
                    findings.append(finding)
            for api in policy.get('unsafe_apis',[]):
                if api in line:findings.append(make_finding('policy.unsafe-api',f'Forbidden API: {api}',relative,number,line,'high','architecture',
                  'This API violates the project security boundary.','Use an approved alternative or amend the reviewed guardrail.'))
            if re.search(r'\b(?:import|from|require\s*\(|using)\b',line):
                for boundary in policy.get('architecture',[]):
                    if fnmatch.fnmatch(relative,boundary['from']):
                        for dependency in boundary['forbidden']:
                            if dependency in line:findings.append(make_finding('policy.layer-boundary','Forbidden architectural dependency',relative,number,line,'medium','architecture',
                              'An import crosses an explicitly forbidden component boundary.','Move the shared interface to an allowed layer or remove the dependency.'))
    limit=['Original pattern rules do not prove exploitability or complete data-flow coverage.','Business logic, authorization design, and threat modeling require manual review.']
    if inv['excluded_or_oversized']:limit.append('PARTIAL: Some files exceeded limits or could not be safely snapshotted.')
    return findings,execution('guardrails','completed',start,list(inv['languages']),limit)

def execution(engine: str,status: str,start: float,coverage: list[str],limitations: list[str],version=VERSION,error: str | None=None) -> dict:
    result={'engine':engine,'version':version,'status':status,'duration_ms':round((time.monotonic()-start)*1000),'coverage':coverage,'limitations':limitations}
    if error:result['error']=redact(error)
    return result

def quality(root: Path,inv: dict) -> tuple[list[dict],dict,dict]:
    start=time.monotonic();lines=0;complexity=0;blocks:dict[str,list[str]]={};findings=[];functions=[];parse_errors=False;coverage_invalid=False
    for relative in inv['files']:
        file=root/relative
        if file.suffix not in LANGUAGES:continue
        text=file.read_text(errors='replace');content=text.splitlines();lines+=len(content)
        if file.suffix=='.py':
            from .quality_metrics import python_functions
            try:
                records=python_functions(text,relative)
                if len(functions)+len(records)>2000:raise ValueError('Function metric limit exceeded')
                functions.extend(records)
            except (SyntaxError,ValueError,RecursionError):parse_errors=True
        file_complexity=1+len(re.findall(r'\b(?:if|elif|for|while|case|catch)\b|&&|\|\|',text));complexity+=file_complexity
        if file_complexity>40:findings.append(make_finding('quality.branch-density','High file branch density',relative,1,'','low','quality',
          'Dense branching can make security-sensitive behavior harder to review.','Split cohesive responsibilities and add focused tests.',engine='quality',confidence='low',limitation='Lexical file-level estimate, not function-level cyclomatic complexity.'))
        clean=[re.sub(r'\s+',' ',x.strip()) for x in content if x.strip() and not x.strip().startswith(('#','//'))]
        for i in range(0,len(clean)-7,8):
            block='\n'.join(clean[i:i+8]);digest=hashlib.sha256(block.encode()).hexdigest();blocks.setdefault(digest,[]).append(relative)
    coverage_reports={}
    for relative in inv['files']:
        file=root/relative
        if file.name=='lcov.info':
            text=file.read_text(errors='replace');found=sum(map(int,re.findall(r'^LF:(\d+)',text,re.M)));hit=sum(map(int,re.findall(r'^LH:(\d+)',text,re.M)))
            if found and 0<=hit<=found:coverage_reports[relative]={'lines_found':found,'lines_hit':hit,'percent':round(hit/found*100,2)}
            else:coverage_invalid=True
        elif file.name in ('coverage.xml','cobertura.xml'):
            # Parse only the root's numeric line-rate; never expand XML entities.
            match=re.search(r'<coverage\b[^>]*\bline-rate=["\']([\d.]+)',file.read_text(errors='replace'))
            if match and 0<=float(match[1])<=1:coverage_reports[relative]={'percent':round(float(match[1])*100,2)}
            else:coverage_invalid=True
    metrics={'source_lines':lines,'branch_density_estimate':complexity,'duplicate_8_line_blocks':sum(1 for v in blocks.values() if len(v)>1),
      'imported_coverage':coverage_reports,'coverage_status':'imported' if coverage_reports else 'not_provided',
      'coverage_invalid':coverage_invalid,'python_functions':functions,'python_parse_errors':parse_errors,
      'limitations':['File branching and duplication remain lexical estimates. Function metrics use Python syntax only; other languages are unsupported. Coverage is imported, not independently measured or revision-attested.']}
    return findings,metrics,execution('quality','completed',start,list(inv['languages']),metrics['limitations'])

def load_policy(file: Path) -> dict:
    import yaml
    class UniqueLoader(yaml.SafeLoader): pass
    def mapping(loader,node,deep=False):
        values={}
        for key,value in node.value:
            name=loader.construct_object(key,deep=deep)
            if name in values:raise ValueError('Duplicate policy key')
            values[name]=loader.construct_object(value,deep=deep)
        return values
    UniqueLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,mapping)
    text=file.read_text()
    if len(text)>30000 or re.search(r'(^|\s)[&*][A-Za-z0-9]',text):raise ValueError('Policy too large or contains YAML aliases')
    policy=yaml.load(text,Loader=UniqueLoader)
    if not isinstance(policy,dict) or set(policy)!=set(DEFAULT_POLICY):raise ValueError('Policy keys must match the documented schema')
    if policy['version']!=1 or policy['mode'] not in ('advisory','enforce'):raise ValueError('Unsupported policy version or mode')
    if not isinstance(policy['checks'],list) or not policy['checks'] or not set(policy['checks'])<=set(DEFAULT_POLICY['checks']+['dast']):raise ValueError('Unsupported checks')
    for key in ['exclusions','unsafe_apis']:
        if not isinstance(policy[key],list) or len(policy[key])>100 or not all(isinstance(x,str) and len(x)<=200 for x in policy[key]):raise ValueError('Invalid '+key)
    if type(policy['compiler_analysis']) is not bool:raise ValueError('compiler_analysis must be a boolean')
    gate=policy['gate']
    if not isinstance(gate,dict) or not {'severities','new_only','rules'}<=set(gate) or not set(gate)<={'severities','new_only','rules','min_imported_coverage','max_python_function_complexity'} or type(gate['new_only']) is not bool or not isinstance(gate['severities'],list) or not set(gate['severities'])<= {'critical','high','medium','low','info'} or not isinstance(gate['rules'],list):raise ValueError('Invalid gate')
    if 'min_imported_coverage' in gate and (type(gate['min_imported_coverage']) not in (int,float) or not 0<=gate['min_imported_coverage']<=100):raise ValueError('Invalid coverage threshold')
    if 'max_python_function_complexity' in gate and (type(gate['max_python_function_complexity']) is not int or not 1<=gate['max_python_function_complexity']<=1000):raise ValueError('Invalid complexity threshold')
    for boundary in policy['architecture']:
        if not isinstance(boundary,dict) or set(boundary)!={'from','forbidden'} or not isinstance(boundary['from'],str) or not isinstance(boundary['forbidden'],list) or not all(isinstance(x,str) for x in boundary['forbidden']):raise ValueError('Invalid architecture boundary')
    monitoring=policy['monitoring']
    if not isinstance(monitoring,dict) or set(monitoring)!=set(DEFAULT_POLICY['monitoring']) or not all(type(v) is int and v>0 for v in monitoring.values()):raise ValueError('Invalid monitoring configuration')
    return policy
