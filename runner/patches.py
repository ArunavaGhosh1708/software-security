"""Validate a reviewed diff against a disposable snapshot; never edit the project."""
from pathlib import Path
import subprocess
import tempfile
from .core import DEFAULT_POLICY,snapshot

def validate_patch(root:Path,patch:Path):
    if patch.stat().st_size>20000:raise ValueError('Patch exceeds 20 KB limit')
    text=patch.read_text(encoding='utf-8')
    if 'GIT binary patch' in text:raise ValueError('Binary patches are unsupported')
    headers=[line[4:] for line in text.splitlines() if line.startswith(('--- ','+++ '))]
    if not headers or len(headers)%2:raise ValueError('A unified diff with file headers is required')
    for header in headers:
        if header=='/dev/null':continue
        if not header.startswith(('a/','b/')):raise ValueError('Use a/ and b/ relative diff paths')
        path=header[2:]
        if not path or '\\' in path or ':' in path or '\t' in path or '"' in path or any(part in ('','..','.git') for part in path.split('/')):raise ValueError('Unsafe patch path')
    with tempfile.TemporaryDirectory(prefix='sentinel-patch-') as tmp:
        copied=Path(tmp)/'source';copied.mkdir();snapshot(root,copied,DEFAULT_POLICY['exclusions'])
        candidate=Path(tmp)/'proposal.diff';candidate.write_text(text,encoding='utf-8')
        result=subprocess.run(['git','-c','core.hooksPath=','apply','--check','--',str(candidate)],cwd=copied,
            capture_output=True,timeout=15,shell=False)
        return {'applies_to_snapshot':result.returncode==0,'validation':'applicability_only',
                'security_checks_run':False,'limitation':'No source changes, builds, tests, or security checks were executed. Applicability does not establish correctness or safety.'}
