"""Explicit network maintenance; never runs target repository code."""
from pathlib import Path
import subprocess
from .adapters import image_ref

def refresh_advisories(cache: Path):
    cache=cache.resolve();cache.mkdir(parents=True,exist_ok=True)
    for flag in ('--download-db-only','--download-java-db-only'):
        subprocess.run(['docker','run','--rm','--pull=never','--cap-drop=ALL','--security-opt=no-new-privileges',
            '--pids-limit=128','--memory=2g','--cpus=2','--mount',f'type=bind,source={cache},target=/cache',
            image_ref('trivy'),'image','--quiet','--cache-dir','/cache',flag],check=True,timeout=600)

