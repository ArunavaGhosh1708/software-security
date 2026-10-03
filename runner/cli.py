from __future__ import annotations
import argparse
import json
import os
import time
from pathlib import Path
from .adapters import IMAGES,pin_prepared_images
from .core import DEFAULT_POLICY
from .service import Client,assess,gate,run_once

class SettingsError(ValueError):
    """An actionable configuration error safe to display without file contents."""

def settings_from(path: Path):
    try:
        settings=json.loads(path.read_text(encoding='utf-8-sig'))
    except FileNotFoundError:
        raise SettingsError(f'Runner settings not found: {path}. In the dashboard, open Private runners, enroll a runner for your project, and download runner-settings.json. Move it to this folder or pass its full path with --config. Registration requires that downloaded credential file.') from None
    except (json.JSONDecodeError,UnicodeError):
        raise SettingsError(f'Runner settings are not valid UTF-8 JSON: {path}. Use the settings file downloaded from Private runners; do not paste the dashboard password here.') from None
    except OSError:
        raise SettingsError(f'Cannot read runner settings: {path}. Check the file path and read permissions.') from None
    if not isinstance(settings,dict):raise SettingsError('Runner settings must be a JSON object.')
    roots=settings.get('roots',{})
    if not isinstance(roots,dict) or any(not isinstance(root,str) or not root.strip() for root in roots.values()):
        raise SettingsError('roots must be a mapping of aliases to explicit directory paths.')
    return settings

def main():
    parser=argparse.ArgumentParser(description='Sentinel private runner and CI scanner')
    sub=parser.add_subparsers(dest='command',required=True)
    register=sub.add_parser('register');register.add_argument('--config',type=Path,required=True);register.add_argument('--alias',required=True);register.add_argument('--path',type=Path,required=True)
    run=sub.add_parser('run');run.add_argument('--config',type=Path,required=True);run.add_argument('--once',action='store_true')
    scan=sub.add_parser('scan');scan.add_argument('--path',type=Path,required=True);scan.add_argument('--config',type=Path);scan.add_argument('--checks');scan.add_argument('--enforce',action='store_true');scan.add_argument('--output',type=Path,default=Path('artifacts/report.json'));scan.add_argument('--baseline',type=Path);scan.add_argument('--compiler-analysis',action='store_true',help='Explicitly opt in to isolated offline compiler checks')
    collect=sub.add_parser('collect');collect.add_argument('--config',type=Path,required=True);collect.add_argument('--project',required=True);collect.add_argument('--log',type=Path,required=True);collect.add_argument('--checkpoint',type=Path,default=Path('.data/collector-checkpoint.json'));collect.add_argument('--environment',choices=['local','staging','production'],default='local');collect.add_argument('--once',action='store_true')
    prepare=sub.add_parser('prepare');prepare.add_argument('--cache',type=Path,default=Path('.data/trivy-cache'));prepare.add_argument('--build-linters',action='store_true')
    scan.add_argument('--sarif',type=Path,help='Also export SARIF 2.1.0 for code-scanning integrations')
    doctor=sub.add_parser('doctor');doctor.add_argument('--config',type=Path)
    args=parser.parse_args()
    try:
        settings=settings_from(args.config) if getattr(args,'config',None) else {'scanner_mode':'container'}
    except SettingsError as error:
        parser.error(str(error))
    if args.command=='doctor':
        from .doctor import diagnose
        result=diagnose(settings)
        print(json.dumps(result,indent=2));return 0 if result['ready'] else 2
    if args.command=='register':
        import re
        if not re.fullmatch('[A-Za-z0-9_-]+',args.alias):parser.error('Alias must use letters, digits, underscores, or hyphens')
        try:root=args.path.resolve(strict=True)
        except (OSError,RuntimeError):parser.error('Source directory does not exist or cannot be accessed. Check --path.')
        if not root.is_dir():parser.error('Registered source must be a directory')
        settings.setdefault('roots',{})[args.alias]=str(root)
        try:
            args.config.write_text(json.dumps(settings,indent=2),encoding='utf-8');os.chmod(args.config,0o600)
        except OSError:parser.error('Cannot save runner settings. Check the file write permissions.')
        print('Registered alias '+args.alias+' on this runner.');return 0
    if args.command=='scan':
        policy=None
        if args.checks:
            policy=json.loads(json.dumps(DEFAULT_POLICY));policy['checks']=args.checks.split(',')
            if not set(policy['checks'])<=set(DEFAULT_POLICY['checks']+['dast']):parser.error('Unknown scanner check')
        if args.enforce:
            from .core import load_policy
            policy=policy or (load_policy(args.path/'security-guardrails.yml') if (args.path/'security-guardrails.yml').exists() else json.loads(json.dumps(DEFAULT_POLICY)))
            policy['mode']='enforce'
        from .core import load_policy
        policy=policy or (load_policy(args.path/'security-guardrails.yml') if (args.path/'security-guardrails.yml').exists() else json.loads(json.dumps(DEFAULT_POLICY)))
        policy['compiler_analysis']=args.compiler_analysis
        report=assess(args.path.resolve(strict=True),settings,policy)
        baseline={f['fingerprint'] for f in json.loads(args.baseline.read_text()).get('findings',[])} if args.baseline else set()
        outcome=gate(report,baseline);report['gate']=outcome
        args.output.parent.mkdir(parents=True,exist_ok=True);args.output.write_text(json.dumps(report,indent=2))
        if args.sarif:
            from .reporting import sarif
            args.sarif.parent.mkdir(parents=True,exist_ok=True);args.sarif.write_text(json.dumps(sarif(report),indent=2))
        print(f"Assessment: {len(report['findings'])} findings; gate={outcome}; report={args.output}")
        return {'pass':0,'fail':1,'incomplete':2}[outcome]
    if args.command=='prepare':
        import subprocess
        repo=Path(__file__).resolve().parents[1]
        subprocess.run(['docker','build','-f',str(repo/'infra/opengrep.Dockerfile'),'-t',IMAGES['opengrep'],str(repo)],check=True)
        for engine in ['gitleaks','trivy','ruff','zap']:
            subprocess.run(['docker','pull',IMAGES[engine]],check=True)
        args.cache.mkdir(parents=True,exist_ok=True)
        subprocess.run(['docker','run','--rm','--mount',f'type=bind,source={args.cache.resolve()},target=/cache',IMAGES['trivy'],'image','--quiet','--cache-dir','/cache','--download-db-only'],check=True)
        subprocess.run(['docker','run','--rm','--mount',f'type=bind,source={args.cache.resolve()},target=/cache',IMAGES['trivy'],'image','--quiet','--cache-dir','/cache','--download-java-db-only'],check=True)
        for engine in ['dast-guard']+(['eslint','checkstyle','roslyn','staticcheck'] if args.build_linters else []):
            subprocess.run(['docker','build','-f',str(repo/'infra'/f'{engine}.Dockerfile'),'-t',f'sentinel-{engine}:0.1.0',str(repo)],check=True)
        pin_prepared_images()
        print('Scanner images prepared and locked to immutable image IDs. Assessments do not pull images or update databases. Refresh databases regularly.');return 0
    if args.command=='run':
        while True:
            try:
                picked=run_once(settings)
                if args.once:return 0
                if not picked:time.sleep(5)
            except KeyboardInterrupt:return 0
            except Exception as error:
                print('Runner connection unavailable: '+str(error)[:150])
                if args.once:return 2
                time.sleep(10)
    if args.command=='collect':
        from .collector import collect_once
        client=Client(settings)
        while True:
            try:
                result=collect_once(client,args.project,args.log,args.checkpoint,args.environment)
                if result['unparsed']:print(f"Skipped {result['unparsed']} unparseable log lines; monitoring coverage is partial.")
                if args.once:return 0
                time.sleep(2)
            except KeyboardInterrupt:return 0
            except Exception as error:
                print('Collector delivery failed; checkpoint not advanced: '+str(error)[:150])
                if args.once:return 2
                time.sleep(10)

if __name__=='__main__':raise SystemExit(main())
