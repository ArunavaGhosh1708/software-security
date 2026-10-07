"""Restart private runners after failures. Credentials stay in their local files."""
import argparse
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time

def main():
    parser=argparse.ArgumentParser(description='Supervise existing scoped Sentinel runners')
    parser.add_argument('--config',type=Path,action='append',required=True)
    parser.add_argument('--state-dir',type=Path,default=Path('.data/supervisor'))
    parser.add_argument('--refresh-advisories',action='store_true',help='Opt in to network advisory updates before starting workers')
    args=parser.parse_args()
    from .cli import settings_from
    configs=list(dict.fromkeys(p.resolve(strict=True) for p in args.config))
    settings=[settings_from(p) for p in configs]
    state=args.state_dir.resolve();state.mkdir(parents=True,exist_ok=True)
    # OS lock prevents two supervisors competing for the same state directory.
    lock=(state/'lock').open('a+b');lock.seek(0);lock.write(b'0');lock.flush();lock.seek(0)
    try:
        if os.name=='nt':
            import msvcrt
            msvcrt.locking(lock.fileno(),msvcrt.LK_NBLCK,1)
        else:
            import fcntl
            fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
    except OSError:parser.error('Supervisor already running for this state directory.')
    running=True
    def stop(*_):
        nonlocal running
        running=False
    signal.signal(signal.SIGTERM,stop);signal.signal(signal.SIGINT,stop)
    repo=Path(__file__).resolve().parents[1]
    workers={};handles={};last_refresh=0;retry_at=0;update_status='disabled';drain=state/'drain'
    drain.unlink(missing_ok=True)
    try:
        while running:
            now=time.monotonic()
            due=args.refresh_advisories and now>=retry_at and (not last_refresh or now-last_refresh>86400)
            if due:drain.touch()
            drained=all(p.poll() is not None for p in workers.values())
            # Workers stop claiming jobs and finish their current assessment before refresh.
            if due and drained:
                try:
                    from .maintenance import refresh_advisories
                    for cache in {Path(s.get('cache_dir','.data/trivy-cache')).resolve() for s in settings}:refresh_advisories(cache)
                    last_refresh=now;update_status='updated';drain.unlink(missing_ok=True)
                except Exception:
                    update_status='failed';retry_at=now+300
                    print('Advisory refresh unavailable; retrying in five minutes. No credentials logged.',flush=True)
            for index,config in enumerate(configs):
                process=workers.get(index)
                if process and process.poll() is None:continue
                if drain.exists():continue
                if args.refresh_advisories and not last_refresh:continue
                if index in handles:handles[index].close()
                log=state/f'runner-{index}.log'
                if log.exists() and log.stat().st_size>5_000_000:log.replace(state/f'runner-{index}.previous.log')
                handle=log.open('ab');handles[index]=handle
                workers[index]=subprocess.Popen([sys.executable,'-u','-m','runner.cli','run','--config',str(config),'--drain-file',str(drain)],cwd=repo,
                    stdout=handle,stderr=subprocess.STDOUT,shell=False,creationflags=subprocess.CREATE_NO_WINDOW if os.name=='nt' else 0)
            temporary=state/'status.tmp';temporary.write_text(json.dumps({'pid':os.getpid(),'updated_at':time.time(),
                'advisories':update_status,'workers':[{'index':i,'pid':p.pid,'running':p.poll() is None} for i,p in workers.items()]}));temporary.replace(state/'status.json')
            for _ in range(10):
                if not running:break
                time.sleep(1)
    finally:
        for process in workers.values():
            if process.poll() is None:
                process.terminate()
                try:process.wait(timeout=10)
                except subprocess.TimeoutExpired:process.kill();process.wait()
        for handle in handles.values():handle.close()
        lock.close()
    return 0

if __name__=='__main__':raise SystemExit(main())
