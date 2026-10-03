"""Restore a local backup into a newly created throwaway database, then remove only it."""
import subprocess
import uuid
from pathlib import Path
name='sentinel_restore_check_'+uuid.uuid4().hex
def docker(*args,input=None):
    return subprocess.run(['docker','exec','-i','sentinel-db-1',*args],input=input,stdout=subprocess.PIPE,stderr=subprocess.PIPE,check=True).stdout
backup=docker('pg_dump','-U','postgres','-d','sentinel','--format=custom')
Path('artifacts').mkdir(exist_ok=True)
Path('artifacts/local-verification.dump').write_bytes(backup)
docker('createdb','-U','postgres',name)
try:
    docker('pg_restore','-U','postgres','-d',name,'--no-owner',input=backup)
    tables=docker('psql','-U','postgres','-d',name,'-Atc',"SELECT count(*) FROM information_schema.tables WHERE table_schema='public'")
    assert int(tables)>=15
    print('PASS: local pg_dump backup restored into a separate disposable database; assessment tables verified.')
finally:
    docker('dropdb','-U','postgres',name)
