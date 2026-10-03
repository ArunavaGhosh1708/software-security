from __future__ import annotations
import datetime as dt
import hashlib
import json
import os
import re
import time
from pathlib import Path
from .service import Client
from .core import redact
from urllib.parse import urlsplit,parse_qsl,urlencode,quote

NGINX=re.compile(r'(?P<actor>\S+) \S+ \S+ \[(?P<time>[^]]+)\] "\S+ (?P<path>\S+) [^"]+" (?P<status>\d{3})')

def safe_path(value: str) -> str:
    url=urlsplit(value)
    private={'password','passwd','secret','token','access_token','refresh_token','id_token','api_key','apikey','authorization','cookie','session','session_token','key'}
    query=[(k,'[REDACTED]' if k.lower() in private else redact(v)) for k,v in parse_qsl(url.query,keep_blank_values=True)]
    return (redact(url.path or '/')+('?' + urlencode(query,quote_via=quote) if query else ''))[:1000]
def normalize(line: str,event_key: str,environment: str) -> dict | None:
    try:
        payload=json.loads(line)
        event={'event_key':event_key,'timestamp':payload.get('timestamp') or payload.get('time'),'environment':environment,
          'actor':str(payload.get('actor') or payload.get('ip') or 'unknown')[:300],'path':str(payload.get('path') or '/')[:1000]}
        if not isinstance(payload.get('path','/'),str):return None
        if not isinstance(payload.get('actor',payload.get('ip','unknown')),(str,int,float)):return None
        event['path']=safe_path(event['path'])
        for field in ('status','auth_outcome','security_event','revision'):
            if field in payload:event[field]=payload[field]
        when=dt.datetime.fromisoformat(event['timestamp'].replace('Z','+00:00'))
        if when.tzinfo is None:return None
        event['timestamp']=when.astimezone(dt.timezone.utc).isoformat()
        if 'status' in event:
            event['status']=int(event['status'])
            if not 100<=event['status']<=599:return None
        if 'auth_outcome' in event and event['auth_outcome'] not in ('success','failure'):return None
        if 'security_event' in event and event['security_event'] not in ('authorization_failure','integrity_failure'):return None
        if 'revision' in event:
            if not isinstance(event['revision'],str):return None
            event['revision']=redact(event['revision'])[:200]
        if isinstance(payload.get('endpoint'),str):
            endpoint=urlsplit(payload['endpoint'])
            if endpoint.scheme in ('http','https') and endpoint.hostname and not endpoint.username and not endpoint.password:
                event['endpoint']=endpoint.scheme+'://'+endpoint.netloc+(endpoint.path or '/')
        return event
    except (ValueError,TypeError,AttributeError):
        match=NGINX.match(line)
        if not match:return None
        return {'event_key':event_key,'timestamp':dt.datetime.strptime(match['time'],'%d/%b/%Y:%H:%M:%S %z').isoformat(),
          'environment':environment,'actor':match['actor'],'path':safe_path(match['path']),'status':int(match['status'])}

def collect_once(client: Client,project: str,log: Path,checkpoint: Path,environment: str):
    stat=log.stat();identity=f'{stat.st_dev}:{stat.st_ino}';state={}
    if checkpoint.exists():state=json.loads(checkpoint.read_text())
    offset=state.get('offset',0) if state.get('identity')==identity and stat.st_size>=state.get('offset',0) else 0
    events=[];bad=0
    with log.open('rb') as f:
        f.seek(offset)
        for _ in range(250):
            start=f.tell();line=f.readline(65537)
            if not line:break
            if not line.endswith(b'\n') and len(line)<65537:f.seek(start);break # Wait for a complete write.
            if len(line)>65536:
                while line and not line.endswith(b'\n'):line=f.readline(65537)
                bad+=1;continue
            event=normalize(line.decode(errors='replace'),'pending',environment)
            if event:
                # Do not upload an unkeyed digest of passwords, bodies, or actor identifiers.
                identity_fields=[identity,start,event['timestamp'],event['path'].split('?')[0],event.get('status'),environment]
                event['event_key']=hashlib.sha256(json.dumps(identity_fields).encode()).hexdigest()
                events.append(event)
            else:bad+=1
        offset=f.tell()
    if events:client.post('runner/events',{'project_id':project,'events':events},retries=3)
    # Only advance after successful delivery. API deduplication makes retries safe.
    checkpoint.parent.mkdir(parents=True,exist_ok=True);temporary=checkpoint.with_suffix('.tmp')
    temporary.write_text(json.dumps({'identity':identity,'offset':offset}));temporary.replace(checkpoint)
    return {'events':len(events),'unparsed':bad}
