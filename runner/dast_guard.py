"""Reverse proxy used on a Docker internal network; stdlib only, no project code.

The scanner sees http://guard:8080, while this service alone can reach the
authorized target. DNS is pinned at startup and revalidated for each request.
"""
from __future__ import annotations
import fnmatch
import http.client
import ipaddress
import json
import re
import socket
import ssl
import threading
import time
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
from pathlib import Path
from urllib.parse import unquote,urljoin,urlsplit,urlunsplit

def origin(url: str) -> tuple:
    u=urlsplit(url)
    if u.scheme not in ('http','https') or u.username or u.password or not u.hostname:raise ValueError('Invalid target URL')
    return (u.scheme,u.hostname.lower(),u.port or (443 if u.scheme=='https' else 80))

def resolve(host: str,port: int) -> set[str]:
    return {r[4][0] for r in socket.getaddrinfo(host,port,type=socket.SOCK_STREAM)}

class Scope:
    def __init__(self,config: dict):
        self.config=config;self.base=config['url'];self.origin=origin(self.base);self.base_path=urlsplit(self.base).path.rstrip('/')
        self.connect_host=config.get('connect_host') or self.origin[1]
        self.addresses=resolve(self.connect_host,self.origin[2])
        if not self.addresses:raise ValueError('No target address found')
        if config.get('hosted') and any(not ipaddress.ip_address(a).is_global for a in self.addresses):raise ValueError('Hosted workers cannot reach private addresses')
        self.lock=threading.Lock();self.last=0.;self.requests=0

    def validate(self,path: str) -> str:
        u=urlsplit(path)
        if u.scheme or u.netloc:raise ValueError('Absolute proxy URLs rejected')
        decoded=u.path
        for _ in range(3):decoded=unquote(decoded)
        if '\\' in decoded or any(x=='..' for x in decoded.split('/')) or decoded.startswith('//'):raise ValueError('Traversal rejected')
        if self.base_path and not (decoded==self.base_path or decoded.startswith(self.base_path+'/')):raise ValueError('Path outside registered target')
        if any(fnmatch.fnmatch(decoded,p) for p in self.config.get('exclusions',[])):raise ValueError('Excluded path')
        current=resolve(self.connect_host,self.origin[2])
        if current!=self.addresses:raise ValueError('Target DNS changed during assessment')
        return sorted(self.addresses)[0]

    def redirect(self,location: str,path: str) -> str:
        target=urljoin(urljoin(self.base,path),location)
        if origin(target)!=self.origin:raise ValueError('Redirect leaves authorized origin')
        u=urlsplit(target);self.validate(urlunsplit(('','',u.path,u.query,'')))
        return urlunsplit(('','',u.path,u.query,''))

    def throttle(self):
        with self.lock:
            if self.requests>=3600:raise ValueError('Request budget exhausted')
            delay=.5-(time.monotonic()-self.last)
            if delay>0:time.sleep(delay)
            self.last=time.monotonic();self.requests+=1

class PinnedHTTPS(http.client.HTTPSConnection):
    def __init__(self,host,port,address):super().__init__(host,port,timeout=15,context=ssl.create_default_context());self.address=address
    def connect(self):
        self.sock=socket.create_connection((self.address,self.port),self.timeout)
        self.sock=self._context.wrap_socket(self.sock,server_hostname=self.host)

def verify_target(scope: Scope):
    """Fail before scanning when connectivity, scope, or supplied credentials fail."""
    path=scope.base_path or '/';address=scope.validate(path);scope.throttle()
    scheme,host,port=scope.origin
    connection=PinnedHTTPS(host,port,address) if scheme=='https' else http.client.HTTPConnection(address,port,timeout=15)
    try:
        headers={'Host':urlsplit(scope.base).netloc,'Accept-Encoding':'identity'}
        if scope.config.get('credential'):headers['Authorization']=scope.config['credential']
        connection.request('GET',path,headers=headers);response=connection.getresponse()
        if response.status>=500:raise ValueError('Target is unavailable')
        if scope.config.get('credential') and response.status in (401,403):raise ValueError('Supplied target credentials were rejected')
        if response.getheader('Location'):scope.redirect(response.getheader('Location'),path)
    finally:connection.close()

def handler(scope: Scope):
    class Handler(BaseHTTPRequestHandler):
        protocol_version='HTTP/1.0'
        def log_message(self,*args):pass # URLs, credentials, and bodies must never be logged.
        def do_CONNECT(self):self.send_error(403,'CONNECT is disabled')
        def forward(self):
            connection=None
            try:
                if not scope.config.get('active') and self.command not in ('GET','HEAD'):raise ValueError('Passive profile permits GET and HEAD only')
                address=scope.validate(self.path);scope.throttle()
                length=int(self.headers.get('Content-Length','0'))
                if length<0 or length>1_000_000 or self.headers.get('Transfer-Encoding'):raise ValueError('Unsupported request body')
                body=self.rfile.read(length) if length else None
                scheme,host,port=scope.origin
                if scheme=='https':connection=PinnedHTTPS(host,port,address)
                else:connection=http.client.HTTPConnection(address,port,timeout=15)
                headers={k:v for k,v in self.headers.items() if k.lower() not in {'host','authorization','cookie','connection','proxy-authorization','transfer-encoding','accept-encoding'}}
                headers['Host']=urlsplit(scope.base).netloc;headers['Accept-Encoding']='identity'
                if scope.config.get('credential'):headers['Authorization']=scope.config['credential']
                connection.request(self.command,self.path,body=body,headers=headers);response=connection.getresponse()
                payload=response.read(2_000_001)
                if len(payload)>2_000_000:raise ValueError('Response exceeds assessment limit')
                location=response.getheader('Location')
                if location:location=scope.redirect(location,self.path)
                self.send_response_only(response.status)
                for name,value in response.getheaders():
                    if name.lower() not in {'location','content-length','transfer-encoding','connection','set-cookie','content-encoding'}:self.send_header(name,value)
                if location:self.send_header('Location',location)
                self.send_header('Content-Length',str(len(payload)));self.end_headers()
                if self.command!='HEAD':self.wfile.write(payload)
            except Exception:
                self.send_error(403,'Request outside assessment scope or target unavailable')
            finally:
                if connection:connection.close()
        do_GET=do_HEAD=do_POST=do_PUT=do_PATCH=do_DELETE=do_OPTIONS=forward
    return Handler

if __name__=='__main__':
    scope=Scope(json.loads(Path('/config/target.json').read_text()))
    verify_target(scope)
    ThreadingHTTPServer(('0.0.0.0',8080),handler(scope)).serve_forever()
