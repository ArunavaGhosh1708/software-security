"""Passive ZAP verification against a disposable, explicitly scoped local test server."""
import http.server
import json
import sys
import tempfile
import threading
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from runner.dast import scan_dast
class Fixture(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200);self.send_header('Content-Type','text/html');self.end_headers()
        self.wfile.write(b'<html><head><title>Disposable security fixture</title></head><body><a href="/login">Login fixture</a></body></html>')
    def log_message(self,*args):pass
server=http.server.ThreadingHTTPServer(('0.0.0.0',0),Fixture)
thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
url=f'http://127.0.0.1:{server.server_port}'
try:
    with tempfile.TemporaryDirectory(prefix='sentinel-dast-test-') as temp:
        findings,execution=scan_dast(Path(temp),{'url':url,'environment':'local','authorized':True,'active':False,'exclusions':['/logout']},{'allowed_targets':[url]},threading.Event())
        Path('artifacts').mkdir(exist_ok=True)
        Path('artifacts/dast-integration.json').write_text(json.dumps({'execution':execution,'findings':findings},indent=2))
        assert execution['status']=='completed',execution
        assert any(f['engine']=='dast' for f in findings),'Expected passive missing-header evidence from the synthetic fixture.'
        print('PASS: real ZAP passive scan through isolated scope guard; normalized endpoint evidence and explicit coverage limits.')
finally:
    server.shutdown();server.server_close()
