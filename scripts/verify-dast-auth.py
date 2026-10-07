"""Real fixed-cookie DAST against a disposable local fixture; no user application."""
import http.server
import json
import os
from pathlib import Path
import sys
import tempfile
import threading
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from runner.dast import scan_dast
class Fixture(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        authorized=self.headers.get('Cookie')=='session=synthetic-fixture'
        self.send_response(200 if authorized else 401);self.send_header('Content-Type','text/html');self.end_headers()
        self.wfile.write(b'<html><body>signed-in <a href="/private">Protected fixture</a></body></html>' if authorized else b'unauthorized')
    def log_message(self,*args):pass
server=http.server.ThreadingHTTPServer(('0.0.0.0',0),Fixture);threading.Thread(target=server.serve_forever,daemon=True).start()
url=f'http://127.0.0.1:{server.server_port}';os.environ['SENTINEL_FIXTURE_COOKIE']='session=synthetic-fixture'
try:
    with tempfile.TemporaryDirectory(prefix='sentinel-cookie-test-') as tmp:
        findings,execution=scan_dast(Path(tmp),{'url':url,'environment':'local','authorized':True,'active':False,'credential_ref':'SENTINEL_FIXTURE_COOKIE','credential_type':'cookie','verify_path':'/private','success_marker':'signed-in'}, {'allowed_targets':[url]},threading.Event())
        assert execution['status']=='completed',execution
        assert not any(s.startswith('PARTIAL:') for s in execution['limitations']),execution
        assert 'synthetic-fixture' not in json.dumps(findings)
        Path('artifacts').mkdir(exist_ok=True);Path('artifacts/dast-cookie-integration.json').write_text(json.dumps({'execution':execution,'findings':findings},indent=2))
        print('PASS: isolated fixed-cookie authentication and protected endpoint verification with real ZAP.')
finally:
    server.shutdown();server.server_close();os.environ.pop('SENTINEL_FIXTURE_COOKIE',None)
