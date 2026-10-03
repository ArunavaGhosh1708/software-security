"""Original request-to-SQL rules with parameterized-query false-positive controls."""
import json
import sys
import tempfile
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from runner.service import assess
from runner.core import DEFAULT_POLICY
with tempfile.TemporaryDirectory(prefix='sentinel-taint-test-') as temporary:
    root=Path(temporary)
    (root/'app.ts').write_text('function route(req: any, db: any) { const name = req.query.name; db.query("SELECT * FROM users WHERE name = "+name); }')
    (root/'app.py').write_text('from flask import request\ndef route(cursor):\n    name = request.args.get("name")\n    cursor.execute("SELECT * FROM users WHERE name = " + name)\n')
    bad=assess(root,{}, {**DEFAULT_POLICY,'checks':['opengrep']})
    assert bad['executions'][0]['status']=='completed',bad['executions']
    assert len(bad['findings'])==2,bad
    (root/'app.ts').write_text('function route(req: any, db: any) { db.query("SELECT * FROM users WHERE name = $1", [req.query.name]); }')
    (root/'app.py').write_text('from flask import request\ndef route(cursor):\n    cursor.execute("SELECT * FROM users WHERE name = %s", (request.args.get("name"),))\n')
    good=assess(root,{}, {**DEFAULT_POLICY,'checks':['opengrep']})
    assert good['executions'][0]['status']=='completed' and not good['findings'],good
    Path('artifacts').mkdir(exist_ok=True)
    Path('artifacts/taint-integration.json').write_text(json.dumps({'vulnerable':bad,'corrected':good},indent=2))
    print('PASS: original Express and Flask/Django request-to-SQL taint rules; parameterized-query controls do not alert.')
