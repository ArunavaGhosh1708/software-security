"""Portable SARIF 2.1.0 exports; no snippets or unvalidated fixes are embedded."""
from urllib.parse import quote
import re

def source_uri(path):
    if not path:return None
    path=path.replace('\\','/')
    if path.startswith('/') or re.match(r'^[a-z]+:',path,re.I) or '..' in path.split('/'):return None
    return '/'.join(quote(part,safe='') for part in path.split('/'))

def sarif(report):
    findings=report.get('findings',[]);executions={e['engine']:e for e in report.get('executions',[])};runs=[]
    for engine in sorted(set(executions)|{f['engine'] for f in findings}):
        items=[f for f in findings if f['engine']==engine];rules=list({f['rule']:f for f in items}.values());execution=executions.get(engine,{})
        results=[]
        for f in items:
            result={'ruleId':f['rule'],'ruleIndex':next(i for i,r in enumerate(rules) if r['rule']==f['rule']),
              'level':'error' if f['severity'] in ('critical','high') else 'warning' if f['severity']=='medium' else 'note',
              'message':{'text':f"{f['title']}\n{f['impact']}\nRemediation: {f['remediation']}"},'partialFingerprints':{'sentinel/v1':f['fingerprint']},
              'properties':{k:f[k] for k in ('severity','confidence','category','endpoint','limitation','dependency','vulnerability_id') if k in f}}
            uri=source_uri(f.get('path'))
            if uri:result['locations']=[{'physicalLocation':{'artifactLocation':{'uri':uri,'uriBaseId':'%SRCROOT%'},'region':{'startLine':f.get('line',1)}}}]
            results.append(result)
        runs.append({'tool':{'driver':{'name':'Sentinel/'+engine,'version':execution.get('version','unknown'),'rules':[{'id':f['rule'],'shortDescription':{'text':f['title']},'help':{'text':f['remediation']},'properties':{'tags':[f['category']]+f.get('cwe',[])}} for f in rules]}},
          'automationDetails':{'id':f'sentinel/{engine}/'},'properties':{'revision':report.get('revision'),'gate':report.get('gate','incomplete'),'coverage':execution.get('coverage',[]),'limitations':execution.get('limitations',[])},
          'invocations':[{'executionSuccessful':execution.get('status')=='completed' and not any(x.startswith('PARTIAL:') for x in execution.get('limitations',[]))}], 'results':results})
    return {'$schema':'https://json.schemastore.org/sarif-2.1.0.json','version':'2.1.0','runs':runs}
