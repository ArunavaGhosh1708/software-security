"""Opt-in compiler adapters on tiny, offline, disposable C# and Go projects."""
import json
import sys
import tempfile
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from runner.service import assess
from runner.core import DEFAULT_POLICY
reports={}
for language in ['csharp','go']:
    with tempfile.TemporaryDirectory(prefix='sentinel-compiler-test-') as temp:
        source=Path(temp)
        if language=='csharp':
            (source/'App.csproj').write_text('<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><TargetFramework>net8.0</TargetFramework><OutputType>Library</OutputType></PropertyGroup></Project>')
            (source/'App.cs').write_text('public class App { public void Test() { int unused = 1; } }')
        else:
            (source/'go.mod').write_text('module example.test/sentinel-fixture\n\ngo 1.24\n')
            (source/'app.go').write_text('package fixture\nimport "fmt"\nfunc Test() { fmt.Printf("%d", "text") }\n')
        report=assess(source,{}, {**DEFAULT_POLICY,'checks':['lint'],'compiler_analysis':True})
        reports[language]=report
        assert report['executions'][0]['status']=='completed',report['executions']
        assert report['findings'],'Expected analyzer evidence from the synthetic compiler fixture.'
        if language=='csharp':
            (source/'App.cs').write_text('public static class App { public static int Test() => 1; }')
            intended='CS0219'
        else:
            (source/'app.go').write_text('package fixture\nimport "fmt"\nfunc Test() { fmt.Printf("%d", 1) }\n')
            intended='SA5009'
        assert any(f['rule']==intended for f in report['findings']),report
        fixed=assess(source,{}, {**DEFAULT_POLICY,'checks':['lint'],'compiler_analysis':True})
        assert fixed['executions'][0]['status']=='completed' and not any(f['rule']==intended for f in fixed['findings']),fixed
        reports[language+'_corrected']=fixed
Path('artifacts').mkdir(exist_ok=True)
Path('artifacts/compiler-integration.json').write_text(json.dumps(reports,indent=2))
print('PASS: opt-in Roslyn and Staticcheck on isolated offline fixtures.')
