import type {FindingInput,ExecutionInput} from './types';

export function sourceUri(path:string|undefined) {
  if(!path)return undefined;
  const normalized=path.replaceAll('\\','/');
  if(normalized.startsWith('/')||/^[a-z]+:/i.test(normalized)||normalized.split('/').includes('..'))return undefined;
  return normalized.split('/').map(encodeURIComponent).join('/');
}
export function sarif(findings:FindingInput[],executions:ExecutionInput[],revision:string,gate?:string) {
  const engines=[...new Set([...executions.map(e=>e.engine),...findings.map(f=>f.engine)])];
  return {$schema:'https://json.schemastore.org/sarif-2.1.0.json',version:'2.1.0',runs:engines.map(engine=>{
    const items=findings.filter(f=>f.engine===engine),execution=executions.find(e=>e.engine===engine);
    const rules=[...new Map(items.map(f=>[f.rule,f])).values()];
    return {tool:{driver:{name:`Sentinel/${engine}`,version:execution?.version??items[0]?.engine_version??'unknown',rules:rules.map(f=>({id:f.rule,shortDescription:{text:f.title},help:{text:f.remediation},properties:{tags:[f.category,...f.cwe??[]],...(f.category==='security'?{'security-severity':String(f.cvss??({critical:9.5,high:8,medium:5,low:2,info:0}[f.severity]))}:{})}}))}},
      automationDetails:{id:`sentinel/${engine}/`},properties:{revision,gate:gate??'incomplete',coverage:execution?.coverage??[],limitations:execution?.limitations??['No execution metadata']},
      invocations:[{executionSuccessful:execution?.status==='completed'&&!execution.limitations.some(x=>x.startsWith('PARTIAL:')),toolExecutionNotifications:execution?.error?[{level:'error',message:{text:execution.error}}]:[]}],
      results:items.map(f=>({ruleId:f.rule,ruleIndex:rules.findIndex(r=>r.rule===f.rule),level:['critical','high'].includes(f.severity)?'error':f.severity==='medium'?'warning':'note',message:{text:`${f.title}\n${f.impact}\nRemediation: ${f.remediation}`},
        partialFingerprints:{'sentinel/v1':f.fingerprint},...(sourceUri(f.path)?{locations:[{physicalLocation:{artifactLocation:{uri:sourceUri(f.path),uriBaseId:'%SRCROOT%'},region:{startLine:f.line??1}}}]}:{}),
        properties:{severity:f.severity,confidence:f.confidence,category:f.category,endpoint:f.endpoint,limitation:f.limitation,dependency:f.dependency,vulnerability_id:f.vulnerability_id}}))};
  })};
}

// Absence is only a candidate fix if that engine actually covered the location again.
export function compareReports(before:any,after:any) {
  const old=new Map<string,any>(before.findings.map((x:any)=>[x.data.fingerprint,x.data])),current=new Map<string,any>(after.findings.map((x:any)=>[x.data.fingerprint,x.data]));
  const comparable=JSON.stringify(before.policy?.exclusions??[])===JSON.stringify(after.policy?.exclusions??[])
    && JSON.stringify(before.inventory?.languages??{})===JSON.stringify(after.inventory?.languages??{});
  const completed=new Set<string>(after.executions.filter((e:any)=>e.engine!=='dast'&&e.status==='completed'&&e.coverage.length&&!e.limitations.some((s:string)=>s.startsWith('PARTIAL:'))).map((e:any)=>e.engine));
  const result:{new:any[];persistent:any[];no_longer_detected:any[];not_rechecked:any[]}={new:[],persistent:[],no_longer_detected:[],not_rechecked:[]};
  for(const [fp,f] of current)result[old.has(fp)?'persistent':'new'].push(f);
  for(const [fp,f] of old)if(!current.has(fp))result[comparable&&completed.has(f.engine)?'no_longer_detected':'not_rechecked'].push(f);
  return {...result,comparable,limitation:'No longer detected means absent from a comparable completed engine run; it is not proof of remediation. Changed coverage and failed engines remain not rechecked.'};
}
