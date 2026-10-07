/** Declared SBOM relationships only. This does not infer function reachability. */
export function dependencyPaths(sbom:Record<string,any>,target:string) {
  const components:Array<Record<string,any>>=Array.isArray(sbom.components)?sbom.components.slice(0,10000):[];
  const match=components.filter(c=>[c['bom-ref'],c.purl,c.name].includes(target));
  const root=sbom.metadata?.component?.['bom-ref'];
  const edges=new Map<string,string[]>();
  for(const item of (Array.isArray(sbom.dependencies)?sbom.dependencies:[]).slice(0,10000))if(typeof item.ref==='string')edges.set(item.ref,(Array.isArray(item.dependsOn)?item.dependsOn:[]).filter((x:unknown)=>typeof x==='string').slice(0,1000));
  const targets=new Set(match.map(c=>c['bom-ref']).filter(Boolean));const paths:string[][]=[];
  let traversed=0;let truncated=false;
  if(root) {
    const queue=[[root]];
    while(queue.length&&paths.length<20&&traversed<20000) {
      const path=queue.shift()!;traversed++;const last=path.at(-1)!;
      if(targets.has(last)){paths.push(path);continue;}
      if(path.length>=30){truncated=true;continue;}
      for(const child of edges.get(last)??[])if(!path.includes(child)){
        if(queue.length>=20000){truncated=true;break;}queue.push([...path,child]);
      }
    }
    if(queue.length)truncated=true;
  }
  return {components:match.map(c=>({ref:c['bom-ref'],name:c.name,version:c.version,purl:c.purl,licenses:c.licenses??[]})),paths,truncated,
    coverage:!root||!edges.size?'relationships_not_supplied':paths.length?'declared_paths_found':'path_not_found',
    limitation:'Paths come only from supplied CycloneDX relationships. Missing paths do not establish absence, directness, exploitability, or runtime/function reachability. License declarations are not a legal assessment.'};
}
