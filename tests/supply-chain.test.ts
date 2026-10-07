import {test} from 'node:test';
import assert from 'node:assert/strict';
import {dependencyPaths} from '../lib/supply-chain';
test('SBOM relationship paths preserve versions and licenses without inferring reachability',()=>{
  const sbom={metadata:{component:{'bom-ref':'root'}},components:[{'bom-ref':'vulnerable',name:'package',version:'1',licenses:[{license:{id:'MIT'}}]}],dependencies:[{ref:'root',dependsOn:['parent']},{ref:'parent',dependsOn:['vulnerable','root']}]};
  const result=dependencyPaths(sbom,'package');assert.deepEqual(result.paths,[['root','parent','vulnerable']]);assert.equal(result.components[0].version,'1');assert.equal(result.coverage,'declared_paths_found');
  assert.equal(dependencyPaths({components:sbom.components},'package').coverage,'relationships_not_supplied');
  assert.equal(dependencyPaths(sbom,'unknown').coverage,'path_not_found');
});
