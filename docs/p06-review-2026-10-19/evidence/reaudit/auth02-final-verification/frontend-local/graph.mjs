import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
import { parse } from '/Users/Vivian/Documents/Liveuin/www-lovable/node_modules/acorn/dist/acorn.mjs';
const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
const manifest=JSON.parse(fs.readFileSync(path.join(root,'candidate-manifest.json'),'utf8'));
const candidate=path.join(root,'candidate');
let parsed=0,imports=0,dynamic=0,indexImports=0;
const sha=data=>crypto.createHash('sha256').update(data).digest('hex');
for(const record of manifest.files){
  const full=path.join(candidate,record.path),data=fs.readFileSync(full);
  assert.equal(sha(data),record.sha256);
  if(!record.changed) assert.equal(sha(data),record.baseline_sha256);
  if(!record.path.endsWith('.js'))continue;
  const tree=parse(data.toString('utf8'),{ecmaVersion:'latest',sourceType:'module'});parsed++;
  function inspect(node){
    if(!node||typeof node!=='object')return;
    if(['ImportDeclaration','ExportNamedDeclaration','ExportAllDeclaration','ImportExpression'].includes(node.type)&&node.source){
      const value=node.source.value;
      assert.equal(typeof value,'string','literal imports only');
      if(value.startsWith('.')){
        const target=path.resolve(path.dirname(full),value);
        assert.ok(target.startsWith(path.join(candidate,'assets',manifest.release_id)+path.sep));
        assert.ok(fs.existsSync(target),'missing import '+value);
        if(value==='./index-DPZwxwE9.js')indexImports++;
      }else throw new Error('Unexpected non-relative JS import: '+value);
      if(node.type==='ImportExpression')dynamic++;else imports++;
    }
    for(const value of Object.values(node))if(value&&typeof value==='object')Array.isArray(value)?value.forEach(inspect):inspect(value);
  }
  inspect(tree);
}
const html=fs.readFileSync(path.join(candidate,'app-entry.html'),'utf8');
assert.ok(html.includes('/assets/'+manifest.release_id+'/index-DPZwxwE9.js'));
assert.equal(html,fs.readFileSync(path.join(candidate,'public-entry.html'),'utf8'));
const preload=new URL('assets/Login-Mh8o3oad.js'.replace(/^assets\//,''),'https://app.liveuin.com/assets/'+manifest.release_id+'/index-DPZwxwE9.js').href;
assert.equal(preload,'https://app.liveuin.com/assets/'+manifest.release_id+'/Login-Mh8o3oad.js');
const result={status:'pass',release_id:manifest.release_id,parsed_javascript:parsed,static_imports:imports,dynamic_imports:dynamic,shared_index_imports:indexImports,unchanged_files:manifest.files.filter(x=>!x.changed).length,changed_javascript:manifest.files.filter(x=>x.changed&&x.path.endsWith('.js')).map(x=>path.basename(x.path))};
fs.writeFileSync(path.join(root,'tests/graph-results.json'),JSON.stringify(result,null,2)+'\n');console.log(JSON.stringify(result));
