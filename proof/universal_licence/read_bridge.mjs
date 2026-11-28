// Trusted local subprocess adapter; disposable test profile, no HTTP endpoint.
import { readFileSync, lstatSync } from 'node:fs';
import { join } from 'node:path';
import { EntitlementStore } from './state.mjs';

function need(ok){if(!ok)throw new Error('denied');}
try{
  need(process.argv.length===3);
  const dir=process.argv[2], configPath=join(dir,'config.json');
  need(lstatSync(configPath).isFile());
  const cfg=JSON.parse(readFileSync(configPath,'utf8'));
  need(cfg.issuerProfile==='current-v1'&&cfg.binding.environment==='staging'&&cfg.policy.requireSnapshot===true);
  const config={...cfg,keys:new Map(cfg.keys)};
  const bytes=readFileSync(0);
  need(bytes.length>0&&bytes.length<=1024);
  const r=JSON.parse(bytes.toString('utf8'));
  need(Object.keys(r).sort().join(',')==='action,now,requestId,target');
  need(Number.isSafeInteger(r.now)&&r.now>=0);
  need(['read_items','read_notes'].includes(r.action));
  const store=new EntitlementStore(join(dir,'state.sqlite'),config,()=>r.now);
  const status=store.execute(r.action,r.requestId,r.target);
  need(status==='applied'||status==='duplicate');
  process.stdout.write(status);
}catch{
  process.exitCode=1;
}
