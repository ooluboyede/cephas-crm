// Trusted, disposable operator-side verifier; no application-facing endpoint.
import {readFileSync} from 'node:fs';
import {join} from 'node:path';
import {createHash} from 'node:crypto';
import {verifyCurrentLicence} from './current_issuer.mjs';
import {allowsCapability} from './validator.mjs';
try{
  if(process.argv.length!==4)throw Error('arguments');
  const dir=process.argv[2],mode=process.argv[3];
  if(!['initial','revoked'].includes(mode))throw Error('mode');
  const cfg=JSON.parse(readFileSync(join(dir,'config.json'),'utf8'));
  if(cfg.issuerProfile!=='current-v1'||cfg.binding.environment!=='staging'||
     cfg.binding.customerCode!=='TEST-A'||cfg.binding.deploymentId!=='TEST-D')throw Error('scope');
  const raw=readFileSync(join(dir,'licence.json'));
  const snapshot=readFileSync(join(dir,mode==='initial'?'snapshot.json':'revoked.json'));
  const now=Date.now();
  const licence=verifyCurrentLicence(raw,new Map(cfg.keys),{...cfg.binding,now,previousTime:0},cfg.policy,snapshot);
  if(!allowsCapability(licence,'module','contact_management')||licence.graceActive)throw Error('capability');
  const p=JSON.parse(snapshot.toString('utf8')).payload;
  const expiry=Math.min(licence.expiresAt,Date.parse(p.expiresAt));
  process.stdout.write(JSON.stringify({licence:createHash('sha256').update(raw).digest('hex'),
    snapshot:createHash('sha256').update(snapshot).digest('hex'),cap:licence.limits.transactions,expiry}));
}catch{process.exitCode=1;}
