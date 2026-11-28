// Synthetic operator-only setup/revocation. No genuine issuer private key.
import {generateKeyPairSync,sign,createHash} from 'node:crypto';
import {writeFileSync,readFileSync} from 'node:fs';
import {join} from 'node:path';
import {EntitlementStore} from './state.mjs';
const [mode,dir,rawNow,profile]=process.argv.slice(2);
const now=Number(rawNow), iso=n=>new Date(n).toISOString();
if(!Number.isSafeInteger(now))throw new Error('clock');
const path=join(dir,'state.sqlite');
if(mode==='revoke'){
  const c=JSON.parse(readFileSync(join(dir,'config.json'),'utf8'));
  new EntitlementStore(path,{...c,keys:new Map(c.keys)},()=>now)
    .importSnapshot(readFileSync(join(dir,'revoked.json')));
}else if(mode==='init'){
  if(!['full','no_notes','no_api','zero'].includes(profile))throw new Error('profile');
  const pair=generateKeyPairSync('ed25519'), der=pair.publicKey.export({type:'spki',format:'der'});
  const keys=[['v1',{status:'active',material:der.toString('base64'),
    fingerprint:'sha256:'+createHash('sha256').update(der).digest('hex')}]];
  const binding={productCode:'CEPHAS_CRM',customerCode:'TEST-A',deploymentId:'TEST-D',environment:'test'};
  const modules=['contact_management','customer_service'],features=['api_access'];
  const limits={users:1,transactions:1,apiCalls:2,sites:1,businessUnits:1};
  const policy={tier:'professional',modules,features,maxLimits:limits,maxGraceDays:0,unlimitedQuotas:[],requireSnapshot:true};
  const signed=p=>Buffer.from(JSON.stringify({payload:p,signature:sign(null,Buffer.from(JSON.stringify(p)),pair.privateKey).toString('base64url'),algorithm:'Ed25519'}));
  const raw=signed({schemaVersion:'1.0',licenseId:'TEST-L',customer:{code:'TEST-A',name:'Test'},
    product:{code:'CEPHAS_CRM',name:'CEPHAS CRM'},tier:{code:'professional',name:'Professional'},
    deployment:{id:'TEST-D',model:'on_premises',environment:'test'},issuedAt:iso(now-1000),
    expiresAt:iso(now+120000),gracePeriodDays:0,
    limits:{...limits,apiCalls:profile==='zero'?0:2},
    modules:profile==='no_notes'?['contact_management']:modules,
    features:profile==='no_api'?[]:features,keyVersion:'v1'});
  const snap=(generation,entries)=>signed({schemaVersion:'1.0',snapshotId:'TEST-S',...binding,
    generatedAt:iso(generation),expiresAt:iso(now+120000),keyVersion:'v1',revokedKeyVersions:[],entries});
  EntitlementStore.initialize(path,{binding,keys:new Map(keys),policy},()=>now,raw,snap(now-1000,[]));
  writeFileSync(join(dir,'config.json'),JSON.stringify({binding,keys,policy}),{flag:'wx',mode:0o600});
  writeFileSync(join(dir,'revoked.json'),snap(now,[{licenseId:'TEST-L',status:'revoked',changedAt:iso(now)}]),{flag:'wx',mode:0o600});
}else throw new Error('mode');
