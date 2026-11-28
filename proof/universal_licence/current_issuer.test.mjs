import test from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync,sign,createHash} from 'node:crypto';
import {verifyCurrentLicence,verifyCurrentSnapshot} from './current_issuer.mjs';
import {Invalid} from './validator.mjs';
const now=1800000000000, DAY=86400000, iso=n=>new Date(n).toISOString();
const pair=generateKeyPairSync('ed25519'),der=pair.publicKey.export({type:'spki',format:'der'});
const keys=new Map([['v1',{status:'active',material:der.toString('base64'),fingerprint:'sha256:'+createHash('sha256').update(der).digest('hex')}]]);
const context={productCode:'CEPHAS_CRM',customerCode:'C',deploymentId:'D',environment:'staging',deploymentModel:'on_premises',now,previousTime:now};
const limits={users:10,transactions:100,apiCalls:0,sites:1,businessUnits:1};
const policy={tier:'pov',modules:['contact_management'],features:[],maxLimits:limits,maxGraceDays:0,unlimitedQuotas:[],requireSnapshot:true};
const signed=p=>Buffer.from(JSON.stringify({payload:p,signature:sign(null,Buffer.from(JSON.stringify(p)),pair.privateKey).toString('base64url'),algorithm:'Ed25519'}));
function payload(){return {schemaVersion:'1.0',licenseId:'L',customer:{code:'C',name:'Customer'},product:{code:'CEPHAS_CRM',name:'CEPHAS CRM'},tier:{code:'pov',name:'POV'},deployment:{id:'D',model:'on_premises',environment:'staging'},issuedAt:iso(now-1000),expiresAt:iso(now-1000+90*DAY),gracePeriodDays:0,limits:{...limits},modules:['contact_management'],features:[],keyVersion:'v1'};}
function snapshot(c=context,ttl=5){return signed({schemaVersion:'1.0',snapshotId:'S',customerCode:c.customerCode,productCode:c.productCode,deploymentId:c.deploymentId,environment:c.environment,generatedAt:iso(now),expiresAt:iso(now+ttl*60000),keyVersion:'v1',revokedKeyVersions:[],entries:[]});}
function verify(p=payload(),c=context,pol=policy,s=snapshot(c)){return verifyCurrentLicence(signed(p),keys,c,pol,s);}
test('current finite staging POV validates with exact scope and zero API quota',()=>assert.equal(verify().limits.apiCalls,0));
test('deployment model mismatch and unsupported environment denied',()=>{
  assert.throws(()=>verify(payload(),{...context,deploymentModel:'private_cloud'}),Invalid);
  const p=payload();p.deployment.environment='test';
  assert.throws(()=>verify(p,{...context,environment:'test'}),Invalid);
});
test('POV production, duration and grace denied',()=>{
  const p=payload();p.deployment.environment='production';
  assert.throws(()=>verify(p,{...context,environment:'production'}),Invalid);
  assert.throws(()=>verify({...payload(),expiresAt:iso(now+90*DAY)}),Invalid);
  assert.throws(()=>verify({...payload(),gracePeriodDays:1},context,{...policy,maxGraceDays:1}),Invalid);
});
test('POV quota ceilings and explicit finite policy enforced',()=>{
  const cap={...limits,users:51};
  assert.throws(()=>verify({...payload(),limits:cap},context,{...policy,maxLimits:cap}),Invalid);
  assert.throws(()=>verify(payload(),context,{...policy,maxLimits:{...limits,sites:null},unlimitedQuotas:['sites']}),Invalid);
});
test('Enterprise Unlimited still requires finite caps and values',()=>{
  const p={...payload(),tier:{code:'enterprise_unlimited',name:'Enterprise Unlimited'}};
  const pol={...policy,tier:'enterprise_unlimited'};
  assert.equal(verify(p,context,pol).tier,'enterprise_unlimited');
  assert.throws(()=>verify({...p,limits:{...limits,users:null}},context,{...pol,maxLimits:{...limits,users:null},unlimitedQuotas:['users']}),Invalid);
});
test('production term, grace and int32 site bounds checked',()=>{
  const p={...payload(),tier:{code:'enterprise',name:'Enterprise'}};
  const pol={...policy,tier:'enterprise'};
  assert.throws(()=>verify({...p,expiresAt:iso(now+366*DAY)},context,pol),Invalid);
  assert.throws(()=>verify({...p,gracePeriodDays:91},context,{...pol,maxGraceDays:91}),Invalid);
  const cap={...limits,sites:2147483648};
  assert.throws(()=>verify({...p,limits:cap},context,{...pol,maxLimits:cap}),Invalid);
});
test('snapshot required and TTL range bounded to issuer contract',()=>{
  assert.throws(()=>verify(payload(),context,policy,null),Invalid);
  for(const ttl of [4,1441,5.5])assert.throws(()=>verifyCurrentSnapshot(snapshot(context,ttl),keys,context),Invalid);
  assert.equal(verifyCurrentSnapshot(snapshot(context,1440),keys,context).entries.length,0);
});
test('empty modules and wrong signed customer remain denied',()=>{
  assert.throws(()=>verify({...payload(),modules:[]}),Invalid);
  assert.throws(()=>verify({...payload(),customer:{code:'OTHER',name:'Other'}}),Invalid);
});
