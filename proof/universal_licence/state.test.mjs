import test from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync,sign,createHash} from 'node:crypto';
import {mkdtempSync,rmSync,unlinkSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {DatabaseSync} from 'node:sqlite';
import {Worker} from 'node:worker_threads';
import {EntitlementStore} from './state.mjs';
import {Invalid} from './validator.mjs';
const NOW=1800000000000, iso=n=>new Date(n).toISOString();
const pair=generateKeyPairSync('ed25519');
const der=pair.publicKey.export({type:'spki',format:'der'});
const keys=new Map([['v1',{status:'active',material:der.toString('base64'),fingerprint:'sha256:'+createHash('sha256').update(der).digest('hex')}]]);
const binding={productCode:'CEPHAS_CRM',customerCode:'TEST',deploymentId:'TEST-D',environment:'test'};
const limits={users:1,transactions:1,apiCalls:1,sites:1,businessUnits:1};
const modules=['contact_management','account_management'],features=['api_access','multi_site'];
function signed(p){return Buffer.from(JSON.stringify({payload:p,signature:sign(null,Buffer.from(JSON.stringify(p)),pair.privateKey).toString('base64url'),algorithm:'Ed25519'}));}
function payload(){return {schemaVersion:'1.0',licenseId:'TEST-L',customer:{code:'TEST',name:'Test'},product:{code:'CEPHAS_CRM',name:'CEPHAS CRM'},tier:{code:'professional',name:'Professional'},deployment:{id:'TEST-D',model:'on_premises',environment:'test'},issuedAt:iso(NOW-1000),expiresAt:iso(NOW+10000),gracePeriodDays:0,limits:{...limits},modules:[...modules],features:[...features],keyVersion:'v1'};}
function snap(overrides={}){return signed({schemaVersion:'1.0',snapshotId:'TEST-S',...binding,generatedAt:iso(NOW-500),expiresAt:iso(NOW+10000),keyVersion:'v1',revokedKeyVersions:[],entries:[],...overrides});}
function fixture(t,options={}){
  const directory=mkdtempSync(join(tmpdir(),'cephas-state-'));t.after(()=>rmSync(directory,{recursive:true,force:true}));
  const path=join(directory,'state.sqlite'),config={binding,keys,policy:{tier:'professional',modules,features,maxLimits:limits,maxGraceDays:0,unlimitedQuotas:[],requireSnapshot:false,...options.policy}};
  let now=NOW;const clock=()=>now;const raw=signed(options.payload??payload());
  const store=EntitlementStore.initialize(path,config,clock,raw,options.snapshot??null);
  return {store,path,config,clock,raw,setNow:n=>{now=n;},reopen:()=>new EntitlementStore(path,config,clock)};
}
test('all five quotas persisted with synthetic atomic effects',t=>{
  const x=fixture(t);
  for(const [i,action] of ['create_contact','read_api','activate_user','add_site','add_unit'].entries()){
    assert.equal(x.store.execute(action,'r'+i,'a'+i),'applied');
    assert.throws(()=>x.reopen().execute(action,'more'+i,'b'+i),Invalid);
  }
});
test('idempotent retry, conflicting request and duplicate target denied',t=>{
  const x=fixture(t);assert.equal(x.store.execute('create_contact','r','a'),'applied');
  assert.equal(x.reopen().execute('create_contact','r','a'),'duplicate');
  assert.throws(()=>x.reopen().execute('create_contact','r','b'),Invalid);
  assert.throws(()=>x.reopen().execute('create_contact','another','a'),Invalid);
});
test('snapshot revocation persists independently of exhausted quota',t=>{
  const x=fixture(t);x.store.execute('create_contact','r','a');
  assert.throws(()=>x.store.execute('create_contact','more','b'),Invalid);
  x.store.importSnapshot(snap({entries:[{licenseId:'TEST-L',status:'revoked',changedAt:iso(NOW-600)}]}));
  assert.throws(()=>x.reopen().execute('read_api','r2','b'),Invalid);
  assert.throws(()=>x.reopen().execute('create_contact','r','a'),Invalid);
});
test('snapshot stale, rollback and revocation removal rejected after reopen',t=>{
  const x=fixture(t,{snapshot:snap({entries:[{licenseId:'OLD-L',status:'revoked',changedAt:iso(NOW-600)}]})});
  assert.throws(()=>x.reopen().importSnapshot(snap({generatedAt:iso(NOW-700)})),Invalid);
  assert.throws(()=>x.reopen().importSnapshot(snap({generatedAt:iso(NOW-100)})),Invalid);
  x.setNow(NOW+10001);assert.throws(()=>x.reopen().execute('create_contact','r','a'),Invalid);
});
test('clock high water advances even on denied capability',t=>{
  const x=fixture(t);x.setNow(NOW+100);
  assert.throws(()=>x.store.execute('unknown','r','a'),Invalid);
  x.setNow(NOW);assert.throws(()=>x.reopen().execute('create_contact','r','a'),Invalid);
});
test('missing state, corrupted licence and wrong config fail closed',t=>{
  const x=fixture(t);const different=new EntitlementStore(x.path,{...x.config,binding:{...binding,customerCode:'OTHER'}},x.clock);
  assert.throws(()=>different.execute('create_contact','r','a'),Invalid);
  const db=new DatabaseSync(x.path);db.exec("UPDATE authority SET licence=x'00'");db.close();
  assert.throws(()=>x.reopen().execute('create_contact','r','a'),Invalid);
  unlinkSync(x.path);assert.throws(()=>x.reopen().execute('create_contact','r','a'),Invalid);
});
test('missing capability and zero user quota denied',t=>{
  const p=payload();p.features=[];p.limits.users=0;
  const x=fixture(t,{payload:p});
  assert.throws(()=>x.store.execute('read_api','r','a'),Invalid);
  assert.throws(()=>x.store.execute('activate_user','r','a'),Invalid);
  assert.equal(x.store.execute('create_contact','r','a'),'applied');
});
test('snapshot expires without silently falling back to no snapshot',t=>{
  const x=fixture(t,{snapshot:snap({expiresAt:iso(NOW+100)})});
  x.setNow(NOW+101);assert.throws(()=>x.reopen().execute('create_contact','r','a'),Invalid);
  x.reopen().importSnapshot(snap({generatedAt:iso(NOW+100),expiresAt:iso(NOW+500)}));
  assert.equal(x.reopen().execute('create_contact','r','a'),'applied');
});

test('same-id renewal persists and does not reset quota or idempotency',t=>{
  const x=fixture(t);x.store.execute('create_contact','r','a');
  const next=signed({...payload(),expiresAt:iso(NOW+20000)});
  assert.equal(x.store.renew(next),'renewed');
  assert.equal(x.reopen().renew(next),'duplicate');
  assert.equal(x.reopen().execute('create_contact','r','a'),'duplicate');
  assert.throws(()=>x.reopen().execute('create_contact','r2','b'),Invalid);
  assert.throws(()=>x.reopen().renew(x.raw),Invalid);
});
test('renewal after expiry retains consumed quota and permits entitled unused quota',t=>{
  const x=fixture(t);x.store.execute('create_contact','r','a');x.setNow(NOW+10001);
  const next=signed({...payload(),licenseId:'TEST-L2',issuedAt:iso(NOW+10000),expiresAt:iso(NOW+30000)});
  assert.equal(x.reopen().renew(next),'renewed');
  assert.throws(()=>x.reopen().execute('create_contact','new','b'),Invalid);
  assert.equal(x.reopen().execute('read_api','new','b'),'applied');
});
test('renewal rejects foreign binding, shortened term and invalid signature',t=>{
  const x=fixture(t);const p=payload();
  for(const raw of [signed({...p,customer:{code:'OTHER',name:'Other'},expiresAt:iso(NOW+20000)}),
    signed({...p,expiresAt:iso(NOW+9000)}),Buffer.from('invalid')])
    assert.throws(()=>x.reopen().renew(raw),Invalid);
  assert.equal(x.reopen().execute('create_contact','r','a'),'applied');
});
test('revoked predecessor and expired snapshot deny renewal',t=>{
  const x=fixture(t);const next=signed({...payload(),licenseId:'TEST-L2',expiresAt:iso(NOW+20000)});
  x.store.importSnapshot(snap({entries:[{licenseId:'TEST-L',status:'revoked',changedAt:iso(NOW-600)}]}));
  assert.throws(()=>x.reopen().renew(next),Invalid);
  const y=fixture(t,{snapshot:snap({expiresAt:iso(NOW+100)})});y.setNow(NOW+101);
  assert.throws(()=>y.reopen().renew(next),Invalid);
});
function compete(x,action,ids){
  const barrier=new SharedArrayBuffer(4);
  return Promise.all(ids.map(id=>new Promise((resolve,reject)=>{
    const worker=new Worker(new URL('./state-worker.mjs',import.meta.url),{workerData:{path:x.path,config:x.config,now:x.clock(),action,id,barrier}});
    worker.once('message',resolve);worker.once('error',reject);
    worker.once('exit',code=>{if(code!==0)reject(new Error('worker failed'));});
  })));
}
test('concurrent independent SQLite connections cannot overspend quota',async t=>{
  const x=fixture(t);
  const results=await compete(x,'create_contact',['a','b']);
  assert.deepEqual(results.sort(),['applied','denied']);
  const db=new DatabaseSync(x.path);try{assert.equal(db.prepare("SELECT count(*) AS n FROM effects WHERE quota='transactions'").get().n,1);}finally{db.close();}
});
test('concurrent duplicate requests have exactly one effect',async t=>{
  const x=fixture(t);
  assert.deepEqual((await compete(x,'activate_user',['same','same'])).sort(),['applied','duplicate']);
});
