// Experimental issuer-compatible verifier; trusted configuration is not request input.
import { createHash, createPublicKey, verify } from 'node:crypto';
const PRODUCT = 'CEPHAS_CRM';
const TIERS = new Set(['pov','professional','enterprise','enterprise_unlimited']);
const MODULES = new Set(('contact_management account_management lead_management opportunity_pipeline sales_automation marketing_automation customer_service workflow_automation ai_customer_intelligence predictive_analytics sales_forecasting reporting_dashboard integration_gateway').split(' '));
const FEATURES = new Set(['api_access','advanced_analytics','advanced_reporting','external_integrations','multi_site']);
const QUOTAS = ['users','transactions','apiCalls','sites','businessUnits'];
const FIELDS = 'schemaVersion licenseId customer product tier deployment issuedAt expiresAt gracePeriodDays limits modules features keyVersion'.split(' ');
const SNAP_FIELDS = 'schemaVersion snapshotId customerCode productCode deploymentId environment generatedAt expiresAt keyVersion revokedKeyVersions entries'.split(' ');
export class Invalid extends Error {}
function require(ok) { if (!ok) throw new Invalid('invalid offline licence evidence'); }
function record(x, keys) {
  require(x !== null && typeof x === 'object' && !Array.isArray(x));
  require(Object.keys(x).length === keys.length && keys.every(k=>Object.hasOwn(x,k)));
}
function str(s) { require(typeof s==='string' && s.length>0 && s.length<=512 && s.trim()===s && !/[\u0000-\u001f\u007f]/u.test(s)); return s; }
function integer(n,lo=0) { require(Number.isSafeInteger(n) && n>=lo); return n; }
function time(s) {
  require(typeof s==='string' && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(s));
  const n=Date.parse(s); require(Number.isSafeInteger(n) && new Date(n).toISOString()===s); return n;
}
function members(a, catalogue) {
  require(Array.isArray(a) && a.length<=256 && new Set(a).size===a.length);
  for(const v of a) {str(v); if(catalogue)require(catalogue.has(v));}
}
function sha(raw) {return createHash('sha256').update(raw).digest('hex');}
function keyFor(keys, version, now) {
  str(version); require(keys instanceof Map && keys.has(version));
  const k=keys.get(version);
  require(k && (k.status==='active'||k.status==='retired') && typeof k.material==='string');
  if(k.status==='retired')require(integer(k.verifyUntil)>=now);
  const material=k.material;
  const key=material.startsWith('-----BEGIN PUBLIC KEY-----')
    ? createPublicKey(material)
    : createPublicKey({key:Buffer.from(material,'base64'),format:'der',type:'spki'});
  require(key.asymmetricKeyType==='ed25519');
  require(k.fingerprint==='sha256:'+sha(key.export({format:'der',type:'spki'})));
  return key;
}
function signed(raw,keys,now,fields) {
  require(Buffer.isBuffer(raw) && raw.length>0 && raw.length<=65536);
  // Restrict to the exact compact export format of the current issuer.
  // Round trip equality rejects duplicate keys, BOM, malformed UTF-8, whitespace
  // and alternate encodings. Do not sort keys or reserialize using Python.
  const s=new TextDecoder('utf-8',{fatal:true,ignoreBOM:true}).decode(raw);
  const a=JSON.parse(s);
  require(Buffer.from(JSON.stringify(a),'utf8').equals(raw));
  record(a,['payload','signature','algorithm']);
  require(a.algorithm==='Ed25519');
  record(a.payload,fields);
  require(a.payload.schemaVersion==='1.0');
  require(typeof a.signature==='string' && /^[A-Za-z0-9_-]{86}$/.test(a.signature));
  const sig=Buffer.from(a.signature,'base64url');
  require(sig.length===64 && sig.toString('base64url')===a.signature);
  const key=keyFor(keys,a.payload.keyVersion,now);
  require(verify(null,Buffer.from(JSON.stringify(a.payload),'utf8'),key,sig));
  return a.payload;
}
function context(c) {
  require(c && c.productCode===PRODUCT);
  for(const k of ['customerCode','deploymentId','environment'])str(c[k]);
  integer(c.now); integer(c.previousTime);
  require(c.now>=c.previousTime);
}
function wrap(fn) {try{return fn();}catch{throw new Invalid('invalid offline licence evidence');}}
export function verifySnapshot(raw,keys,c,previous) {return wrap(()=>{
  context(c);
  const p=signed(raw,keys,c.now,SNAP_FIELDS);
  str(p.snapshotId);
  for(const k of ['customerCode','productCode','deploymentId','environment'])require(p[k]===c[k]);
  const generated=time(p.generatedAt), expires=time(p.expiresAt);
  // Conservative deployment profile: no future timestamp tolerance.
  require(generated<=c.now && c.now<=expires && expires>generated);
  members(p.revokedKeyVersions);
  require(!p.revokedKeyVersions.includes(p.keyVersion));
  require(Array.isArray(p.entries) && p.entries.length<=1024);
  const seen=new Set();
  for(const e of p.entries) {
    record(e,['licenseId','status','changedAt']); str(e.licenseId);
    require(!seen.has(e.licenseId) && ['revoked','suspended'].includes(e.status));
    require(time(e.changedAt)<=generated); seen.add(e.licenseId);
  }
  const digest=sha(raw);
  // Caller must load previous from independently protected state and persist
  // accepted snapshot separately from feature authorization.
  if(previous!==null) {
    require(previous && /^[0-9a-f]{64}$/.test(previous.digest));
    require(generated>=integer(previous.generated));
    if(generated===previous.generated)require(digest===previous.digest);
    // Permanently revoked key/license cannot be silently removed by refresh.
    require(Array.isArray(previous.revokedKeys) && Array.isArray(previous.revokedLicences));
    require(previous.revokedKeys.every(k=>p.revokedKeyVersions.includes(k)));
    require(previous.revokedLicences.every(id=>p.entries.some(e=>e.licenseId===id&&e.status==='revoked')));
  }
  return {generated,digest,revokedKeys:[...p.revokedKeyVersions],
    revokedLicences:p.entries.filter(e=>e.status==='revoked').map(e=>e.licenseId),
    entries:p.entries.map(e=>({...e}))};
});}
export function verifyLicence(raw,keys,c,policy,snapshot=null,previousSnapshot=null) {return wrap(()=>{
  context(c);
  require(policy && Array.isArray(policy.modules) && Array.isArray(policy.features)
    && Array.isArray(policy.unlimitedQuotas) && typeof policy.requireSnapshot==='boolean');
  const p=signed(raw,keys,c.now,FIELDS);
  str(p.licenseId);
  for(const k of ['customer','product','tier']){record(p[k],['code','name']);str(p[k].code);str(p[k].name);}
  record(p.deployment,['id','model','environment']);str(p.deployment.model);
  require(p.customer.code===c.customerCode && p.product.code===PRODUCT &&
    p.deployment.id===c.deploymentId && p.deployment.environment===c.environment);
  require(TIERS.has(p.tier.code)&&p.tier.code===policy.tier);
  const issued=time(p.issuedAt),expiry=time(p.expiresAt),grace=integer(p.gracePeriodDays);
  require(issued<=c.now && issued<expiry && grace<=365 && grace<=integer(policy.maxGraceDays));
  require(p.tier.code!=='pov'||grace===0);
  // Match issuer's inclusive expiry/grace endpoint; stricter zero grace via policy.
  require(c.now<=expiry+grace*86400000);
  members(p.modules,MODULES);members(p.features,FEATURES);
  members(policy.modules,MODULES);members(policy.features,FEATURES);
  require(p.modules.every(m=>policy.modules.includes(m))&&p.features.every(m=>policy.features.includes(m)));
  record(p.limits,QUOTAS);
  members(policy.unlimitedQuotas,new Set(QUOTAS));
  record(policy.maxLimits,QUOTAS);
  for(const q of QUOTAS){
    const value=p.limits[q], max=policy.maxLimits[q];
    if(max!==null)integer(max);
    if(value===null)require(max===null&&policy.unlimitedQuotas.includes(q));
    else {integer(value);require(max===null||value<=max);}
  }
  let revocation=null;
  if(snapshot!==null){
    revocation=verifySnapshot(snapshot,keys,c,previousSnapshot);
    require(!revocation.revokedKeys.includes(p.keyVersion));
    require(!revocation.entries.some(e=>e.licenseId===p.licenseId));
  }else require(!policy.requireSnapshot&&previousSnapshot===null);
  return {licenseId:p.licenseId,tier:p.tier.code,keyVersion:p.keyVersion,
    graceActive:c.now>expiry,modules:[...p.modules],features:[...p.features],
    limits:{...p.limits},revocation};
});}
export function allowsQuota(licence,name,current,requested=1){return wrap(()=>{
  require(QUOTAS.includes(name)&&licence&&Object.hasOwn(licence.limits,name));
  integer(current);integer(requested,1);
  const limit=licence.limits[name]; if(limit===null)return true;
  return integer(limit)-current>=requested;
});}
export function allowsCapability(licence,kind,code){
  return Boolean(licence&&((kind==='module'&&licence.modules.includes(code))||
    (kind==='feature'&&licence.features.includes(code))));
}
