// Narrow candidate profile matching current issuer issuance/export constraints.
import { Invalid, verifyLicence, verifySnapshot } from './validator.mjs';
const DAY=86400000;
const QUOTAS=['users','transactions','apiCalls','sites','businessUnits'];
const ENVS=['development','staging','production','disaster_recovery'];
const POV={users:50,transactions:250000,apiCalls:250000,sites:1,businessUnits:1};
function need(ok){if(!ok)throw new Invalid('current issuer profile denied');}
function finite(v){return Number.isSafeInteger(v)&&v>=0;}
function wrap(fn){try{return fn();}catch{throw new Invalid('current issuer profile denied');}}
export function verifyCurrentSnapshot(raw,keys,c,prior=null){return wrap(()=>{
  const result=verifySnapshot(raw,keys,c,prior);
  const p=JSON.parse(raw.toString('utf8')).payload;
  const ttl=(Date.parse(p.expiresAt)-Date.parse(p.generatedAt))/60000;
  need(Number.isInteger(ttl)&&ttl>=5&&ttl<=1440);
  return result;
});}
export function verifyCurrentLicence(raw,keys,c,policy,snapshot,prior=null){return wrap(()=>{
  need(ENVS.includes(c.environment)&&typeof c.deploymentModel==='string'&&c.deploymentModel.length>0);
  need(policy.requireSnapshot===true&&Buffer.isBuffer(snapshot));
  need(Array.isArray(policy.unlimitedQuotas)&&policy.unlimitedQuotas.length===0);
  need(finite(policy.maxGraceDays)&&policy.maxGraceDays<=90);
  need(QUOTAS.every(q=>finite(policy.maxLimits[q])));
  const result=verifyLicence(raw,keys,c,policy,snapshot,prior);
  const p=JSON.parse(raw.toString('utf8')).payload;
  need(p.deployment.model===c.deploymentModel);
  need(result.modules.length>0&&result.modules.length<=100&&result.features.length<=200);
  need(QUOTAS.every(q=>finite(result.limits[q])));
  need(result.limits.sites<=2147483647&&result.limits.businessUnits<=2147483647);
  const duration=result.expiresAt-result.issuedAt;
  need(duration>0&&duration<=366*DAY);
  if(result.tier==='pov'){
    need(['development','staging'].includes(c.environment)&&duration<=90*DAY&&p.gracePeriodDays===0);
    need(QUOTAS.every(q=>result.limits[q]<=POV[q]&&policy.maxLimits[q]<=POV[q]));
  }
  verifyCurrentSnapshot(snapshot,keys,c,prior);
  return result;
});}
