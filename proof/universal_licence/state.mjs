// Disposable common-contract entitlement state; trusted host and config assumed.
import { DatabaseSync } from 'node:sqlite';
import { closeSync, openSync, lstatSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { Invalid, verifyLicence, verifySnapshot, allowsQuota, allowsCapability } from './validator.mjs';

const OPERATIONS = Object.freeze({
  create_contact: ['module','contact_management','transactions'],
  read_api: ['feature','api_access','apiCalls'],
  activate_user: ['module','contact_management','users'],
  add_site: ['feature','multi_site','sites'],
  add_unit: ['module','account_management','businessUnits'],
  read_items: ['module','contact_management','apiCalls','api_access'],
  read_notes: ['module','customer_service','apiCalls','api_access'],
});
function demand(ok){if(!ok)throw new Invalid('offline entitlement denied');}
function hash(s){return createHash('sha256').update(s).digest('hex');}
function identifier(s){demand(typeof s==='string'&&/^[A-Za-z0-9_-]{1,64}$/.test(s));return s;}
function normalized(config){
  const c=structuredClone(config);
  demand(c&&c.binding&&c.binding.productCode==='CEPHAS_CRM'&&c.binding.environment==='test');
  for(const k of ['customerCode','deploymentId','environment'])identifier(c.binding[k]);
  demand(c.keys instanceof Map&&c.keys.size>0&&c.policy);
  return c;
}
function configHash(c){return hash(JSON.stringify({binding:c.binding,keys:[...c.keys],policy:c.policy}));}
function connect(path){
  demand(lstatSync(path).isFile());
  const db=new DatabaseSync(path);
  try{db.exec('PRAGMA busy_timeout=3000; PRAGMA synchronous=FULL;');return db;}
  catch(e){db.close();throw e;}
}
function transaction(path,fn){
  let db;
  try{
    db=connect(path);db.exec('BEGIN IMMEDIATE');
    const result=fn(db);db.exec('COMMIT');return result;
  }catch(e){
    if(db)try{db.exec('ROLLBACK');}catch{}
    throw new Invalid('offline entitlement denied');
  }finally{if(db)db.close();}
}
export class EntitlementStore {
  #path; #config; #clock;
  constructor(path,config,clock){
    this.#path=path;this.#config=normalized(config);
    demand(typeof clock==='function');this.#clock=clock;
  }
  static initialize(path,config,clock,raw,snapshot=null){
    const store=new EntitlementStore(path,config,clock);
    const c=store.#context(0);
    const licence=verifyLicence(raw,store.#config.keys,c,store.#config.policy,snapshot);
    const accepted=snapshot===null?null:verifySnapshot(snapshot,store.#config.keys,c,null);
    // Explicit operator bootstrap only. Never auto-create a missing store.
    closeSync(openSync(path,'wx',0o600));
    transaction(path,db=>{
      db.exec("CREATE TABLE authority(id INTEGER PRIMARY KEY CHECK(id=1), config TEXT NOT NULL, licence BLOB NOT NULL, licence_digest TEXT NOT NULL, licence_id TEXT NOT NULL, issued INTEGER NOT NULL, expiry INTEGER NOT NULL, observed INTEGER NOT NULL, snapshot BLOB, snapshot_digest TEXT, imported INTEGER) STRICT;"
        +"CREATE TABLE effects(request_id TEXT PRIMARY KEY, action TEXT NOT NULL, target TEXT NOT NULL, quota TEXT NOT NULL, UNIQUE(action,target)) STRICT;"
        +"CREATE TABLE licence_history(digest TEXT PRIMARY KEY, licence_id TEXT NOT NULL, issued INTEGER NOT NULL, expiry INTEGER NOT NULL) STRICT;");
      db.prepare('INSERT INTO authority VALUES(1,?,?,?,?,?,?,?,?,?,?)').run(configHash(store.#config),raw,hash(raw),licence.licenseId,licence.issuedAt,licence.expiresAt,c.now,snapshot,accepted?.digest??null,accepted===null?null:c.now);
      db.prepare('INSERT INTO licence_history VALUES(?,?,?,?)').run(hash(raw),licence.licenseId,licence.issuedAt,licence.expiresAt);
    });
    return store;
  }
  #context(previous){
    const now=this.#clock();demand(Number.isSafeInteger(now)&&now>=previous&&Number.isSafeInteger(previous)&&previous>=0);
    return {...this.#config.binding,now,previousTime:previous};
  }
  #load(db){
    const row=db.prepare('SELECT * FROM authority WHERE id=1').get();
    demand(row&&row.config===configHash(this.#config)&&hash(row.licence)===row.licence_digest);
    demand(Number.isSafeInteger(row.observed)&&row.observed>=0);
    const history=db.prepare('SELECT licence_id,issued,expiry FROM licence_history WHERE digest=?').get(row.licence_digest);
    demand(history&&history.licence_id===row.licence_id&&history.issued===row.issued&&history.expiry===row.expiry);
    demand(Number.isSafeInteger(row.issued)&&Number.isSafeInteger(row.expiry)&&row.issued<row.expiry);
    let prior=null,raw=null;
    if(row.snapshot!==null){
      demand(Number.isSafeInteger(row.imported)&&row.imported<=row.observed&&row.imported>=0);
      raw=Buffer.from(row.snapshot);
      prior=verifySnapshot(raw,this.#config.keys,{...this.#config.binding,now:row.imported,previousTime:0},null);
      demand(prior.digest===row.snapshot_digest);
    }else demand(row.snapshot_digest===null&&row.imported===null);
    return {row,prior,raw};
  }
  importSnapshot(snapshot){
    // No licence authorization here: even a revoked/exhausted licence must
    // allow a valid newer revocation snapshot to become durable.
    return transaction(this.#path,db=>{
      const {row,prior}=this.#load(db),c=this.#context(row.observed);
      const next=verifySnapshot(snapshot,this.#config.keys,c,prior);
      db.prepare('UPDATE authority SET snapshot=?,snapshot_digest=?,imported=?,observed=? WHERE id=1')
        .run(snapshot,next.digest,c.now,c.now);
      return next.digest;
    });
  }
  // Trusted operator-only path; no API exposure. Same approved installation and
  // policy. Conservative carry-forward of every quota and idempotency record.
  renew(raw){
    return transaction(this.#path,db=>{
      const {row,prior,raw:snapshot}=this.#load(db),c=this.#context(row.observed);
      const next=verifyLicence(raw,this.#config.keys,c,this.#config.policy,snapshot,prior);
      const digest=hash(raw);
      if(digest===row.licence_digest)return 'duplicate';
      demand(!db.prepare('SELECT digest FROM licence_history WHERE digest=?').get(digest));
      // No automatic replacement of a revoked or suspended licence; recovery
      // requires independently approved rebind. Old expiry need not be valid now.
      demand(!prior?.entries.some(e=>e.licenseId===row.licence_id));
      demand(next.issuedAt>=row.issued&&next.expiresAt>row.expiry);
      // Equal issuedAt supports issuer's same-ID expiry extension; any shorter
      // expiry or historical digest is rejected, even when signed.
      db.prepare('INSERT INTO licence_history VALUES(?,?,?,?)').run(digest,next.licenseId,next.issuedAt,next.expiresAt);
      db.prepare('UPDATE authority SET licence=?,licence_digest=?,licence_id=?,issued=?,expiry=?,observed=? WHERE id=1')
        .run(raw,digest,next.licenseId,next.issuedAt,next.expiresAt,c.now);
      return 'renewed';
    });
  }
  execute(action,requestId,target){
    const result=transaction(this.#path,db=>{
      const {row,prior,raw}=this.#load(db),c=this.#context(row.observed);
      // Valid trusted time persists even when capability or quota is denied.
      db.prepare('UPDATE authority SET observed=? WHERE id=1').run(c.now);
      let q;
      try{
        demand(typeof action==='string'&&Object.hasOwn(OPERATIONS,action));
        identifier(requestId);identifier(target);
        const [kind,code,quota,feature]=OPERATIONS[action];q=quota;
        const licence=verifyLicence(Buffer.from(row.licence),this.#config.keys,c,this.#config.policy,raw,prior);
        demand(licence.licenseId===row.licence_id&&licence.issuedAt===row.issued&&licence.expiresAt===row.expiry&&allowsCapability(licence,kind,code)&&(!feature||allowsCapability(licence,'feature',feature)));
        const existing=db.prepare('SELECT action,target FROM effects WHERE request_id=?').get(requestId);
        if(existing){demand(existing.action===action&&existing.target===target);return 'duplicate';}
        demand(!db.prepare('SELECT request_id FROM effects WHERE action=? AND target=?').get(action,target));
        const count=db.prepare('SELECT count(*) AS n FROM effects WHERE quota=?').get(quota).n;
        demand(allowsQuota(licence,quota,count,1));
      }catch(e){
        if(e instanceof Invalid)return 'denied';
        throw e;
      }
      // Synthetic effect and its quota usage are a single transactional row.
      // Real CRM tables, active-user lifecycle and distributed effects not here.
      db.prepare('INSERT INTO effects VALUES(?,?,?,?)').run(requestId,action,target,q);
      return 'applied';
    });
    if(result==='denied')throw new Invalid('offline entitlement denied');
    return result;
  }
}
