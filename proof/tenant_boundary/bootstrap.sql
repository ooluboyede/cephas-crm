-- Disposable PostgreSQL cluster only. Executed as bootstrap administrator.
\set ON_ERROR_STOP on
CREATE ROLE proof_auth_owner NOLOGIN NOSUPERUSER NOBYPASSRLS;
CREATE ROLE proof_data_owner NOLOGIN NOSUPERUSER NOBYPASSRLS;
CREATE ROLE proof_runtime LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB NOREPLICATION PASSWORD :'runtime_pw';
CREATE ROLE proof_issuer_a LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB NOREPLICATION PASSWORD :'issuer_a_pw';
CREATE ROLE proof_issuer_b LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB NOREPLICATION PASSWORD :'issuer_b_pw';
REVOKE ALL ON DATABASE postgres FROM PUBLIC;
GRANT CONNECT ON DATABASE postgres TO proof_runtime, proof_issuer_a, proof_issuer_b;
REVOKE ALL ON SCHEMA public FROM PUBLIC;
-- Same-login sessions can otherwise observe one another's SQL text.
REVOKE SELECT ON pg_catalog.pg_stat_activity FROM PUBLIC;
DO $block$
DECLARE f record;
BEGIN
  FOR f IN SELECT p.oid::regprocedure AS identity
    FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON p.pronamespace=n.oid
    WHERE n.nspname='pg_catalog' AND p.proname IN ('pg_stat_get_activity','pg_stat_get_backend_activity')
  LOOP
    EXECUTE format('REVOKE EXECUTE ON FUNCTION %s FROM PUBLIC', f.identity);
  END LOOP;
END
$block$;
CREATE SCHEMA auth AUTHORIZATION proof_auth_owner;
CREATE SCHEMA crm AUTHORIZATION proof_data_owner;
SET ROLE proof_auth_owner;
ALTER DEFAULT PRIVILEGES REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;
CREATE TABLE auth.epoch (singleton boolean PRIMARY KEY CHECK (singleton), value uuid NOT NULL);
INSERT INTO auth.epoch VALUES (true,'00000000-0000-4000-8000-000000000001');
CREATE TABLE auth.issuer (login name PRIMARY KEY, principal text NOT NULL);
INSERT INTO auth.issuer VALUES ('proof_issuer_a','alice'),('proof_issuer_b','bob');
CREATE TABLE auth.membership (
 principal text NOT NULL, tenant text NOT NULL, bu text NOT NULL,
 revision bigint NOT NULL CHECK (revision>0), active boolean NOT NULL,
 PRIMARY KEY(principal,tenant,bu)
);
INSERT INTO auth.membership VALUES
 ('alice','A','1',1,true),('alice','A','2',1,true),
 ('bob','B','1',1,true),('bob','B','2',1,true);
CREATE TABLE auth.binding (
 epoch uuid NOT NULL, boot timestamptz NOT NULL, pid integer NOT NULL,
 xid xid8 NOT NULL, login name NOT NULL, principal text NOT NULL,
 tenant text NOT NULL, bu text NOT NULL, revision bigint NOT NULL,
 expires timestamptz NOT NULL,
 PRIMARY KEY(epoch,boot,pid,xid,login)
);
-- Separate authenticated broker login is the authority. Runtime cannot call this.
-- The trusted broker must bind the supplied tuple to its actual pinned connection.
CREATE FUNCTION auth.issue(target_pid integer, target_xid xid8, requested_tenant text, requested_bu text)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,pg_temp AS $body$
DECLARE actor text; rev bigint; deployment_epoch uuid;
BEGIN
 IF target_pid IS NULL OR target_pid<=0 OR target_xid IS NULL THEN
   RAISE EXCEPTION 'invalid binding' USING ERRCODE='42501';
 END IF;
 SELECT i.principal INTO STRICT actor FROM auth.issuer i WHERE i.login=session_user;
 SELECT m.revision INTO rev FROM auth.membership m
 WHERE m.principal=actor AND m.tenant=requested_tenant AND m.bu=requested_bu AND m.active;
 IF NOT FOUND THEN RAISE EXCEPTION 'scope denied' USING ERRCODE='42501'; END IF;
 SELECT e.value INTO STRICT deployment_epoch FROM auth.epoch e WHERE e.singleton;
 INSERT INTO auth.binding(epoch,boot,pid,xid,login,principal,tenant,bu,revision,expires)
 VALUES(deployment_epoch,pg_catalog.pg_postmaster_start_time(),target_pid,target_xid,
        'proof_runtime',actor,requested_tenant,requested_bu,rev,pg_catalog.clock_timestamp()+interval '30 seconds');
END
$body$;
CREATE FUNCTION auth.allowed(requested_tenant text, requested_bu text)
RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER
SET search_path=pg_catalog,pg_temp AS $body$
 SELECT session_user='proof_runtime'
 AND pg_catalog.current_setting('transaction_isolation')='read committed'
 AND EXISTS(
  SELECT 1 FROM auth.binding b
  JOIN auth.epoch e ON e.singleton AND e.value=b.epoch
  JOIN auth.membership m ON m.principal=b.principal AND m.tenant=b.tenant
   AND m.bu=b.bu AND m.active AND m.revision=b.revision
  WHERE b.boot=pg_catalog.pg_postmaster_start_time()
    AND b.pid=pg_catalog.pg_backend_pid()
    AND b.xid=pg_catalog.pg_current_xact_id_if_assigned()
    AND b.login=session_user AND b.tenant=requested_tenant AND b.bu=requested_bu
    AND b.expires>pg_catalog.statement_timestamp()
 )
$body$;
REVOKE ALL ON ALL TABLES IN SCHEMA auth FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA auth FROM PUBLIC;
GRANT USAGE ON SCHEMA auth TO proof_runtime,proof_issuer_a,proof_issuer_b,proof_data_owner;
GRANT EXECUTE ON FUNCTION auth.issue(integer,xid8,text,text) TO proof_issuer_a,proof_issuer_b;
GRANT EXECUTE ON FUNCTION auth.allowed(text,text) TO proof_runtime,proof_data_owner;
RESET ROLE;
SET ROLE proof_data_owner;
CREATE TABLE crm.item(tenant text NOT NULL,bu text NOT NULL,id integer NOT NULL,value text NOT NULL,PRIMARY KEY(tenant,bu,id));
CREATE TABLE crm.note(tenant text NOT NULL,bu text NOT NULL,id integer NOT NULL,item_id integer NOT NULL,value text NOT NULL,
 PRIMARY KEY(tenant,bu,id),FOREIGN KEY(tenant,bu,item_id) REFERENCES crm.item(tenant,bu,id));
INSERT INTO crm.item VALUES ('A','1',1,'A1'),('A','2',1,'A2'),('B','1',1,'B1'),('B','2',1,'B2');
INSERT INTO crm.note VALUES ('A','1',1,1,'note-A1'),('A','2',1,1,'note-A2'),('B','1',1,1,'note-B1'),('B','2',1,1,'note-B2');
ALTER TABLE crm.item ENABLE ROW LEVEL SECURITY;
ALTER TABLE crm.item FORCE ROW LEVEL SECURITY;
ALTER TABLE crm.note ENABLE ROW LEVEL SECURITY;
ALTER TABLE crm.note FORCE ROW LEVEL SECURITY;
CREATE POLICY item_scope ON crm.item TO proof_runtime USING (auth.allowed(tenant,bu)) WITH CHECK (auth.allowed(tenant,bu));
CREATE POLICY note_scope ON crm.note TO proof_runtime USING (auth.allowed(tenant,bu)) WITH CHECK (auth.allowed(tenant,bu));
GRANT USAGE ON SCHEMA crm TO proof_runtime;
GRANT SELECT,INSERT,DELETE ON crm.item,crm.note TO proof_runtime;
GRANT UPDATE(value) ON crm.item,crm.note TO proof_runtime;
RESET ROLE;
