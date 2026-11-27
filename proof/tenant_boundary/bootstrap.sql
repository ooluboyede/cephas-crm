-- Disposable PostgreSQL cluster only. Executed as bootstrap administrator.
\set ON_ERROR_STOP on
CREATE ROLE proof_auth_owner NOLOGIN NOSUPERUSER NOBYPASSRLS;
CREATE ROLE proof_data_owner NOLOGIN NOSUPERUSER NOBYPASSRLS;
CREATE ROLE proof_runtime LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB NOREPLICATION PASSWORD :'runtime_pw';
CREATE ROLE proof_issuer_a LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB NOREPLICATION PASSWORD :'issuer_a_pw';
CREATE ROLE proof_issuer_b LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB NOREPLICATION PASSWORD :'issuer_b_pw';
CREATE ROLE proof_a1 LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB NOREPLICATION PASSWORD :'proof_a1_pw';
CREATE ROLE proof_a2 LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB NOREPLICATION PASSWORD :'proof_a2_pw';
CREATE ROLE proof_b1 LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB NOREPLICATION PASSWORD :'proof_b1_pw';
CREATE ROLE proof_b2 LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB NOREPLICATION PASSWORD :'proof_b2_pw';
CREATE ROLE proof_alice_a1 LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB NOREPLICATION PASSWORD :'proof_alice_a1_pw';
CREATE ROLE proof_charlie_a1 LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB NOREPLICATION PASSWORD :'proof_charlie_a1_pw';
CREATE ROLE proof_bob_b1 LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB NOREPLICATION PASSWORD :'proof_bob_b1_pw';
REVOKE ALL ON DATABASE postgres FROM PUBLIC;
GRANT CONNECT ON DATABASE postgres TO proof_runtime, proof_issuer_a, proof_issuer_b, proof_a1, proof_a2, proof_b1, proof_b2;
GRANT CONNECT ON DATABASE postgres TO proof_alice_a1,proof_charlie_a1,proof_bob_b1;
REVOKE ALL ON SCHEMA public FROM PUBLIC;
-- Same-login sessions can otherwise observe one another's SQL text.
REVOKE SELECT ON pg_catalog.pg_stat_activity FROM PUBLIC;
-- Narrow verifier/issuer owner needs live backend identity; no runtime membership.
GRANT pg_read_all_stats TO proof_auth_owner;
GRANT SELECT ON pg_catalog.pg_stat_activity TO proof_auth_owner;
DO $block$
DECLARE f record;
BEGIN
  FOR f IN SELECT p.oid::regprocedure AS identity
    FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON p.pronamespace=n.oid
    WHERE n.nspname='pg_catalog' AND p.proname IN ('pg_stat_get_activity','pg_stat_get_backend_activity')
  LOOP
    EXECUTE format('REVOKE EXECUTE ON FUNCTION %s FROM PUBLIC', f.identity);
    EXECUTE format('GRANT EXECUTE ON FUNCTION %s TO proof_auth_owner', f.identity);
  END LOOP;
END
$block$;
CREATE SCHEMA auth AUTHORIZATION proof_auth_owner;
CREATE SCHEMA crm AUTHORIZATION proof_data_owner;
SET ROLE proof_auth_owner;
ALTER DEFAULT PRIVILEGES REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;
CREATE TABLE auth.epoch (singleton boolean PRIMARY KEY CHECK (singleton), value uuid NOT NULL);
INSERT INTO auth.epoch VALUES (true,pg_catalog.gen_random_uuid());
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
-- Legacy shared login retained exclusively for regression comparison.
CREATE TABLE auth.scope_login (
 login name PRIMARY KEY, tenant text NOT NULL, bu text NOT NULL, UNIQUE(tenant,bu)
);
INSERT INTO auth.scope_login VALUES ('proof_a1','A','1'),('proof_a2','A','2'),
 ('proof_b1','B','1'),('proof_b2','B','2');
-- Actor-specific read-only proof path; distinct from legacy target issuer.
CREATE TABLE auth.actor_login (
 login name PRIMARY KEY, principal text NOT NULL, tenant text NOT NULL, bu text NOT NULL,
 UNIQUE(principal,tenant,bu)
);
INSERT INTO auth.actor_login VALUES
 ('proof_alice_a1','alice','A','1'),('proof_charlie_a1','charlie','A','1'),
 ('proof_bob_b1','bob','B','1');
INSERT INTO auth.membership VALUES ('charlie','A','1',1,true);
CREATE TABLE auth.binding (
 epoch uuid NOT NULL, boot timestamptz NOT NULL, pid integer NOT NULL,
 backend_start timestamptz NOT NULL,
 xid xid8 NOT NULL, login name NOT NULL, principal text NOT NULL,
 tenant text NOT NULL, bu text NOT NULL, revision bigint NOT NULL,
 expires timestamptz NOT NULL,
 -- Epoch change invalidates access but never permits rebinding a live transaction.
 PRIMARY KEY(boot,pid,backend_start,xid,login)
);
-- Separate authenticated broker login is the authority. Runtime cannot call this.
-- The trusted broker must bind the supplied tuple to its actual pinned connection.
CREATE FUNCTION auth.issue(target_pid integer, target_xid xid8, requested_tenant text, requested_bu text)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,pg_temp AS $body$
DECLARE actor text; rev bigint; deployment_epoch uuid; target_start timestamptz; target_login name;
BEGIN
 IF target_pid IS NULL OR target_pid<=0 OR target_xid IS NULL THEN
   RAISE EXCEPTION 'invalid binding' USING ERRCODE='42501';
 END IF;
 SELECT i.principal INTO STRICT actor FROM auth.issuer i WHERE i.login=session_user;
 SELECT m.revision INTO rev FROM auth.membership m
 WHERE m.principal=actor AND m.tenant=requested_tenant AND m.bu=requested_bu AND m.active;
 IF NOT FOUND THEN RAISE EXCEPTION 'scope denied' USING ERRCODE='42501'; END IF;
 -- PostgreSQL exposes the low 32-bit live XID in activity; the verifier also
 -- requires exact xid8 in the target session. This is not client authentication.
 SELECT a.backend_start,a.usename INTO target_start,target_login FROM pg_catalog.pg_stat_activity a
 WHERE a.pid=target_pid AND (a.usename='proof_runtime' OR EXISTS (
  SELECT 1 FROM auth.scope_login s WHERE s.login=a.usename AND s.tenant=requested_tenant AND s.bu=requested_bu))
   AND a.datname=pg_catalog.current_database()
   AND a.backend_type='client backend' AND a.state='idle in transaction'
   AND a.backend_xid::text::numeric=pg_catalog.mod(target_xid::text::numeric,4294967296::numeric);
 IF NOT FOUND THEN RAISE EXCEPTION 'target transaction denied' USING ERRCODE='42501'; END IF;
 SELECT e.value INTO STRICT deployment_epoch FROM auth.epoch e WHERE e.singleton;
 INSERT INTO auth.binding(epoch,boot,pid,backend_start,xid,login,principal,tenant,bu,revision,expires)
 VALUES(deployment_epoch,pg_catalog.pg_postmaster_start_time(),target_pid,target_start,target_xid,
        target_login,actor,requested_tenant,requested_bu,rev,pg_catalog.clock_timestamp()+interval '30 seconds');
END
$body$;
-- No externally selected target tuple. The authenticated session is the
-- principal and can bind only its own current transaction.
CREATE FUNCTION auth.bind_self(requested_tenant text, requested_bu text, expected_epoch uuid)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,pg_temp AS $body$
DECLARE actor text; rev bigint; epoch_value uuid; started timestamptz;
BEGIN
 IF pg_catalog.current_setting('transaction_isolation') <> 'read committed' THEN
   RAISE EXCEPTION 'context denied' USING ERRCODE='42501';
 END IF;
 SELECT a.principal,m.revision INTO actor,rev FROM auth.actor_login a
 JOIN auth.membership m ON m.principal=a.principal AND m.tenant=a.tenant AND m.bu=a.bu
 WHERE a.login=session_user AND a.tenant=requested_tenant AND a.bu=requested_bu AND m.active;
 IF NOT FOUND THEN RAISE EXCEPTION 'context denied' USING ERRCODE='42501'; END IF;
 SELECT e.value INTO STRICT epoch_value FROM auth.epoch e WHERE singleton;
 IF epoch_value IS DISTINCT FROM expected_epoch THEN
   RAISE EXCEPTION 'context denied' USING ERRCODE='42501';
 END IF;
 SELECT a.backend_start INTO STRICT started FROM pg_catalog.pg_stat_activity a
 WHERE a.pid=pg_catalog.pg_backend_pid();
 INSERT INTO auth.binding(epoch,boot,pid,backend_start,xid,login,principal,tenant,bu,revision,expires)
 VALUES(epoch_value,pg_catalog.pg_postmaster_start_time(),pg_catalog.pg_backend_pid(),
 started,pg_catalog.pg_current_xact_id(),session_user,actor,requested_tenant,requested_bu,rev,
 pg_catalog.clock_timestamp()+interval '30 seconds');
END
$body$;
CREATE FUNCTION auth.allowed(requested_tenant text, requested_bu text)
RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER
SET search_path=pg_catalog,pg_temp AS $body$
 SELECT (session_user='proof_runtime' OR EXISTS (
  SELECT 1 FROM auth.scope_login s WHERE s.login=session_user AND s.tenant=requested_tenant AND s.bu=requested_bu) OR EXISTS (
  SELECT 1 FROM auth.actor_login a WHERE a.login=session_user AND a.tenant=requested_tenant AND a.bu=requested_bu))
 AND pg_catalog.current_setting('transaction_isolation')='read committed'
 AND EXISTS(
  SELECT 1 FROM auth.binding b
  JOIN auth.epoch e ON e.singleton AND e.value=b.epoch
  JOIN auth.membership m ON m.principal=b.principal AND m.tenant=b.tenant
   AND m.bu=b.bu AND m.active AND m.revision=b.revision
  WHERE b.boot=pg_catalog.pg_postmaster_start_time()
    AND b.pid=pg_catalog.pg_backend_pid()
    AND b.backend_start=(SELECT a.backend_start FROM pg_catalog.pg_stat_activity a WHERE a.pid=pg_catalog.pg_backend_pid())
    AND b.xid=pg_catalog.pg_current_xact_id_if_assigned()
    AND b.login=session_user AND b.tenant=requested_tenant AND b.bu=requested_bu
    AND (NOT EXISTS (SELECT 1 FROM auth.actor_login a WHERE a.login=session_user) OR EXISTS (
      SELECT 1 FROM auth.actor_login a WHERE a.login=session_user AND a.principal=b.principal
      AND a.tenant=b.tenant AND a.bu=b.bu))
    AND b.expires>pg_catalog.statement_timestamp()
 )
$body$;
CREATE FUNCTION auth.current_epoch()
RETURNS uuid LANGUAGE sql STABLE SECURITY DEFINER
SET search_path=pg_catalog,pg_temp AS $body$
 SELECT value FROM auth.epoch WHERE singleton
$body$;
REVOKE ALL ON ALL TABLES IN SCHEMA auth FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA auth FROM PUBLIC;
GRANT USAGE ON SCHEMA auth TO proof_runtime,proof_issuer_a,proof_issuer_b,proof_data_owner,proof_a1, proof_a2, proof_b1, proof_b2;
GRANT EXECUTE ON FUNCTION auth.issue(integer,xid8,text,text) TO proof_issuer_a,proof_issuer_b;
GRANT EXECUTE ON FUNCTION auth.current_epoch() TO proof_issuer_a,proof_issuer_b;
GRANT USAGE ON SCHEMA auth TO proof_alice_a1,proof_charlie_a1,proof_bob_b1;
GRANT EXECUTE ON FUNCTION auth.bind_self(text,text,uuid) TO proof_alice_a1,proof_charlie_a1,proof_bob_b1;
GRANT EXECUTE ON FUNCTION auth.allowed(text,text) TO proof_alice_a1,proof_charlie_a1,proof_bob_b1;
GRANT EXECUTE ON FUNCTION auth.allowed(text,text) TO proof_runtime,proof_data_owner,proof_a1, proof_a2, proof_b1, proof_b2;
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
CREATE POLICY item_scope ON crm.item TO proof_runtime, proof_a1, proof_a2, proof_b1, proof_b2 USING (auth.allowed(tenant,bu)) WITH CHECK (auth.allowed(tenant,bu));
CREATE POLICY note_scope ON crm.note TO proof_runtime, proof_a1, proof_a2, proof_b1, proof_b2 USING (auth.allowed(tenant,bu)) WITH CHECK (auth.allowed(tenant,bu));
GRANT USAGE ON SCHEMA crm TO proof_runtime, proof_a1, proof_a2, proof_b1, proof_b2;
GRANT SELECT,INSERT,DELETE ON crm.item,crm.note TO proof_runtime, proof_a1, proof_a2, proof_b1, proof_b2;
GRANT UPDATE(value) ON crm.item,crm.note TO proof_runtime, proof_a1, proof_a2, proof_b1, proof_b2;
RESET ROLE;

SET ROLE proof_data_owner;
CREATE POLICY actor_item_scope ON crm.item FOR SELECT TO proof_alice_a1,proof_charlie_a1,proof_bob_b1 USING (auth.allowed(tenant,bu));
CREATE POLICY actor_note_scope ON crm.note FOR SELECT TO proof_alice_a1,proof_charlie_a1,proof_bob_b1 USING (auth.allowed(tenant,bu));
GRANT USAGE ON SCHEMA crm TO proof_alice_a1,proof_charlie_a1,proof_bob_b1;
GRANT SELECT ON crm.item,crm.note TO proof_alice_a1,proof_charlie_a1,proof_bob_b1;
RESET ROLE;
