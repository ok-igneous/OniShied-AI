-- Run as database administrator after applying migration 017.
-- Proves authenticated policy writes, step-up enforcement, versioning and grants.
BEGIN;

SET LOCAL ROLE onishield_owner;
INSERT INTO onishield.operators
  (email,password_hash,display_name,status,email_verified_at)
VALUES
  ('autopilot-smoke@example.invalid','not-a-login-hash','Autopilot Smoke','active',NOW())
RETURNING id \gset

INSERT INTO onishield.operator_memberships(tenant_id,operator_id,role,status)
VALUES ('autopilot-smoke-tenant', :'id', 'admin', 'active')
RETURNING id \gset membership_

INSERT INTO onishield.operator_sessions
  (tenant_id,operator_id,membership_id,token_hash,expires_at,step_up_at)
VALUES
  ('autopilot-smoke-tenant', :'id', :'membership_id',
   repeat('a',64), NOW()+INTERVAL '1 hour', NOW());

SET LOCAL ROLE onishield_auth;
SELECT * FROM onishield.save_autopilot_policy(
  repeat('a',64), 0, TRUE, 'observe', 0::SMALLINT,
  ARRAY['evidence.collect'], ARRAY['lab-host-1'],
  10, 1, NULL, FALSE, 'initial isolated lab policy'
);
SELECT * FROM onishield.get_autopilot_policy(repeat('a',64));
SELECT onishield.record_autopilot_simulation(
  repeat('a',64),1,'evidence.collect','lab-host-1','allow',
  'observe_only_no_dispatch',0::SMALLINT,'never_dispatch'
);

SET LOCAL ROLE onishield_owner;
DO $$
DECLARE audit_count INTEGER; decision_count INTEGER;
BEGIN
  SELECT count(*) INTO audit_count FROM onishield.autopilot_policy_audit;
  SELECT count(*) INTO decision_count FROM onishield.autopilot_policy_decisions;
  IF audit_count <> 1 THEN RAISE EXCEPTION 'Policy audit was not recorded'; END IF;
  IF decision_count <> 1 THEN RAISE EXCEPTION 'Simulation decision audit was not recorded'; END IF;
END $$;

SET LOCAL ROLE onishield_auth;
DO $$
BEGIN
  BEGIN
    PERFORM * FROM onishield.save_autopilot_policy(
      repeat('a',64), 0, TRUE, 'observe', 0::SMALLINT,
      ARRAY['evidence.collect'], ARRAY['lab-host-1'],
      10, 1, NULL, FALSE, 'stale version should fail'
    );
    RAISE EXCEPTION 'Stale policy version was accepted';
  EXCEPTION WHEN OTHERS THEN
    IF SQLERRM NOT LIKE '%Stale Autopilot policy version%' THEN RAISE; END IF;
  END;

  BEGIN
    PERFORM * FROM onishield.save_autopilot_policy(
      repeat('a',64), 1, TRUE, 'guarded', 2::SMALLINT,
      ARRAY['device.wipe'], ARRAY['lab-host-1'],
      10, 1, NULL, FALSE, 'destructive action must fail'
    );
    RAISE EXCEPTION 'Tier 3 action was accepted';
  EXCEPTION WHEN OTHERS THEN
    IF SQLERRM NOT LIKE '%Invalid Autopilot policy%' THEN RAISE; END IF;
  END;
END $$;

SET LOCAL ROLE onishield_app;
DO $$
BEGIN
  IF has_table_privilege(current_user,'onishield.autopilot_policies','SELECT')
     OR has_table_privilege(current_user,'onishield.autopilot_policies','UPDATE')
     OR has_table_privilege(current_user,'onishield.autopilot_policy_audit','SELECT')
     OR has_table_privilege(current_user,'onishield.autopilot_policy_audit','DELETE')
     OR has_table_privilege(current_user,'onishield.autopilot_policy_decisions','SELECT')
     OR has_table_privilege(current_user,'onishield.autopilot_policy_decisions','DELETE')
     OR has_function_privilege(current_user,'onishield.get_autopilot_policy(text)','EXECUTE')
     OR has_function_privilege(current_user,'onishield.save_autopilot_policy(text,integer,boolean,text,smallint,text[],text[],integer,integer,timestamp with time zone,boolean,text)','EXECUTE')
     OR has_function_privilege(current_user,'onishield.record_autopilot_simulation(text,integer,text,text,text,text,smallint,text)','EXECUTE') THEN
    RAISE EXCEPTION 'Runtime role has excessive Autopilot privileges';
  END IF;
END $$;

ROLLBACK;
