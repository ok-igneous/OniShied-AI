\set ON_ERROR_STOP on
SET ROLE onishield_owner;
\i database/migrations/001_create_security_events.sql
\i database/migrations/002_tenant_rls_and_payload_digest.sql
\i database/migrations/003_threat_intelligence.sql
\i database/grant-runtime-privileges.sql
REVOKE INSERT ON onishield.threat_intelligence_sources FROM onishield_app;
\i database/migrations/004_threat_indicator_review.sql
\i database/migrations/005_operator_identity.sql
\i database/migrations/006_auth_throttling_and_operator_review.sql
\i database/migrations/007_operator_session_lifecycle.sql
\i database/migrations/008_session_revocation_race_hardening.sql
\i database/migrations/009_operator_step_up.sql

\i database/migrations/010_operator_totp_mfa.sql
\i database/migrations/011_operator_mfa_recovery_codes.sql
\i database/migrations/012_operator_email_lifecycle.sql
\i database/migrations/013_detection_findings.sql
\i database/migrations/014_threat_match_connector_identity.sql
\i database/migrations/015_finding_threat_intel_enrichment.sql
\i database/migrations/016_stable_finding_episodes.sql
