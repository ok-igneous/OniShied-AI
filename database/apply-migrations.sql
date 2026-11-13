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
