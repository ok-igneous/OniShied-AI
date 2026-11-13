\set ON_ERROR_STOP on
SET ROLE onishield_owner;
\i database/migrations/001_create_security_events.sql
\i database/migrations/002_tenant_rls_and_payload_digest.sql
\i database/migrations/003_threat_intelligence.sql
\i database/grant-runtime-privileges.sql
