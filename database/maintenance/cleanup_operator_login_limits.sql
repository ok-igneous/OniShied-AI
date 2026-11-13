-- Run as a trusted database administrator during scheduled maintenance.
-- Retains recent throttle state for operational investigation while bounding growth.
\set ON_ERROR_STOP on
BEGIN;
SET LOCAL ROLE onishield_owner;
DELETE FROM onishield.operator_login_challenges
 WHERE expires_at < NOW() - INTERVAL '1 day';
DELETE FROM onishield.operator_login_limits
 WHERE updated_at < NOW() - INTERVAL '30 days';
COMMIT;
