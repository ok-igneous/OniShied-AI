-- Run as onishield_owner after applying all migrations.
-- The runtime role is deliberately not a schema owner and cannot run migrations.
GRANT USAGE ON SCHEMA onishield TO onishield_app;
GRANT SELECT, INSERT ON ALL TABLES IN SCHEMA onishield TO onishield_app;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA onishield TO onishield_app;

ALTER DEFAULT PRIVILEGES IN SCHEMA onishield
  GRANT SELECT, INSERT ON TABLES TO onishield_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA onishield
  GRANT USAGE, SELECT ON SEQUENCES TO onishield_app;
