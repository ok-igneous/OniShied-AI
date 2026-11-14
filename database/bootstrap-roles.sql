-- One-time role bootstrap for a disposable PostgreSQL lab database.
-- Run as a PostgreSQL administrator. Supply secrets via psql variables;
-- never put real passwords in this file or in source control.
-- Example:
-- psql -v ON_ERROR_STOP=1 -v migrator_password="$MIGRATOR_DB_PASSWORD" \
--   -v app_password="$APP_DB_PASSWORD" -v auth_password="$AUTH_DB_PASSWORD" \
--   -v endpoint_ingest_password="$ENDPOINT_INGEST_DB_PASSWORD" \
--   -f database/bootstrap-roles.sql

CREATE ROLE onishield_owner NOLOGIN;
CREATE ROLE onishield_migrator LOGIN PASSWORD :'migrator_password';
CREATE ROLE onishield_app LOGIN PASSWORD :'app_password';
CREATE ROLE onishield_auth LOGIN PASSWORD :'auth_password';
CREATE ROLE onishield_ingest LOGIN PASSWORD :'endpoint_ingest_password';
CREATE ROLE onishield_reviewer NOLOGIN;

GRANT onishield_owner TO onishield_migrator;

CREATE DATABASE onishield_lab OWNER onishield_owner;
