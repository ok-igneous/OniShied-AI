-- Run this only against a disposable local development database.
-- Do not use this file against a production or customer database.
CREATE USER onishield_lab WITH PASSWORD 'replace-this-local-password';
CREATE DATABASE onishield_lab OWNER onishield_lab;
