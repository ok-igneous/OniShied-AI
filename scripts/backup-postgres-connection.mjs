export function postgresEnvironment(connectionUrl, baseEnvironment = process.env) {
  const url = new URL(connectionUrl);
  if (!["postgres:", "postgresql:"].includes(url.protocol) || !url.hostname || !url.pathname || url.pathname === "/") {
    throw new Error("A valid PostgreSQL connection URL with a database name is required");
  }
  const env = { ...baseEnvironment };
  env.PGHOST = url.hostname.replace(/^\[|\]$/g, "");
  env.PGPORT = url.port || "5432";
  env.PGDATABASE = decodeURIComponent(url.pathname.slice(1));
  if (url.username) env.PGUSER = decodeURIComponent(url.username);
  if (url.password) env.PGPASSWORD = decodeURIComponent(url.password);
  const mappings = {
    sslmode: "PGSSLMODE",
    sslrootcert: "PGSSLROOTCERT",
    sslcert: "PGSSLCERT",
    sslkey: "PGSSLKEY",
    application_name: "PGAPPNAME",
    connect_timeout: "PGCONNECT_TIMEOUT",
    options: "PGOPTIONS",
    target_session_attrs: "PGTARGETSESSIONATTRS"
  };
  for (const [parameter, variable] of Object.entries(mappings)) {
    if (url.searchParams.has(parameter)) env[variable] = url.searchParams.get(parameter);
  }
  return env;
}

export function isLocalPostgresHost(host) {
  return ["localhost", "127.0.0.1", "::1"].includes(host.replace(/^\[|\]$/g, "").toLowerCase());
}
