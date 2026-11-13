import pg from "pg";
import { config } from "./config.js";

const { Pool } = pg;

export function createOperatorAuthPool(): pg.Pool {
  if (!config.authDatabaseUrl) {
    throw new Error("AUTH_DATABASE_URL is required for operator authentication");
  }
  const authPool = new Pool({
    connectionString: config.authDatabaseUrl,
    max: 2,
    idleTimeoutMillis: 10_000,
    connectionTimeoutMillis: 5_000,
    application_name: "onishield-operator-auth",
    ...(config.databaseSsl ? { ssl: { rejectUnauthorized: true } } : {})
  });
  authPool.on("error", () => {
    // Never log credentials, connection strings, or authentication payloads.
    process.stderr.write("Unexpected idle operator-auth database client error\n");
  });
  return authPool;
}
