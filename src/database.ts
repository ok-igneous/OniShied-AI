import pg from "pg";
import { config } from "./config.js";

const { Pool } = pg;

export const pool = new Pool({
  connectionString: config.databaseUrl,
  max: 5,
  idleTimeoutMillis: 10_000,
  connectionTimeoutMillis: 5_000,
  application_name: "onishield-lab-ingestion",
  ...(config.databaseSsl ? { ssl: { rejectUnauthorized: true } } : {})
});

pool.on("error", (error) => {
  console.error("Unexpected idle PostgreSQL client error", error);
});

/**
 * Endpoint credentials have a separate database identity. This pool is never
 * substituted with the operator-auth or general application pool.
 */
export const endpointIngestionPool = config.endpointIngestDatabaseUrl
  ? new Pool({
      connectionString: config.endpointIngestDatabaseUrl,
      max: 5,
      idleTimeoutMillis: 10_000,
      connectionTimeoutMillis: 5_000,
      application_name: "onishield-endpoint-ingestion",
      ...(config.databaseSsl ? { ssl: { rejectUnauthorized: true } } : {})
    })
  : null;

endpointIngestionPool?.on("error", (error) => {
  console.error("Unexpected idle endpoint-ingestion PostgreSQL client error", error);
});

export async function withTenantTransaction<T>(
  tenantId: string,
  operation: (client: pg.PoolClient) => Promise<T>
): Promise<T> {
  const client = await pool.connect();

  try {
    await client.query("BEGIN");
    await client.query("SELECT set_config('app.tenant_id', $1, true)", [tenantId]);
    const result = await operation(client);
    await client.query("COMMIT");
    return result;
  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  } finally {
    client.release();
  }
}

/**
 * Authentication functions are intentionally isolated from the general
 * application pool. Do not fall back to DATABASE_URL if this URL is absent.
 */
export const authPool = config.authDatabaseUrl
  ? new Pool({
      connectionString: config.authDatabaseUrl,
      max: 3,
      idleTimeoutMillis: 10_000,
      connectionTimeoutMillis: 5_000,
      application_name: "onishield-operator-auth",
      ...(config.databaseSsl ? { ssl: { rejectUnauthorized: true } } : {})
    })
  : null;

authPool?.on("error", (error) => {
  console.error("Unexpected idle operator-auth PostgreSQL client error", error);
});
