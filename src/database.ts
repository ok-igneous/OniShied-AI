import pg from "pg";
import { config } from "./config.js";

const { Pool } = pg;

export const pool = new Pool({
  connectionString: config.databaseUrl,
  max: 5,
  idleTimeoutMillis: 10_000,
  connectionTimeoutMillis: 5_000,
  application_name: "onishield-lab-ingestion"
});

pool.on("error", (error) => {
  console.error("Unexpected idle PostgreSQL client error", error);
});
