// Test tooling for the Python PostgreSQL adapter: applies the schema owned by
// @redact-secret/store-postgres (migrate and grantStatements, from its build
// output) and the test-only clock table. The Python adapter creates no table.
// Needs `npm run build` and RSV_PG_ADMIN_URL and RSV_PG_APP_URL. Synthetic data only.
import pg from "pg";

import { grantStatements, migrate } from "../../store-postgres/dist/index.js";

const admin = process.env.RSV_PG_ADMIN_URL;
const app = process.env.RSV_PG_APP_URL;
const schema = process.env.RSV_PG_SCHEMA ?? "rsv";
if (!admin || !app) {
  console.error("RSV_PG_ADMIN_URL and RSV_PG_APP_URL must be set");
  process.exit(1);
}
const pool = new pg.Pool({ connectionString: admin, max: 1 });
try {
  await migrate(pool, schema);
  const role = new URL(app).username;
  for (const statement of grantStatements(schema, role)) await pool.query(statement);
  // Test-only clock table, one row per test clock. Not part of the schema the package creates.
  await pool.query(`CREATE TABLE IF NOT EXISTS "${schema}".rsv_test_clock (id text PRIMARY KEY, now_ms bigint NOT NULL)`);
  await pool.query(`GRANT SELECT, INSERT, UPDATE, DELETE ON "${schema}".rsv_test_clock TO "${role}"`);
  console.log(`schema ${schema} ready for role ${role}`);
} finally {
  await pool.end();
}
