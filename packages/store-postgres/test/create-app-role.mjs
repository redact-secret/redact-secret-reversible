// Creates the unprivileged serving role named in RSV_PG_APP_URL, with the
// password given there, using the admin connection. For CI and local runs
// against a disposable database only: the password is synthetic.
import pg from "pg";

const admin = process.env.RSV_PG_ADMIN_URL;
const app = process.env.RSV_PG_APP_URL;
if (!admin || !app) {
  console.error("RSV_PG_ADMIN_URL and RSV_PG_APP_URL must be set");
  process.exit(1);
}
const { username, password } = new URL(app);
if (!/^[a-z_][a-z0-9_]{0,62}$/.test(username)) {
  console.error("the serving role name must be a plain lowercase identifier");
  process.exit(1);
}
const client = new pg.Client({ connectionString: admin });
await client.connect();
try {
  const existing = await client.query("SELECT 1 FROM pg_roles WHERE rolname = $1", [username]);
  if (existing.rowCount === 0) {
    // CREATE ROLE takes no bind parameters; the password is passed through format() with %L.
    const statement = await client.query("SELECT format('CREATE ROLE %I LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE PASSWORD %L', $1::text, $2::text) AS sql", [username, decodeURIComponent(password)]);
    await client.query(statement.rows[0].sql);
  }
  console.log(`serving role ready: ${username}`);
} finally {
  await client.end();
}
