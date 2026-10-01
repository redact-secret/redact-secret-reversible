// One process that runs `migrate` on a schema, for the concurrent-migration
// case. It waits for the parent's "go" so two of them start together.
import { migrate } from "../../dist/index.js";
import { openPool } from "./harness.mjs";

const config = JSON.parse(process.env.RSVQ_MIGRATE_CONFIG ?? "null");

if (config !== null && typeof process.send === "function") {
  const pool = openPool(config.url, 2);
  process.once("message", async () => {
    let failures = 0;
    for (let round = 0; round < config.rounds; round += 1) {
      try {
        await migrate(pool, config.schema);
      } catch {
        failures += 1;
      }
    }
    await pool.end();
    process.send({ failures }, () => process.exit(failures === 0 ? 0 : 1));
  });
  process.send({ event: "ready" });
}
