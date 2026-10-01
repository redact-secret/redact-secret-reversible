// Docker orchestration for the qualification scenarios. Test and qualification
// code only: nothing under `src` starts a process.
//
// Every container, volume, and network this module creates carries the label
// `rsvq.run=<run id>` and a name that starts with `rsvq-`, so a failed run can
// be cleaned up by label. Nothing here uses `--privileged`, and every
// password is the synthetic `synthetic-local-only`.
import { execFile, execFileSync } from "node:child_process";
import { promisify } from "node:util";

const exec = promisify(execFile);

export const IMAGE = process.env.RSVQ_IMAGE ?? "postgres:17";
export const PASSWORD = "synthetic-local-only";
export const RUN_ID = process.env.RSVQ_RUN_ID ?? `${process.pid.toString(36)}${Date.now().toString(36).slice(-5)}`;
export const DATABASE = "rsv";
export const APP_ROLE = "rsv_app";
export const REPLICATION_ROLE = "rsvq_repl";
const PGDATA = "/var/lib/postgresql/data/pgdata";

let available;
/** `false`, or the reason Docker cannot be used. A scenario that needs it reports that reason as its skip. */
export function dockerUnavailable() {
  if (available === undefined) {
    if (process.env.RSVQ_NO_DOCKER === "1") available = "RSVQ_NO_DOCKER=1";
    else {
      try {
        execFileSync("docker", ["version", "--format", "{{.Server.Version}}"], { stdio: ["ignore", "pipe", "ignore"], timeout: 20_000 });
        execFileSync("docker", ["image", "inspect", IMAGE, "--format", "{{.Id}}"], { stdio: ["ignore", "pipe", "ignore"], timeout: 20_000 });
        available = false;
      } catch {
        available = `Docker with the ${IMAGE} image is not available`;
      }
    }
  }
  return available;
}

export async function docker(args, options = {}) {
  const { stdout } = await exec("docker", args, { maxBuffer: 64 * 1024 * 1024, timeout: options.timeout ?? 180_000 });
  return stdout.trim();
}

/** A container's log, stdout and stderr together. PostgreSQL writes its server log to stderr. */
export async function logs(container) {
  const { stdout, stderr } = await exec("docker", ["logs", container], { maxBuffer: 256 * 1024 * 1024, timeout: 60_000 });
  return `${stdout}\n${stderr}`;
}

export const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

export async function until(check, { timeoutMs = 90_000, intervalMs = 150, what = "condition" } = {}) {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    try {
      const value = await check();
      if (value) return value;
    } catch {
      // Not ready yet.
    }
    if (Date.now() > deadline) throw new Error(`timed out waiting for ${what}`);
    await sleep(intervalMs);
  }
}

export function url(port, role = "postgres", database = DATABASE) {
  return `postgres://${role}:${PASSWORD}@127.0.0.1:${port}/${database}`;
}

/** Runs SQL inside the container over its local socket, as the superuser. */
export async function psql(container, sql, database = DATABASE) {
  return docker(["exec", container, "psql", "-X", "-q", "-A", "-t", "-v", "ON_ERROR_STOP=1", "-U", "postgres", "-d", database, "-c", sql]);
}

async function ready(container) {
  // The image starts a temporary server for initialization first; the final
  // server is the one that listens on TCP.
  await until(
    async () => {
      await docker(["exec", container, "pg_isready", "-q", "-h", "127.0.0.1", "-U", "postgres", "-d", "postgres"]);
      return true;
    },
    { what: `${container} to accept connections` },
  );
}

/**
 * A group of Docker resources with one teardown. Scenario files create one in
 * `before` and call `cleanup` in `after`; `run.mjs` also removes everything
 * carrying the run label in its `finally`.
 */
export function createTopology(tag) {
  const prefix = `rsvq-${RUN_ID}-${tag}`;
  const containers = [];
  const volumes = [];
  let network;
  const label = ["--label", `rsvq.run=${RUN_ID}`];

  const topology = {
    prefix,
    name: (suffix) => `${prefix}-${suffix}`,

    async network() {
      if (network === undefined) {
        network = `${prefix}-net`;
        await docker(["network", "create", ...label, network]);
      }
      return network;
    },

    /** A named volume the `postgres` user of the image can write. */
    async sharedVolume(suffix) {
      const volume = `${prefix}-${suffix}`;
      await docker(["volume", "create", ...label, volume]);
      volumes.push(volume);
      await docker(["run", "--rm", ...label, "-v", `${volume}:/share`, IMAGE, "bash", "-c", "mkdir -p /share/archive && chown -R postgres:postgres /share"]);
      return volume;
    },

    /**
     * A new cluster: `initdb` by the image, database `rsv`, the serving role
     * `rsv_app`, and a replication role. `settings` are `-c name=value` server
     * options; `mounts` are `volume:/path` pairs.
     */
    async primary(suffix, port, { settings = {}, mounts = [], networked = false } = {}) {
      const name = `${prefix}-${suffix}`;
      const net = networked ? ["--network", await topology.network(), "--network-alias", suffix] : [];
      await docker([
        "run", "-d", "--name", name, ...label, ...net,
        "-e", `POSTGRES_PASSWORD=${PASSWORD}`, "-e", `POSTGRES_DB=${DATABASE}`, "-e", `PGDATA=${PGDATA}`,
        "-p", `127.0.0.1:${port}:5432`,
        ...mounts.flatMap((mount) => ["-v", mount]),
        IMAGE, "postgres", "-c", "max_connections=300",
        ...Object.entries(settings).flatMap(([key, value]) => ["-c", `${key}=${value}`]),
      ]);
      containers.push(name);
      await ready(name);
      await psql(name, `CREATE ROLE ${APP_ROLE} LOGIN PASSWORD '${PASSWORD}'`);
      await psql(name, `CREATE ROLE ${REPLICATION_ROLE} LOGIN REPLICATION PASSWORD '${PASSWORD}'`);
      await docker(["exec", name, "bash", "-c", `echo "host replication ${REPLICATION_ROLE} all scram-sha-256" >> ${PGDATA}/pg_hba.conf`]);
      await psql(name, "SELECT pg_reload_conf()");
      return { name, port, adminUrl: url(port), appUrl: url(port, APP_ROLE), alias: suffix };
    },

    /** A streaming standby of `primary`, built with `pg_basebackup`. Its `cluster_name` is its replication `application_name`. */
    async standby(suffix, port, primary, { applicationName = suffix.replaceAll("-", "_") } = {}) {
      const name = `${prefix}-${suffix}`;
      // The base backup is taken once; a restarted container starts from the data it already has.
      const script = [
        `export PGPASSWORD=${PASSWORD}`,
        `if [ ! -s ${PGDATA}/PG_VERSION ]; then pg_basebackup -h ${primary.alias} -U ${REPLICATION_ROLE} -D ${PGDATA} -R -X stream -c fast || exit 1; fi`,
        `exec postgres -c max_connections=300 -c cluster_name=${applicationName} -c hot_standby=on`,
      ].join("; ");
      await docker([
        "run", "-d", "--name", name, ...label, "--network", await topology.network(), "--network-alias", suffix,
        "--user", "postgres", "-e", `PGDATA=${PGDATA}`, "-p", `127.0.0.1:${port}:5432`,
        IMAGE, "bash", "-c", script,
      ]);
      containers.push(name);
      await ready(name);
      await until(async () => (await psql(primary.name, `SELECT count(*) FROM pg_stat_replication WHERE application_name = '${applicationName}' AND state = 'streaming'`)) === "1", {
        what: `${name} to stream from ${primary.name}`,
      });
      return { name, port, adminUrl: url(port), appUrl: url(port, APP_ROLE), alias: suffix, applicationName };
    },

    /** A cluster started from files prepared on a shared volume by `prepare` (a shell script run as `postgres`). */
    async fromFiles(suffix, port, volume, prepare) {
      const name = `${prefix}-${suffix}`;
      await docker([
        "run", "-d", "--name", name, ...label, "--user", "postgres", "-e", `PGDATA=${PGDATA}`,
        "-v", `${volume}:/share`, "-p", `127.0.0.1:${port}:5432`,
        IMAGE, "bash", "-c", `if [ ! -s ${PGDATA}/PG_VERSION ]; then ${prepare} || exit 1; fi; exec postgres -c max_connections=300`,
      ]);
      containers.push(name);
      await ready(name);
      return { name, port, adminUrl: url(port), appUrl: url(port, APP_ROLE) };
    },

    async waitReady(node) {
      await ready(node.name);
    },

    async cleanup() {
      for (const name of containers.splice(0)) await docker(["rm", "-f", "-v", name]).catch(() => undefined);
      for (const volume of volumes.splice(0)) await docker(["volume", "rm", "-f", volume]).catch(() => undefined);
      if (network !== undefined) {
        await docker(["network", "rm", network]).catch(() => undefined);
        network = undefined;
      }
    },
  };
  return topology;
}

export const DATA_DIRECTORY = PGDATA;

/** Removes every container, volume, and network of a run, whatever created them. */
export async function removeRun(runId = RUN_ID) {
  const filter = ["--filter", `label=rsvq.run=${runId}`];
  const list = async (args) => (await docker(args).catch(() => "")).split("\n").filter((line) => line !== "");
  for (const id of await list(["ps", "-aq", ...filter])) await docker(["rm", "-f", "-v", id]).catch(() => undefined);
  for (const volume of await list(["volume", "ls", "-q", ...filter])) await docker(["volume", "rm", "-f", volume]).catch(() => undefined);
  for (const id of await list(["network", "ls", "-q", ...filter])) await docker(["network", "rm", id]).catch(() => undefined);
}

/** What was left behind by a run: empty when cleanup worked. */
export async function remaining(runId = RUN_ID) {
  const filter = ["--filter", `label=rsvq.run=${runId}`];
  const [containers, volumes, networks] = await Promise.all([
    docker(["ps", "-aq", ...filter]),
    docker(["volume", "ls", "-q", ...filter]),
    docker(["network", "ls", "-q", ...filter]),
  ]);
  return { containers, volumes, networks };
}
