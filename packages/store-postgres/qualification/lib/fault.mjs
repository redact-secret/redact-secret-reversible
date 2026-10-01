// Fault injection in front of a real PostgreSQL server: a pool wrapper that
// runs hooks around every statement, and a TCP proxy that reads the frontend
// protocol far enough to see `COMMIT` on the wire. Test code only.
import net from "node:net";

/** Text that must never reach a caller: it stands for a driver message carrying a connection string and row data. */
export const DRIVER_MARKER = "synthetic-driver-message";

/** An error shaped like a `pg` error, with text a sanitized `StoreError` must not carry. */
export function driverError(sqlState = "08006") {
  const error = new Error(`${DRIVER_MARKER}: connection to postgres://rsv_app:synthetic-local-only@db.invalid:5432/rsv lost`);
  error.code = sqlState;
  error.detail = `${DRIVER_MARKER}: Key (namespace, tenant, entry_id)=(synthetic) already exists.`;
  error.cause = new Error(`${DRIVER_MARKER}: socket hang up`);
  return error;
}

export const isApply = (text) => text.includes("SET used = e.used + u.count");
export const isEntryLock = (text) => text.includes("ORDER BY entry_id FOR UPDATE");

/**
 * Wraps a pool so a test can act immediately before or after any statement
 * of the adapter's transaction. `state.writing` is true inside a write
 * transaction; `client` is the real `pg` client, so a hook can destroy its
 * socket or read its backend pid.
 */
export function hookPool(pool) {
  let hooks = {};
  const statements = [];
  return {
    statements,
    set(next) {
      hooks = next;
    },
    clear() {
      hooks = {};
    },
    async connect() {
      const client = await pool.connect();
      const state = { writing: false, client };
      return {
        async query(text, values) {
          if (text.startsWith("BEGIN")) state.writing = text.includes("READ COMMITTED");
          statements.push(text);
          if (hooks.before !== undefined) await hooks.before({ text, values, client, state });
          const result = await client.query(text, values);
          if (hooks.after !== undefined) await hooks.after({ text, values, client, state, result });
          return result;
        },
        release: (destroy) => client.release(destroy),
        on: (event, listener) => client.on(event, listener),
        removeListener: (event, listener) => client.removeListener(event, listener),
      };
    },
  };
}

/**
 * A TCP proxy in front of PostgreSQL (no TLS). It forwards whole frontend
 * messages, counts every `COMMIT` it forwards, and can be armed to lose the
 * client at the commit of the next write transaction:
 *
 * - `"after-forward"`: `COMMIT` reaches the server, the server's answer is
 *   withheld, and the client connection is destroyed once the server has
 *   answered. The transaction is committed; the acknowledgement is lost.
 * - `"before-forward"`: the client connection is destroyed and `COMMIT` is
 *   never forwarded. The server rolls the transaction back.
 */
export async function startCommitProxy({ targetPort, targetHost = "127.0.0.1" }) {
  // `sent`: COMMIT messages the client put on the wire for a write transaction. `writeCommits`: those forwarded to the server.
  const stats = { connections: 0, commits: 0, sent: 0, writeCommits: 0, rollbacks: 0, dropped: [] };
  let armed;
  const sockets = new Set();

  const server = net.createServer((client) => {
    stats.connections += 1;
    const upstream = net.connect(targetPort, targetHost);
    sockets.add(client);
    sockets.add(upstream);
    let startup = true;
    let writing = false;
    let swallow = false;
    let buffer = Buffer.alloc(0);
    const close = () => {
      client.destroy();
      upstream.destroy();
      sockets.delete(client);
      sockets.delete(upstream);
    };
    client.on("error", close);
    upstream.on("error", close);
    client.on("close", close);
    upstream.on("close", close);

    upstream.on("data", (chunk) => {
      if (swallow) {
        // The server has answered the COMMIT: it is durable there. The client never hears.
        stats.dropped.push("after-forward");
        close();
        return;
      }
      client.write(chunk);
    });

    client.on("data", (chunk) => {
      buffer = Buffer.concat([buffer, chunk]);
      for (;;) {
        let length;
        let query;
        if (startup) {
          if (buffer.length < 8) return;
          length = buffer.readInt32BE(0);
          if (buffer.length < length) return;
          const code = buffer.readInt32BE(4);
          // An SSL or GSS encryption request is followed by another startup packet.
          if (code !== 80877103 && code !== 80877104) startup = false;
        } else {
          if (buffer.length < 5) return;
          length = 1 + buffer.readInt32BE(1);
          if (buffer.length < length) return;
          if (buffer[0] === 0x51) query = buffer.toString("utf8", 5, length - 1);
        }
        const message = buffer.subarray(0, length);
        buffer = buffer.subarray(length);
        if (query !== undefined) {
          if (query.startsWith("BEGIN")) writing = query.includes("READ COMMITTED");
          if (query === "ROLLBACK") stats.rollbacks += 1;
          if (query === "COMMIT") {
            if (writing) stats.sent += 1;
            if (writing && armed === "before-forward") {
              armed = undefined;
              stats.dropped.push("before-forward");
              close();
              return;
            }
            stats.commits += 1;
            if (writing) {
              stats.writeCommits += 1;
              if (armed === "after-forward") {
                armed = undefined;
                swallow = true;
              }
            }
          }
        }
        upstream.write(message);
      }
    });
  });

  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  return {
    port: server.address().port,
    stats,
    arm(mode) {
      armed = mode;
    },
    async close() {
      for (const socket of sockets) socket.destroy();
      await new Promise((resolve) => server.close(resolve));
    },
  };
}
