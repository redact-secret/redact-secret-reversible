/**
 * Opening a connection and verifying the deployment it runs under, and the
 * restore tripwire's marker file (docs/reference/store-sqlite.md).
 *
 * Nothing here reports a path, a pragma value of another process, or a driver
 * message: a refusal is a list of fixed check names.
 */
import { mkdirSync, readFileSync, realpathSync, renameSync, unlinkSync, writeFileSync } from "node:fs";
import { basename, dirname, join, resolve } from "node:path";

import { StoreError } from "@redact-secret/vault-contracts";

/** The part of a `better-sqlite3` statement this adapter uses. Declared here so no public type names the driver. */
export interface Statement {
  run(...parameters: unknown[]): { changes: number | bigint };
  get(...parameters: unknown[]): Record<string, unknown> | undefined;
  all(...parameters: unknown[]): Record<string, unknown>[];
}

/** The part of a `better-sqlite3` connection this adapter uses. */
export interface Database {
  readonly inTransaction: boolean;
  prepare(source: string): Statement;
  exec(source: string): unknown;
  close(): unknown;
}

export type JournalMode = "wal" | "delete";

/** The oldest SQLite release line member that carries the WAL fix of 3.51.3 (2026-03-13), per release line. */
const MIN_VERSION = [3, 51, 3] as const;
const BACKPORTS = [
  { minor: 44, patch: 6 },
  { minor: 50, patch: 7 },
] as const;

/**
 * Whether `version` (for example "3.53.2") carries the fix for the WAL
 * corruption that affects two connections writing or checkpointing at once
 * (https://www.sqlite.org/wal.html): 3.51.3 or later, or the backports 3.44.6
 * and 3.50.7 or later in their own lines.
 */
export function sqliteVersionAcceptable(version: unknown): boolean {
  if (typeof version !== "string") return false;
  const match = /^(\d+)\.(\d+)\.(\d+)(?:\.\d+)?$/.exec(version);
  if (match === null) return false;
  const [major, minor, patch] = [Number(match[1]), Number(match[2]), Number(match[3])];
  if (major !== MIN_VERSION[0]) return major > MIN_VERSION[0];
  if (minor !== MIN_VERSION[1]) {
    if (minor > MIN_VERSION[1]) return true;
    return BACKPORTS.some((line) => line.minor === minor && patch >= line.patch);
  }
  return patch >= MIN_VERSION[2];
}

export interface OpenOptions {
  readonly filename: string;
  readonly journalMode: JournalMode;
  readonly busyTimeoutMs: number;
}

export interface Opened {
  readonly db: Database;
  /** The canonical path the connection was opened under. */
  readonly path: string;
  readonly sqliteVersion: string;
  /** Names of the checks that failed. Empty when the deployment is acceptable. */
  readonly failures: readonly string[];
}

export function expectedSynchronous(mode: JournalMode): number {
  // FULL is 2, EXTRA is 3 (https://www.sqlite.org/pragma.html#pragma_synchronous).
  return mode === "wal" ? 2 : 3;
}

/**
 * One canonical path for one database: every process names the file the same
 * way, because two names mean two journals (https://www.sqlite.org/howtocorrupt.html).
 * An in-memory, temporary, or URI name is refused.
 */
export function canonicalPath(filename: unknown): string {
  if (typeof filename !== "string" || filename === "" || filename.includes("\0") || filename === ":memory:" || filename.startsWith("file:")) {
    throw new StoreError("STORE_INVALID_ARGUMENT");
  }
  const absolute = resolve(filename);
  try {
    return realpathSync(absolute);
  } catch {
    try {
      return join(realpathSync(dirname(absolute)), basename(absolute));
    } catch {
      throw new StoreError("STORE_UNAVAILABLE");
    }
  }
}

let driver: (new (filename: string, options?: { fileMustExist?: boolean; timeout?: number }) => Database) | undefined;

async function loadDriver(): Promise<NonNullable<typeof driver>> {
  if (driver !== undefined) return driver;
  try {
    const loaded = (await import("better-sqlite3")) as unknown as { default?: unknown };
    if (typeof loaded.default !== "function") throw new Error("no default export");
    driver = loaded.default as NonNullable<typeof driver>;
    return driver;
  } catch {
    // The driver is an optional peer: its absence is a capability the deployment lacks, not a bug.
    throw new StoreError("STORE_CAPABILITY");
  }
}

function pragma(db: Database, text: string): unknown {
  const row = db.prepare(`PRAGMA ${text}`).get();
  if (row === undefined) return undefined;
  const [first] = Object.values(row);
  return first;
}

/**
 * Opens a connection to `options.filename` and sets and reads back every
 * pragma the profile requires. The connection is returned even when a check
 * failed, so the caller can close it; it must not be used then.
 */
export async function openConnection(options: OpenOptions, mustExist: boolean): Promise<Opened> {
  const path = canonicalPath(options.filename);
  const Driver = await loadDriver();
  let db: Database;
  try {
    db = new Driver(path, { fileMustExist: mustExist, timeout: options.busyTimeoutMs });
  } catch {
    throw new StoreError(mustExist ? "STORE_CAPABILITY" : "STORE_UNAVAILABLE");
  }
  const failures: string[] = [];
  let sqliteVersion = "";
  try {
    sqliteVersion = String(db.prepare("SELECT sqlite_version() AS v").get()?.v);
    if (!sqliteVersionAcceptable(sqliteVersion)) failures.push("sqlite-version");

    // `synchronous`, `busy_timeout`, `foreign_keys`, and `fullfsync` are per connection; set each time.
    // `journal_mode` is persistent in the file, and is set and read back too.
    db.exec(`PRAGMA journal_mode = ${options.journalMode.toUpperCase()}`);
    if (String(pragma(db, "journal_mode")).toLowerCase() !== options.journalMode) failures.push("journal-mode");
    db.exec(`PRAGMA synchronous = ${options.journalMode === "wal" ? "FULL" : "EXTRA"}`);
    if (pragma(db, "synchronous") !== expectedSynchronous(options.journalMode)) failures.push("synchronous");
    db.exec(`PRAGMA busy_timeout = ${options.busyTimeoutMs}`);
    if (pragma(db, "busy_timeout") !== options.busyTimeoutMs) failures.push("busy-timeout");
    db.exec("PRAGMA foreign_keys = ON");
    if (pragma(db, "foreign_keys") !== 1) failures.push("foreign-keys");
    db.exec("PRAGMA locking_mode = NORMAL");
    if (String(pragma(db, "locking_mode")).toLowerCase() !== "normal") failures.push("locking-mode");
    if (process.platform === "darwin") {
      // The documented default of fullfsync is off; without F_FULLFSYNC a sync does not reach the platter on macOS.
      db.exec("PRAGMA fullfsync = ON");
      db.exec("PRAGMA checkpoint_fullfsync = ON");
      if (pragma(db, "fullfsync") !== 1 || pragma(db, "checkpoint_fullfsync") !== 1) failures.push("fullfsync");
    }
  } catch {
    failures.push("pragma");
  }
  return { db, path, sqliteVersion, failures };
}

/** The pragmas a transaction re-checks, because another process can change `journal_mode` of a file. */
export function currentConfiguration(db: Database): { journalMode: string; synchronous: unknown } {
  return { journalMode: String(pragma(db, "journal_mode")).toLowerCase(), synchronous: pragma(db, "synchronous") };
}

// ------------------------------------------------------------------- marker

export interface Marker {
  readonly databaseId: string;
  readonly counter: number;
}

/** `null`: no marker file. `"invalid"`: a file that does not parse: treated as a rollback signal. */
export function readMarker(path: string): Marker | null | "invalid" {
  let text: string;
  try {
    text = readFileSync(path, "utf8");
  } catch (thrown) {
    return (thrown as { code?: unknown }).code === "ENOENT" ? null : "invalid";
  }
  try {
    const parsed = JSON.parse(text) as { v?: unknown; databaseId?: unknown; counter?: unknown };
    if (parsed.v !== 1 || typeof parsed.databaseId !== "string" || typeof parsed.counter !== "number" || !Number.isSafeInteger(parsed.counter) || parsed.counter < 0) {
      return "invalid";
    }
    return { databaseId: parsed.databaseId, counter: parsed.counter };
  } catch {
    return "invalid";
  }
}

/** Atomic replace: a reader sees the old marker or the new one, never a partial file. Throws on failure. */
export function writeMarker(path: string, marker: Marker): void {
  mkdirSync(dirname(path), { recursive: true });
  const temporary = `${path}.${process.pid}.tmp`;
  writeFileSync(temporary, `${JSON.stringify({ v: 1, databaseId: marker.databaseId, counter: marker.counter })}\n`, { mode: 0o600 });
  renameSync(temporary, path);
}

/** Whether a marker can be written where it is expected: a probe file next to it, removed again. Throws if not. */
export function probeMarkerDirectory(path: string): void {
  mkdirSync(dirname(path), { recursive: true });
  const probe = `${path}.${process.pid}.probe`;
  writeFileSync(probe, "probe\n", { mode: 0o600 });
  unlinkSync(probe);
}
