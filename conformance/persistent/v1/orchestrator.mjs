#!/usr/bin/env node
// Orchestrator for conformance/persistent/v1/schedules.json (plan §6.3).
//
// It interprets the schedule corpus and drives one or more *drivers* over a
// line-delimited JSON protocol (see README.md in this directory). It knows no
// store, no crypto, and no language: every operation is a request to a driver.
// Node.js standard library only; no workspace package is imported.
//
//   node orchestrator.mjs --driver "node driver-js.mjs" [--level store]
//        [--filter text] [--seed n] [--parallelism n] [--store-options '{"…"}']
//        [--actor-driver B="…"] [--json]
//
// Exit status: 0 when no case failed, 1 when a case failed, 2 on a usage error.
// A skipped case is reported with its reason and is never a pass.
import { spawn } from "node:child_process";
import { randomBytes } from "node:crypto";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";

export const SCHEDULES_URL = new URL("./schedules.json", import.meta.url);
export const HOUR_MS = 3_600_000;
export const DAY_MS = 24 * HOUR_MS;

/** Thrown by a step that finds the store (or driver) wrong. */
export class ScheduleFailure extends Error {}
/** Thrown by a step that cannot run against this driver. */
export class ScheduleSkip extends Error {}

// ---------------------------------------------------------------- utilities

const BASE32 = "abcdefghijklmnopqrstuvwxyz234567";
const HEX = "0123456789abcdef";

function hashSeed(seed, label) {
  let h = (seed ^ 0x811c9dc5) >>> 0;
  for (let i = 0; i < label.length; i += 1) {
    h ^= label.charCodeAt(i);
    h = Math.imul(h, 0x01000193) >>> 0;
  }
  return h;
}

/** mulberry32. Chooses synthetic identifiers and bytes. Not for keys. */
class Prng {
  constructor(seed) {
    this.state = seed >>> 0;
  }
  next() {
    this.state = (this.state + 0x6d2b79f5) >>> 0;
    let t = this.state;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  }
  int(bound) {
    return Math.floor(this.next() * bound);
  }
  text(alphabet, length) {
    let out = "";
    for (let i = 0; i < length; i += 1) out += alphabet[this.int(alphabet.length)];
    return out;
  }
  hex(byteLength) {
    return this.text(HEX, byteLength * 2);
  }
}

/** A description that is safe to print: enum-like strings, numbers, shapes. Never bytes or free text. */
export function describe(value) {
  if (value === null) return "null";
  if (value === undefined) return "undefined";
  if (typeof value === "string") return /^[A-Za-z0-9 :_.,|/-]{0,64}$/.test(value) ? `"${value}"` : "a string";
  if (typeof value === "number" || typeof value === "boolean") return String(value);
  if (Array.isArray(value)) return `array(${value.length})`;
  if (typeof value === "object") {
    if (typeof value.outcome === "string") {
      return typeof value.reason === "string"
        ? `${describe(value.outcome)} (${describe(value.reason)})`
        : describe(value.outcome);
    }
    if (typeof value.state === "string") return `state ${describe(value.state)}`;
    return "an object";
  }
  return typeof value;
}

function fail(message) {
  throw new ScheduleFailure(message);
}

function isPlainObject(value) {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** Resolves `a.b[0].c` in `root`. Returns `undefined` when any step is missing. */
function lookupPath(root, path) {
  let current = root;
  for (const part of path.match(/[^.[\]]+/g) ?? []) {
    if (current === null || current === undefined) return undefined;
    current = current[part];
  }
  return current;
}

function clone(value) {
  return value === undefined ? undefined : JSON.parse(JSON.stringify(value));
}

function setPath(root, path, value) {
  const parts = path.match(/[^.[\]]+/g) ?? [];
  let current = root;
  for (let i = 0; i < parts.length - 1; i += 1) {
    current = current[parts[i]];
    if (current === undefined || current === null) fail(`schedule: path ${path} does not exist in the source value`);
  }
  const last = parts[parts.length - 1];
  if (last === undefined) fail("schedule: empty path");
  current[last] = value;
}

function deepEqual(a, b) {
  return JSON.stringify(a) === JSON.stringify(b);
}

// ------------------------------------------------------------ driver clients

/**
 * A driver is anything with `request(message) -> Promise<response>`, `onEvent(fn)`, and `close()`.
 * `stdioDriver` speaks the line protocol with a child process; tests may pass an in-process object.
 */
export function stdioDriver(command, args = [], { env = process.env, cwd } = {}) {
  const child = spawn(command, args, { stdio: ["pipe", "pipe", "pipe"], env, cwd });
  const pending = new Map();
  const listeners = new Set();
  let nextId = 1;
  let buffer = "";
  let exited = false;
  const failAll = (what) => {
    for (const { reject } of pending.values()) reject(new ScheduleFailure(`driver: ${what}`));
    pending.clear();
  };
  child.stdout.setEncoding("utf8");
  child.stdout.on("data", (chunk) => {
    buffer += chunk;
    for (let at = buffer.indexOf("\n"); at >= 0; at = buffer.indexOf("\n")) {
      const line = buffer.slice(0, at);
      buffer = buffer.slice(at + 1);
      if (line.trim() === "") continue;
      let message;
      try {
        message = JSON.parse(line);
      } catch {
        failAll("wrote a line that is not JSON");
        continue;
      }
      if (message.event !== undefined) {
        for (const listener of listeners) listener(message);
      } else if (pending.has(message.id)) {
        const { resolve } = pending.get(message.id);
        pending.delete(message.id);
        resolve(message);
      }
    }
  });
  // Driver stderr is not forwarded: the protocol carries structures and codes only.
  child.stderr.resume();
  child.on("exit", () => {
    exited = true;
    failAll("exited while a request was outstanding");
  });
  child.on("error", () => failAll("could not be started"));
  return {
    request(message) {
      if (exited) return Promise.reject(new ScheduleFailure("driver: has exited"));
      const id = nextId;
      nextId += 1;
      return new Promise((resolve, reject) => {
        pending.set(id, { resolve, reject });
        child.stdin.write(`${JSON.stringify({ id, ...message })}\n`);
      });
    },
    onEvent(listener) {
      listeners.add(listener);
      return () => listeners.delete(listener);
    },
    async close() {
      if (exited) return;
      child.stdin.end();
      await new Promise((done) => {
        const timer = setTimeout(() => {
          child.kill();
          done();
        }, 2000);
        child.on("exit", () => {
          clearTimeout(timer);
          done();
        });
      });
    },
  };
}

// ----------------------------------------------------------------- the case

const MATCH_OPERATORS = new Set(["$in", "$length", "$absent", "$atLeast", "$atMost", "$notMatch", "$all", "$any"]);

class Run {
  constructor({ doc, schedule, drivers, options, seed }) {
    this.doc = doc;
    this.schedule = schedule;
    this.drivers = drivers; // actor -> driver
    this.options = options;
    this.seed = seed;
    this.rng = new Prng(hashSeed(seed, schedule.id));
    this.vars = new Map();
    this.pending = new Map(); // async name -> {promise}
    this.holds = new Map(); // holdId -> {reached: Promise, resolve}
    this.attempts = 0;
    this.features = { testClock: false, holds: [], faults: [], levels: [] };
    this.caps = null;
    this.stepNo = 0;
    this.unsubscribe = [];
    this.where = "";
  }

  // --- infrastructure ------------------------------------------------------

  driverFor(actor) {
    const driver = this.drivers.get(actor) ?? this.drivers.get("*");
    if (driver === undefined) fail(`no driver for actor ${describe(actor)}`);
    return driver;
  }

  async send(actor, message) {
    const response = await this.driverFor(actor).request(message);
    return response;
  }

  async configure() {
    this.vars.set("NS", `conf-${randomBytes(10).toString("hex")}`);
    this.vars.set("NS2", `conf-${randomBytes(10).toString("hex")}`);
    const first = new Set();
    for (const [actor, driver] of this.drivers) {
      if (first.has(driver)) continue;
      first.add(driver);
      this.unsubscribe.push(
        driver.onEvent((message) => {
          if (message.event === "held") this.holds.get(message.holdId)?.markReached();
        }),
      );
      const response = await driver.request({
        op: "configure",
        level: this.schedule.level,
        caseId: this.schedule.id,
        actors: this.schedule.actors ?? ["A"],
        store: this.options.storeOptions ?? {},
        server: this.schedule.server ?? null,
        namespace: this.vars.get("NS"),
        otherNamespace: this.vars.get("NS2"),
        fixtures: this.doc.fixtures,
      });
      if (response.ok !== true) {
        throw new ScheduleSkip(`the driver cannot be configured for this case (${describe(response.error)})`);
      }
      if (actor === [...this.drivers.keys()][0]) {
        this.features = { testClock: false, holds: [], faults: [], levels: [], ...(response.features ?? {}) };
        this.caps = response.capabilities ?? null;
      }
    }
    const tenantA = this.doc.fixtures.tenantA;
    const tenantB = this.doc.fixtures.tenantB;
    this.vars.set("TENANT_A", tenantA);
    this.vars.set("TENANT_B", tenantB);
    this.vars.set("SCOPE_A", { namespace: this.vars.get("NS"), tenant: tenantA });
    this.vars.set("SCOPE_B", { namespace: this.vars.get("NS"), tenant: tenantB });
    this.vars.set("SCOPE_A2", { namespace: this.vars.get("NS2"), tenant: tenantA });
    this.vars.set("CTX", this.doc.fixtures.contexts ?? {});
    for (const [name, value] of Object.entries(this.doc.fixtures.values ?? {})) this.vars.set(name, value);
    this.vars.set("PARALLELISM", this.options.parallelism ?? 100);
    this.vars.set("FAR", 60_000);
    this.vars.set("HOUR", HOUR_MS);
    this.vars.set("DAY", DAY_MS);
    if (this.caps !== null) {
      this.vars.set("CAPS", this.caps);
      this.vars.set("SKEW", this.caps.maxClockSkewMs);
    }
  }

  checkRequires() {
    const requires = this.schedule.requires ?? {};
    if (requires.testClock === true && !this.features.testClock) {
      throw new ScheduleSkip("the driver supplies no controllable store clock (testClock)");
    }
    for (const hold of requires.holds ?? []) {
      if (!this.features.holds.includes(hold)) {
        throw new ScheduleSkip(`the driver supplies no hold point ${hold}, so the two-connection schedules cannot be run`);
      }
    }
    for (const fault of requires.faults ?? []) {
      if (!this.features.faults.includes(fault)) throw new ScheduleSkip(`the driver cannot inject the fault ${fault}`);
    }
    if (requires.crossProcess === true) {
      const distinct = new Set(this.drivers.values()).size;
      if (this.caps?.crossProcess !== true || distinct < (this.schedule.actors ?? []).length) {
        throw new ScheduleSkip("the case needs actors in separate processes against a store that declares crossProcess");
      }
    }
    if (requires.durability !== undefined && this.caps?.durability !== requires.durability) {
      throw new ScheduleSkip(`the case needs a ${requires.durability} store`);
    }
    if (requires.level !== undefined && !this.features.levels.includes(requires.level)) {
      throw new ScheduleSkip(`the driver does not serve level ${requires.level}`);
    }
  }

  async now(actor) {
    if (!this.features.testClock) return Date.now();
    const response = await this.send(actor ?? this.firstActor(), { op: "clock", action: "now" });
    if (typeof response.result?.now !== "number") fail("the driver's clock did not answer");
    return response.result.now;
  }

  firstActor() {
    return (this.schedule.actors ?? ["A"])[0];
  }

  // --- expressions -----------------------------------------------------------

  lookup(name, scope) {
    const root = name.match(/^[^.[]+/)?.[0] ?? name;
    let base;
    if (scope !== undefined && root in scope) base = scope[root];
    else if (this.vars.has(root)) base = this.vars.get(root);
    else fail(`schedule: unknown variable ${describe(root)}`);
    const rest = name.slice(root.length);
    return rest === "" ? base : lookupPath(base, rest);
  }

  async evaluate(value, scope) {
    if (typeof value === "string") {
      const whole = value.match(/^\{([^{}]+)\}$/);
      if (whole !== null) return this.lookup(whole[1], scope);
      if (!value.includes("{")) return value;
      return value.replace(/\{([^{}]+)\}/g, (_all, name) => String(this.lookup(name, scope)));
    }
    if (Array.isArray(value)) {
      const out = [];
      for (const item of value) out.push(await this.evaluate(item, scope));
      return out;
    }
    if (!isPlainObject(value)) return value;
    if ("$from" in value) return this.evalFrom(value, scope);
    const keys = Object.keys(value);
    if (keys.length >= 1 && keys[0].startsWith("$") && !MATCH_OPERATORS.has(keys[0]) && keys[0] !== "$when") {
      return this.evalOperator(keys[0], value[keys[0]], value, scope);
    }
    const out = {};
    for (const key of keys) out[key] = await this.evaluate(value[key], scope);
    return out;
  }

  async evalFrom(spec, scope) {
    const source = clone(await this.evaluate(spec.$from, scope));
    const pristine = clone(source);
    for (const [path, expression] of Object.entries(spec.set ?? {})) {
      const value = await this.evaluate(expression, { ...scope, $src: pristine });
      if (path.endsWith("[]")) {
        const list = lookupPath(source, path.slice(0, -2));
        if (!Array.isArray(list)) fail(`schedule: ${path} is not a list`);
        list.push(value);
      } else {
        setPath(source, path, value);
      }
    }
    for (const path of spec.unset ?? []) {
      const parts = path.match(/[^.[\]]+/g) ?? [];
      const parent = lookupPath(source, parts.slice(0, -1).join("."));
      if (parent !== undefined && parent !== null) delete parent[parts[parts.length - 1]];
    }
    return source;
  }

  async evalOperator(name, argument, whole, scope) {
    const ev = (item) => this.evaluate(item, scope);
    const list = async () => {
      const out = [];
      for (const item of argument) out.push(await ev(item));
      return out;
    };
    switch (name) {
      case "$now":
        return (await this.now()) + (await ev(argument));
      case "$cap":
        return this.caps?.[argument];
      case "$param":
        return this.options.parallelism ?? 100;
      case "$src":
        return lookupPath(scope?.$src, argument);
      case "$add": {
        let sum = 0;
        for (const item of await list()) sum += item;
        return sum;
      }
      case "$sub": {
        const [a, b] = await list();
        return a - b;
      }
      case "$mul": {
        let product = 1;
        for (const item of await list()) product *= item;
        return product;
      }
      case "$div": {
        const [a, b] = await list();
        return Math.floor(a / b);
      }
      case "$contains": {
        const [haystack, needle] = await list();
        return typeof haystack === "string" ? haystack.includes(needle) : Array.isArray(haystack) && haystack.some((item) => deepEqual(item, needle));
      }
      case "$neg":
        return -(await ev(argument));
      case "$min":
        return Math.min(...(await list()));
      case "$max":
        return Math.max(...(await list()));
      case "$pow": {
        const [a, b] = await list();
        return a ** b;
      }
      case "$repeat": {
        const [text, times] = await list();
        return String(text).repeat(times);
      }
      case "$concat":
        return (await list()).map(String).join("");
      case "$len": {
        const value = await ev(argument);
        return typeof value === "string" || Array.isArray(value) ? value.length : fail("schedule: $len of a non-list");
      }
      case "$bytes": {
        // `{"$bytes": {"length": n, "fill": b}}` is the wire run form; without `fill`, n pseudo-random bytes as hex.
        const spec = await ev(argument);
        if (spec.fill !== undefined) return { $fill: spec.fill, length: spec.length };
        return this.rng.hex(spec.length);
      }
      case "$gen": {
        const kind = await ev(argument);
        if (kind === "captureId") return `cap_${this.rng.text(BASE32, 26)}`;
        if (kind === "entryId") return this.rng.text(HEX, 64);
        if (kind === "digest") return this.rng.hex(32);
        if (kind === "attemptId") {
          this.attempts += 1;
          return `attempt-synthetic-${this.attempts}-${this.rng.text(BASE32, 8)}`;
        }
        return fail(`schedule: unknown generator ${describe(kind)}`);
      }
      case "$if": {
        const [condition, a, b] = argument;
        return (await ev(condition)) ? ev(a) : ev(b);
      }
      case "$eq": {
        const [a, b] = await list();
        return deepEqual(a, b);
      }
      case "$ne": {
        const [a, b] = await list();
        return !deepEqual(a, b);
      }
      case "$lt": {
        const [a, b] = await list();
        return a < b;
      }
      case "$lte": {
        const [a, b] = await list();
        return a <= b;
      }
      case "$gt": {
        const [a, b] = await list();
        return a > b;
      }
      case "$gte": {
        const [a, b] = await list();
        return a >= b;
      }
      case "$and": {
        for (const item of argument) if (!(await ev(item))) return false;
        return true;
      }
      case "$or": {
        for (const item of argument) if (await ev(item)) return true;
        return false;
      }
      case "$not":
        return !(await ev(argument));
      case "$match": {
        const [actual, pattern] = argument;
        return this.matches(await ev(actual), await ev(pattern), scope).ok;
      }
      case "$count": {
        const over = await ev(argument.over);
        let total = 0;
        for (const [index, item] of over.entries()) {
          const local = { ...scope, item, i: index };
          if (argument.where === undefined || this.matches(item, await this.evaluate(argument.where, local), local).ok) total += 1;
        }
        return total;
      }
      case "$find": {
        const over = await ev(argument.over);
        for (const [index, item] of over.entries()) {
          const local = { ...scope, [argument.as ?? "item"]: item, i: index };
          if (this.matches(item, await this.evaluate(argument.where, local), local).ok) return item;
        }
        return null;
      }
      case "$map": {
        const over = await ev(argument.over);
        const out = [];
        for (const [index, item] of over.entries()) out.push(await this.evaluate(argument.do, { ...scope, item, i: index }));
        return out;
      }
      case "$list": {
        const count = await ev(argument.count);
        const out = [];
        for (let i = 0; i < count; i += 1) out.push(await this.evaluate({ $gen: argument.gen }, scope));
        return out;
      }
      case "$concatList":
        return (await list()).flat(1);
      case "$flatten":
        return (await ev(argument)).flat(1);
      case "$mod": {
        const [a, b] = await list();
        return a % b;
      }
      case "$range": {
        const [from, to] = await list();
        const out = [];
        for (let i = from; i < to; i += 1) out.push(i);
        return out;
      }
      case "$slice": {
        const [items, from, to] = await list();
        return items.slice(from, to);
      }
      case "$sum": {
        const over = await ev(argument.over);
        let total = 0;
        for (const [index, item] of over.entries()) {
          total += await this.evaluate(argument.of, { ...scope, item, i: index });
        }
        return total;
      }
      case "$hex":
        return String(await ev(argument.byte)).padStart(2, "0").repeat(await ev(argument.times));
      default:
        return fail(`schedule: unknown operator ${describe(name)}`);
    }
  }

  // --- matching ------------------------------------------------------------

  /** Whether `actual` satisfies `pattern`. Objects match by key subset, lists by index prefix. */
  matches(actual, pattern, scope) {
    if (isPlainObject(pattern)) {
      for (const [key, expected] of Object.entries(pattern)) {
        if (key === "$when") continue;
        if (key === "$in") {
          if (!expected.some((candidate) => deepEqual(candidate, actual))) return { ok: false, at: "value" };
          continue;
        }
        if (key === "$notMatch") {
          if (this.matches(actual, expected, scope).ok) return { ok: false, at: "value" };
          continue;
        }
        if (key === "$length") {
          if (!Array.isArray(actual) || actual.length !== expected) return { ok: false, at: "length" };
          continue;
        }
        if (key === "$absent") {
          if (actual !== undefined && actual !== null) return { ok: false, at: "presence" };
          continue;
        }
        if (key === "$all") {
          if (!expected.every((candidate) => this.matches(actual, candidate, scope).ok)) return { ok: false, at: "value" };
          continue;
        }
        if (key === "$any") {
          if (!expected.some((candidate) => this.matches(actual, candidate, scope).ok)) return { ok: false, at: "value" };
          continue;
        }
        if (key === "$atLeast") {
          if (!(actual >= expected)) return { ok: false, at: "value" };
          continue;
        }
        if (key === "$atMost") {
          if (!(actual <= expected)) return { ok: false, at: "value" };
          continue;
        }
        if (actual === null || actual === undefined || typeof actual !== "object") return { ok: false, at: key };
        const inner = this.matches(actual[key], expected, scope);
        if (!inner.ok) return { ok: false, at: inner.at === "value" ? key : `${key}.${inner.at}` };
      }
      return { ok: true };
    }
    if (Array.isArray(pattern)) {
      if (!Array.isArray(actual) || actual.length < pattern.length) return { ok: false, at: "length" };
      for (const [index, expected] of pattern.entries()) {
        const inner = this.matches(actual[index], expected, scope);
        if (!inner.ok) return { ok: false, at: `[${index}]` };
      }
      return { ok: true };
    }
    return deepEqual(actual, pattern) ? { ok: true } : { ok: false, at: "value" };
  }

  async expectResult(step, outcome, scope, what) {
    // outcome: {result} | {error}
    if (step.expectError !== undefined) {
      const allowed = [].concat(await this.evaluate(step.expectError, scope));
      if (outcome.error !== undefined && step.expectReason !== undefined) {
        const reason = await this.evaluate(step.expectReason, scope);
        if (![].concat(reason).includes(outcome.detail?.reason)) {
          fail(`${what}: expected ${describe(outcome.error)} with reason ${describe(reason)}, got reason ${describe(outcome.detail?.reason)}`);
        }
      }
      if (outcome.error === undefined || !allowed.includes(outcome.error)) {
        fail(`${what}: expected ${describe(allowed.join("|"))} to be thrown, got ${outcome.error === undefined ? describe(outcome.result) : `error ${describe(outcome.error)}`}`);
      }
      return;
    }
    if (outcome.error !== undefined) fail(`${what}: unexpected error ${describe(outcome.error)}`);
    if (step.expect !== undefined) {
      const pattern = await this.evaluate(step.expect, scope);
      const verdict = this.matches(outcome.result, pattern, scope);
      if (!verdict.ok) fail(`${what}: expected ${this.shape(pattern)}, got ${describe(outcome.result)} (differs at ${describe(verdict.at)})`);
    }
    if (step.expectOneOf !== undefined) {
      let allowedAny = false;
      for (const alternative of step.expectOneOf) {
        if (alternative.$when !== undefined) {
          let applies = true;
          for (const [name, expected] of Object.entries(alternative.$when)) {
            if (!deepEqual(this.lookup(name, scope), expected)) applies = false;
          }
          if (!applies) continue;
        }
        const pattern = await this.evaluate(alternative, scope);
        if (this.matches(outcome.result, pattern, scope).ok) {
          allowedAny = true;
          break;
        }
      }
      if (!allowedAny) fail(`${what}: ${describe(outcome.result)} is none of the allowed results`);
    }
  }

  shape(pattern) {
    if (isPlainObject(pattern) && typeof pattern.outcome === "string") return describe(pattern);
    return "a result of the stated shape";
  }

  // --- the store call ----------------------------------------------------------

  async call(actor, op, input, extra = {}) {
    const response = await this.send(actor, { op, actor, input, ...extra });
    if (response.error !== undefined) return { error: response.error, detail: response.detail };
    if (response.result === undefined) fail(`the driver answered ${describe(op)} with neither a result nor an error`);
    return { result: response.result };
  }

  /** Runs `steps` in order with `scope` as the local variables. */
  async runSteps(steps, scope) {
    for (const step of steps) {
      this.stepNo += 1;
      const before = this.where;
      this.where = step.what ?? step.op ?? Object.keys(step)[0];
      try {
        await this.runStep(step, scope);
      } finally {
        this.where = before;
      }
    }
  }

  save(name, value, scope) {
    if (scope !== undefined && scope.$locals) scope[name] = value;
    else this.vars.set(name, value);
  }

  async runStep(step, scope) {
    if (step.skipIf !== undefined) {
      if (await this.evaluate(step.skipIf, scope)) throw new ScheduleSkip(step.reason ?? "a precondition of the case does not hold");
      if (Object.keys(step).length === 2) return;
    }
    if (step.when !== undefined) {
      for (const [name, expected] of Object.entries(step.when)) {
        const actual = name === "testClock" ? this.features.testClock : this.lookup(name, scope);
        if (!deepEqual(actual, expected)) return;
      }
    }
    if (step.let !== undefined) {
      for (const [name, expression] of Object.entries(step.let)) this.save(name, await this.evaluate(expression, scope), scope);
      return;
    }
    if (step.check !== undefined) {
      const truth = await this.evaluate(step.check, scope);
      if (truth !== true) fail(`${step.what ?? "a check"}: not satisfied`);
      return;
    }
    if (step.advance !== undefined) {
      await this.clockOp({ action: "advance", ms: await this.evaluate(step.advance, scope) }, step.actor);
      return;
    }
    if (step.setClock !== undefined) {
      await this.clockOp({ action: "set", ms: await this.evaluate(step.setClock, scope) }, step.actor);
      return;
    }
    if (step.capabilities !== undefined) return this.stepCapabilities(step, scope);
    if (step.build !== undefined) return this.stepBuild(step, scope);
    if (step.create !== undefined) return this.stepCreate(step, scope, false);
    if (step.createExpired !== undefined) return this.stepCreate(step, scope, true);
    if (step.entry !== undefined) return this.stepEntry(step, scope);
    if (step.captureRow !== undefined) return this.stepCaptureRow(step, scope);
    if (step.snapshot !== undefined) return this.stepSnapshot(step, scope);
    if (step.expectSnapshot !== undefined) return this.stepExpectSnapshot(step, scope);
    if (step.restoreRetry !== undefined) return this.stepRestoreRetry(step, scope);
    if (step.release !== undefined) return this.stepRelease(step, scope);
    if (step.await !== undefined) return this.stepAwait(step, scope);
    if (step.parallel !== undefined) return this.stepParallel(step, scope);
    if (step.forEach !== undefined) return this.stepForEach(step, scope);
    if (step.loop !== undefined) return this.stepLoop(step, scope);
    if (step.op !== undefined) return this.stepOp(step, scope);
    return fail(`schedule: unknown step ${describe(Object.keys(step).join(","))}`);
  }

  async clockOp(message, actor) {
    if (!this.features.testClock) throw new ScheduleSkip("the driver supplies no controllable store clock (testClock)");
    const response = await this.send(actor ?? this.firstActor(), { op: "clock", ...message });
    if (response.error !== undefined) fail(`the driver refused a clock change (${describe(response.error)})`);
  }

  async stepCapabilities(step, scope) {
    const response = await this.send(step.actor ?? this.firstActor(), { op: "capabilities" });
    if (response.result === undefined) fail("capabilities: the driver returned none");
    const caps = response.result;
    if (step.capabilities === "complete") {
      const missing = missingCapabilities(caps);
      if (missing.length > 0) fail(`missingCapabilities must be empty (first: ${describe(missing[0])})`);
      const again = (await this.send(step.actor ?? this.firstActor(), { op: "capabilities" })).result;
      if (!deepEqual(again, caps)) fail("capabilities are declared once and do not change");
    }
    if (step.save !== undefined) this.save(step.save, caps, scope);
  }

  // --- builders (mirror the JavaScript harness's Bench) ---------------------

  async stepBuild(step, scope) {
    if (step.build === "capture") {
      const handle = await this.buildCapture(step.options ?? {}, scope);
      this.save(step.as, handle, scope);
      return;
    }
    if (step.build === "commit") {
      const input = await this.buildCommit(step, scope);
      this.save(step.as, input, scope);
      return;
    }
    fail(`schedule: unknown builder ${describe(step.build)}`);
  }

  async buildCapture(rawOptions, scope) {
    const options = await this.evaluate(rawOptions, scope);
    const now = await this.now();
    const caps = this.caps ?? {};
    const count = options.entryIds?.length ?? options.entries ?? 1;
    const entries = [];
    for (let i = 0; i < count; i += 1) {
      const maxUses = typeof options.maxUses === "number" ? options.maxUses : (options.maxUses?.[i] ?? 1);
      const bytes = options.envelopeBytes ?? 24;
      entries.push({
        entryId: options.entryIds?.[i] ?? this.rng.text(HEX, 64),
        maxUses,
        envelope: options.envelopeFill === undefined ? this.rng.hex(bytes) : { $fill: options.envelopeFill, length: bytes },
      });
    }
    const input = {
      scope: options.scope ?? this.vars.get("SCOPE_A"),
      epoch: options.epoch ?? 1,
      now,
      capture: {
        captureId: options.captureId ?? `cap_${this.rng.text(BASE32, 26)}`,
        sessionTag: options.sessionTag ?? null,
        createdAt: now,
        expiresAt: now + (options.lifetimeMs ?? HOUR_MS),
        lookupVersion: 1,
        keyRef: "synthetic-key:v1",
        wrappedKey: this.rng.hex(40),
      },
      entries,
    };
    void caps;
    return {
      scope: input.scope,
      captureId: input.capture.captureId,
      entryIds: entries.map((entry) => entry.entryId),
      createdAt: input.capture.createdAt,
      expiresAt: input.capture.expiresAt,
      input,
    };
  }

  async stepCreate(step, scope, expired) {
    const name = expired ? step.createExpired : step.create;
    const actor = step.actor ?? this.firstActor();
    const options = step.options ?? {};
    let handle;
    if (expired && this.features.testClock) {
      handle = await this.buildCapture(options, scope);
      await this.createChecked(actor, handle, "createCapture of a new capture");
      await this.clockOp({ action: "set", ms: handle.expiresAt }, actor);
    } else if (expired) {
      const skew = this.caps.maxClockSkewMs;
      const back = Math.min(1000, skew);
      if (back < 100) throw new ScheduleSkip("without a controllable clock this case needs maxClockSkewMs of at least 100");
      handle = await this.buildCapture(options, scope);
      handle.input.capture.createdAt = handle.input.now - back;
      handle.input.capture.expiresAt = handle.input.now - back + 1;
      handle.createdAt = handle.input.capture.createdAt;
      handle.expiresAt = handle.input.capture.expiresAt;
      await this.createChecked(actor, handle, "createCapture of a capture that is already expired");
    } else {
      handle = await this.buildCapture(options, scope);
      await this.createChecked(actor, handle, "createCapture of a new capture");
    }
    this.save(name, handle, scope);
  }

  async createChecked(actor, handle, what) {
    const outcome = await this.call(actor, "createCapture", handle.input);
    if (outcome.error !== undefined) fail(`${what}: unexpected error ${describe(outcome.error)}`);
    if (outcome.result.outcome !== "created") fail(`${what}: expected outcome "created", got ${describe(outcome.result)}`);
  }

  async buildCommit(step, scope) {
    const actor = step.actor ?? this.firstActor();
    const commitScope = step.scope === undefined ? this.vars.get("SCOPE_A") : await this.evaluate(step.scope, scope);
    const specs = [];
    for (const spec of step.uses) {
      const capture = this.lookup(spec.capture, scope);
      specs.push({
        capture,
        entry: spec.entry === undefined ? 0 : await this.evaluate(spec.entry, scope),
        count: spec.count === undefined ? 1 : await this.evaluate(spec.count, scope),
      });
    }
    let result;
    if (step.fromRead !== undefined) {
      result = await this.evaluate(step.fromRead, scope);
    } else {
      const entryIds = specs.map((spec) => spec.capture.entryIds[spec.entry]);
      const outcome = await this.call(actor, "readEntries", { scope: commitScope, entryIds });
      if (outcome.error !== undefined) fail(`readEntries: unexpected error ${describe(outcome.error)}`);
      result = outcome.result;
    }
    const captures = new Map();
    let latest = 0;
    const uses = specs.map((spec) => {
      const entryId = spec.capture.entryIds[spec.entry];
      const entry = result.entries.find((candidate) => candidate.entryId === entryId);
      const capture = result.captures.find((candidate) => candidate.captureId === spec.capture.captureId);
      if (entry === undefined || capture === undefined) {
        fail("readEntries: an entry that was created and not deleted must be returned with its capture");
      }
      captures.set(capture.captureId, { captureId: capture.captureId, generation: capture.generation });
      latest = Math.max(latest, capture.expiresAt);
      return {
        entryId,
        captureId: capture.captureId,
        count: spec.count,
        lifecycleRevision: entry.lifecycleRevision,
        ciphertextRevision: entry.ciphertextRevision,
      };
    });
    const skew = this.caps.maxClockSkewMs;
    this.attempts += 1;
    return {
      scope: commitScope,
      epoch: result.recovery.epoch === 0 ? 1 : result.recovery.epoch,
      now: await this.now(actor),
      attempt: {
        attemptId: `attempt-synthetic-${this.attempts}-${this.rng.text(BASE32, 8)}`,
        requestDigest: this.rng.hex(32),
      },
      receiptExpiresAt: latest + skew + HOUR_MS,
      captures: [...captures.values()],
      uses,
    };
  }

  async stepEntry(step, scope) {
    const handle = this.lookup(step.of, scope);
    const index = step.index ?? 0;
    const entryId = handle.entryIds[index];
    const outcome = await this.call(step.actor ?? this.firstActor(), "readEntries", { scope: handle.scope, entryIds: [entryId] });
    if (outcome.error !== undefined) fail(`readEntries: unexpected error ${describe(outcome.error)}`);
    const found = outcome.result.entries.find((entry) => entry.entryId === entryId);
    if (found === undefined) fail("readEntries: an entry that was created and not deleted must be returned");
    this.save(step.entry, found, scope);
  }

  async stepCaptureRow(step, scope) {
    const handle = this.lookup(step.of, scope);
    const outcome = await this.call(step.actor ?? this.firstActor(), "readCaptures", { scope: handle.scope, captureIds: [handle.captureId] });
    if (outcome.error !== undefined) fail(`readCaptures: unexpected error ${describe(outcome.error)}`);
    const found = outcome.result.find((row) => row.captureId === handle.captureId);
    if (found === undefined) fail("readCaptures: a capture row that exists must be returned");
    this.save(step.captureRow, found, scope);
  }

  async fingerprint(handles, actor) {
    const parts = [];
    const recovery = await this.call(actor, "recoveryState", { namespace: this.vars.get("NS") });
    parts.push(recovery.result ?? recovery.error);
    for (const handle of handles) {
      const captures = await this.call(actor, "readCaptures", { scope: handle.scope, captureIds: [handle.captureId] });
      const entries = await this.call(actor, "readEntries", { scope: handle.scope, entryIds: handle.entryIds });
      if (captures.error !== undefined || entries.error !== undefined) fail("the driver could not read back for a snapshot");
      parts.push(
        captures.result,
        [...entries.result.entries].sort((a, b) => (a.entryId < b.entryId ? -1 : 1)),
      );
    }
    return JSON.stringify(parts);
  }

  async stepSnapshot(step, scope) {
    const handles = step.captures.map((name) => this.lookup(name, scope));
    this.save(step.snapshot, await this.fingerprint(handles, step.actor ?? this.firstActor()), scope);
  }

  async stepExpectSnapshot(step, scope) {
    const handles = step.captures.map((name) => this.lookup(name, scope));
    const now = await this.fingerprint(handles, step.actor ?? this.firstActor());
    const before = this.lookup(step.expectSnapshot, scope);
    if (now !== before) fail(`${step.what ?? "state"}: the stored rows changed, and must not have`);
  }

  async stepRestoreRetry(step, scope) {
    const actor = await this.evaluate(step.actor ?? this.firstActor(), scope);
    const bound = await this.evaluate(step.maxTries, scope);
    for (let attempt = 0; attempt < bound; attempt += 1) {
      const input = await this.buildCommit({ ...step, actor }, scope);
      const outcome = await this.call(actor, "commitRestore", input);
      if (outcome.error !== undefined) fail(`commitRestore: unexpected error ${describe(outcome.error)}`);
      if (outcome.result.outcome === "committed") return this.save(step.restoreRetry, "committed", scope);
      if (outcome.result.outcome !== "rejected") fail("a fresh attempt can only be committed or rejected");
      if (outcome.result.reason !== "stale") return this.save(step.restoreRetry, outcome.result.reason, scope);
    }
    return fail("a commit was still stale after every retry; retries must make progress");
  }

  // --- operations, holds, and async ----------------------------------------------

  async stepOp(step, scope) {
    const actor = await this.evaluate(step.actor ?? this.firstActor(), scope);
    const input = step.input === undefined ? undefined : await this.evaluate(step.input, scope);
    const extra = {};
    if (step.fault !== undefined) extra.fault = step.fault;
    let holdId;
    if (step.hold !== undefined) {
      holdId = step.holdId;
      extra.hold = step.hold;
      extra.holdId = holdId;
      let release;
      const reached = new Promise((resolve) => {
        release = resolve;
      });
      this.holds.set(holdId, { reached, markReached: release });
    }
    const what = step.what ?? `${step.op}`;
    const run = async () => {
      let outcome = await this.call(actor, step.op, input, extra);
      if (step.retryOn !== undefined) {
        const pattern = await this.evaluate(step.retryOn, scope);
        const bound = await this.evaluate(step.maxTries ?? 1, scope);
        let tries = 1;
        while (outcome.result !== undefined && this.matches(outcome.result, pattern, scope).ok) {
          if (tries >= bound) fail(`${what}: still ${describe(outcome.result)} after every retry`);
          tries += 1;
          outcome = await this.call(actor, step.op, input, extra);
        }
      }
      return outcome;
    };
    if (step.async !== undefined) {
      const promise = run();
      promise.catch(() => {});
      this.pending.set(step.async, { promise, step, scope, what, settled: false });
      promise.then(() => {
        const entry = this.pending.get(step.async);
        if (entry !== undefined) entry.settled = true;
      });
      if (holdId !== undefined) {
        const reachedFirst = await Promise.race([this.holds.get(holdId).reached.then(() => true), promise.then(() => false)]);
        if (!reachedFirst) fail(`${what}: the call finished without reaching its hold point ${describe(step.hold)}`);
      }
      return;
    }
    if (holdId !== undefined) fail("schedule: a hold needs an async call");
    const outcome = await run();
    await this.expectResult(step, outcome, scope, what);
    if (step.save !== undefined) this.save(step.save, outcome.result ?? { error: outcome.error, ...(outcome.detail ?? {}) }, scope);
  }

  async stepRelease(step, scope) {
    const holdId = await this.evaluate(step.release, scope);
    const response = await this.send(this.firstActor(), { op: "release", holdId });
    if (response.error !== undefined) fail(`release: the driver refused (${describe(response.error)})`);
  }

  async stepAwait(step, scope) {
    const name = step.await;
    const entry = this.pending.get(name);
    if (entry === undefined) fail(`schedule: nothing to await under ${describe(name)}`);
    if (step.within !== undefined) {
      const timer = new Promise((resolve) => setTimeout(() => resolve("timeout"), step.within));
      const winner = await Promise.race([entry.promise.then(() => "settled"), timer]);
      this.save(step.settledAs ?? `${name}_settled`, winner === "settled", scope);
      if (winner !== "settled") return;
    }
    const value = await entry.promise;
    if (entry.parallel === true) {
      if (step.as !== undefined) this.save(step.as, value, scope);
      return;
    }
    await this.expectResult({ ...entry.step, ...pickExpectation(step) }, value, entry.scope, entry.what);
    const target = step.as ?? entry.step.save;
    if (target !== undefined) this.save(target, value.result ?? { error: value.error }, scope);
  }

  async stepParallel(step, scope) {
    const spec = step.parallel;
    const over = await this.evaluate(spec.over, scope);
    const actors = spec.actors ?? [this.firstActor()];
    const work = over.map((item, index) => {
      const local = { $locals: true, ...scope, item, i: index, ACTOR: actors[index % actors.length] };
      return this.runSteps(spec.steps, local).then(() => {
        const out = {};
        for (const [key, value] of Object.entries(local)) if (!["$locals", "ACTOR"].includes(key) && !(key in (scope ?? {}))) out[key] = value;
        out.item = item;
        out.i = index;
        return out;
      });
    });
    const promise = Promise.all(work);
    if (step.async !== undefined) {
      promise.catch(() => {});
      this.pending.set(step.async, { promise, parallel: true, step });
      return;
    }
    this.save(spec.as, await promise, scope);
  }

  async stepLoop(step, scope) {
    const spec = step.loop;
    for (let round = 0; round < spec.max; round += 1) {
      await this.runSteps(spec.steps, scope);
      if ((await this.evaluate(spec.until, scope)) === true) return;
    }
    fail(step.what ?? "a loop did not finish within its bound");
  }

  async stepForEach(step, scope) {
    const spec = step.forEach;
    const over = await this.evaluate(spec.over, scope);
    const collected = [];
    for (const [index, item] of over.entries()) {
      const local = { $locals: true, ...scope, [spec.itemAs ?? "item"]: item, i: index };
      await this.runSteps(spec.steps, local);
      if (spec.collect !== undefined) collected.push(local[spec.collect]);
    }
    if (spec.as !== undefined) this.save(spec.as, collected, scope);
  }

  async finish() {
    for (const holdId of this.holds.keys()) {
      try {
        await this.send(this.firstActor(), { op: "release", holdId });
      } catch {
        /* nothing is held any longer */
      }
    }
    this.holds.clear();
    // Drain anything still in flight so no driver call outlives its case.
    for (const { promise } of this.pending.values()) {
      try {
        await promise;
      } catch {
        /* the case has already been judged */
      }
    }
    for (const stop of this.unsubscribe) stop();
    this.unsubscribe = [];
  }
}

function pickExpectation(step) {
  const out = {};
  for (const key of ["expect", "expectOneOf", "expectError"]) if (step[key] !== undefined) out[key] = step[key];
  return out;
}

/** The capability requirements of a persistent server (docs/specs/persistent-vault.md §4.1), as `missingCapabilities` in vault-contracts. */
export function missingCapabilities(c) {
  if (typeof c !== "object" || c === null) return ["capabilities"];
  const missing = [];
  const positive = (value, ceiling) => Number.isSafeInteger(value) && value >= 1 && (ceiling === undefined || value <= ceiling);
  if (c.contractVersion !== 1) missing.push("contractVersion");
  for (const flag of ["atomicCreate", "atomicRestore", "authoritativeCommit", "revocationFences", "attemptReceipts", "storeClock"]) {
    if (c[flag] !== true) missing.push(flag);
  }
  if (!positive(c.maxCreateEntries, 1024)) missing.push("maxCreateEntries");
  if (!positive(c.maxCreateBytes)) missing.push("maxCreateBytes");
  if (!positive(c.maxRestoreEntries, 1024)) missing.push("maxRestoreEntries");
  if (!positive(c.maxRestoreCaptures, 64)) missing.push("maxRestoreCaptures");
  if (!positive(c.maxEnvelopeBytes, 1_048_576 + 65_536)) missing.push("maxEnvelopeBytes");
  if (!Number.isSafeInteger(c.maxClockSkewMs) || c.maxClockSkewMs < 0 || c.maxClockSkewMs > 60_000) missing.push("maxClockSkewMs");
  if (c.durability !== "volatile" && c.durability !== "durable") missing.push("durability");
  if (typeof c.crossProcess !== "boolean") missing.push("crossProcess");
  if (typeof c.restoreDetection !== "string" || c.restoreDetection.length === 0) missing.push("restoreDetection");
  if (typeof c.adapter !== "string" || typeof c.profile !== "string") missing.push("adapter");
  return missing;
}

// ------------------------------------------------------------------ the run

export async function loadSchedules(url = SCHEDULES_URL) {
  return JSON.parse(await readFile(url, "utf8"));
}

/**
 * Runs the selected cases. `drivers` maps an actor name (or `"*"` for all
 * actors) to a driver. Returns `[{id, group, status, detail, native}]`.
 */
export async function runSchedules({ doc, drivers, options = {} }) {
  const seed = options.seed ?? 20261001;
  const results = [];
  for (const schedule of doc.cases) {
    if (options.level !== undefined && schedule.level !== options.level) continue;
    if (options.filter !== undefined && !schedule.id.includes(options.filter)) continue;
    if (options.ids !== undefined && !options.ids.includes(schedule.id)) continue;
    const run = new Run({ doc, schedule, drivers, options, seed });
    const base = { id: schedule.id, group: schedule.group, native: schedule.native ?? null };
    try {
      await run.configure();
      run.checkRequires();
      await run.runSteps(schedule.steps, undefined);
      await run.finish();
      results.push({ ...base, status: "passed" });
    } catch (error) {
      await run.finish();
      if (error instanceof ScheduleSkip) results.push({ ...base, status: "skipped", detail: error.message });
      else if (error instanceof ScheduleFailure) {
        results.push({ ...base, status: "failed", detail: `${schedule.id}: step ${describe(run.where)}: ${error.message} [seed ${seed}]` });
      } else {
        if (options.debug) process.stderr.write(`${error?.stack ?? error}\n`);
        results.push({ ...base, status: "failed", detail: `${schedule.id}: unexpected ${describe(error?.name ?? typeof error)} in the orchestrator [seed ${seed}]` });
      }
    }
    // Each case starts from a fresh store: the driver is told to forget this one.
    const seen = new Set();
    for (const driver of drivers.values()) {
      if (seen.has(driver)) continue;
      seen.add(driver);
      try {
        await driver.request({ op: "reset" });
      } catch {
        /* a driver that has exited is reported by the next case */
      }
    }
  }
  return results;
}

// ---------------------------------------------------------------------- CLI

function parseArgs(argv) {
  const out = { actorDrivers: {} };
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    const value = () => {
      i += 1;
      if (argv[i] === undefined) throw new Error(`missing value for ${arg}`);
      return argv[i];
    };
    if (arg === "--driver") out.driver = value();
    else if (arg === "--actor-driver") {
      const [actor, ...rest] = value().split("=");
      out.actorDrivers[actor] = rest.join("=");
    } else if (arg === "--level") out.level = value();
    else if (arg === "--filter") out.filter = value();
    else if (arg === "--seed") out.seed = Number(value());
    else if (arg === "--parallelism") out.parallelism = Number(value());
    else if (arg === "--store-options") out.storeOptions = JSON.parse(value());
    else if (arg === "--schedules") out.schedules = value();
    else if (arg === "--json") out.json = true;
    else if (arg === "--debug") out.debug = true;
    else throw new Error(`unknown argument ${arg}`);
  }
  return out;
}

function splitCommand(text) {
  const parts = text.match(/"[^"]*"|'[^']*'|\S+/g) ?? [];
  return parts.map((part) => part.replace(/^["']|["']$/g, ""));
}

async function main() {
  let args;
  try {
    args = parseArgs(process.argv.slice(2));
    if (args.driver === undefined) throw new Error("--driver is required");
  } catch (error) {
    process.stderr.write(`orchestrator: ${error.message}\n`);
    process.exit(2);
  }
  const doc = await loadSchedules(args.schedules === undefined ? SCHEDULES_URL : new URL(`file://${args.schedules}`));
  const made = new Map();
  const make = (command) => {
    if (!made.has(command)) {
      const [program, ...rest] = splitCommand(command);
      made.set(command, stdioDriver(program, rest));
    }
    return made.get(command);
  };
  const drivers = new Map([["*", make(args.driver)]]);
  for (const [actor, command] of Object.entries(args.actorDrivers)) drivers.set(actor, make(command));
  const results = await runSchedules({
    doc,
    drivers,
    options: { debug: args.debug, seed: args.seed, parallelism: args.parallelism, level: args.level, filter: args.filter, storeOptions: args.storeOptions },
  });
  for (const driver of made.values()) await driver.close();
  const counts = { passed: 0, failed: 0, skipped: 0 };
  for (const result of results) counts[result.status] += 1;
  if (args.json) {
    process.stdout.write(`${JSON.stringify({ counts, results })}\n`);
  } else {
    for (const result of results) {
      if (result.status !== "passed") process.stdout.write(`${result.status.toUpperCase()} ${result.id}${result.detail === undefined ? "" : `: ${result.detail}`}\n`);
    }
    process.stdout.write(`schedules: ${counts.passed} passed, ${counts.failed} failed, ${counts.skipped} skipped, ${results.length} total\n`);
  }
  process.exit(counts.failed > 0 ? 1 : 0);
}

if (process.argv[1] === fileURLToPath(import.meta.url)) await main();
