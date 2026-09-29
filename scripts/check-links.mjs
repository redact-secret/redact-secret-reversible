#!/usr/bin/env node
// Checks that every relative link and image in tracked Markdown files points
// at a tracked file or directory, and that `#anchor` fragments on Markdown
// targets match a heading there. External (scheme) links are ignored.
// Usage: node scripts/check-links.mjs [file.md ...]   (default: git ls-files)
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { dirname, join, normalize, relative, resolve } from "node:path";

const root = execFileSync("git", ["rev-parse", "--show-toplevel"], { encoding: "utf8" }).trim();
const tracked = execFileSync("git", ["ls-files", "-z"], { cwd: root, encoding: "utf8" })
  .split("\0")
  .filter(Boolean);
const files = new Set(tracked);
const dirs = new Set([""]);
for (const file of tracked) {
  for (let d = dirname(file); d !== "." && !dirs.has(d); d = dirname(d)) dirs.add(d);
}

const argv = process.argv.slice(2);
const targets = argv.length
  ? argv.map((f) => relative(root, resolve(f)))
  : tracked.filter((f) => f.endsWith(".md"));

// Lines outside fenced code blocks (fenced lines become ""); with
// `blankCode`, inline code spans are blanked out too.
function proseLines(text, blankCode = true) {
  const out = [];
  let fence = null;
  for (const line of text.split("\n")) {
    const m = line.match(/^\s*(`{3,}|~{3,})/);
    if (fence) {
      if (m && m[1][0] === fence[0] && m[1].length >= fence.length) fence = null;
      out.push("");
      continue;
    }
    if (m) {
      fence = m[1];
      out.push("");
      continue;
    }
    out.push(blankCode ? line.replace(/(`+)(?:(?!\1).)+?\1/g, (s) => " ".repeat(s.length)) : line);
  }
  return out;
}

// GitHub heading slugs, including the -1, -2 suffixes for duplicates.
const anchorCache = new Map();
function anchorsOf(file) {
  if (anchorCache.has(file)) return anchorCache.get(file);
  const seen = new Map();
  const anchors = new Set();
  for (const line of proseLines(readFileSync(join(root, file), "utf8"), false)) {
    const m = line.match(/^ {0,3}#{1,6}\s+(.*?)\s*#*\s*$/);
    if (m) {
      const base = m[1]
        .replace(/!?\[([^\]]*)\]\([^)]*\)/g, "$1")
        .replace(/<[^>]+>/g, "")
        .toLowerCase()
        .replace(/[^\p{L}\p{N}\p{M}\s_-]/gu, "")
        .replace(/\s/g, "-");
      const n = seen.get(base) ?? 0;
      seen.set(base, n + 1);
      anchors.add(n ? `${base}-${n}` : base);
    }
    for (const a of line.matchAll(/<a\s+(?:name|id)="([^"]+)"/g)) anchors.add(a[1]);
  }
  anchorCache.set(file, anchors);
  return anchors;
}

const linkPatterns = [
  /!?\[(?:[^\]]|\\\])*\]\(\s*<([^>]+)>[^)]*\)/g, // [text](<target>)
  /!?\[(?:[^\]]|\\\])*\]\(\s*([^)\s]+)(?:\s+"[^"]*")?\s*\)/g, // [text](target "title")
  /^\s{0,3}\[[^\]]+\]:\s*<?([^\s>]+)>?/g, // [ref]: target
  /\b(?:href|src)="([^"]+)"/g, // inline HTML
];

const broken = [];
for (const file of targets) {
  const lines = proseLines(readFileSync(join(root, file), "utf8"));
  lines.forEach((line, i) => {
    for (const pattern of linkPatterns) {
      for (const match of line.matchAll(pattern)) {
        const raw = match[1];
        if (/^[a-z][a-z0-9+.-]*:/i.test(raw) || raw.startsWith("//")) continue;
        const [pathPart, anchor] = raw.split("#", 2);
        let decoded;
        try {
          decoded = decodeURIComponent(pathPart);
        } catch {
          decoded = pathPart;
        }
        const target = pathPart
          ? normalize(decoded.startsWith("/") ? decoded.slice(1) : join(dirname(file), decoded)).replace(/\/$/, "")
          : file;
        const where = `${file}:${i + 1}`;
        if (target.startsWith("..")) {
          broken.push(`${where}: ${raw} (outside the repository)`);
        } else if (target !== file && !files.has(target) && !dirs.has(target === "." ? "" : target)) {
          broken.push(`${where}: ${raw} (no such file)`);
        } else if (anchor && target.endsWith(".md") && !anchorsOf(target).has(anchor.toLowerCase())) {
          broken.push(`${where}: ${raw} (no heading #${anchor} in ${target})`);
        }
      }
    }
  });
}

if (broken.length) {
  console.error(`${broken.length} broken relative link(s):`);
  for (const b of broken) console.error(`  ${b}`);
  process.exit(1);
}
console.log(`check-links: ${targets.length} Markdown file(s), no broken relative links`);
