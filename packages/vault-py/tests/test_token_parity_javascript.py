"""Token grammar and marker detection against the JavaScript implementation (issue #18, the "candid differences" table).

The two implementations are written differently (JavaScript: ``/r\\p{Cf}*s\\p{Cf}*v\\p{Cf}*_/giu``; Python: strip every
Unicode format character, then search for ``rsv_`` case-insensitively), and their documentation says the Python one is
"slightly more permissive". This test runs the *built* JavaScript ``token.js`` and the Python module over the same
seeded random strings, built from marker letters, format characters (``U+200B``, ``U+00AD``, ``U+FEFF``, ``U+2060``,
``U+200D``, a tag character), case-folding look-alikes (``U+017F``, ``U+0131``, ``U+212A``), and whole and broken
tokens, and requires equal marker counts and equal exact-token matches. Needs ``node`` and a built ``packages/vault``
(``npm run build``); skipped, with the reason, without them. Every string is synthetic.
"""

from __future__ import annotations

import json
import random
import shutil
import subprocess
from pathlib import Path

import pytest

from redact_secret_vault.token import TOKEN_PATTERN, count_markers

REPO = Path(__file__).resolve().parents[3]
TOKEN_JS = REPO / "packages" / "vault" / "dist" / "token.js"

pytestmark = pytest.mark.skipif(
    shutil.which("node") is None or not TOKEN_JS.is_file(),
    reason="node and a built packages/vault are needed (npm run build)",
)

ALPHABET = [
    *"rsvRSV_a <>",
    "​",
    "­",
    "﻿",
    "⁠",
    "‍",
    "\U000e0001",
    "ſ",
    "ı",
    "K",
    "rsv_",
    "<rsv_aaaaaaaaaaaaaaaaaaaaaaaaaa>",
    "<rsv_aaaaaaaaaaaaaaaaaaaaaaaaa>",
    "<rsv_aaaaaaaaaaaaaaaaaaaaaaaaaaa>",
    "<rsv_AAAAAAAAAAAAAAAAAAAAAAAAAA>",
    "<rsv_a1aaaaaaaaaaaaaaaaaaaaaaaa>",
]

SCRIPT = """
import { pathToFileURL } from "node:url";
import { readFileSync } from "node:fs";
const { MARKER_PATTERN, TOKEN_PATTERN, countMatches } = await import(pathToFileURL(process.argv[2]).href);
const lines = readFileSync(process.argv[3], "utf8").split("\\n").filter((line) => line.length > 0);
const texts = lines.map((line) => JSON.parse(line));
console.log(JSON.stringify(texts.map((text) => ({
  markers: countMatches(MARKER_PATTERN, text),
  tokens: [...text.matchAll(new RegExp(TOKEN_PATTERN.source, "g"))].map((m) => m[0]),
}))));
"""


def test_marker_counts_and_exact_token_matches_equal_the_javascript_ones(tmp_path: Path) -> None:
    rng = random.Random(7)
    texts = ["".join(rng.choice(ALPHABET) for _ in range(rng.randint(0, 12))) for _ in range(6000)]
    texts += ["", "plain text", "<rsv_" + "a" * 26 + ">", "r​s‍v⁠_"]
    data = tmp_path / "texts.jsonl"
    data.write_text("".join(json.dumps(text) + "\n" for text in texts), encoding="utf-8")
    script = tmp_path / "compare.mjs"
    script.write_text(SCRIPT)
    done = subprocess.run(
        ["node", str(script), str(TOKEN_JS), str(data)], capture_output=True, text=True, check=True, timeout=120
    )
    js = json.loads(done.stdout)
    assert len(js) == len(texts)
    markers = sum(1 for entry in js if entry["markers"] > 0)
    assert markers > 500, "the generator must exercise the marker"
    different_markers = [i for i, text in enumerate(texts) if count_markers(text) != js[i]["markers"]]
    different_tokens = [i for i, text in enumerate(texts) if TOKEN_PATTERN.findall(text) != js[i]["tokens"]]
    assert different_markers == [], f"{len(different_markers)} strings with another marker count"
    assert different_tokens == [], f"{len(different_tokens)} strings with other exact-token matches"
