"""Loader for conformance/persistent/v1/vectors.json (docs/plans/python-persistence-parity.md section 5.2).

* The path comes from ``RSV_PERSISTENT_VECTORS``, and defaults to the file in the
  repository checkout. The wheel does not ship the vectors, so a run from a
  directory outside the checkout sets the variable.
* The file's ``formatVersion`` must be the major version this loader knows, and
  every group must hold at least the number of cases it held when the loader was
  written, so a truncated file cannot pass.
* ``json.loads`` accepts lone surrogates and returns ``int`` of any size and
  ``float`` for ``1.0``; the tests therefore pass vector inputs through the same
  boundary validation as any other input.
* Bytes are lowercase hexadecimal strings, as the file's README states.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from redact_secret_vault.persistent import Grant, RecordBinding, RecordPayload

ENV = "RSV_PERSISTENT_VECTORS"
DEFAULT = Path(__file__).resolve().parents[3] / "conformance" / "persistent" / "v1" / "vectors.json"
KNOWN_FORMAT_VERSION = 1

MIN_POSITIVE = {
    "entryId": 3,
    "sessionTag": 4,
    "requestDigest": 4,
    "entryKey": 2,
    "aad": 3,
    "payload": 6,
    "envelope": 2,
    "localWrap": 1,
}
MIN_NEGATIVE = {"envelope": 18, "payload": 33, "open": 16, "localUnwrap": 14}

_cache: dict[str, Any] = {}


def vectors_path() -> Path:
    override = os.environ.get(ENV)
    return Path(override) if override else DEFAULT


def load_vectors() -> dict[str, Any]:
    path = vectors_path()
    key = str(path)
    if key not in _cache:
        if not path.is_file():
            raise FileNotFoundError(f"vectors file not found: {path} (set {ENV})")
        data = json.loads(path.read_text(encoding="utf-8"))
        if data.get("formatVersion") != KNOWN_FORMAT_VERSION:
            raise AssertionError(f"unknown vectors formatVersion {data.get('formatVersion')!r}")
        for group, minimum in MIN_POSITIVE.items():
            if len(data[group]) < minimum:
                raise AssertionError(f"vectors group {group} holds {len(data[group])} cases, expected {minimum}")
        for group, minimum in MIN_NEGATIVE.items():
            if len(data["negative"][group]) < minimum:
                raise AssertionError(f"negative group {group} holds fewer than {minimum} cases")
        _cache[key] = data
    return _cache[key]


def binding_from(data: dict[str, Any]) -> RecordBinding:
    return RecordBinding(
        namespace=data["namespace"],
        tenant=data["tenant"],
        capture_id=data["captureId"],
        entry_id=data["entryId"],
        session_id=data["sessionId"],
        created_at=data["createdAt"],
        expires_at=data["expiresAt"],
        max_uses=data["maxUses"],
    )


def payload_from(data: dict[str, Any]) -> RecordPayload:
    return RecordPayload(
        value=bytearray(bytes.fromhex(data["value"])),
        type=data["type"],
        grants=tuple(Grant(g["sink"], tuple(g["paths"])) for g in data["grants"]),
        policy_revision=data["policyRevision"],
    )
