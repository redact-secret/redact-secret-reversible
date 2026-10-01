#!/usr/bin/env python3
"""Independent cross-check of vectors.json.

Uses none of the JavaScript package's code: the byte layouts below are
written from docs/specs/persistent-vault.md, hashing and HKDF come from the
Python standard library, and AES-256-GCM comes from the `cryptography`
package.

    python3 conformance/persistent/v1/verify_vectors.py
    uv run --with cryptography python conformance/persistent/v1/verify_vectors.py

Exit status: 0 when every check passed, 1 when a check failed, 3 when
`cryptography` is not importable (the hash and HKDF checks still run and are
reported, but the AES-GCM checks did not, so the run is not a pass).
"""

from __future__ import annotations

import hashlib
import hmac
import json
import struct
import sys
from pathlib import Path

try:
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except ImportError:  # pragma: no cover - depends on the environment
    AESGCM = None
    InvalidTag = Exception

VECTORS = Path(__file__).with_name("vectors.json")
ZERO_SALT = bytes(32)


def utf8(text: str) -> bytes:
    # "strict" refuses a lone surrogate instead of substituting for it.
    return text.encode("utf-8", "strict")


def lp16(data: bytes | str) -> bytes:
    raw = utf8(data) if isinstance(data, str) else data
    return struct.pack(">H", len(raw)) + raw


def lp32(data: bytes) -> bytes:
    return struct.pack(">I", len(data)) + data


def label(name: str) -> bytes:
    return name.encode("ascii") + b"\x00"


def hkdf_sha256(ikm: bytes, info: bytes, length: int = 32) -> bytes:
    """RFC 5869 with a 32-byte zero salt, written out with hmac only."""
    prk = hmac.new(ZERO_SALT, ikm, hashlib.sha256).digest()
    okm = b""
    block = b""
    counter = 1
    while len(okm) < length:
        block = hmac.new(prk, block + info + bytes([counter]), hashlib.sha256).digest()
        okm += block
        counter += 1
    return okm[:length]


def mac(mode: str, key_hex: str | None, message: bytes) -> bytes:
    if mode == "keyed":
        return hmac.new(bytes.fromhex(key_hex), message, hashlib.sha256).digest()
    return hashlib.sha256(message).digest()


def entry_key(dek: bytes, entry_id: str) -> bytes:
    return hkdf_sha256(dek, label("rsv-entry-key-v1") + b"\x01" + lp16(entry_id))


def aad_bytes(binding: dict) -> bytes:
    session = binding["sessionId"]
    return (
        label("rsv-aad-v1")
        + b"\x01\x01"
        + lp16(binding["namespace"])
        + lp16(binding["tenant"])
        + lp16(binding["captureId"])
        + lp16(binding["entryId"])
        + (b"\x00" if session is None else b"\x01")
        + lp16("" if session is None else session)
        + struct.pack(">Q", binding["createdAt"])
        + struct.pack(">Q", binding["expiresAt"])
        + struct.pack(">I", binding["maxUses"])
    )


def payload_bytes(payload: dict) -> bytes:
    grants = sorted(payload["grants"], key=lambda grant: utf8(grant["sink"]))
    out = b"\x01" + lp32(bytes.fromhex(payload["value"])) + lp16(payload["type"]) + struct.pack(">H", len(grants))
    for grant in grants:
        paths = sorted(grant["paths"], key=utf8)
        out += lp16(grant["sink"]) + struct.pack(">H", len(paths)) + b"".join(lp16(path) for path in paths)
    revision = payload["policyRevision"]
    out += (b"\x00" if revision is None else b"\x01") + lp16("" if revision is None else revision)
    return out


def request_bytes(request: dict) -> bytes:
    session = request["sessionId"]
    captures = sorted(request["captureIds"], key=utf8)
    uses = sorted(request["uses"], key=lambda use: utf8(use["entryId"]))
    out = (
        label("rsv-request-v1")
        + lp16(request["namespace"])
        + lp16(request["tenant"])
        + lp16(request["principalId"])
        + (b"\x00" if session is None else b"\x01")
        + lp16("" if session is None else session)
        + lp16(request["sink"])
        + lp16(request["purpose"])
        + struct.pack(">H", len(captures))
        + b"".join(lp16(capture) for capture in captures)
        + struct.pack(">H", len(uses))
    )
    for use in uses:
        paths = sorted(use["paths"], key=lambda item: utf8(item["path"]))
        out += lp16(use["entryId"]) + struct.pack(">H", len(paths))
        for item in paths:
            out += lp16(item["path"]) + struct.pack(">I", item["occurrences"])
    return out


def split_envelope(envelope: bytes) -> tuple[bytes, bytes]:
    """Returns (nonce, ciphertext || tag) of a well-formed version 1 envelope."""
    assert envelope[:4] == b"RSVE", "magic"
    assert envelope[4] == 1 and envelope[5] == 1, "version or algorithm"
    nonce = envelope[6:18]
    (length,) = struct.unpack(">I", envelope[18:22])
    assert length == len(envelope) - 22, "length"
    return nonce, envelope[22:]


class Report:
    def __init__(self) -> None:
        self.passed = 0
        self.failed: list[str] = []

    def check(self, name: str, condition: bool) -> None:
        if condition:
            self.passed += 1
        else:
            self.failed.append(name)


def main() -> int:
    vectors = json.loads(VECTORS.read_text(encoding="utf-8"))
    report = Report()

    for i, v in enumerate(vectors["entryId"]):
        preimage = label("rsv-entry-id-v1") + lp16(v["namespace"]) + lp16(v["tenant"]) + lp16(v["token"])
        report.check(f"entryId[{i}] preimage", preimage.hex() == v["preimage"])
        report.check(f"entryId[{i}]", hashlib.sha256(preimage).hexdigest() == v["entryId"])

    for i, v in enumerate(vectors["sessionTag"]):
        s = v["input"]
        preimage = label("rsv-session-tag-v1") + lp16(s["namespace"]) + lp16(s["tenant"]) + lp16(s["captureId"]) + lp16(s["sessionId"])
        report.check(f"sessionTag[{i}]", mac(v["mode"], v["key"], preimage).hex() == v["sessionTag"])

    for i, v in enumerate(vectors["requestDigest"]):
        preimage = request_bytes(v["input"])
        report.check(f"requestDigest[{i}] preimage", preimage.hex() == v["preimage"])
        report.check(f"requestDigest[{i}]", mac(v["mode"], v["key"], preimage).hex() == v["requestDigest"])

    for i, v in enumerate(vectors["entryKey"]):
        report.check(f"entryKey[{i}]", entry_key(bytes.fromhex(v["dek"]), v["entryId"]).hex() == v["entryKey"])

    for i, v in enumerate(vectors["aad"]):
        report.check(f"aad[{i}]", aad_bytes(v["binding"]).hex() == v["aad"])

    for i, v in enumerate(vectors["payload"]):
        report.check(f"payload[{i}]", payload_bytes(v["payload"]).hex() == v["bytes"])

    for i, v in enumerate(vectors["envelope"]):
        report.check(f"envelope[{i}] entry key", entry_key(bytes.fromhex(v["dek"]), v["binding"]["entryId"]).hex() == v["entryKey"])
        report.check(f"envelope[{i}] aad", aad_bytes(v["binding"]).hex() == v["aad"])
        report.check(f"envelope[{i}] plaintext", payload_bytes(v["payload"]).hex() == v["plaintext"])

    for i, v in enumerate(vectors["localWrap"]):
        c = v["context"]
        info = label("rsv-local-wrap-v1") + lp16(c["namespace"]) + lp16(c["tenant"]) + lp16(c["captureId"])
        report.check(f"localWrap[{i}] info", info.hex() == v["info"])
        report.check(f"localWrap[{i}] wrapping key", hkdf_sha256(bytes.fromhex(v["material"]), info).hex() == v["wrappingKey"])

    aead_ran = AESGCM is not None
    if aead_ran:
        for i, v in enumerate(vectors["envelope"]):
            key = entry_key(bytes.fromhex(v["dek"]), v["binding"]["entryId"])
            nonce, sealed = split_envelope(bytes.fromhex(v["envelope"]))
            report.check(f"envelope[{i}] nonce", nonce.hex() == v["nonce"])
            try:
                plaintext = AESGCM(key).decrypt(nonce, sealed, aad_bytes(v["binding"]))
            except InvalidTag:
                plaintext = None
            report.check(f"envelope[{i}] decrypts", plaintext is not None and plaintext.hex() == v["plaintext"])
            resealed = AESGCM(key).encrypt(nonce, payload_bytes(v["payload"]), aad_bytes(v["binding"]))
            report.check(f"envelope[{i}] re-encrypts to the same bytes", resealed == sealed)

        for i, v in enumerate(vectors["localWrap"]):
            wrapped = bytes.fromhex(v["wrappedKey"])
            report.check(f"localWrap[{i}] layout", wrapped[0] == 1 and len(wrapped) == 61 and wrapped[1:13].hex() == v["nonce"])
            try:
                dek = AESGCM(bytes.fromhex(v["wrappingKey"])).decrypt(wrapped[1:13], wrapped[13:], None)
            except InvalidTag:
                dek = None
            report.check(f"localWrap[{i}] unwraps", dek is not None and dek.hex() == v["dek"])

        for i, v in enumerate(vectors["negative"]["open"]):
            if v["error"] != "RECORD_INTEGRITY":
                continue
            key = entry_key(bytes.fromhex(v["dek"]), v["binding"]["entryId"])
            nonce, sealed = split_envelope(bytes.fromhex(v["envelope"]))
            try:
                AESGCM(key).decrypt(nonce, sealed, aad_bytes(v["binding"]))
                authenticated = True
            except InvalidTag:
                authenticated = False
            report.check(f"negative.open[{i}] {v['name']}: must not authenticate", not authenticated)

    for name in report.failed:
        print(f"FAIL {name}")
    print(f"{report.passed} checks passed, {len(report.failed)} failed")
    if report.failed:
        return 1
    if not aead_ran:
        print("SKIPPED: the AES-GCM checks did not run because `cryptography` is not importable.")
        return 3
    print("AES-256-GCM checks ran with the `cryptography` package.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
