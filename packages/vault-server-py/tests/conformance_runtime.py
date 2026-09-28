"""Interpreter for the shared language-neutral conformance corpus
(``conformance/v1/corpus.json``), adapted from the reference JS runner
(``packages/vault/test/suite.js``) to this package's async, principal/policy
-aware ``InMemoryVaultServer`` API.

The corpus was written against the single-tenant, single-process in-memory
vault (V2/V3): it has no tenant, purpose, or principal concept. To replay it
against the S1 server-authority layer, every case runs under one fixed
synthetic principal/tenant/purpose so none of the *new* S1 checks (steps 1,
4, 7 of the restore preflight) fire unless a case is specifically about them
— those are covered separately in ``test_server_authority.py``. This module
therefore proves: given the same tenant/purpose/principal on every call, the
S1 server produces the same capture/restore/revoke/lifecycle/limit outcomes
as `@redact-secret/vault` for the corpus's V2/V3 classes.

One case, ``policy.throwing-callback-denies``, is a deliberate, documented
exception (see ``_POLICY_REASON_OVERRIDES`` below): the vault-level
``ReleasePolicy`` and the S1 ``ServerReleasePolicy`` disagree, by contract,
on what a throwing policy callback means.

PII activation (corpus 1.2.0, #42). Every case runs in one of two *lanes*,
``PII_LANES``: ``off`` gives each ``NodeCoreBridge`` the selection ``()``
(``selectors=off``) and ``on`` gives it ``("pii",)`` (``selectors=pii:global``).
A case's ``piiActivation`` restricts it to the matching lane; the runner
raises ``CaseSkipped`` otherwise. Two adapter rules differ from the JS
runner, where activation is realm-global and one-shot:

- The bridge starts a fresh core per ``scan``, so an activation conflict
  cannot arise. Cases marked ``requiresSharedRealm`` raise ``CaseSkipped``.
- The bridge reports its activation only on its first core call, not at
  construction. A ``vault`` step whose ``expect`` names an error therefore
  makes one ``scan("")`` call right after construction, and that call must
  raise the expected error (``PII_ACTIVATION_MISMATCH`` for an
  ``expectPiiActivation`` the core does not report).
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from redact_secret_vault_server import (
    CaptureGrant,
    CaptureOptions,
    InMemoryVaultServer,
    NodeCoreBridge,
    PiiRetention,
    PolicyDecision,
    Principal,
    RestoreRequest,
    ServerDenialReason,
    VaultServerError,
)

CORPUS_PATH = Path(__file__).resolve().parents[3] / "conformance" / "v1" / "corpus.json"

# One fixed synthetic principal/tenant/purpose for the whole corpus replay —
# see the module docstring for why.
SYNTHETIC_TENANT = "tenant-conformance-synthetic"
SYNTHETIC_PURPOSE = "conformance-purpose-synthetic"

_LIMIT_KEY_MAP = {
    "maxEntries": "max_entries",
    "maxRetainedBytes": "max_retained_bytes",
    "maxValueBytes": "max_value_bytes",
    "entryTtlMs": "entry_ttl_ms",
    "vaultTtlMs": "vault_ttl_ms",
    "maxInputBytes": "max_input_bytes",
    "maxFindings": "max_findings",
    "maxRestoreFields": "max_restore_fields",
    "maxRestoreFieldBytes": "max_restore_field_bytes",
    "maxUsesPerEntry": "max_uses_per_entry",
}

# Cases where this package's S1 server intentionally reports a different
# (still-conformant) denial reason than the in-memory vault, each traced to
# an explicit ADR allowance:
#
# - "policy.throwing-callback-denies": the S1 ADR's ServerReleasePolicy
#   contract diverges from the in-memory vault's boolean ReleasePolicy by
#   design — a throwing policy is "policy-evaluation-error" (ADR section 3),
#   not "policy".
# - "lifecycle.revoke-before-restore" / "lifecycle.restore-before-revoke":
#   this server keeps a short-lived revocation tombstone (ADR section 4
#   explicitly permits this), so a restore attempt against a token an
#   explicit `revoke()` call just removed reports "revoked" rather than
#   "unknown-token". The in-memory vault keeps no tombstone and reports
#   "unknown-token" for the same case; the ADR states both are conformant.
_POLICY_REASON_OVERRIDES = {
    "policy.throwing-callback-denies": "policy-evaluation-error",
    "lifecycle.revoke-before-restore": "revoked",
    "lifecycle.restore-before-revoke": "revoked",
}

TOKEN_RE = re.compile(r"^<rsv_[a-z2-7]{26}>$")

_TEMPLATE_PATTERN = re.compile(
    r"\{([A-Za-z0-9_]+)(?:\.([a-z0-9]+))?(?::([a-z]+))?\}|\{repeat:(.):(\d+)\}"
)


class ConformanceFailure(AssertionError):
    pass


class CaseSkipped(Exception):
    """The case does not apply to this lane or to the per-call bridge realm."""


# lane name -> the PII selection every bridge in that lane forwards.
PII_LANES: dict[str, tuple[str, ...]] = {"off": (), "on": ("pii",)}


def case_skip_reason(case: dict[str, Any], lane: str) -> str | None:
    """Why ``case`` does not run in ``lane``, or ``None`` when it does."""

    required = case.get("piiActivation")
    if required is not None and required != lane:
        return f"needs PII activation {required}, lane is {lane}"
    if case.get("requiresSharedRealm"):
        return (
            "needs one realm-global core activation shared by every vault; "
            "NodeCoreBridge starts a fresh core per scan, so no activation conflict can arise"
        )
    return None


def load_corpus() -> dict[str, Any]:
    return json.loads(CORPUS_PATH.read_text())


def _resolve_principal(_context: Any) -> Principal:
    return Principal(id="user-conformance-synthetic", tenant=SYNTHETIC_TENANT)


def _allow_all(_input: Any) -> PolicyDecision:
    return PolicyDecision(allow=True)


def _make_release_policy(spec: dict[str, Any] | None):
    """Adapts a corpus ``releasePolicy`` spec (written for the vault-level
    boolean ``ReleasePolicy``) to an S1 ``ServerReleasePolicy``. Absent a
    spec, the in-memory vault performs no policy check at all (implicit
    allow) — reproduced here as an explicit allow-all policy, since the S1
    server fails closed when no policy is configured at all."""

    if spec is None:
        return _allow_all
    if spec.get("throw"):

        def _throwing(_input: Any) -> PolicyDecision:
            raise RuntimeError("policy failure (conformance fixture, synthetic)")

        return _throwing
    if "returns" in spec:
        value = spec["returns"]

        def _returns(_input: Any) -> PolicyDecision:
            if value is True:
                return PolicyDecision(allow=True)
            return PolicyDecision(allow=False, reason=ServerDenialReason.POLICY)

        return _returns
    deny_types = set(spec.get("denyTypes", []))

    def _deny_types(input: Any) -> PolicyDecision:
        if input.type in deny_types:
            return PolicyDecision(allow=False, reason=ServerDenialReason.POLICY)
        return PolicyDecision(allow=True)

    return _deny_types


def _translate_limits(limits: dict[str, int] | None) -> dict[str, int] | None:
    if not limits:
        return None
    return {_LIMIT_KEY_MAP[key]: value for key, value in limits.items()}


def _expand(template: str, fixtures: dict[str, str], captures: dict[str, dict[str, Any]]) -> str:
    def repl(match: re.Match[str]) -> str:
        name, index, transform, ch, n = match.groups()
        if ch is not None:
            return ch * int(n)
        if index is None:
            if name not in fixtures:
                raise ConformanceFailure(f"unknown fixture {name}")
            return fixtures[name]
        capture = captures.get(name)
        if capture is None:
            raise ConformanceFailure(f"unknown capture {name}")
        value = capture["text"] if index == "text" else capture["tokens"][int(index)]
        if value is None:
            raise ConformanceFailure(f"capture {name} has no {index}")
        if transform == "upper":
            value = value.upper()
        elif transform == "truncate":
            value = value[:-3] + ">"
        elif transform == "space":
            value = "< " + value[1:]
        elif transform == "zwsp":
            value = value[:2] + "​" + value[2:]
        return value

    return _TEMPLATE_PATTERN.sub(repl, template)


def _check_error(
    where: str,
    expect: dict[str, Any],
    error: VaultServerError | None,
    *,
    reason_override: str | None = None,
) -> None:
    if "error" not in expect:
        if error is not None:
            raise ConformanceFailure(f"{where}: unexpected {error.code}/{error.reason}")
        return
    if error is None:
        raise ConformanceFailure(f"{where}: expected {expect['error']}, operation succeeded")
    if error.code.value != expect["error"]:
        raise ConformanceFailure(f"{where}: expected {expect['error']}, got {error.code.value}")
    expected_reason = reason_override or expect.get("reason")
    if expected_reason is not None:
        actual = error.reason.value if error.reason is not None else None
        if actual != expected_reason:
            raise ConformanceFailure(f"{where}: expected reason {expected_reason}, got {actual}")
    if expect.get("coreCode") and error.core_code != expect["coreCode"]:
        raise ConformanceFailure(f"{where}: expected core {expect['coreCode']}, got {error.core_code}")


async def run_case(
    case: dict[str, Any],
    fixtures: dict[str, str],
    *,
    observed: dict[str, list[Any]] | None = None,
    lane: str = "off",
) -> None:
    """Raises ``ConformanceFailure`` on the first mismatch, or
    ``CaseSkipped`` when the case does not apply to ``lane``.

    ``observed``, when given, collects every ``VaultServerError`` raised and
    every audit event emitted, for a leakage check across the whole corpus
    (see ``test_leakage_across_corpus`` in ``test_conformance.py``).
    """

    skip = case_skip_reason(case, lane)
    if skip is not None:
        raise CaseSkipped(skip)
    lane_selection = PII_LANES[lane]
    clock = {"value": 0}
    vaults: dict[str, InMemoryVaultServer] = {}
    captures: dict[str, dict[str, Any]] = {}

    def where(i: int) -> str:
        return f"{case['id']} step {i}"

    def on_audit(event: Any) -> None:
        if observed is not None:
            observed["audit"].append(event)

    for i, step in enumerate(case["steps"]):
        op = step["op"]

        if op == "vault":
            expect = step.get("expect", {})
            try:
                bridge = NodeCoreBridge(
                    pii=tuple(step.get("pii", lane_selection)),
                    expected_pii_activation=step.get("expectPiiActivation"),
                )
                if "error" in expect:
                    # The bridge observes activation on its first core call.
                    bridge.scan("")
                error = None
            except VaultServerError as exc:
                error = exc
            if observed is not None and error is not None:
                observed["errors"].append(error)
            _check_error(where(i), expect, error)
            if error is not None:
                continue
            server = InMemoryVaultServer(
                core_client=bridge,
                principal_resolver=_resolve_principal,
                release_policy=_make_release_policy(step.get("releasePolicy")),
                on_audit=on_audit if observed is not None else None,
                limits=_translate_limits(step.get("limits")),
                now=lambda: clock["value"],
            )
            vaults[step.get("id", "A")] = server
            continue

        vault_name = step.get("vault", "A")
        server = vaults[vault_name]
        expect = step.get("expect", {})

        if op == "capture":
            options = step["options"]
            eligible_types = options.get("eligibleTypes")
            pii_option = options.get("pii")
            capture_options = CaptureOptions(
                issued_tenant=SYNTHETIC_TENANT,
                release=tuple(
                    CaptureGrant(sink=g["sink"], paths=tuple(g["paths"]))
                    for g in options.get("release", [])
                ),
                max_uses=options.get("maxUses", 1),
                unredacted=options.get("unredacted", "reject"),
                policy=options.get("policy"),
                eligible=(lambda f, _t=eligible_types: f["type"] in _t) if eligible_types else None,
                pii=PiiRetention(retain=tuple(pii_option["retain"])) if pii_option is not None else None,
            )
            input_text = _expand(step["input"], fixtures, captures)
            try:
                result = server.capture(input_text, capture_options)
                error = None
            except VaultServerError as exc:
                result, error = None, exc
            if observed is not None and error is not None:
                observed["errors"].append(error)
            _check_error(where(i), expect, error)
            if error is not None:
                continue
            if step.get("as"):
                captures[step["as"]] = {
                    "capture_id": result.capture_id,
                    "text": result.text,
                    "tokens": [t.token for t in result.tokens],
                    "vault": vault_name,
                }
            if "tokens" in expect and len(result.tokens) != expect["tokens"]:
                raise ConformanceFailure(f"{where(i)}: expected {expect['tokens']} tokens, got {len(result.tokens)}")
            if "types" in expect and [t.type for t in result.tokens] != expect["types"]:
                raise ConformanceFailure(f"{where(i)}: token types differ")
            if "passedThrough" in expect and result.passed_through != expect["passedThrough"]:
                raise ConformanceFailure(f"{where(i)}: passedThrough {result.passed_through}")
            if "passedThroughTypes" in expect and list(result.passed_through_types) != expect["passedThroughTypes"]:
                raise ConformanceFailure(f"{where(i)}: passedThroughTypes differ")
            if "unrestorable" in expect and result.unrestorable != expect["unrestorable"]:
                raise ConformanceFailure(f"{where(i)}: unrestorable {result.unrestorable}")
            if "text" in expect and result.text != _expand(expect["text"], fixtures, captures):
                raise ConformanceFailure(f"{where(i)}: text differs")
            for t in expect.get("textIncludes", []):
                if _expand(t, fixtures, captures) not in result.text:
                    raise ConformanceFailure(f"{where(i)}: text lacks an expected span")
            for t in expect.get("textExcludes", []):
                if _expand(t, fixtures, captures) in result.text:
                    raise ConformanceFailure(f"{where(i)}: text still contains a redacted value")
            if expect.get("distinctTokens") and len({t.token for t in result.tokens}) != len(result.tokens):
                raise ConformanceFailure(f"{where(i)}: tokens not distinct")
            for t in result.tokens:
                if not TOKEN_RE.match(t.token):
                    raise ConformanceFailure(f"{where(i)}: token grammar")
            continue

        if op == "restore":
            fields = {k: _expand(v, fixtures, captures) for k, v in step["fields"].items()}
            if "captures" in step:
                capture_ids = tuple(captures[name]["capture_id"] for name in step["captures"])
            else:
                capture_ids = tuple(
                    c["capture_id"] for c in captures.values() if c["vault"] == vault_name
                )
            request = RestoreRequest(
                sink=step["sink"],
                captures=capture_ids,
                fields=fields,
                purpose=SYNTHETIC_PURPOSE,
                tenant=SYNTHETIC_TENANT,
                context={},
            )
            try:
                result = await server.restore(request)
                error = None
            except VaultServerError as exc:
                result, error = None, exc
            if observed is not None and error is not None:
                observed["errors"].append(error)
            override = _POLICY_REASON_OVERRIDES.get(case["id"])
            _check_error(where(i), expect, error, reason_override=override)
            if error is not None:
                continue
            for path, text in expect.get("fields", {}).items():
                expected = _expand(text, fixtures, captures)
                if result.fields[path] != expected:
                    raise ConformanceFailure(f"{where(i)}: field {path} differs")
            if set(result.fields.keys()) != set(fields.keys()):
                raise ConformanceFailure(f"{where(i)}: field set differs")
            if "restored" in expect and result.restored != expect["restored"]:
                raise ConformanceFailure(f"{where(i)}: restored {result.restored}")
            continue

        if op == "revoke":
            capture_id = captures.get(step["capture"], {}).get("capture_id", "cap_unknown")
            try:
                removed = server.revoke(capture_id)
                error = None
            except VaultServerError as exc:
                removed, error = None, exc
            if observed is not None and error is not None:
                observed["errors"].append(error)
            _check_error(where(i), expect, error)
            if error is None and "removed" in expect and removed != expect["removed"]:
                raise ConformanceFailure(f"{where(i)}: removed {removed}")
            continue

        if op == "advance":
            clock["value"] += step["ms"]
            continue

        if op == "dispose":
            server.dispose()
            continue

        if op == "stats":
            stats = server.stats()
            stats_map = {
                "entries": stats.entries,
                "retainedBytes": stats.retained_bytes,
                "captures": stats.captures,
                "disposed": stats.disposed,
                "expiresAt": stats.expires_at,
            }
            for key, value in expect.items():
                if stats_map.get(key) != value:
                    raise ConformanceFailure(f"{where(i)}: stats.{key} = {stats_map.get(key)}, expected {value}")
            continue

        raise ConformanceFailure(f"{where(i)}: unknown op {op}")
