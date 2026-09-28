"""PII retention in ``InMemoryVaultServer.capture`` (PII ADR §1).

docs/decisions/2026-09-27-decide-pii-retention-and-activation-ownership.md
§1 and §3 "Python bridge". A fake ``CoreClient`` supplies the findings and the
observed activation identity, so these cases run without Node.js and do not
depend on which core version is installed. The rules mirror the main-thread
vault (``packages/vault/src/pii.ts`` and the capture loop in
``packages/vault/src/vault.ts``) exactly.

All literals are unmistakably synthetic (``*-synthetic*``). Finding types are
public ``pii_`` type names; the fake core never sees a real value.
"""

from __future__ import annotations

import asyncio
from collections.abc import Mapping

import pytest

from redact_secret_vault_server import (
    CaptureGrant,
    CaptureOptions,
    CoreFinding,
    CoreScanOutcome,
    InMemoryVaultServer,
    PiiRetention,
    PolicyDecision,
    Principal,
    RestoreRequest,
    VaultServerError,
    VaultServerErrorCode,
)
from redact_secret_vault_server.pii import is_pii_active, resolve_pii_retention

TENANT = "tenant-acme-synthetic"
SINK = "reply-sink-synthetic"
RELEASE = (CaptureGrant(sink=SINK, paths=("body",)),)
ACTIVE = "credentials=full;selectors=pii:global;families=pii:global:iban;vocabulary=pii-context/v1"
OFF = "credentials=full;selectors=off;families=;vocabulary=pii-context/v1"

# Input: a credential-shaped value and a PII-shaped value, both synthetic.
CRED = "cred-synthetic-0001"
IBAN_LIKE = "iban-synthetic-0002"
TEXT = f"a {CRED} b {IBAN_LIKE} c"


def _finding(fid: str, ftype: str, value: str, action: str = "redact") -> CoreFinding:
    start = TEXT.index(value)
    return CoreFinding(
        id=fid,
        type=ftype,
        detector="fake-detector",
        confidence="high",
        obfuscation="none",
        start=start,
        end=start + len(value),
        action=action,
    )


FINDINGS = (
    _finding("finding-1", "github_token", CRED),
    _finding("finding-2", "pii_global_iban", IBAN_LIKE),
)


class FakeCore:
    def __init__(self, activation: str | None = ACTIVE, findings=FINDINGS) -> None:
        self.activation = activation
        self.findings = findings
        self.calls = 0

    def scan(
        self,
        text: str,
        *,
        policy: Mapping[str, str] | None = None,
        limits: Mapping[str, int] | None = None,
    ) -> CoreScanOutcome:
        self.calls += 1
        return CoreScanOutcome(
            findings=self.findings,
            core_version="fake",
            artifact="fake",
            pii_activation=self.activation,
        )


def _server(core: FakeCore) -> InMemoryVaultServer:
    return InMemoryVaultServer(
        core_client=core,
        principal_resolver=lambda _ctx: Principal(id="user-synthetic-1", tenant=TENANT),
        release_policy=lambda _input: PolicyDecision(allow=True),
    )


def _capture(core: FakeCore, **kwargs):
    return _server(core).capture(TEXT, CaptureOptions(issued_tenant=TENANT, release=RELEASE, **kwargs))


# -- Default: PII is never retained -----------------------------------------


def test_pii_not_retained_by_default():
    result = _capture(FakeCore())
    assert [t.type for t in result.tokens] == ["github_token"]
    assert result.unrestorable == 1
    assert IBAN_LIKE not in result.text
    assert "<SECRET_2>" in result.text


def test_allow_all_eligible_does_not_retain_pii_and_is_not_called_for_it():
    seen: list[str] = []

    def allow_all(finding):
        seen.append(finding["type"])
        return True

    result = _capture(FakeCore(), eligible=allow_all)
    assert [t.type for t in result.tokens] == ["github_token"]
    assert result.unrestorable == 1
    assert seen == ["github_token"]


def test_pii_outside_allowlist_not_retained_and_eligible_not_called():
    seen: list[str] = []

    def allow_all(finding):
        seen.append(finding["type"])
        return True

    result = _capture(
        FakeCore(), pii=PiiRetention(retain=("pii_global_email",)), eligible=allow_all
    )
    assert [t.type for t in result.tokens] == ["github_token"]
    assert result.unrestorable == 1
    assert seen == ["github_token"]


def test_allowlisted_pii_retained_and_restorable():
    async def run():
        server = _server(FakeCore())
        result = server.capture(
            TEXT,
            CaptureOptions(
                issued_tenant=TENANT, release=RELEASE, pii=PiiRetention(retain=("pii_global_iban",))
            ),
        )
        assert sorted(t.type for t in result.tokens) == ["github_token", "pii_global_iban"]
        assert result.unrestorable == 0
        assert IBAN_LIKE not in result.text
        pii_token = next(t.token for t in result.tokens if t.type == "pii_global_iban")
        restored = await server.restore(
            RestoreRequest(
                sink=SINK,
                captures=(result.capture_id,),
                fields={"body": f"x {pii_token} y"},
                purpose="purpose-synthetic",
                tenant=TENANT,
            )
        )
        assert restored.fields["body"] == f"x {IBAN_LIKE} y"

    asyncio.run(run())


def test_eligible_narrows_the_pii_allowlist():
    seen: list[str] = []

    def no_iban(finding):
        seen.append(finding["type"])
        return finding["type"] != "pii_global_iban"

    result = _capture(FakeCore(), pii=PiiRetention(retain=("pii_global_iban",)), eligible=no_iban)
    assert [t.type for t in result.tokens] == ["github_token"]
    assert result.unrestorable == 1
    assert seen == ["github_token", "pii_global_iban"]


def test_duplicates_and_unknown_well_formed_types_are_accepted():
    result = _capture(
        FakeCore(),
        pii=PiiRetention(retain=("pii_global_iban", "pii_global_iban", "pii_future_family_synthetic")),
    )
    assert sorted(t.type for t in result.tokens) == ["github_token", "pii_global_iban"]


def test_block_still_rejects_pii_and_warn_still_gates():
    blocked = FakeCore(findings=(_finding("finding-1", "pii_global_iban", IBAN_LIKE, action="block"),))
    with pytest.raises(VaultServerError) as excinfo:
        _capture(blocked, pii=PiiRetention(retain=("pii_global_iban",)))
    assert excinfo.value.code == VaultServerErrorCode.BLOCKED_FINDING

    warned = FakeCore(findings=(_finding("finding-1", "pii_global_iban", IBAN_LIKE, action="warn"),))
    with pytest.raises(VaultServerError) as excinfo:
        _capture(warned)
    assert excinfo.value.code == VaultServerErrorCode.UNREDACTED_FINDINGS
    passed = _capture(warned, unredacted="pass-through")
    assert passed.passed_through_types == ("pii_global_iban",)


# -- Validation and availability ---------------------------------------------


@pytest.mark.parametrize(
    "pii",
    [
        {"retain": ("pii_global_iban",)},  # not a PiiRetention
        PiiRetention(retain=()),  # empty
        PiiRetention(retain="pii_global_iban"),  # a bare str, not a sequence
        PiiRetention(retain=tuple(f"pii_t{i}" for i in range(65))),  # > 64
        PiiRetention(retain=("pii_",)),  # prefix alone
        PiiRetention(retain=("pii_*",)),  # wildcard
        PiiRetention(retain=("pii:global",)),  # a selector, not a type
        PiiRetention(retain=("github_token",)),  # not a PII type
        PiiRetention(retain=("PII_GLOBAL_IBAN",)),  # uppercase
        PiiRetention(retain=("pii_global_iban\n",)),  # trailing newline
        PiiRetention(retain=("pii_" + "a" * 125,)),  # 129 characters
        PiiRetention(retain=(1,)),  # not a string
    ],
)
def test_malformed_pii_retention_is_invalid_argument_before_availability(pii):
    # `activation=None` would raise PII_UNAVAILABLE; INVALID_ARGUMENT wins
    # and the core is never called.
    core = FakeCore(activation=None)
    with pytest.raises(VaultServerError) as excinfo:
        _capture(core, pii=pii)
    assert excinfo.value.code == VaultServerErrorCode.INVALID_ARGUMENT
    assert core.calls == 0


def test_longest_valid_type_is_accepted():
    assert resolve_pii_retention(PiiRetention(retain=("pii_" + "a" * 124,))) == frozenset({"pii_" + "a" * 124})


@pytest.mark.parametrize("activation", [None, OFF, "credentials=full;families=;vocabulary=v", "selectors=", ""])
def test_pii_retention_without_active_pii_is_unavailable(activation):
    with pytest.raises(VaultServerError) as excinfo:
        _capture(FakeCore(activation=activation), pii=PiiRetention(retain=("pii_global_iban",)))
    assert excinfo.value.code == VaultServerErrorCode.PII_UNAVAILABLE
    assert str(excinfo.value) == "PII_UNAVAILABLE"


def test_no_pii_option_is_unchanged_on_a_core_without_pii():
    result = _capture(FakeCore(activation=None, findings=FINDINGS[:1]))
    assert [t.type for t in result.tokens] == ["github_token"]


def test_is_pii_active_mirrors_the_js_rule():
    assert is_pii_active(ACTIVE)
    assert not is_pii_active(None)
    assert not is_pii_active(OFF)
    assert not is_pii_active("credentials=full")
    # The first `selectors=` field decides, as `Array.prototype.find` does.
    assert not is_pii_active("selectors=off;selectors=pii")
