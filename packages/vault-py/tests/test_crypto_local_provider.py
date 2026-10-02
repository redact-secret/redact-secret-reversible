"""The local key provider (docs/specs/persistent-vault.md section 6.3): states, scope, context binding, buffers."""

from __future__ import annotations

import asyncio
import dataclasses
import pickle
from typing import Any

import pytest
from crypto_support import CAPTURE_2, DEK, MATERIAL, NS, TENANT, all_zero, context, track_buffers

pytest.importorskip("cryptography")

from redact_secret_vault.crypto import (  # noqa: E402
    LOCAL_KEY_PROVIDER_PROFILE,
    LocalKey,
    LocalKeyScope,
    create_local_key_provider,
)
from redact_secret_vault.persistent import KeyProviderError, StoredKey  # noqa: E402

OLD = bytes(range(0x10, 0x30))
NEW = bytes(range(0x50, 0x70))


def run(coro: Any) -> Any:
    return asyncio.run(coro)


def code_of(fn: Any) -> str:
    captured: KeyProviderError | None = None
    try:
        fn()
    except KeyProviderError as thrown:
        captured = thrown
    assert captured is not None, "expected an error"
    assert captured.__cause__ is None and captured.__context__ is None
    assert not hasattr(captured, "__notes__")
    return captured.code


def build(keys: Any, scope: Any = None) -> Any:
    return create_local_key_provider(keys=keys, scope=scope or LocalKeyScope((NS,)))


def rotated() -> Any:
    return build(
        (
            LocalKey("2026-10", NEW, "active"),
            LocalKey("2026-07", OLD, "decrypt-only"),
            LocalKey("2025", MATERIAL, "retired"),
        )
    )


def test_the_profile_names_bytes_material_not_the_javascript_profile() -> None:
    provider = build((LocalKey("k", MATERIAL, "active"),))
    assert provider.profile == LOCAL_KEY_PROVIDER_PROFILE == "local-bytes-hkdf-aes-256-gcm-v1"


def test_a_generated_key_is_fresh_random_and_wrapped_under_the_active_key() -> None:
    provider = rotated()
    first = run(provider.generate_data_key(context()))
    second = run(provider.generate_data_key(context()))
    assert isinstance(first.plaintext_key, bytearray) and len(first.plaintext_key) == 32
    assert first.plaintext_key != second.plaintext_key
    assert first.key_ref == "local:2026-10"
    assert len(first.wrapped_key) == 61 and first.wrapped_key[0] == 1
    assert first.wrapped_key != second.wrapped_key
    unwrapped = run(provider.unwrap_data_key(StoredKey(first.key_ref, first.wrapped_key), context()))
    assert unwrapped == first.plaintext_key


def test_active_and_decrypt_only_keys_unwrap_and_a_retired_key_does_not() -> None:
    old_only = build((LocalKey("2026-07", OLD, "active"),))
    made_under_old = run(old_only.generate_data_key(context()))
    provider = rotated()
    got = run(provider.unwrap_data_key(StoredKey(made_under_old.key_ref, made_under_old.wrapped_key), context()))
    assert got == made_under_old.plaintext_key
    retired_only = build((LocalKey("2025", MATERIAL, "active"),))
    made_under_retired = run(retired_only.generate_data_key(context()))
    stored = StoredKey(made_under_retired.key_ref, made_under_retired.wrapped_key)
    assert code_of(lambda: run(provider.unwrap_data_key(stored, context()))) == "KEY_UNAVAILABLE"
    assert "2025" not in provider._held, "the material of a retired key is not kept"


def test_a_decrypt_only_key_never_wraps() -> None:
    provider = rotated()
    for _ in range(5):
        assert run(provider.generate_data_key(context())).key_ref == "local:2026-10"
    stored = StoredKey(
        "local:2026-07", run(build((LocalKey("2026-07", OLD, "active"),)).generate_data_key(context())).wrapped_key
    )
    assert run(provider.rewrap_data_key(stored, context())).key_ref == "local:2026-10"


def test_unwrap_uses_exactly_the_named_key_and_never_tries_another() -> None:
    provider = rotated()
    under_new = run(provider.generate_data_key(context()))
    # The same wrapped bytes under the name of another held key: that key is tried, fails, and nothing else is.
    assert (
        code_of(lambda: run(provider.unwrap_data_key(StoredKey("local:2026-07", under_new.wrapped_key), context())))
        == "KEY_INTEGRITY"
    )
    assert (
        code_of(lambda: run(provider.unwrap_data_key(StoredKey("local:unknown", under_new.wrapped_key), context())))
        == "KEY_UNAVAILABLE"
    )
    assert (
        code_of(lambda: run(provider.unwrap_data_key(StoredKey("2026-10", under_new.wrapped_key), context())))
        == "KEY_UNAVAILABLE"
    )


def test_the_context_is_bound_through_the_derivation() -> None:
    provider = build((LocalKey("k", MATERIAL, "active"),))
    made = run(provider.generate_data_key(context()))
    stored = StoredKey(made.key_ref, made.wrapped_key)
    for other in (
        dataclasses.replace(context(), capture_id=CAPTURE_2),
        dataclasses.replace(context(), tenant="tenant-other-synthetic"),
    ):
        assert code_of(lambda o=other: run(provider.unwrap_data_key(stored, o))) == "KEY_INTEGRITY"
    assert run(provider.unwrap_data_key(stored, context())) == made.plaintext_key


def test_the_scope_is_explicit_and_checked_on_every_call() -> None:
    provider = build((LocalKey("k", MATERIAL, "active"),), LocalKeyScope((NS,), (TENANT,)))
    made = run(provider.generate_data_key(context()))
    outside_ns = dataclasses.replace(context(), namespace="ns-other")
    outside_tenant = context(tenant="tenant-other-synthetic")
    for outside in (outside_ns, outside_tenant):
        assert code_of(lambda o=outside: run(provider.generate_data_key(o))) == "KEY_UNAVAILABLE"
        assert (
            code_of(lambda o=outside: run(provider.unwrap_data_key(StoredKey(made.key_ref, made.wrapped_key), o)))
            == "KEY_UNAVAILABLE"
        )
        assert (
            code_of(lambda o=outside: run(provider.rewrap_data_key(StoredKey(made.key_ref, made.wrapped_key), o)))
            == "KEY_UNAVAILABLE"
        )


def test_construction_requires_one_active_key_unique_ids_valid_material_and_a_scope() -> None:
    ok = LocalKey("k", MATERIAL, "active")
    other = LocalKey("j", OLD, "decrypt-only")
    bad_keys: list[Any] = [
        (),
        [ok],
        (LocalKey("k", MATERIAL, "decrypt-only"),),  # none active
        (ok, LocalKey("j", OLD, "active")),  # two active
        (ok, LocalKey("k", OLD, "decrypt-only")),  # duplicate id
        (LocalKey("", MATERIAL, "active"),),
        (LocalKey("x" * 65, MATERIAL, "active"),),
        (LocalKey("has space", MATERIAL, "active"),),
        (LocalKey("k\n", MATERIAL, "active"),),
        (LocalKey("k", MATERIAL, "paused"),),  # type: ignore[arg-type]
        (LocalKey("k", MATERIAL[:31], "active"),),
        (LocalKey("k", MATERIAL + b"x", "active"),),
        (LocalKey("k", "m" * 32, "active"),),  # type: ignore[arg-type]
        (LocalKey("k", list(MATERIAL), "active"),),  # type: ignore[arg-type]
        (LocalKey(1, MATERIAL, "active"),),  # type: ignore[arg-type]
        (ok, "key"),
        ("key",),
        None,
    ]
    for keys in bad_keys:
        assert code_of(lambda k=keys: build(k)) == "KEY_INVALID_ARGUMENT"
    bad_scopes: list[Any] = [
        None,
        {"namespaces": [NS]},
        LocalKeyScope(()),
        LocalKeyScope([NS]),  # type: ignore[arg-type]
        LocalKeyScope(("bad ns",)),
        LocalKeyScope((NS,), ()),
        LocalKeyScope((NS,), ("",)),
        LocalKeyScope((NS,), ["tenant"]),  # type: ignore[arg-type]
    ]
    for scope in bad_scopes:
        assert code_of(lambda s=scope: create_local_key_provider(keys=(ok, other), scope=s)) == "KEY_INVALID_ARGUMENT"
    assert build((ok, other, LocalKey("r", NEW, "retired")))


def test_accepts_bytearray_material_and_copies_it() -> None:
    caller = bytearray(MATERIAL)
    provider = build((LocalKey("k", caller, "active"),))
    made = run(provider.generate_data_key(context()))
    caller[:] = bytes(32)  # the caller overwrites its buffer after construction
    assert run(provider.unwrap_data_key(StoredKey(made.key_ref, made.wrapped_key), context())) == made.plaintext_key


def test_invalid_call_arguments_are_key_invalid_argument() -> None:
    provider = build((LocalKey("k", MATERIAL, "active"),))
    made = run(provider.generate_data_key(context()))
    good = StoredKey(made.key_ref, made.wrapped_key)
    for bad_context in (
        None,
        "ctx",
        dataclasses.replace(context(), capture_id="cap_x"),
        dataclasses.replace(context(), tenant="lone-\ud800"),
    ):
        assert code_of(lambda c=bad_context: run(provider.generate_data_key(c))) == "KEY_INVALID_ARGUMENT"
        assert code_of(lambda c=bad_context: run(provider.unwrap_data_key(good, c))) == "KEY_INVALID_ARGUMENT"
    for bad_stored in (
        None,
        "stored",
        StoredKey("", b"x"),
        StoredKey("local:k", b""),
        StoredKey("local:k", bytes(4097)),
        StoredKey("local:k", bytearray(61)),
    ):
        assert code_of(lambda s=bad_stored: run(provider.unwrap_data_key(s, context()))) == "KEY_INVALID_ARGUMENT"
        assert code_of(lambda s=bad_stored: run(provider.rewrap_data_key(s, context()))) == "KEY_INVALID_ARGUMENT"


def test_a_wrapped_key_of_the_wrong_length_or_version_is_key_integrity() -> None:
    provider = build((LocalKey("k", MATERIAL, "active"),))
    made = run(provider.generate_data_key(context()))
    wrapped = made.wrapped_key
    for bad in (wrapped[:-1], wrapped + b"\x00", b"\x02" + wrapped[1:], b"\x00" + wrapped[1:], wrapped[:1]):
        assert (
            code_of(lambda b=bad: run(provider.unwrap_data_key(StoredKey("local:k", b), context()))) == "KEY_INTEGRITY"
        )
    for index in range(1, len(wrapped)):
        flipped = bytearray(wrapped)
        flipped[index] ^= 0x01
        assert (
            code_of(lambda f=bytes(flipped): run(provider.unwrap_data_key(StoredKey("local:k", f), context())))
            == "KEY_INTEGRITY"
        )


def test_no_environment_default_or_cache(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("REDACT_SECRET_VAULT_KEY", MATERIAL.hex())
    with pytest.raises(TypeError):
        create_local_key_provider(scope=LocalKeyScope((NS,)))  # type: ignore[call-arg]
    provider = build((LocalKey("k", MATERIAL, "active"),))
    made = run(provider.generate_data_key(context()))
    # Nothing is cached: unwrapping twice allocates two distinct buffers.
    a = run(provider.unwrap_data_key(StoredKey(made.key_ref, made.wrapped_key), context()))
    b = run(provider.unwrap_data_key(StoredKey(made.key_ref, made.wrapped_key), context()))
    assert a == b and a is not b


def test_close_overwrites_the_copies_and_later_calls_fail() -> None:
    provider = build((LocalKey("k", MATERIAL, "active"),))
    made = run(provider.generate_data_key(context()))
    held = list(provider._held.values())
    provider.close()
    assert held and all(not any(m) for m in held)
    assert code_of(lambda: run(provider.generate_data_key(context()))) == "KEY_UNAVAILABLE"
    assert (
        code_of(lambda: run(provider.unwrap_data_key(StoredKey(made.key_ref, made.wrapped_key), context())))
        == "KEY_UNAVAILABLE"
    )
    provider.close()


def test_buffers_are_zero_after_every_path(monkeypatch: pytest.MonkeyPatch) -> None:
    provider = rotated()
    created = track_buffers(monkeypatch)
    made = run(provider.generate_data_key(context()))
    stored = StoredKey(made.key_ref, made.wrapped_key)
    kept = (made.plaintext_key,)
    unwrapped = run(provider.unwrap_data_key(stored, context()))
    rewrapped = run(provider.rewrap_data_key(stored, context()))
    assert rewrapped.key_ref == "local:2026-10"
    kept = (*kept, unwrapped)
    assert all_zero(created, except_=kept)
    # failures
    tampered = bytearray(made.wrapped_key)
    tampered[-1] ^= 1
    code_of(lambda: run(provider.unwrap_data_key(StoredKey(made.key_ref, bytes(tampered)), context())))
    code_of(lambda: run(provider.unwrap_data_key(stored, context(CAPTURE_2))))
    code_of(lambda: run(provider.unwrap_data_key(StoredKey("local:nope", made.wrapped_key), context())))
    code_of(lambda: run(provider.generate_data_key(dataclasses.replace(context(), namespace="ns-other"))))
    assert all_zero(created, except_=kept)
    for buffer in kept:
        buffer[:] = bytes(len(buffer))
    assert all_zero(created)


def test_the_provider_and_its_key_never_print_or_pickle_material() -> None:
    key = LocalKey("k", MATERIAL, "active")
    provider = build((key,))
    for obj in (key, provider):
        text = repr(obj) + str(obj)
        assert MATERIAL.hex() not in text and str(MATERIAL) not in text
    for obj in (key, provider):
        with pytest.raises(TypeError):
            pickle.dumps(obj)
    assert DEK.hex() not in repr(run(provider.generate_data_key(context())))
