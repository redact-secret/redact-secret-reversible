"""Record crypto and the local key provider, over ``cryptography``.

Python persistence is **not implemented and not supported**; this module is
groundwork (docs/plans/python-persistence-parity.md section 8, handoff 4). It needs
the ``crypto`` extra: ``pip install 'redact-secret-vault[crypto]'``. Importing it
without that raises ``ImportError`` naming the extra, and nothing falls back to
another implementation.

``create_record_crypto`` builds a ``RecordCrypto`` over any ``KeyProvider``.
``create_local_key_provider`` is the local provider of the specification, over bytes
in process memory; its limits are stated in ``local_key_provider``.
"""

from __future__ import annotations

from .._extras import require_extra

require_extra("redact_secret_vault.crypto", "cryptography", "crypto")

from .local_key_provider import (  # noqa: E402
    LOCAL_KEY_PROVIDER_PROFILE,
    LOCAL_WRAP_VERSION,
    LocalKey,
    LocalKeyProvider,
    LocalKeyScope,
    LocalKeyState,
    create_local_key_provider,
)
from .record_crypto import (  # noqa: E402
    DEFAULT_KEY_TIMEOUT_S,
    RECORD_CRYPTO_PROFILE,
    KeyProviderRecordCrypto,
    create_record_crypto,
)

__all__ = [
    "DEFAULT_KEY_TIMEOUT_S",
    "LOCAL_KEY_PROVIDER_PROFILE",
    "LOCAL_WRAP_VERSION",
    "RECORD_CRYPTO_PROFILE",
    "KeyProviderRecordCrypto",
    "LocalKey",
    "LocalKeyProvider",
    "LocalKeyScope",
    "LocalKeyState",
    "create_local_key_provider",
    "create_record_crypto",
]
