"""Record crypto and the local key provider, over ``cryptography``.

Skeleton: the implementation arrives with issue #122. Python persistence is not
implemented and not supported. Importing this module without the ``crypto`` extra
raises ``ImportError`` naming it.
"""

from __future__ import annotations

from .._extras import require_extra

require_extra("redact_secret_vault.crypto", "cryptography", "crypto")
