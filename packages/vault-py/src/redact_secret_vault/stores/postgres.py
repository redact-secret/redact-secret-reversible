"""PostgreSQL store adapter, over ``psycopg`` 3.

Skeleton: the implementation arrives with a later issue of the plan. Python
persistence is not implemented and not supported. Importing this module without
the ``postgres`` extra raises ``ImportError`` naming it.
"""

from __future__ import annotations

from .._extras import require_extra

require_extra("redact_secret_vault.stores.postgres", "psycopg", "postgres")
