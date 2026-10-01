"""AWS KMS key provider, over ``boto3``.

Skeleton: the implementation arrives with a later issue of the plan. Python
persistence is not implemented and not supported. Importing this module without
the ``aws-kms`` extra raises ``ImportError`` naming it.
"""

from __future__ import annotations

from .._extras import require_extra

require_extra("redact_secret_vault.keys.aws_kms", "boto3", "aws-kms")
