"""The Python server: capture for one tenant, deny another, restore for the owner.

Run: python examples/05-python-server.py
Needs `pip install redact-secret-vault`, Node.js, and @redact-secret/core
(`python -m redact_secret_vault doctor` checks all three).
"""

import asyncio

from redact_secret_vault import (
    CaptureGrant,
    CaptureOptions,
    InMemoryVaultServer,
    NodeCoreBridge,
    Principal,
    RestoreRequest,
    VaultServerError,
    VaultServerErrorCode,
)
from redact_secret_vault.policies import allow_same_tenant_only

SINK = "support-ticket-reply-sink-synthetic"
PURPOSE = "support-reply-purpose-synthetic"
ACME = {"user_id": "user-synthetic-1", "tenant": "tenant-acme-synthetic"}
OTHER = {"user_id": "user-synthetic-2", "tenant": "tenant-other-synthetic"}


def resolve_principal(context):
    # Your application's own authentication. Raise when it cannot be established.
    return Principal(id=context["user_id"], tenant=context["tenant"])


async def main() -> None:
    with NodeCoreBridge() as bridge:  # or NodeCoreBridge(node_modules="/srv/myapp/core/node_modules")
        server = InMemoryVaultServer(
            core_client=bridge,
            principal_resolver=resolve_principal,
            release_policy=allow_same_tenant_only,
        )
        # Unmistakably synthetic; never a real credential.
        captured = server.capture(
            "Rotate ghp_SYNTHETICxREVOKEDxTESTx0000000000000 today",
            CaptureOptions(issued_tenant=ACME["tenant"], release=(CaptureGrant(sink=SINK, paths=("body",)),)),
        )
        print("to the model:   ", captured.text)
        assert "ghp_" not in captured.text

        def request(context):
            return RestoreRequest(
                sink=SINK,
                purpose=PURPOSE,
                captures=(captured.capture_id,),
                fields={"body": captured.text},
                tenant=context["tenant"],
                context=context,
            )

        try:
            await server.restore(request(OTHER))
            raise AssertionError("another tenant must be denied")
        except VaultServerError as error:
            assert error.code is VaultServerErrorCode.RESTORE_DENIED
            print("another tenant: ", error.reason.value)

        result = await server.restore(request(ACME))
        print("the owner:      ", result.fields["body"])
        assert "ghp_SYNTHETIC" in result.fields["body"]


asyncio.run(main())
