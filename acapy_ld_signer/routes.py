"""Routes for the external-ld-signer plugin."""

from aiohttp import web
from aiohttp_apispec import docs, response_schema

from aries_cloudagent.admin.request_context import AdminRequestContext
from aries_cloudagent.utils.multiformats import multibase
from aries_cloudagent.utils.multiformats import multicodec
from aries_cloudagent.wallet.did_info import DIDInfo
from aries_cloudagent.wallet.did_method import PEER4
from aries_cloudagent.wallet.error import WalletError
from aries_cloudagent.wallet.key_type import ED25519
from aries_cloudagent.wallet.routes import DIDSchema, format_did_info
from aries_cloudagent.wallet.base import BaseWallet
from aries_cloudagent.wallet.util import b58_to_bytes
from did_peer_4 import encode

from .kms import KMSInterface


@docs(tags=["external-ld-signer"], summary="Create a DID using the KMS")
@response_schema(DIDSchema())
async def create_did(request: web.Request):
    """Create DID."""
    context: AdminRequestContext = request["context"]
    client = context.inject(KMSInterface)
    wallet_id = context.settings.get_str("wallet.id")
    if wallet_id:
        client = client.with_profile(wallet_id)

    key = await client.generate_key("ed25519")
    multikey = multibase.encode(
        multicodec.wrap("ed25519-pub", b58_to_bytes(key.b58)), "base58btc"
    )
    doc = {
        "@context": [
            "https://www.w3.org/ns/did/v1",
            "https://w3id.org/security/multikey/v1",
        ],
        "verificationMethod": [
            {
                "id": "#key-1",
                "type": "Multikey",
                "publicKeyMultibase": multikey,
            }
        ],
        "authentication": ["#key-1"],
        "assertionMethod": ["#key-1"],
    }
    did = encode(doc)
    info = DIDInfo(did=did, verkey=key.b58, metadata={}, method=PEER4, key_type=ED25519)

    # Associate key
    await client.associate_key(key.kid, f"{did}#key-1")

    try:
        async with context.session() as session:
            wallet = session.inject(BaseWallet)
            await wallet.store_did(info)
    except WalletError as e:
        raise web.HTTPBadRequest(reason=str(e))

    return web.json_response(format_did_info(info))


async def register(app: web.Application):
    """Register routes."""
    app.add_routes(
        [
            web.post("/ext/did/create", create_did),
        ]
    )


def post_process_routes(app: web.Application):
    """Amend swagger API."""
    # Add top-level tags description
    if "tags" not in app._state["swagger_dict"]:
        app._state["swagger_dict"]["tags"] = []

    app._state["swagger_dict"]["tags"].append(
        {
            "name": "external-ld-signer",
            "description": "external ld signer plugin",
        }
    )
