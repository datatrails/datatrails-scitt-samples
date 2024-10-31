"""Obtain the merkle log leaf hash and event hash for a DataTrails event

For SCITT Statements registered with datatrails, the leaf hash currently
includes content that is additional to the signed statement.  It currently
requires a proprietary API call to DataTrails to obtain that content.  The
content is available on a public access endpoint (no authorisation is required)

These limitations are not inherent to the SCITT architecture.  The are specific
to the current DataTrails implementation, and will be addressed in future
releases.

Note that the leaf hash can be read directly from the merkle log given only
information in the receipt.  And, as the log data is public and easily
replicable, this does not require interaction with datatrails.

However, on its own, this does not show that the leaf hash commits the statement
to the log.
"""

import base64
import requests
from scitt.datatrails.servicecontext import ServiceContext
from scitt.datatrails.v3eventhash import v3leaf_hash
from scitt.datatrails.entryid import entryid_to_identity


def get_leaf_hash(ctx: ServiceContext, entryid: str, public=True) -> bytes:
    """Obtain the leaf hash for a given event identity

    The leaf hash is the value that is proven by the COSE Receipt attached to
    the transparent statement.
    """
    identity = entryid_to_identity(entryid)
    event = get_event(ctx, identity, public)
    return v3leaf_hash(event)


def get_signed_statement(ctx: ServiceContext, identity: str, public=True) -> bytes:
    """Obtain the signed statement for a given event identity

    The signed statement is the value that is registered with the DataTrails
    service.  It is the value that is signed by the statement counter signing
    key.
    """
    headers = None
    url = f"{ctx.cfg.datatrails_url}/archivist/v2/{identity}"
    if public:
        url = f"{ctx.cfg.datatrails_url}/archivist/v2/public{identity}"
    else:
        headers = {"Authorization": ctx.auth_header}

    response = requests.get(url, headers=headers, timeout=ctx.cfg.request_timeout)
    response.raise_for_status()
    return base64.b64decode(signed_statement_from_event(response.json()))


def get_event(ctx: ServiceContext, identity: str, public=True) -> dict:
    """Fetch the event from the DataTrails service event api"""
    headers = None
    url = f"{ctx.cfg.datatrails_url}/archivist/v2/{identity}"
    if public:
        if not identity.startswith("public"):
            url = f"{ctx.cfg.datatrails_url}/archivist/v2/public{identity}"
    else:
        headers = {"Authorization": ctx.auth_header}

    response = requests.get(url, headers=headers, timeout=ctx.cfg.request_timeout)
    response.raise_for_status()
    return response.json()


def signed_statement_from_event(event: dict) -> str:
    """Extract the signed statement from an event"""
    return event["event_attributes"]["signed_statement"]
