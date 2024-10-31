"""
This module illustrates how to calculate the append only log Merkle leaf hash
of a scitt statement registered on the Data Trails transparency ledger.

Currently the DataTrails implementation, scitt statements are recorded as a base64
encoded event attribute. To reproduce the leaf hash from appendn only log,
this original [event](https://docs.datatrails.ai/platform/overview/core-concepts/#events) data is required to obtain the hash.

This module implements the full process for obtaining the event and generating the ledger leaf hash.

See KB: https://support.datatrails.ai/hc/en-gb/articles/18120936244370-How-to-independently-verify-Merkle-Log-Events-recorded-on-the-DataTrails-transparency-ledger#h_01HTYDD6ZH0FV2K95D61RQ61ZJ

This limitation will be removed in a future release of the DataTrails API.

Note that if you have access to the DataTrails UI, the leaf hash will match what
is displayed there for the public view of the event.
"""

from typing import List
import hashlib
import bencodepy

V3FIELDS = [
    "identity",
    "event_attributes",
    "asset_attributes",
    "operation",
    "behaviour",
    "timestamp_declared",
    "timestamp_accepted",
    "timestamp_committed",
    "principal_accepted",
    "principal_declared",
    "tenant_identity",
]


def v3leaf_hash(event: dict, domain=0) -> bytes:
    """
    Return the leaf hash which is proven by a scitt receipt for the provided CONFIRMED event

    Computes:

    SHA256(BYTE(0x00) || BYTES(idTimestamp) || BENCODE(redactedEvent))

    See KB: https://support.datatrails.ai/hc/en-gb/articles/18120936244370-How-to-independently-verify-Merkle-Log-Events-recorded-on-the-DataTrails-transparency-ledger#h_01HTYDD6ZH0FV2K95D61RQ61ZJ
    """
    salt = get_mmrsalt(event, domain)
    preimage = get_v3preimage(event)
    return hashlib.sha256(salt + preimage).digest()


def v3event_hash(event: dict, domain=0) -> bytes:
    """Returns the V3 event hash"""
    preimage = get_v3preimage(event)
    return hashlib.sha256(preimage).digest()


def get_mmrsalt(event: dict, domain=0) -> bytes:
    """
    Get the public salt details from a v3 event record.

    Returns the bytes comprised of

    DOMAIN || BYTES(IDTIMESTAMP)
    """

    # Note this value is also present in the trie index data in the public merkle log
    # which can be obtained directly from app.datatrails.ai/verifiabledata/merklelogs
    # without authentication. veracity provides cli tooling for this sort of thing.
    hexidtimestamp = event["merklelog_entry"]["commit"]["idtimestamp"]
    idtimestamp = bytes.fromhex(hexidtimestamp[2:])  # strip the epoch from the front
    return bytes([domain]) + idtimestamp


def get_v3preimage(event: dict) -> bytes:
    """
    Calculate the leaf hash of a V3 leaf
    """

    preimage = {}
    for field in V3FIELDS:
        # Ensure the leaf contains all required fields
        try:
            value = event[field]
        except KeyError:
            raise KeyError(f"V3 leaf is missing required field: {field}")

        preimage[field] = value

    # their is only one occurence
    if preimage["identity"].startswith("public"):
        preimage["identity"] = preimage["identity"].replace("public", "")

    return bencodepy.encode(preimage)
