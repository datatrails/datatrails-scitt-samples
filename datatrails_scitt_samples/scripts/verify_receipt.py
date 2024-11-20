""" Module for verifying the counter signed receipt signature """

import re
import argparse
import sys

import requests

from jwcrypto import jwk

from pycose.messages import Sign1Message
from pycose.keys.curves import P384
from pycose.keys.keyparam import KpKty, EC2KpX, EC2KpY, KpKeyOps, EC2KpCurve
from pycose.keys.keytype import KtyEC2
from pycose.keys.keyops import VerifyOp
from pycose.keys import CoseKey
from pycose.headers import KID

from datatrails_scitt_samples.datatrails.v3eventhash import v3leaf_hash
from datatrails_scitt_samples.datatrails.eventpreimage import get_event
from datatrails_scitt_samples.cose_receipt_verification import verify_receipt_mmriver
from datatrails_scitt_samples.datatrails.servicecontext import ServiceContext
from datatrails_scitt_samples.scripts.fileaccess import read_cbor_file

HEADER_LABEL_DID = 391

def read_receipt_bytes(filename:str) -> bytes:
    """read the file as binary"""
    with open(filename, "rb") as file:
        return file.read()


def get_didweb_pubkey(didurl: str, kid: bytes) -> dict:
    """
    gets the given did web public key, given the key ID (kid) and didurl.
    see https://w3c-ccg.github.io/did-method-web/
    NOTE: expects the key to be ecdsa P-384.
    """

    # check the didurl is a valid did web url
    # pylint: disable=line-too-long
    pattern = r"did:web:(?P<host>[a-zA-Z0-9/.\-_]+)(?:%3A(?P<port>[0-9]+))?(:*)(?P<path>[a-zA-Z0-9/.:\-_]*)"
    match = re.match(pattern, didurl)

    if not match:
        raise ValueError("DID is not a valid did:web")

    # convert the didweb url into a url:
    #
    #  e.g. did:web:example.com:foo:bar
    #  becomes: https://example.com/foo/bar/did.json
    groups = match.groupdict()
    host = groups["host"]
    port = groups.get("port")  # might be None
    path = groups["path"]

    origin = f"{host}:{port}" if port else host

    protocol = "https"

    decoded_partial_path = path.replace(":", "/")

    endpoint = (
        f"{protocol}://{origin}/{decoded_partial_path}/did.json"
        if path
        else f"{protocol}://{origin}/.well-known/did.json"
    )

    # do a https GET on the url to get the did document
    resp = requests.get(endpoint, timeout=60)
    assert resp.status_code == 200

    did_document = resp.json()

    # now search the verification methods for the correct public key
    for verification_method in did_document["verificationMethod"]:
        if verification_method["publicKeyJwk"]["kid"] != kid.decode("utf-8"):
            continue

        x_part = verification_method["publicKeyJwk"]["x"]
        y_part = verification_method["publicKeyJwk"]["y"]

        cose_key = {
            KpKty: KtyEC2,
            EC2KpCurve: P384,
            KpKeyOps: [VerifyOp],
            EC2KpX: jwk.base64url_decode(x_part),
            EC2KpY: jwk.base64url_decode(y_part),
        }

        return cose_key

    raise ValueError(f"no key with kid: {kid} in verification methods of did document")


def verify_receipt(
    ctx: ServiceContext,
    receipt: bytes,
    leaf: str|None = None,
    event_identity: str | None = None) -> bool:
    """
    Verifies the COSE Receipt
    """

    if leaf is None:
        if event_identity is None:
            raise ValueError("leaf or event must be supplied")
        public = False
        if event_identity.startswith("public"):
            public = True
            event_identity.replace("public", "", 1)
        event = get_event(ctx, event_identity, public)
        leafbytes = v3leaf_hash(event)
    else:
        if leaf.startswith("0x"):
            leaf = leaf[2:]

        # Convert the hexadecimal string to bytes
        leafbytes = bytes.fromhex(leaf)
        

    # XXX: TODO: move away from did web and check the issuer & key are consistent and trusted.

    return verify_receipt_mmriver(receipt, leafbytes)


def verify_transparent_statement(
    ctx: ServiceContext,
    transparent_statement: Sign1Message,
    leaf: str|None = None,
    event_identity: str | None = None) -> bool:
    """
    verifies the counter signed receipt signature in a TS
    """

    # Pull the receipt out of the structure
    try:
        receipt_bytes = transparent_statement.uhdr["receipts"][0]
    except (ValueError, AttributeError, KeyError):
        print("failed to extract receipt from Transparent Statement", file=sys.stderr)
        return False

    # Re-constitute it as a COSE object
    try:
        receipt = Sign1Message.decode(receipt_bytes)
    except (ValueError, AttributeError):
        print("failed to extract receipt from Transparent Statement", file=sys.stderr)
        return False

    # Verify it
    return verify_receipt(ctx, receipt_bytes, event_identity=event_identity, leaf=leaf)


def main():
    """Verifies a counter signed receipt signature"""

    parser = argparse.ArgumentParser(
        description="Verify countersigned signature from a Receipt or Transparent Statement."
    )

    options = parser.add_argument_group("Input File Type")
    options.add_argument(
        "--receipt-file",
        type=str,
        help="filepath to a stored Receipt, in CBOR format.",
    )

    parser.add_argument(
        "--datatrails-url",
        type=str,
        help="The url of the DataTrails transparency service. (only needed if fetching event to verify)",
        default=None,
    )

    options.add_argument(
        "--leaf",
        type=str,
        help="the leaf hash value verified by the receipt",
        default=None
    )
    options.add_argument(
        "--event",
        type=str,
        help="the event identity"
    )

    options.add_argument(
        "--transparent-statement-file",
        type=str,
        help="filepath to a stored Transparent Statement, in CBOR format.",
        default="transparent-statement.cbor",
    )

    args = parser.parse_args()
    cfg_overrides = {}
    if args.datatrails_url:
        cfg_overrides["datatrails_url"] = args.datatrails_url
    ctx = ServiceContext.from_env("verify-receipt", **cfg_overrides)

    if args.receipt_file:
        receipt = read_receipt_bytes(args.receipt_file)
        verified = verify_receipt(
            ctx, receipt, event_identity=args.event, leaf=args.leaf)
    else:
        # Note this logic works because only the transparent statement arg
        # has a default. Don't change that without changing this!
        transparent_statement = read_cbor_file(args.transparent_statement_file)
        verified = verify_transparent_statement(
            ctx, transparent_statement,
            event_identity=args.event, leaf=args.leaf)

    if verified:
        print("signature verification succeeded")
    else:
        print("signature verification failed")


if __name__ == "__main__":
    main()
