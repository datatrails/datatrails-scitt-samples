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

HEADER_LABEL_DID = 391


def read_cbor_file(cbor_file: str) -> Sign1Message:
    """
    opens the receipt from the receipt file.
    NOTE: the receipt is expected to be in cbor encoding.
    """
    with open(cbor_file, "rb") as file:
        receipt = file.read()

    # decode the cbor encoded cose sign1 message
    try:
        message = Sign1Message.decode(receipt)
    except (ValueError, AttributeError):
        print("failed to decode cose sign1 from file", file=sys.stderr)
        return None

    return message


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


def verify_receipt(receipt: Sign1Message) -> bool:
    """
    verifies the counter signed receipt signature
    """

    # get the verification key from didweb
    kid: bytes = receipt.phdr[KID]
    didurl = receipt.phdr[HEADER_LABEL_DID]

    cose_key_dict = get_didweb_pubkey(didurl, kid)
    cose_key = CoseKey.from_dict(cose_key_dict)

    receipt.key = cose_key

    # verify the counter signed receipt signature
    verified = receipt.verify_signature()

    return verified


def verify_transparent_statement(transparent_statement: Sign1Message) -> bool:
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
        print(receipt_bytes)
        receipt = Sign1Message.decode(receipt_bytes)
    except (ValueError, AttributeError):
        print("failed to extract receipt from Transparent Statement", file=sys.stderr)
        return False

    # Verify it
    print(receipt)
    return verify_receipt(receipt)


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
    options.add_argument(
        "--transparent-statement-file",
        type=str,
        help="filepath to a stored Transparent Statement, in CBOR format.",
        default="transparent-statement.cbor",
    )

    args = parser.parse_args()

    if args.receipt_file:
        receipt = read_cbor_file(args.receipt_file)
        verified = verify_receipt(receipt)
    else:
        # Note this logic works because only the transparent statement arg
        # has a default. Don't change that without changing this!
        transparent_statement = read_cbor_file(args.transparent_statement_file)
        verified = verify_transparent_statement(transparent_statement)

    if verified:
        print("signature verification succeeded")
    else:
        print("signature verification failed")


if __name__ == "__main__":
    main()
