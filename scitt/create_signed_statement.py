""" Module for creating a SCITT signed statement """

import hashlib
import json
import argparse

from typing import Optional

from pycose.messages import Sign1Message
from pycose.headers import Algorithm, KID, ContentType
from pycose.algorithms import Es256
from pycose.keys.curves import P256
from pycose.keys.keyparam import KpKty, EC2KpD, EC2KpX, EC2KpY, KpKeyOps, EC2KpCurve
from pycose.keys.keytype import KtyEC2
from pycose.keys.keyops import SignOp, VerifyOp
from pycose.keys import CoseKey

from ecdsa import SigningKey, VerifyingKey


# CWT header label comes from version 4 of the scitt architecture document
# https://www.ietf.org/archive/id/draft-ietf-scitt-architecture-07.html##name-signed-statements
HEADER_LABEL_CWT = 15

# Various CWT header labels come from:
# https://www.rfc-editor.org/rfc/rfc8392.html#section-3.1
HEADER_LABEL_CWT_ISSUER = 1
HEADER_LABEL_CWT_SUBJECT = 2

# CWT CNF header labels come from:
# https://datatracker.ietf.org/doc/html/rfc8747#name-confirmation-claim
HEADER_LABEL_CWT_CNF = 8
HEADER_LABEL_CNF_COSE_KEY = 1


def open_signing_key(key_file: str) -> SigningKey:
    """
    opens the signing key from the key file.
    NOTE: the signing key is expected to be a P-256 ecdsa key in PEM format.
    """
    with open(key_file, encoding="UTF-8") as file:
        signing_key = SigningKey.from_pem(file.read(), hashlib.sha256)
        return signing_key


def open_payload(payload_file: str) -> str:
    """
    opens the payload from the payload file.
    NOTE: the payload is expected to be in json format.
          however, any payload of type bytes is allowed.
    """
    with open(payload_file, mode='rb') as file:
        payload = file.read()
        return payload


def create_signed_statement(
    signing_key: SigningKey,
    payload: str,
    subject: str,
    issuer: str,
    content_type: str,
) -> bytes:
    """
    creates a signed statement, given the signing_key, payload, subject and issuer
    """

    verifying_key: Optional[VerifyingKey] = signing_key.verifying_key
    assert verifying_key is not None

    # pub key is the x and y parts concatenated
    xy_parts = verifying_key.to_string()

    # ecdsa P256 is 64 bytes
    x_part = xy_parts[0:32]
    y_part = xy_parts[32:64]

    # create a protected header where
    #  the verification key is attached to the cwt claims
    protected_header = {
        Algorithm: Es256,
        KID: b"testkey",
        ContentType: content_type,
        HEADER_LABEL_CWT: {
            HEADER_LABEL_CWT_ISSUER: issuer,
            HEADER_LABEL_CWT_SUBJECT: subject,
            HEADER_LABEL_CWT_CNF: {
                HEADER_LABEL_CNF_COSE_KEY: {
                    KpKty: KtyEC2,
                    EC2KpCurve: P256,
                    EC2KpX: x_part,
                    EC2KpY: y_part,
                },
            },
        },
    }

    # create the statement as a sign1 message using the protected header and payload
    statement = Sign1Message(phdr=protected_header, payload=payload)

    # create the cose_key to sign the statement using the signing key
    cose_key = {
        KpKty: KtyEC2,
        EC2KpCurve: P256,
        KpKeyOps: [SignOp, VerifyOp],
        EC2KpD: signing_key.to_string(),
        EC2KpX: x_part,
        EC2KpY: y_part,
    }

    cose_key = CoseKey.from_dict(cose_key)
    statement.key = cose_key

    # sign and cbor encode the statement.
    # NOTE: the encode() function performs the signing automatically
    signed_statement = statement.encode([None])

    return signed_statement


def main():
    """Creates a signed statement"""

    parser = argparse.ArgumentParser(description="Create a signed statement.")

    # content-type
    parser.add_argument(
        "-t",
        "--content-type",
        type=str,
        help="The iana.org media type for the statement.",
        default="application/json",
    )

    # detached-hash
    parser.add_argument(
        "--detached-hash",
        type=str,
        help='The hash value to assist in payload verification when the payload-type="detached"'
    )

    # detached-hash-type
    parser.add_argument(
        "--detached-hash-type",
        type=str,
        help='When the a payload-type="detached", an optional detached-hash may be set to assist in payload verification. detached-hash-type identifies the hashing algorithm used'
    )

    # issuer
    parser.add_argument(
        "--issuer",
        required=True,
        type=str,
        help="Owner of the signing key",
    )

    # location-hint
    parser.add_argument(
        "-l",
        "--location-hint",
        type=str,
        help="An optional URI the statement is stored"
    )

    # signing key
    parser.add_argument(
        "-k",
        "--signing-key-file",
        type=str,
        required=True,
        help="filepath to the stored ecdsa P-256 signing key, in pem format.",
        default="key.pem",
    )

    # statement-file
    parser.add_argument(
        "-f",
        "--statement-file",
        required=True,
        type=str,
        help="filepath to the content that will become the payload of the SCITT Signed Statement ",
        default="statement.json",
    )

    # subject
    parser.add_argument(
        "-s", "--subject",
        required=True,
        type=str,
        help="Unique identifier, owned by the Issuer, for the Artifact the statement references",
    )

    # output file
    parser.add_argument(
        "-o",
        "--output-file",
        type=str,
        help="name of the output file for the signed statement",
        default="signed-statement.cbor",
    )

    # statement-type
    parser.add_argument(
        "--payload-type",
        type=str,
        choices=['attached','detached','hash+sha256','hash+sha512'],
        help="Signed Statements may attach the statement within the payload as attached, detached (nil), or sign a hash of the statement: (attached | detached | hash+[algo])",
        default="hash+sha512",
    )

    args = parser.parse_args()

    signing_key = open_signing_key(args.signing_key_file)
    payload = open_payload(args.payload_file)

    signed_statement = create_signed_statement(
        signing_key,
        payload,
        args.subject,
        args.issuer,
        args.content_type,
    )

    with open(args.output_file, "wb") as output_file:
        output_file.write(signed_statement)


if __name__ == "__main__":
    main()
