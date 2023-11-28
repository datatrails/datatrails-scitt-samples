""" Module for creating a SCITT signed statement """

import hashlib
import json
import argparse

from base64 import b64encode

from pycose.messages import Sign1Message
from pycose.headers import Algorithm, KID, ContentType
from pycose.algorithms import Es256
from pycose.keys.curves import P256
from pycose.keys.keyparam import KpKty, EC2KpD, EC2KpX, EC2KpY, KpKeyOps, EC2KpCurve
from pycose.keys.keytype import KtyEC2
from pycose.keys.keyops import SignOp, VerifyOp
from pycose.keys import CoseKey

from ecdsa import SigningKey


HEADER_LABEL_CWT = 13
HEADER_LABEL_FEED = 392

HEADER_LABEL_CWT_ISSUER = 1
HEADER_LABEL_CWT_SUBJECT = 2
HEADER_LABEL_CWT_CNF = 8

HEADER_LABEL_CNF_COSE_KEY = 1


def open_signing_key(key_file: str) -> SigningKey:
    """
    opens the signing key from the key file.
    NOTE: the signing key is expected to be a P-256 ecdsa key in PEM format.
    """
    with open(key_file, encoding='UTF-8') as file:
        signing_key = SigningKey.from_pem(file.read(), hashlib.sha256)
        return signing_key


def open_statement(statement_file: str) -> str:
    """
    opens the statement from the statement file.
    NOTE: the statement is expected to be in json format.
    """
    with open(statement_file, encoding='UTF-8') as file:
        statement = json.loads(file.read())

        # convert the statement to a cose sign1 payload
        payload = json.dumps(statement, ensure_ascii=False)

        return payload


def create_signed_statement(
    signing_key: SigningKey, 
    payload: str, 
    feed: str, 
    issuer: str,
    output: str
    ) -> bytes:
    """
    creates a signed statement, given the signing_key, payload, feed and issuer
    """
    verifying_key = signing_key.verifying_key

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
        ContentType: "application/json",
        HEADER_LABEL_FEED: feed,
        HEADER_LABEL_CWT: {
            HEADER_LABEL_CWT_ISSUER: issuer,
            HEADER_LABEL_CWT_SUBJECT: feed,
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

    # create the sign1 message using the protected header and payload
    msg = Sign1Message(phdr=protected_header, payload=payload.encode("utf-8"))

    # create the cose_key to sign the message using the signing key
    cose_key = {
        KpKty: KtyEC2,
        EC2KpCurve: P256,
        KpKeyOps: [SignOp, VerifyOp],
        EC2KpD: signing_key.to_string(),
        EC2KpX: x_part,
        EC2KpY: y_part,
    }

    cose_key = CoseKey.from_dict(cose_key)
    msg.key = cose_key

    # sign and cbor encode the cose sign1 message.
    # NOTE: the encode() function performs the signing automatically
    cbor_encoded_msg = msg.encode()

    # base64 encode the cbor message
    b64_encoded_msg = b64encode(cbor_encoded_msg)

    with open(output, "wb") as fh:
        fh.write(b64_encoded_msg)

def main():
    """Creates a signed statement"""

    parser = argparse.ArgumentParser(description="Create a signed statement.")

    # signing key file
    parser.add_argument(
        "--signing-key-file",
        type=str,
        help="filepath to the stored ecdsa P-256 signing key, in pem format.",
        default="scitt-signing-key.pem",
    )

    # statement file
    parser.add_argument(
        "--statement-file",
        type=str,
        help="filepath to the stored statement, in json format.",
        default="scitt-statement.json",
    )

    # feed
    parser.add_argument(
        "--feed",
        type=str,
        help="feed to correlate statements made about an artefact.",
    )

    # issuer
    parser.add_argument(
        "--issuer",
        type=str,
        help="issuer who owns the signing key.",
    )

    # output
    parser.add_argument(
        "--output",
        type=str,
        help="filename for the signed statement",
        default="signed-statement.cbor"
    )

    args = parser.parse_args()

    signing_key = open_signing_key(args.signing_key_file)
    payload = open_statement(args.statement_file)

    signed_statement = create_signed_statement(
        signing_key, payload, args.feed, args.issuer, args.output
    )

if __name__ == "__main__":
    main()
