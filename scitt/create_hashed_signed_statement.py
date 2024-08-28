""" Module for creating a SCITT signed statement with a detached payload"""

import argparse
import hashlib
import json
import dump_cbor

from typing import Optional

from hashlib import sha256

from pycose.messages import Sign1Message
from pycose.headers import Algorithm, KID
from pycose.algorithms import Es256
from pycose.keys.curves import P256
from pycose.keys.keyparam import KpKty, EC2KpD, EC2KpX, EC2KpY, KpKeyOps, EC2KpCurve
from pycose.keys.keytype import KtyEC2
from pycose.keys.keyops import SignOp, VerifyOp
from pycose.keys import CoseKey

from ecdsa import SigningKey, VerifyingKey


# CWT header label comes from version 4 of the scitt architecture document
# https://www.ietf.org/archive/id/draft-ietf-scitt-architecture-04.html#name-issuer-identity
HEADER_LABEL_CWT = 13

# Various CWT header labels come from:
# https://www.rfc-editor.org/rfc/rfc8392.html#section-3.1
HEADER_LABEL_CWT_ISSUER = 1
HEADER_LABEL_CWT_SUBJECT = 2

# CWT CNF header labels come from:
# https://datatracker.ietf.org/doc/html/rfc8747#name-confirmation-claim
HEADER_LABEL_CWT_CNF = 8
HEADER_LABEL_CNF_COSE_KEY = 1


# Signed Hash envelope header labels from:
# https://github.com/OR13/draft-steele-cose-hash-envelope/blob/main/draft-steele-cose-hash-envelope.md
# pre-adoption/private use parameters
# https://www.iana.org/assignments/cose/cose.xhtml#header-parameters
HEADER_LABEL_PAYLOAD_HASH_ALGORITHM = -6800
HEADER_LABEL_PAYLOAD_LOCATION = -6801
HEADER_LABEL_PAYLOAD_PRE_CONTENT_TYPE = -6802

# key/value pairs of tstr:tstr supporting metadata
HEADER_LABEL_META_MAP = -6803

def open_signing_key(key_file: str) -> SigningKey:
    """
    opens the signing key from the key file.
    NOTE: the signing key is expected to be a P-256 ecdsa key in PEM format.
    While this sample script uses P-256 ecdsa, DataTrails supports any format
    supported through [go-cose](https://github.com/veraison/go-cose/blob/main/algorithm.go)
    """
    with open(key_file, encoding="UTF-8") as file:
        signing_key = SigningKey.from_pem(file.read(), hashlib.sha256)
        return signing_key


def read_file(payload_file: str) -> str:
    """
    opens the payload from the payload file.
    """
    with open(payload_file, encoding="UTF-8") as file:
        return file.read()


def create_hashed_signed_statement(
    signing_key: SigningKey,
    payload: str,
    subject: str,
    issuer: str,
    content_type: str,
    payload_location: str,
    meta_map: dict,
) -> bytes:
    """
    creates a hashed signed statement, given the signing_key, payload, subject and issuer
    the payload will be hashed and the hash added to the payload field.
    """

    # NOTE: for the sample an ecdsa P256 key is used
    verifying_key: Optional[VerifyingKey] = signing_key.verifying_key
    assert verifying_key is not None

    # pub key is the x and y parts concatenated
    xy_parts = verifying_key.to_string()

    # ecdsa P256 is 64 bytes
    x_part = xy_parts[0:32]
    y_part = xy_parts[32:64]

    # create a protected header where
    # the verification key is attached to the cwt claims
    protected_header = {
        Algorithm: Es256,
        KID: b"testkey",
        HEADER_LABEL_PAYLOAD_PRE_CONTENT_TYPE: content_type,
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
        HEADER_LABEL_PAYLOAD_HASH_ALGORITHM: -16,  # for sha256
        HEADER_LABEL_PAYLOAD_LOCATION: payload_location,
        HEADER_LABEL_META_MAP: meta_map,
    }

    # now create a sha256 hash of the payload
    #
    # NOTE: any hashing algorithm can be used.
    payload_hash = sha256(payload.encode("utf-8")).digest()

    # create the statement as a sign1 message using the protected header and payload
    statement = Sign1Message(phdr=protected_header, payload=payload_hash)

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
        "--content-type",
        type=str,
        help="The iana.org media type for the payload file",
        default="application/json",
    )

    # issuer
    parser.add_argument(
        "--issuer",
        type=str,
        help="issuer who owns the signing key.",
    )

    # meta-map
    parser.add_argument(
        "--meta-map-file",
        type=str,
        help="Filepath containing a dictionary of key:value pairs (str:str) for indexed meta-data.",
    )

    # output file
    parser.add_argument(
        "--output-file",
        type=str,
        help="name of the output file to store the signed statement.",
        default="signed-statement.cbor",
    )

    # payload-file (a reference to the file that will become the payload of the SCITT Statement)
    parser.add_argument(
        "--payload-file",
        type=str,
        help="filepath to the content that will be hashed into the payload of the SCITT Statement.",
        default="scitt-payload.json",
    )

    # payload-location
    parser.add_argument(
        "--payload-location",
        type=str,
        help="location hint for the original statement that was hashed.",
    )

    # signing key file
    parser.add_argument(
        "--signing-key-file",
        type=str,
        help="filepath to the stored ecdsa P-256 signing key, in pem format.",
        default="scitt-signing-key.pem",
    )

    # subject
    parser.add_argument(
        "--subject",
        type=str,
        help="subject to correlate statements made about an artifact.",
    )

    args = parser.parse_args()

    meta_map_dict = json.loads(read_file(args.meta_map_file))

    print("meta_map:", meta_map_dict)

    signing_key = open_signing_key(args.signing_key_file)
    payload_contents = read_file(args.payload_file)

    signed_statement = create_hashed_signed_statement(
        content_type=args.content_type,
        issuer=args.issuer,
        payload=payload_contents,
        payload_location=args.payload_location,
        signing_key=signing_key,
        subject=args.subject,
        meta_map=meta_map_dict,
    )
    
    with open(args.output_file, "wb") as output_file:
        output_file.write(signed_statement)

    dump_cbor.print(args.output_file)


if __name__ == "__main__":
    main()
