"""The issuer creates the statement and signs it.

The statement will then be registered with one or more transparency services.
"""

from hashlib import sha256

from pycose.messages import Sign1Message
from pycose.headers import Algorithm, KID, ContentType
from pycose.algorithms import Es256
from pycose.keys.curves import P256
from pycose.keys.keyparam import KpKty, EC2KpD, EC2KpX, EC2KpY, KpKeyOps, EC2KpCurve
from pycose.keys.keytype import KtyEC2
from pycose.keys.keyops import SignOp, VerifyOp
from pycose.keys import CoseKey

from ecdsa import SigningKey

from scitt.cbor_header_labels import (
    HEADER_LABEL_TYPE,
    COSE_TYPE,
    HEADER_LABEL_FEED,
    HEADER_LABEL_CWT,
    HEADER_LABEL_CWT_ISSUER,
    HEADER_LABEL_CWT_SUBJECT,
    HEADER_LABEL_CWT_CNF,
    HEADER_LABEL_CNF_COSE_KEY,
    HEADER_LABEL_PAYLOAD_HASH_ALGORITHM,
    HEADER_LABEL_LOCATION,
)


# pylint: disable=too-many-positional-arguments
def create_hashed_signed_statement(
    kid: bytes,
    content_type: str,
    issuer: str,
    payload: str,
    payload_location: str,
    signing_key: SigningKey,
    subject: str,
) -> bytes:
    """
    creates a hashed signed statement, given the signing_key, payload, subject and issuer
    the payload will be hashed and the hash added to the payload field.
    """

    # NOTE: for the sample an ecdsa P256 key is used
    verifying_key = signing_key.verifying_key
    if verifying_key is None:
        raise ValueError("signing key does not have a verifying key")

    # pub key is the x and y parts concatenated
    xy_parts = verifying_key.to_string()

    # ecdsa P256 is 64 bytes
    x_part = xy_parts[0:32]
    y_part = xy_parts[32:64]

    # create a protected header where
    #  the verification key is attached to the cwt claims
    protected_header = {
        HEADER_LABEL_TYPE: COSE_TYPE,
        Algorithm: Es256,
        KID: kid,
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
        HEADER_LABEL_PAYLOAD_HASH_ALGORITHM: -16,  # for sha256
        HEADER_LABEL_LOCATION: payload_location,
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


# pylint: disable=too-many-positional-arguments
def create_signed_statement(
    kid: bytes,
    signing_key: SigningKey,
    payload: str,
    subject: str,
    issuer: str,
    content_type: str,
) -> bytes:
    """
    creates a signed statement, given the signing_key, payload, subject and issuer
    """

    verifying_key = signing_key.verifying_key
    if verifying_key is None:
        raise ValueError("signing key does not have a verifying key")

    # pub key is the x and y parts concatenated
    xy_parts = verifying_key.to_string()

    # ecdsa P256 is 64 bytes
    x_part = xy_parts[0:32]
    y_part = xy_parts[32:64]

    # create a protected header where
    #  the verification key is attached to the cwt claims
    protected_header = {
        Algorithm: Es256,
        KID: kid,
        ContentType: content_type,
        HEADER_LABEL_FEED: subject,
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
    statement = Sign1Message(phdr=protected_header, payload=payload.encode("utf-8"))

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
