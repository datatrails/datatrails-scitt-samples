"""The issuer creates the statement and signs it.

The statement will then be registered with one or more transparency services.
"""

from pycose.messages import Sign1Message
from pycose.headers import Algorithm, KID, ContentType
from pycose.algorithms import Es256
from pycose.keys.curves import P256
from pycose.keys.keyparam import KpKty, EC2KpD, EC2KpX, EC2KpY, KpKeyOps, EC2KpCurve
from pycose.keys.keytype import KtyEC2
from pycose.keys.keyops import SignOp, VerifyOp
from pycose.keys import CoseKey

from ecdsa import SigningKey, VerifyingKey

from datatrails_scitt_samples.cbor_header_labels import (
    HEADER_LABEL_TYPE,
    COSE_TYPE,
    HEADER_LABEL_FEED,
    HEADER_LABEL_CWT,
    HEADER_LABEL_CWT_SCITT_DRAFT_04,
    HEADER_LABEL_CWT_ISSUER,
    HEADER_LABEL_CWT_SUBJECT,
    HEADER_LABEL_CWT_CNF,
    HEADER_LABEL_CNF_COSE_KEY,
    HEADER_LABEL_PAYLOAD_HASH_ALGORITHM,
    HEADER_LABEL_LOCATION,
    HEADER_LABEL_META_MAP,
    HEADER_LABEL_PAYLOAD_PRE_CONTENT_TYPE,
    HEADER_LABEL_COSE_ALG_SHA256,
    HEADER_LABEL_COSE_ALG_SHA384,
    HEADER_LABEL_COSE_ALG_SHA512,
)

OPTION_USE_DRAFT_04_LABELS = "draft_04_labels"


# pylint: disable=too-many-positional-arguments
def create_hashed_signed_statement(
    content_type: str,
    issuer: str,
    kid: bytes,
    meta_map: dict,
    payload: bytes,
    payload_hash_alg: str,
    payload_location: str,
    signing_key: SigningKey,
    subject: str,
    **kwargs,
) -> bytes:
    """
    creates a hashed signed statement, given the signing_key, payload, subject and issuer
    the payload will be hashed and the hash added to the payload field.
    """
    verifying_key = signing_key.verifying_key
    if verifying_key is None:
        raise ValueError("signing key does not have a verifying key")

    statement = create_hashed_statement(
        content_type,
        issuer,
        kid,
        meta_map,
        payload,
        payload_hash_alg,
        payload_location,
        verifying_key,
        subject,
        **kwargs,
    )

    # create the cose_key to locally sign the statement using the signing key
    statement.key = CoseKey.from_dict(cose_key_ec2_p256(signing_key))

    # sign and cbor encode the statement.
    # NOTE: the encode() function performs the signing automatically
    signed_statement = statement.encode([None])

    return signed_statement


def create_hashed_statement(
    content_type: str,
    issuer: str,
    kid: bytes,
    meta_map: dict,
    payload: bytes,
    payload_hash_alg: str,
    payload_location: str,
    verifying_key: VerifyingKey,
    subject: str,
    **kwargs,
) -> Sign1Message:
    """
    creates a hashed signed statement, given the verification_key, payload, subject and issuer
    the payload will be hashed and the hash added to the payload field.

    For remote signing, use cose_sign1message.extract_to_be_signed() to get the bytes that need to be signed.

    Further alg  & curve support can be added as needed.
    """

    protected_header = hashed_payload_protected_header(
        content_type, meta_map, payload_hash_alg, payload_location
    )
    # NOTE: for the sample an ecdsa P256 key is used

    cwt = protected_header_cwt(Es256().identifier, verifying_key, issuer, subject)

    # create a protected header where
    #  the verification key is attached to the cwt claims
    protected_header[Algorithm] = Es256
    protected_header[KID] = kid
    cwt_label = HEADER_LABEL_CWT
    if kwargs.get(OPTION_USE_DRAFT_04_LABELS):
        cwt_label = HEADER_LABEL_CWT_SCITT_DRAFT_04

    protected_header[cwt_label] = cwt

    # create the statement as a sign1 message using the protected header and payload
    return Sign1Message(phdr=protected_header, payload=payload)


# pylint: disable=too-many-positional-arguments
def create_signed_statement(
    kid: bytes,
    meta_map: dict,
    signing_key: SigningKey,
    payload: bytes,
    subject: str,
    issuer: str,
    content_type: str,
    payload_location: str,
    **kwargs,
) -> bytes:
    """
    creates a signed statement, given the signing_key, payload, subject and issuer
    """

    verifying_key = signing_key.verifying_key
    if verifying_key is None:
        raise ValueError("signing key does not have a verifying key")

    statement = create_statement(
        kid, meta_map, verifying_key, payload, subject, issuer, content_type, **kwargs
    )

    # create the cose_key for locally signing the statement
    statement.key = CoseKey.from_dict(cose_key_ec2_p256(signing_key))

    # sign and cbor encode the statement.
    # NOTE: the encode() function performs the signing automatically
    signed_statement = statement.encode([None])

    return signed_statement


def create_statement(
    kid: bytes,
    meta_map: dict,
    verifying_key: VerifyingKey,
    payload: bytes,
    subject: str,
    issuer: str,
    content_type: str,
    **kwargs,
) -> Sign1Message:
    """
    creates a statement, given the verification_key, payload, subject and issuer.

    For remote signing, use cose_sign1message.extract_to_be_signed() to get the bytes that need to be signed.

    Further alg  & curve support can be added as needed.
    """

    cwt = protected_header_cwt(Es256().identifier, verifying_key, issuer, subject)

    # create a protected header where
    #  the verification key is attached to the cwt claims
    protected_header = inline_payload_protected_header(subject, content_type, meta_map)
    protected_header[Algorithm] = Es256
    protected_header[KID] = kid

    cwt_label = HEADER_LABEL_CWT
    if kwargs.get(OPTION_USE_DRAFT_04_LABELS):
        cwt_label = HEADER_LABEL_CWT_SCITT_DRAFT_04

    protected_header[cwt_label] = cwt

    protected_header = {
        Algorithm: Es256,
        KID: kid,
        ContentType: content_type,
        HEADER_LABEL_FEED: subject,
        HEADER_LABEL_CWT: cwt,
        HEADER_LABEL_META_MAP: meta_map,
    }

    # create the statement as a sign1 message using the protected header and payload
    return Sign1Message(phdr=protected_header, payload=payload)


def hashed_payload_protected_header(
    content_type: str,
    meta_map: dict,
    payload_hash_alg: str,
    payload_location: str,
) -> dict:
    """Populate the SCITT protected header basics for a hashed payload."""
    # Expectation to create a Hashed Envelope
    match payload_hash_alg:
        case "SHA-256":
            payload_hash_alg_label = HEADER_LABEL_COSE_ALG_SHA256
        case "SHA-384":
            payload_hash_alg_label = HEADER_LABEL_COSE_ALG_SHA384
        case "SHA-512":
            payload_hash_alg_label = HEADER_LABEL_COSE_ALG_SHA512
    # create a protected header where
    #  the verification key is attached to the cwt claims
    protected_header = {
        HEADER_LABEL_TYPE: COSE_TYPE,
        HEADER_LABEL_PAYLOAD_PRE_CONTENT_TYPE: content_type,
        HEADER_LABEL_PAYLOAD_HASH_ALGORITHM: payload_hash_alg_label,
        HEADER_LABEL_LOCATION: payload_location,
        HEADER_LABEL_META_MAP: meta_map,
    }

    return protected_header


def inline_payload_protected_header(
    subject: str, content_type: str, meta_map: dict
) -> dict:
    """Populate the SCITT protected header basics for a hashed payload."""
    # create a protected header where
    #  the verification key is attached to the cwt claims
    return {
        ContentType: content_type,
        HEADER_LABEL_FEED: subject,
        HEADER_LABEL_META_MAP: meta_map,
    }


def protected_header_cwt(
    alg: Algorithm, verifying_key: VerifyingKey, issuer: str, subject: str
) -> dict:
    """Create the HEADER_LABEL_CWT value for the protected header.

    Typically used when remote signing to communicate the verification key to the statement consumer.

    The result of this function can be used to populate protected_header[HEADER_LABEL_CWT].

    The provided alg should also be set in the protected header top level label
    HEADER_LABEL_ALGORITHM.
    """
    if alg != Es256.identifier:
        # TODO: Add more alg & curve support,
        raise ValueError(f"unsupported algorithm {alg}")

    cwt = {
        HEADER_LABEL_CWT_ISSUER: issuer,
        HEADER_LABEL_CWT_SUBJECT: subject,
        HEADER_LABEL_CWT_CNF: {
            HEADER_LABEL_CNF_COSE_KEY: verifying_key_header_ec2_p256(verifying_key),
        },
    }
    return cwt


def verifying_key_header_ec2_p256(verifying_key: VerifyingKey) -> dict:
    """Create the HEADER_LABEL_CNF_COSE_KEY value for the protected header.

    When remote signing with the EC2 algo on the P256 curve.

    The result of this function can be used to populate

    protected_header[HEADER_LABEL_CWT][HEADER_LABEL_CWT_CNF][HEADER_LABEL_CNF_COSE_KEY]
    """
    # pub key is the x and y parts concatenated
    xy_parts = verifying_key.to_string()

    # ecdsa P256 is 64 bytes
    x_part = xy_parts[0:32]
    y_part = xy_parts[32:64]
    return {KpKty: KtyEC2, EC2KpCurve: P256, EC2KpX: x_part, EC2KpY: y_part}


def cose_key_ec2_p256(signing_key: SigningKey) -> dict:
    """Create a cose_key instance for locally signing a statement."""
    verifying_key = signing_key.verifying_key
    if verifying_key is None:
        raise ValueError("signing key does not have a verifying key")
    xy_parts = verifying_key.to_string()
    # ecdsa P256 is 64 bytes
    x_part = xy_parts[0:32]
    y_part = xy_parts[32:64]

    return {
        KpKty: KtyEC2,
        EC2KpCurve: P256,
        KpKeyOps: [SignOp, VerifyOp],
        EC2KpD: signing_key.to_string(),
        EC2KpX: x_part,
        EC2KpY: y_part,
    }
