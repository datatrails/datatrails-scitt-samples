"""Handling for COSE_Sign1 messages

Specific accomodation for detached payloads.
"""

import cbor2
from pycose.messages import Sign1Message


def decode_sign1_detached(message: bytes, payload=None) -> Sign1Message:
    """
    Decodes a COSE sign1 message from a message with a detached payload.

    For COSE Receipts the caller can not provide payload in advance.
    The payload is dependent on the receipt's unprotected header contents which are only available
    after calling this function.

    WARNING: The message will NOT VERIFY unless the payload is replaced with the
    payload that was signed.

    Args:
        message: the bytes of the COSE sign1 message
        payload:
            Used as the payload if not none, otherwise payload is forced to b''.
            Verification will fail until the correct payload has been set on the returned
            Sign1Message.
    """
    # decode the cbor encoded cose sign1 message, per the CoseBase implementation
    try:
        cbor_msg = cbor2.loads(message)
        cose_obj = cbor_msg.value
    except AttributeError as e:
        raise AttributeError("Message was not tagged.") from e
    except ValueError as e:
        raise ValueError("Decode accepts only bytes as input.") from e

    if payload is None:
        payload = b""

    cose_obj[2] = (
        payload  # force replace with b'' if payload is detached, due to lack of pycose support
    )
    return Sign1Message.from_cose_obj(cose_obj, True)
