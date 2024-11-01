"""Miscellaneous functions for file access.
"""

import sys
import json
import hashlib

from pycose.messages import Sign1Message
from ecdsa import SigningKey


def read_cbor_file(cbor_file: str) -> Sign1Message:
    """
    opens the receipt from the receipt file.
    NOTE: the receipt is expected to be in cbor encoding.
    """
    with open(cbor_file, "rb") as file:
        contents = file.read()

    # decode the cbor encoded cose sign1 message
    try:
        cose_object = Sign1Message.decode(contents)
    except (ValueError, AttributeError):
        # This is fatal
        print("failed to decode cose sign1 from file", file=sys.stderr)
        sys.exit(1)

    return cose_object


def open_event_json(event_json_file: str) -> bytes:
    """
    opens the event json
    """
    with open(event_json_file, "rb") as file:
        event_json = file.read()
        return event_json


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
    with open(payload_file, encoding="UTF-8") as file:
        payload = json.loads(file.read())

        # convert the payload to a cose sign1 payload
        payload = json.dumps(payload, ensure_ascii=False)

        return payload
