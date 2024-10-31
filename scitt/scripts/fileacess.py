"""Miscellaneous functions for file access.
"""
import json
import hashlib

from ecdsa import SigningKey


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
