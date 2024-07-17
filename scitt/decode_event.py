""" Module for decoding the event """

import argparse

import json
import base64

from pprint import pprint

from pycose.messages import Sign1Message


def open_event_json(event_json_file: str) -> bytes:
    """
    opens the event json
    """
    with open(event_json_file, "rb") as file:
        event_json = file.read()
        return event_json


def get_base64_statement(event_json: bytes) -> str:
    """
    gets the base64 encoded signed statement from
    the datatrails event
    """

    event = json.loads(event_json)

    base64_signed_statement = event["event_attributes"]["signed_statement"]

    return base64_signed_statement


def decode_base64_statement(base64_statement: str) -> bytes:
    """
    decodes the base64 encoded signed statement
    into a cbor cose sign1 statement
    """
    signed_statement = base64.b64decode(base64_statement)
    return signed_statement


def decode_statement(receipt: bytes):
    """
    decodes the signed statement
    """

    # decode the cbor encoded cose sign1 message
    message = Sign1Message.decode(receipt)

    return message


def main():
    """Decodes an underlying scitt datatrails event back into the original payload"""

    parser = argparse.ArgumentParser(
        description="Decodes an underlying scitt datatrails event back into the original payload."
    )

    # signing key file
    parser.add_argument(
        "--event-json-file",
        type=str,
        help="filepath to the stored event, in json format.",
    )

    args = parser.parse_args()

    event_json = open_event_json(args.event_json_file)

    base64_signed_statement = get_base64_statement(event_json)
    print(f"\nbase64 encoded signed statement: \n\n{base64_signed_statement}")

    signed_statement = decode_base64_statement(base64_signed_statement)
    print(f"\ncbor encoded signed statement: \n\n{signed_statement}")

    decoded_statement = decode_statement(signed_statement)

    print("\ncbor decoded cose sign1 statement:\n")
    print("protected headers:")
    pprint(decoded_statement.phdr)
    print("\nunprotected headers: ")
    pprint(decoded_statement.uhdr)
    print("\npayload: ", decoded_statement.payload)
    print("payload hex: ", decoded_statement.payload.hex())


if __name__ == "__main__":
    main()
