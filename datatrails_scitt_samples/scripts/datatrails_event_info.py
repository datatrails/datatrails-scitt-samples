"""The DataTrails transparencey service embeds the signed statement in a DataTrails event.

This is an example of how to pick out and introspect the signed statement
directly using the proprietary DataTrails API.
"""

import argparse

import json
import base64
from pprint import pprint

from pycose.messages import Sign1Message

from datatrails_scitt_samples.scripts.fileaccess import open_event_json
from datatrails_scitt_samples.datatrails.servicecontext import ServiceContext
from datatrails_scitt_samples.datatrails.eventpreimage import get_event
from datatrails_scitt_samples.datatrails.v3eventhash import v3leaf_hash, v3event_hash


def main():
    """Reports information about an event

    The event can come from a file on disc or be fetched from the DataTrails service.

    If no authorization is provided, the event is assumed to be available on the public endpoint.
    """

    parser = argparse.ArgumentParser(
        description="Verify a counter signed receipt signature."
    )

    # signing key file
    parser.add_argument(
        "--event-json-file",
        type=str,
        help="filepath to the stored event, in json format.",
        default=None,
    )
    parser.add_argument(
        "--datatrails-url",
        type=str,
        help="The url of the DataTrails transparency service.",
        default=None,
    )
    parser.add_argument(
        "--protected-event",
        action="store_true",
        default=False,
    )
    args = parser.parse_args()

    cfg_overrides = {}
    if args.datatrails_url:
        cfg_overrides["datatrails_url"] = args.datatrails_url
    ctx = ServiceContext.from_env("datatrails-event-info", **cfg_overrides)

    if args.event_json_file is None:
        event = get_event(ctx, args.identity, not args.protected_event)
    else:
        event = json.loads(open_event_json(args.event_json_file))

    event_hash = v3event_hash(event)
    leaf_hash = v3leaf_hash(event)
    signed_statement_b64 = event["event_attributes"]["signed_statement"]
    signed_statement = base64.b64decode(signed_statement_b64)

    print(f"\nevent hash: \n\n{event_hash.hex()}")
    print(f"\nleaf hash: \n\n{leaf_hash.hex()}")
    print(f"\nbase64 encoded signed statement: \n\n{signed_statement_b64}")
    print(f"\ncbor encoded signed statement: \n\n{signed_statement}")

    decoded_statement = Sign1Message.decode(signed_statement)

    print("\ncbor decoded cose sign1 statement:\n")
    print("protected headers:")
    pprint(decoded_statement.phdr)
    print("\nunprotected headers: ")
    pprint(decoded_statement.uhdr)
    print("\npayload: ", decoded_statement.payload)
    print("payload hex: ", decoded_statement.payload.hex())


if __name__ == "__main__":
    main()
