"""Module for verifying the counter signed receipt signature"""

import argparse
import sys
import json

from requests import HTTPError

from pycose.messages import Sign1Message

from datatrails_scitt_samples.cose_receipt_verification import verify_receipt_mmriver
from datatrails_scitt_samples.scripts.fileaccess import open_event_json
from datatrails_scitt_samples.datatrails.eventpreimage import get_event
from datatrails_scitt_samples.datatrails.v3eventhash import v3leaf_hash
from datatrails_scitt_samples.datatrails.entryid import entryid_to_identity

from datatrails_scitt_samples.datatrails.servicecontext import ServiceContext


def read_cbor_file(cbor_file: str) -> Sign1Message:
    """
    opens the receipt from the receipt file.
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


def verify_transparent_statement(
    transparent_statement: Sign1Message, leaf: bytes
) -> bool:
    """
    verifies the counter signed receipt signature in a TS
    """

    # Pull the receipt out of the structure
    try:
        receipt_bytes = transparent_statement.uhdr["receipts"][0]
    except (ValueError, AttributeError, KeyError):
        print("failed to extract receipt from Transparent Statement", file=sys.stderr)
        return False

    return verify_receipt_mmriver(receipt_bytes, leaf)


def main(args=None) -> int:
    """Verifies a counter signed receipt signature"""

    parser = argparse.ArgumentParser(
        description="Verify countersigned signature from a Receipt or Transparent Statement."
    )
    parser.add_argument(
        "--datatrails-url",
        type=str,
        help="The url of the DataTrails transparency service.",
        default=None,
    )
    options = parser.add_argument_group("Node (Leaf) Hash")
    options.add_argument(
        "--leaf", type=str, help="hex encoded leaf hash to verify against"
    )

    options.add_argument(
        "--entryid", type=str, help="the SCRAPI entry id of the statement"
    )

    parser.add_argument(
        "--event-json-file",
        type=str,
        help="filepath to the stored event, in json format.",
        default=None,
    )

    options = parser.add_argument_group("Input File Type")
    options.add_argument(
        "--receipt-file",
        type=str,
        help="filepath to a stored Receipt, in CBOR format.",
    )
    options.add_argument(
        "--transparent-statement-file",
        type=str,
        help="filepath to a stored Transparent Statement, in CBOR format.",
        default="transparent-statement.cbor",
    )

    args = parser.parse_args(args or sys.argv[1:])

    # Note: the context is only used if --entryid is
    # used to obtain the leaf hash directly from datatrails
    cfg_overrides = {}
    if args.datatrails_url:
        cfg_overrides["datatrails_url"] = args.datatrails_url
    ctx = ServiceContext.from_env("verify-receipt", **cfg_overrides)

    if not (args.leaf or args.event_json_file or args.entryid):
        ctx.error("either --leaf or --event-json-file is required")
        return 1

    leaf = None
    if args.leaf:
        try:
            leaf = bytes.fromhex(args.leaf)
        except ValueError:
            ctx.error("failed to parse leaf hash")
            return 1

    elif args.event_json_file:
        try:
            event = json.loads(open_event_json(args.event_json_file))
        except ValueError:
            ctx.error("failed to parse event json")
            return 1
        leaf = v3leaf_hash(event)
    elif args.entryid:
        identity = entryid_to_identity(args.entryid)
        try:
            event = get_event(ctx, identity, True)
        except HTTPError as e:
            ctx.error("failed to obtain event: %s", e)
            return 1
        leaf = v3leaf_hash(event)

    if leaf is None:
        ctx.error("failed to obtain leaf hash")
        return False

    if args.receipt_file:
        with open(args.receipt_file, "rb") as file:
            receipt_bytes = file.read()
            verified = verify_receipt_mmriver(receipt_bytes, leaf)
    else:
        # Note this logic works because only the transparent statement arg
        # has a default. Don't change that without changing this!
        transparent_statement = read_cbor_file(args.transparent_statement_file)
        verified = verify_transparent_statement(transparent_statement, leaf)

    if not verified:
        print("verification failed")
        return 1

    print("verification succeeded")
    return 0


if __name__ == "__main__":
    sys.exit(main())
