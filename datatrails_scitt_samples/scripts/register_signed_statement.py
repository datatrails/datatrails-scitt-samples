"""Module for submitting a SCITT signed statement to the
DataTrails Transparency Service and optionally returning
a Transparent Statement"""

import sys
import argparse
from pycose.messages import Sign1Message

from datatrails_scitt_samples.datatrails.servicecontext import ServiceContext
from datatrails_scitt_samples.statement_registration import (
    submit_statement_from_file,
    wait_for_entry_id,
    get_receipt,
)
from datatrails_scitt_samples.datatrails.eventpreimage import get_leaf_hash
from datatrails_scitt_samples.cose_receipt_verification import verify_receipt_mmriver


def attach_receipt(
    receipt: bytes,
    signed_statement_filepath: str,
    transparent_statement_file_path: str,
):
    """
    Given a Signed Statement file on disc and the provided receipt content, from
    the Transparency Service, read the statement fromm disc, attach the provided
    receipt, writing the re-encoded result back to disc.  The resulting
    re-encoded statement is now a Transparent Statement.

    The caller is expected to have *verified* the receipt first.
    """

    # Open up the signed statement
    with open(signed_statement_filepath, "rb") as data_file:
        data = data_file.read()
        message = Sign1Message.decode(data)

    # Add receipt to the unprotected header and re-encode
    message.uhdr["receipts"] = [receipt]
    ts = message.encode(sign=False)

    # Write out the updated Transparent Statement
    with open(transparent_statement_file_path, "wb") as file:
        file.write(ts)


def main(args=None):
    """Creates a Transparent Statement"""

    parser = argparse.ArgumentParser(description="Register a signed statement.")
    parser.add_argument(
        "--datatrails-url",
        type=str,
        help="The url of the DataTrails transparency service.",
        default=None,
    )

    # Signed Statement file
    parser.add_argument(
        "--signed-statement-file",
        type=str,
        help="filepath to the Signed Statement to be registered.",
        default="signed-statement.cbor",
    )

    # Output file
    parser.add_argument(
        "--output-file",
        type=str,
        help="output file to store the Transparent Statement (leave blank to skip saving).",
        default="",
    )
    parser.add_argument(
        "--output-receipt-file",
        type=str,
        help="output file to store the receipt in (leave blank to skip saving).",
        default="",
    )

    # log level
    parser.add_argument(
        "--log-level",
        type=str,
        help="log level. for any individual poll errors use DEBUG, defaults to WARNING",
        default="WARNING",
    )
    parser.add_argument(
        "--verify",
        help="verify the result of registraion",
        default=False,
        action="store_true",
    )

    args = parser.parse_args(args or sys.argv[1:])
    cfg_overrides = {}
    if args.datatrails_url:
        cfg_overrides["datatrails_url"] = args.datatrails_url
    ctx = ServiceContext.from_env("register-statement", **cfg_overrides)

    # Submit Signed Statement to DataTrails
    ctx.info("submit_statement: %s", args.signed_statement_file)

    op_id = submit_statement_from_file(ctx, args.signed_statement_file)
    ctx.info("Successfully submitted with Operation ID %s", op_id)

    # If the client wants the Transparent Statement or receipt, wait for registration to complete
    if args.verify or args.output_file != "":
        ctx.info("Waiting for registration to complete")
        # Wait for the registration to complete
        try:
            entry_id = wait_for_entry_id(ctx, op_id)
        except TimeoutError as e:
            ctx.error(e)
            sys.exit(1)
        ctx.info("Fully Registered with Entry ID %s", entry_id)

        leaf = get_leaf_hash(ctx, entry_id)
        # Notice: the leaf hash corresponds to the leaf hash visible in the UI
        ctx.info("Leaf Hash: %s", leaf.hex())

    if args.verify or args.output_file != "":
        # This script is a client of the transparency service and as such should
        # not blindly trust the receipt is valid. As this script is creating a
        # transparent statement, it should verify the receipt is correct before
        # attaching it to the signed statement.

        receipt = get_receipt(ctx, entry_id)
        if not verify_receipt_mmriver(receipt, leaf):
            ctx.info("Receipt verification failed")
            sys.exit(1)

    if args.output_file == "":
        return

    if args.output_receipt_file != "":
        with open(args.output_receipt_file, "wb") as file:
            file.write(receipt)
        ctx.info(f"Receipt saved successfully {args.output_receipt_file}")

    # Attach the receipt
    attach_receipt(receipt, args.signed_statement_file, args.output_file)
    ctx.info(f"File saved successfully {args.output_file}")


if __name__ == "__main__":
    main()
