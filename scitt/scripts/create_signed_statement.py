""" Module for creating a SCITT signed statement """

import sys
import argparse

from scitt.scripts.fileaccess import open_payload, open_signing_key
from scitt.statement_creation import create_signed_statement


def main(args=None):
    """Creates a signed statement"""

    parser = argparse.ArgumentParser(description="Create a signed statement.")

    # signing key file
    parser.add_argument(
        "--signing-key-file",
        type=str,
        help="filepath to the stored ecdsa P-256 signing key, in pem format.",
        default="scitt-signing-key.pem",
    )

    # payload-file (a reference to the file that will become the payload of the SCITT Statement)
    parser.add_argument(
        "--payload-file",
        type=str,
        help="filepath to the content that will become the payload of the SCITT Statement "
        "(currently limited to json format).",
        default="scitt-payload.json",
    )

    # content-type
    parser.add_argument(
        "--content-type",
        type=str,
        help="The iana.org media type for the payload",
        default="application/json",
    )

    # subject
    parser.add_argument(
        "--subject",
        type=str,
        help="subject to correlate statements made about an artifact.",
        # a default of None breaks registration because registration does not allow nil issuer
        default="scitt-subject",
    )

    # issuer
    parser.add_argument(
        "--issuer",
        type=str,
        help="issuer who owns the signing key.",
        # a default of None breaks registration because registration does not allow nil subject
        default="scitt-issuer",
    )

    # output file
    parser.add_argument(
        "--output-file",
        type=str,
        help="name of the output file to store the signed statement.",
        default="signed-statement.cbor",
    )

    args = parser.parse_args(args or sys.argv[1:])

    signing_key = open_signing_key(args.signing_key_file)
    payload = open_payload(args.payload_file)

    signed_statement = create_signed_statement(
        b"testkey",
        signing_key,
        payload,
        args.subject,
        args.issuer,
        args.content_type,
    )

    with open(args.output_file, "wb") as output_file:
        output_file.write(signed_statement)


if __name__ == "__main__":
    main()
