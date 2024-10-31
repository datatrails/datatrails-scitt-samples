""" Module for creating a SCITT signed statement with a detached payload"""

import argparse

from scitt.statement_creation import create_hashed_signed_statement
from scitt.scripts.fileaccess import open_payload, open_signing_key


def main():
    """Creates a signed statement"""

    parser = argparse.ArgumentParser(description="Create a signed statement.")

    # content-type
    parser.add_argument(
        "--content-type",
        type=str,
        help="The iana.org media type for the payload",
        default="application/json",
    )

    # payload-file (a reference to the file that will become the payload of the SCITT Statement)
    parser.add_argument(
        "--payload-file",
        type=str,
        help="filepath to the content that will be hashed into the payload of the SCITT Statement.",
        default="scitt-payload.json",
    )

    # payload-location
    parser.add_argument(
        "--payload-location",
        type=str,
        help="location hint for the original statement that was hashed.",
    )

    # subject
    parser.add_argument(
        "--subject",
        type=str,
        help="subject to correlate statements made about an artifact.",
    )

    # output file
    parser.add_argument(
        "--output-file",
        type=str,
        help="name of the output file to store the signed statement.",
        default="signed-statement.cbor",
    )

    # issuer
    parser.add_argument(
        "--issuer",
        type=str,
        help="issuer who owns the signing key.",
    )

    # signing key file
    parser.add_argument(
        "--signing-key-file",
        type=str,
        help="filepath to the stored ecdsa P-256 signing key, in pem format.",
        default="scitt-signing-key.pem",
    )

    args = parser.parse_args()

    signing_key = open_signing_key(args.signing_key_file)
    payload_contents = open_payload(args.payload_file)

    signed_statement = create_hashed_signed_statement(
        b"testkey",
        content_type=args.content_type,
        issuer=args.issuer,
        payload=payload_contents,
        payload_location=args.payload_location,
        signing_key=signing_key,
        subject=args.subject,
    )

    with open(args.output_file, "wb") as output_file:
        output_file.write(signed_statement)


if __name__ == "__main__":
    main()
