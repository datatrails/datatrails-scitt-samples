"""Module for creating a SCITT signed statement"""

import sys
import argparse
import json

from datatrails_scitt_samples.scripts.fileaccess import read_file, open_signing_key
from datatrails_scitt_samples.statement_creation import create_signed_statement
from datatrails_scitt_samples.statement_creation import OPTION_USE_DRAFT_04_LABELS


def main(args=None) -> int:
    """Creates a signed statement"""

    parser = argparse.ArgumentParser(description="Create a signed statement.")

    # content-type
    parser.add_argument(
        "--content-type",
        type=str,
        help="The iana.org media type for the payload",
        default="application/json",
    )

    # key ID
    parser.add_argument(
        "--kid",
        type=str,
        help="The Key Identifier",
        default=b"testkey",
    )

    # issuer
    parser.add_argument(
        "--issuer",
        type=str,
        help="issuer who owns the signing key.",
        # a default of None breaks registration because registration does not allow nil subject
        default="scitt-issuer",
    )

    # metadata
    parser.add_argument(
        "--metadata-file",
        type=str,
        help="Filepath containing a dictionary of key:value pairs (tstr:tstr) for indexed metadata.",
        default=None,
    )

    # payload-file (a reference to the file that will become the payload of the SCITT Statement)
    parser.add_argument(
        "--payload-file",
        type=str,
        help="filepath to the content that will be hashed into the payload of the SCITT Statement.",
        default="payload.json",
    )

    # payload-location
    parser.add_argument(
        "--payload-location",
        type=str,
        help="location hint for the original statement that was hashed.",
        default=None,
    )

    # signing key file
    parser.add_argument(
        "--signing-key-file",
        type=str,
        help="filepath to the stored ecdsa P-256 signing key, in pem format.",
        default="my-signing-key.pem",
    )

    # subject
    parser.add_argument(
        "--subject",
        type=str,
        help="subject to correlate statements made about an artifact.",
        # a default of None breaks registration because registration does not allow nil issuer
        default="scitt-subject",
    )

    # output file
    parser.add_argument(
        "--output-file",
        type=str,
        help="name of the output file to store the signed statement.",
        default="signed-statement.cbor",
    )

    parser.add_argument(
        "--use-draft-04-labels",
        help="force use of legacy labels (eg cwt_claims label 13 rather than 15)",
        action="store_true",
    )

    args = parser.parse_args(args or sys.argv[1:])

    if args.metadata_file is not None:
        meta_map_dict = json.loads(read_file(args.metadata_file))
    else:
        meta_map_dict = {}

    signing_key = open_signing_key(args.signing_key_file)
    # Payload must be encoded to bytes
    payload = read_file(args.payload_file).encode("utf-8")

    options = {}
    if args.use_draft_04_labels:
        options[OPTION_USE_DRAFT_04_LABELS] = True

    signed_statement = create_signed_statement(
        content_type=args.content_type,
        issuer=args.issuer,
        kid=args.kid,
        meta_map=meta_map_dict,
        payload=payload,
        payload_location=args.payload_location,
        subject=args.subject,
        signing_key=signing_key,
        **options,
    )

    with open(args.output_file, "wb") as output_file:
        output_file.write(signed_statement)

    return 0


if __name__ == "__main__":
    sys.exit(main())
