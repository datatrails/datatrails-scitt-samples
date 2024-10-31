"""
Generates an EXAMPLE issuer signing key using python ecdsa
"""

import sys
import argparse
from ecdsa import SigningKey, NIST256p

FILE_NAME = "scitt-signing-key.pem"


def generate_key(topem=True):
    """Generate a private key using the NIST256p curve

    Provided for example and test purposes only"""
    key = SigningKey.generate(curve=NIST256p)
    if not topem:
        return key
    return key.to_pem()


def main(args=None):
    """Generate a private key and save it to a file"""

    parser = argparse.ArgumentParser(description="Create a signed statement.")

    # signing key file
    parser.add_argument(
        "--signing-key-file",
        type=str,
        help="filepath to the stored ecdsa P-256 signing key, in pem format.",
        default=FILE_NAME,
    )

    args = parser.parse_args(args or sys.argv[1:])

    pem_key = generate_key(topem=True)
    # Save the private key to a file
    with open(args.signing_key_file, "wb") as pem_file:
        pem_file.write(pem_key)  # type: ignore
    print(f"PEM formatted private key generated and saved as '{args.signing_key_file}'")


if __name__ == "__main__":
    main()
