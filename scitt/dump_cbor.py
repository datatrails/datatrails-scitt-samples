""" Module for dumping a CBOR file """

import argparse

from pycose.messages import Sign1Message

def main():
    """Dumps content of a supposed CBOR file"""

    parser = argparse.ArgumentParser(description="Dumps content of a supposed CBOR file")

    # Signed Statement file
    parser.add_argument(
        "--input",
        type=str,
        help="filepath to the CBOR file.",
        default="transparent-statement.cbor",
    )

    args = parser.parse_args()

    with open(args.input, 'rb') as data_file:
        data = data_file.read()
        message = Sign1Message.decode(data)
        print(message)
        print(f'Protected Header: {message.phdr}')
        print(f'Unprotected Header: {message.uhdr}')

if __name__ == "__main__":
    main()
