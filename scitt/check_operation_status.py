""" Module for checking when a statement has been anchored in the append-only ledger """

import json
import subprocess
import argparse
import time


def check_operation_id(
    operation_id: str
)-> str:
    return subprocess.check_output("curl -s -H @$HOME/.datatrails/bearer-token.txt https://app.datatrails.ai/archivist/v1/publicscitt/operations/"+operation_id, shell=True).decode()


def main():
    """Creates a signed statement"""

    parser = argparse.ArgumentParser(description="Create a signed statement.")

    # signing key file
    parser.add_argument(
        "--operation-id",
        type=str,
        help="the operation-id from a registered statement",
    )

    args = parser.parse_args()

    # Check the operation status until the status=succeeded
    while True:
        retval=check_operation_id(args.operation_id)
        if retval=="Jwt is expired":
            print(retval)
            return

        response = json.loads(check_operation_id(args.operation_id))
        if "status" in response and response["status"] == "succeeded":
            print(response["entryID"])
            break
        else:
            time.sleep(1)


if __name__ == "__main__":
    main()
