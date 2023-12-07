""" Module for checking when a statement has been anchored in the append-only ledger """

import subprocess
import argparse
from json import loads as json_loads
from time import sleep as time_sleep


# all timeouts and durations are in seconds
REQUEST_TIMEOUT = 30
POLL_TIMEOUT = 360
POLL_INTERVAL = 10


def get_operation_status(operation_id: str) -> str:
    """
    gets the operation status from the datatrails API for retrieving operation status
    """

    # pylint: disable=fixme
    # TODO: use requests.get, with the request timeout.
    return subprocess.check_output(
        # pylint: disable=line-too-long
        "curl -s -H @$HOME/.datatrails/bearer-token.txt https://app.datatrails.ai/archivist/v1/publicscitt/operations/"
        + operation_id,
        shell=True,
    ).decode()


def poll_operation_status(operation_id: str) -> str:
    """
    polls for the operation status to be 'succeeded'.
    """

    poll_attempts: int = int(POLL_TIMEOUT / POLL_INTERVAL)

    for _ in range(poll_attempts):
        operation_status = get_operation_status(operation_id)

        # pylint: disable=fixme
        # TODO: ensure get_operation_status handles error cases from the rest request
        response = json_loads(operation_status)
        if "status" in response and response["status"] == "succeeded":
            return response["entryID"]

        time_sleep(POLL_INTERVAL)

    raise TimeoutError("signed statement not registered within polling duration.")


def main():
    """Polls for the signed statement to be registered"""

    parser = argparse.ArgumentParser(
        description="Polls for the signed statement to be registered"
    )

    # operation id
    parser.add_argument(
        "--operation-id",
        type=str,
        help="the operation-id from a registered statement",
    )

    args = parser.parse_args()

    entry_id = poll_operation_status(args.operation_id)
    print(entry_id)


if __name__ == "__main__":
    main()
