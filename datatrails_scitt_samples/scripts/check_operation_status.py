""" Module for checking when a statement has been anchored in the append-only ledger """

import argparse
import sys

from datatrails_scitt_samples.datatrails.servicecontext import ServiceContext
from datatrails_scitt_samples.statement_registration import wait_for_entry_id


def main():
    """Polls for the signed statement to be registered"""

    parser = argparse.ArgumentParser(
        description="Polls for the signed statement to be registered"
    )
    parser.add_argument(
        "--datatrails-url",
        type=str,
        help="The url of the DataTrails transparency service.",
        default=None,
    )

    # operation id
    parser.add_argument(
        "--operation-id",
        type=str,
        help="the operation-id from a registered statement",
    )

    # log level
    parser.add_argument(
        "--log-level",
        type=str,
        help="log level. for any individual poll errors use DEBUG, defaults to WARNING",
        default="WARNING",
    )

    args = parser.parse_args()
    cfg_overrides = {}
    if args.datatrails_url:
        cfg_overrides["datatrails_url"] = args.datatrails_url
    ctx = ServiceContext.from_env("check-operation-status", **cfg_overrides)

    try:
        entry_id = wait_for_entry_id(ctx, args.operation_id)
        print(entry_id)
    except TimeoutError as e:
        print(e, file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
