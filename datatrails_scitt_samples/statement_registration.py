"""SCITT Statement Registration

This module provides functions to register a signed statement with the DataTrails

# pylint: disable=line-too-long
Per https://ietf-wg-scitt.github.io/draft-ietf-scitt-architecture/draft-ietf-scitt-architecture.html#name-registration

They are defined in the expected order of use
"""

from time import sleep as time_sleep
import requests
from datatrails_scitt_samples.errors import ResponseContentError
from datatrails_scitt_samples.datatrails.servicecontext import ServiceContext


def submit_statement(
    ctx: ServiceContext,
    statement_data: bytes,
) -> str:
    """
    Given a Signed Statement CBOR file on disk, register it on the DataTrails
    Transparency Service over the SCITT interface
    """

    # Make the POST request
    response = requests.post(
        f"{ctx.cfg.datatrails_url}/archivist/v1/publicscitt/entries",
        headers={"Authorization": ctx.auth_header},
        data=statement_data,
        timeout=ctx.cfg.request_timeout,
    )
    response.raise_for_status()

    # Make sure it's actually in process and wil work
    res = response.json()
    if not "operationID" in res:
        raise ResponseContentError("FAILED No OperationID locator in response")

    return res["operationID"]


def submit_statement_from_file(
    ctx: ServiceContext,
    statement_file_path: str,
) -> str:
    """
    Given a Signed Statement CBOR file on disk, register it on the DataTrails
    Transparency Service over the SCITT interface
    """
    # Read the binary data from the file
    # Read the binary data from the file
    with open(statement_file_path, "rb") as data_file:
        ctx.info("statement_file_path opened: %s", statement_file_path)
        return submit_statement(ctx, data_file.read())


def get_operation_status(ctx: ServiceContext, operation_id: str) -> dict:
    """
    Gets the status of a long-running registration operation
    """
    response = requests.get(
        f"{ctx.cfg.datatrails_url}/archivist/v1/publicscitt/operations/{operation_id}",
        headers={"Authorization": ctx.auth_header},
        timeout=ctx.cfg.request_timeout,
    )

    response.raise_for_status()

    return response.json()


def wait_for_entry_id(
    ctx: ServiceContext,
    operation_id: str,
) -> str:
    """
    Polls for the operation status to be 'succeeded'.
    """

    poll_attempts: int = int(ctx.cfg.poll_timeout / ctx.cfg.poll_interval)

    ctx.info("starting to poll for operation status 'succeeded'")

    for _ in range(poll_attempts):
        try:
            operation_status = get_operation_status(ctx, operation_id)

            # pylint: disable=fixme
            # TODO: ensure get_operation_status handles error cases from the rest request
            if (
                "status" in operation_status
                and operation_status["status"] == "succeeded"
            ):
                return operation_status["entryID"]

        except requests.HTTPError as e:
            ctx.debug("failed getting operation status, error: %s", e)

        time_sleep(ctx.cfg.poll_interval)

    raise TimeoutError("signed statement not registered within polling duration")


def get_receipt(ctx: ServiceContext, entry_id: str) -> bytes:
    """Get the receipt for the provided entry id"""
    # Get the receipt
    response = requests.get(
        f"{ctx.cfg.datatrails_url}/archivist/v1/publicscitt/entries/{entry_id}/receipt",
        headers={"Authorization": ctx.auth_header},
        timeout=ctx.cfg.request_timeout,
    )
    response.raise_for_status()

    return response.content
