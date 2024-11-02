"""Environment based configuration for the samples and this package"""

import os
from dataclasses import dataclass
import logging

DATATRAILS_URL_DEFAULT = "https://app.datatrails.ai"
LOG_LEVEL_DEFAULT = logging.INFO


@dataclass
class ServiceConfig:
    """Configuration for the DataTrails service"""

    # DATATRAILS_LOG_LEVEL
    log_level: int = LOG_LEVEL_DEFAULT

    # The URL of the DataTrails service
    # DATATRAILS_URL
    datatrails_url: str = DATATRAILS_URL_DEFAULT

    # Note: Authentication is required to registere a statement, verification
    # can be accomplished without authorization.

    # To register a statement you need a DataTrails account and to have created
    # a Custom Integration client id & secret.
    # pylint: disable=line-too-long
    # See: https://docs.datatrails.ai/developers/developer-patterns/getting-access-tokens-using-app-registrations/

    # DATATRAILS_CLIENT_ID
    client_id: str = ""
    # DATATRAILS_CLIENT_SECRET
    client_secret: str = ""

    # Can't currently be configured
    request_timeout: int = 30

    poll_interval: int = 10
    poll_timeout: int = 30


def env_config(require_auth=True) -> ServiceConfig:
    """Get the DataTrails service configuration from the environment"""

    log_level = LOG_LEVEL_DEFAULT
    if "DATATRAILS_LOG_LEVEL" in os.environ:
        named = logging.getLevelNamesMapping()
        log_level = named[os.environ["DATATRAILS_LOG_LEVEL"].upper()]

    datatrails_url = DATATRAILS_URL_DEFAULT
    if "DATATRAILS_URL" in os.environ:
        datatrails_url = os.environ["DATATRAILS_URL"]

    client_id = os.environ.get("DATATRAILS_CLIENT_ID") or ""
    client_secret = os.environ.get("DATATRAILS_CLIENT_SECRET") or ""
    if require_auth and (client_id == "" or client_secret == ""):
        raise ValueError(
            "Please configure your DataTrails credentials in the shell environment"
        )

    return ServiceConfig(log_level, datatrails_url, client_id, client_secret)
