"""Resolve a client id and secret to a DataTrails API authorization token.

Registering a statement on the Data Trails transparency ledger requires an API token.
"""
import os
import envconfig
import requests


def get_auth_header(cfg: envconfig.ServiceConfig | None = None) -> str:
    """
    Get DataTrails bearer token. If a configuration is not provided, it will be
    loaded from the environment.
    """

    if cfg is None:
        cfg = envconfig.env_config()

    # Get token from the auth endpoint
    url = f"{cfg.datatrails_url}/archivist/iam/v1/appidp/token"
    response = requests.post(
        url,
        data={
            "grant_type": "client_credentials",
            "client_id": cfg.client_id,
            "client_secret": cfg.client_secret,
        },
        timeout=cfg.request_timeout,
    )

    if response.status_code != 200:
        raise ValueError(
            "FAILED to acquire bearer token %s, %s", response.text, response.reason
        )

    # Format as a request header
    res = response.json()
    return f'{res["token_type"]} {res["access_token"]}'
