"""
Provides a minimal context for various DataTrails service interactions.

Notably:
* Authentication & Authorization
* Logging
* Development override of the service url
"""
from dataclasses import fields
import logging

from scitt.datatrails.apitoken import get_auth_header
from scitt.datatrails.envconfig import ServiceConfig, env_config


class ServiceContext:
    @classmethod
    def from_env(
        cls, clientname="datatrails-scitt", require_auth=True, **cfg_overrides
    ):
        """Create a service context from the environment.

        With optional overrides given precedence.

        Args:
            require_auth:
                If True, the environment must be configured with
                DATATRAILS_CLIENT_ID and DATATRAILS_CLIENT_SECRET.
                If these are provided on the commandline, set them in cfg_overrides
                and set require_auth=False.

            cfg_overrides:
                can be any of the fields defined on ServiceConfig. This allows
                precedence to be given to commandline arguments.
        """

        ctx = cls(env_config(require_auth=require_auth))

        for field in fields(ctx.cfg):
            if not field.name.startswith("__") and field.name in cfg_overrides:
                setattr(ctx.cfg, field.name, cfg_overrides[field.name])

        ctx.configure_logger(clientname)
        return ctx

    @classmethod
    def from_config(cls, cfg: ServiceConfig, **cfg_logger):
        """Create a service context from a configuration object

        Initialize the logger with the provided configuration."""
        ctx = cls(cfg)
        ctx.configure_logger(**cfg_logger)
        return ctx

    def __init__(self, cfg: ServiceConfig | None = None):
        if cfg is None:
            cfg = env_config()
        self.cfg = cfg
        self._auth_header = None

    @property
    def auth_header(self):
        if not self._auth_header:
            self._auth_header = get_auth_header(self.cfg)
        return self._auth_header

    def refresh_auth(self):
        self._auth_header = get_auth_header(self.cfg)

    def configure_logger(self, name="datatrails-scitt", **kwargs):
        if "level" not in kwargs:
            kwargs["level"] = self.cfg.log_level
        self.logger = logging.getLogger(name)
        logging.basicConfig(**kwargs)
        return self.logger

    # Convenience defaults for the logging methods
    def error(self, msg, *args, **kwargs):
        return self.logger.error(msg, *args, **kwargs)

    def info(self, msg, *args, **kwargs):
        return self.logger.info(msg, *args, **kwargs)

    def debug(self, msg, *args, **kwargs):
        return self.logger.debug(msg, *args, **kwargs)