"""Run the gateway: python -m lono_gateway."""

from __future__ import annotations

import logging
import os

import uvicorn

from lono_gateway.main import create_app


def main() -> None:
    level = os.environ.get("LONO_LOG_LEVEL", "INFO").upper()
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        force=True,
    )
    application = create_app()
    uvicorn.run(
        application,
        host=os.environ.get("LONO_HOST", "0.0.0.0"),
        port=int(os.environ.get("LONO_PORT", "8080")),
        log_level=level.lower(),
        access_log=True,
    )


if __name__ == "__main__":
    main()