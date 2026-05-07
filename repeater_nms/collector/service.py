from __future__ import annotations

import logging
import os


LOGGER = logging.getLogger("repeater_nms.collector")


def configure_logging() -> None:
    logging.basicConfig(
        level=os.getenv("LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )


def main() -> int:
    configure_logging()
    LOGGER.info(
        "collector skeleton started service=%s bind=%s",
        "repeater-nms-collector",
        "0.0.0.0:1162/udp",
    )
    LOGGER.info("snmp trap listener and poller will be implemented in phase 3")
    return 0
