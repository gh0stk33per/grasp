"""GRASP application entrypoint."""

import logging
from grasp.config import settings
from grasp.utils.logging import configure_logging

logger = logging.getLogger(__name__)


def main():
   
    configure_logging(settings.log_level)
    
    """Start the GRASP engine."""
    logger.info(
        "GRASP v%s starting - Graph-based Reconnaissance, Analysis, and Security Posture",
        settings.version,
    )
    logger.info("Log level: %s", settings.log_level)
    logger.info("API port: %s", settings.api_port)
    logger.info("Graph DB: %s", settings.graph_db_uri)


if __name__ == "__main__":
    main()
