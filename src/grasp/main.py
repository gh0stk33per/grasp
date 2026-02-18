"""GRASP application entrypoint."""

import logging
from fastapi import FastAPI
from grasp.config import settings
from grasp.utils.logging import configure_logging

configure_logging(settings.log_level)
logger = logging.getLogger("grasp")

app = FastAPI(
    title="GRASP",
    description="Graph-based Reconnaissance, Analysis, and Security Posture",
    version=settings.version,
)


@app.on_event("startup")
async def startup():
    logger.info(
        "GRASP v%s starting - Graph-based Reconnaissance, Analysis, and Security Posture",
        settings.version,
    )
    logger.info("Log level: %s", settings.log_level)
    logger.info("API port: %s", settings.api_port)
    logger.info("Graph DB: %s", settings.graph_db_uri)


@app.get("/health")
async def health():
    return {"status": "ok", "version": settings.version}
