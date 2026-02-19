"""Index Poller adapter.

Connects to Elasticsearch-compatible search index APIs. Discovers
available indices, samples events for discovery analysis, and streams
new events continuously using search_after pagination.

No transformation, normalization, or enrichment. Raw documents are
wrapped in RawEvent envelopes and delivered as-is.

Supports both Elasticsearch 7.x (http_auth) client APIs.
TLS with custom CA certificates for production deployments.
"""

from __future__ import annotations

import logging
import ssl
from datetime import datetime, timezone
from typing import Any, AsyncIterator

from elasticsearch import AsyncElasticsearch, NotFoundError

from grasp.adapters.base import BaseAdapter, ConnectionState
from grasp.models.events import RawEvent, SampleBatch

logger = logging.getLogger("grasp.adapters.index_poller")


class IndexPollerAdapter(BaseAdapter):
    """Transport adapter for Elasticsearch-compatible search indices.

    Required config keys:
        endpoint: str       - Elasticsearch URL (e.g. https://host:9200)

    Optional config keys:
        auth_user: str      - Username for authentication
        auth_password: str  - Password for authentication
        index_pattern: str  - Index pattern to query (default: '*')
        tls_verify: bool    - Verify TLS certificates (default: True)
        ca_cert: str        - Path to CA certificate file
        poll_interval: int  - Seconds between poll cycles in stream mode (default: 5)
        batch_size: int     - Events per search request (default: 500)
    """

    def __init__(self, source_id: str, config: dict[str, Any]):
        super().__init__(source_id, config)
        self._client: AsyncElasticsearch | None = None
        self._index_pattern = config.get("index_pattern", "*")
        self._tls_verify = config.get("tls_verify", True)
        self._ca_cert = config.get("ca_cert", "")
        self._poll_interval = int(config.get("poll_interval", 5))
        self._batch_size = int(config.get("batch_size", 500))
        self._available_indices: list[str] = []

    @property
    def adapter_type(self) -> str:
        return "search_index"

    def _build_ssl_context(self) -> ssl.SSLContext:
        """Build SSL context from configuration."""
        if not self._tls_verify:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            return ctx

        if self._ca_cert:
            return ssl.create_default_context(cafile=self._ca_cert)

        return ssl.create_default_context()

    async def connect(self) -> ConnectionState:
        """Connect to Elasticsearch and discover available indices."""
        self._state = ConnectionState.CONNECTING
        try:
            endpoint = self.config["endpoint"]
            auth_user = self.config.get("auth_user", "")
            auth_password = self.config.get("auth_password", "")

            client_kwargs: dict[str, Any] = {
                "hosts": [endpoint],
                "ssl_context": self._build_ssl_context(),
                "request_timeout": 30,
                "retry_on_timeout": True,
                "max_retries": 3,
            }

            if auth_user and auth_password:
                client_kwargs["http_auth"] = (auth_user, auth_password)

            self._client = AsyncElasticsearch(**client_kwargs)

            # Validate connection
            info = await self._client.info()
            version = info.get("version", {}).get("number", "unknown")
            logger.info(
                "Connected to Elasticsearch %s at %s", version, endpoint
            )

            # Discover matching indices
            await self._discover_indices()

            self._state = ConnectionState.CONNECTED
            logger.info(
                "Index Poller [%s] connected: %d indices match pattern '%s'",
                self.source_id,
                len(self._available_indices),
                self._index_pattern,
            )
        except Exception as e:
            self._state = ConnectionState.FAILED
            self._record_error(f"Connection failed: {e}")

        return self._state

    async def _discover_indices(self) -> None:
        """Discover indices matching the configured pattern."""
        if not self._client:
            return
        try:
            indices = await self._client.indices.get(
                index=self._index_pattern,
                expand_wildcards="open",
            )
            self._available_indices = sorted(indices.keys())
            logger.info(
                "Discovered %d indices: %s",
                len(self._available_indices),
                self._available_indices[:10],
            )
        except NotFoundError:
            self._available_indices = []
            logger.warning(
                "No indices match pattern '%s'", self._index_pattern
            )

    async def sample(self, n: int = 1000) -> SampleBatch:
        """Sample n events from the configured index pattern.

        Uses standard search with size parameter for sampling.
        Events are returned in index order -- no sorting applied
        to avoid biasing the discovery engine.
        """
        if not self._client or self._state != ConnectionState.CONNECTED:
            logger.error("Cannot sample: adapter not connected")
            return SampleBatch(source_id=self.source_id)

        events: list[RawEvent] = []
        try:
            remaining = n
            search_after = None
            seq = 0

            while remaining > 0:
                page_size = min(remaining, self._batch_size)
                body: dict[str, Any] = {
                    "size": page_size,
                    "sort": [{"_doc": "asc"}],
                }
                if search_after is not None:
                    body["search_after"] = search_after

                resp = await self._client.search(
                    index=self._index_pattern,
                    body=body,
                )
                hits = resp.get("hits", {}).get("hits", [])

                if not hits:
                    break

                for hit in hits:
                    raw = hit.get("_source", {})
                    raw["_index"] = hit.get("_index", "")
                    raw["_id"] = hit.get("_id", "")

                    events.append(RawEvent(
                        source_id=self.source_id,
                        payload=raw,
                        sequence=seq,
                    ))
                    self._record_event()
                    seq += 1

                search_after = hits[-1].get("sort")
                remaining -= len(hits)

                if search_after is None:
                    break

            logger.info(
                "Sampled %d events from [%s] pattern '%s'",
                len(events), self.source_id, self._index_pattern,
            )
        except Exception as e:
            self._record_error(f"Sample failed: {e}")

        return SampleBatch(
            source_id=self.source_id,
            events=events,
        )

    async def stream(self) -> AsyncIterator[RawEvent]:
        """Stream new events using search_after pagination.

        Continuously polls for new documents, yielding each as a
        RawEvent. Tracks position via search_after for stateless
        incremental retrieval.
        """
        import asyncio

        if not self._client or self._state != ConnectionState.CONNECTED:
            logger.error("Cannot stream: adapter not connected")
            return

        search_after = None
        seq = self._events_delivered

        # Establish initial position at the end of current data
        try:
            resp = await self._client.search(
                index=self._index_pattern,
                body={
                    "size": 1,
                    "sort": [{"_doc": "desc"}],
                },
            )
            hits = resp.get("hits", {}).get("hits", [])
            if hits:
                search_after = hits[0].get("sort")
        except Exception as e:
            self._record_error(f"Stream position init failed: {e}")
            return

        logger.info("Streaming started for [%s]", self.source_id)

        while self._state in (ConnectionState.CONNECTED, ConnectionState.DEGRADED):
            try:
                body: dict[str, Any] = {
                    "size": self._batch_size,
                    "sort": [{"_doc": "asc"}],
                }
                if search_after is not None:
                    body["search_after"] = search_after

                resp = await self._client.search(
                    index=self._index_pattern,
                    body=body,
                )
                hits = resp.get("hits", {}).get("hits", [])

                if hits:
                    for hit in hits:
                        raw = hit.get("_source", {})
                        raw["_index"] = hit.get("_index", "")
                        raw["_id"] = hit.get("_id", "")

                        event = RawEvent(
                            source_id=self.source_id,
                            payload=raw,
                            sequence=seq,
                        )
                        self._record_event()
                        seq += 1
                        yield event

                    search_after = hits[-1].get("sort")
                else:
                    await asyncio.sleep(self._poll_interval)

            except Exception as e:
                self._record_error(f"Stream error: {e}")
                self._state = ConnectionState.DEGRADED
                await asyncio.sleep(self._poll_interval * 2)
                self._state = ConnectionState.CONNECTED

    async def disconnect(self) -> None:
        """Close the Elasticsearch client connection."""
        if self._client:
            await self._client.close()
            self._client = None
        self._state = ConnectionState.DISCONNECTED
        logger.info("Index Poller [%s] disconnected", self.source_id)

    @property
    def available_indices(self) -> list[str]:
        """Indices discovered matching the configured pattern."""
        return list(self._available_indices)