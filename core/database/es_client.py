"""
Elasticsearch log sink.

Analysed log batches are mirrored into Elasticsearch so raw SIEM events stay
searchable without bloating PostgreSQL. Like the rest of the storage layer this is
best-effort: if Elasticsearch is down or disabled the agents keep running and the
indexing call simply reports zero documents written.

Disable entirely with ``ELASTICSEARCH_ENABLED=false``.
"""
from __future__ import annotations

from datetime import datetime, timezone

import structlog

from core.config import settings

log = structlog.get_logger()

_client = None
_unavailable = False


def get_es_client():
    """Lazily build the AsyncElasticsearch client. Returns None when unavailable."""
    global _client, _unavailable
    if not settings.elasticsearch_enabled or _unavailable:
        return None
    if _client is None:
        try:
            from elasticsearch import AsyncElasticsearch
            kwargs: dict = {"hosts": [settings.elasticsearch_url], "request_timeout": 5}
            if settings.elasticsearch_user and settings.elasticsearch_password:
                kwargs["basic_auth"] = (
                    settings.elasticsearch_user,
                    settings.elasticsearch_password,
                )
            _client = AsyncElasticsearch(**kwargs)
        except Exception as exc:
            log.warning("elasticsearch.client_init_failed", error=str(exc))
            _unavailable = True
            return None
    return _client


async def ping() -> bool:
    client = get_es_client()
    if client is None:
        return False
    try:
        return bool(await client.ping())
    except Exception:
        return False


async def index_logs(logs: list[dict], anomaly_indices: dict[int, dict] | None = None) -> int:
    """
    Bulk-index a batch of log entries. ``anomaly_indices`` maps a batch position to
    the anomaly detected there so the document carries the analysis verdict.

    Returns the number of documents accepted (0 when Elasticsearch is unavailable).
    """
    client = get_es_client()
    if client is None or not logs:
        return 0

    anomaly_indices = anomaly_indices or {}
    index = settings.elasticsearch_log_index
    operations: list[dict] = []

    for i, entry in enumerate(logs):
        if not isinstance(entry, dict):
            continue
        anomaly = anomaly_indices.get(i)
        doc = {
            "@timestamp": entry.get("timestamp") or datetime.now(timezone.utc).isoformat(),
            "source": entry.get("source"),
            "log_level": entry.get("log_level"),
            "message": entry.get("message"),
            "host": entry.get("host"),
            "service": entry.get("service"),
            "parsed_fields": entry.get("parsed_fields") or {},
            "is_anomalous": anomaly is not None,
        }
        if anomaly:
            doc["anomaly"] = anomaly
        operations.append({"index": {"_index": index}})
        operations.append(doc)

    if not operations:
        return 0

    try:
        response = await client.bulk(operations=operations, refresh=False)
        items = response.get("items", []) if isinstance(response, dict) else response["items"]
        return sum(1 for item in items if item.get("index", {}).get("status", 500) < 300)
    except Exception as exc:
        log.warning("elasticsearch.index_logs_failed", error=str(exc))
        return 0


async def search_logs(query: str | None = None, limit: int = 50, anomalous_only: bool = False) -> list[dict]:
    """Free-text search across indexed logs. Returns [] when Elasticsearch is down."""
    client = get_es_client()
    if client is None:
        return []

    filters: list[dict] = []
    if anomalous_only:
        filters.append({"term": {"is_anomalous": True}})
    must: list[dict] = []
    if query:
        must.append({"multi_match": {"query": query, "fields": ["message", "source", "host", "service"]}})

    body = {
        "size": limit,
        "sort": [{"@timestamp": {"order": "desc"}}],
        "query": {"bool": {"must": must or [{"match_all": {}}], "filter": filters}},
    }
    try:
        response = await client.search(index=settings.elasticsearch_log_index, body=body)
        return [hit["_source"] for hit in response["hits"]["hits"]]
    except Exception as exc:
        log.warning("elasticsearch.search_logs_failed", error=str(exc))
        return []


async def close_es_client() -> None:
    global _client
    if _client is not None:
        try:
            await _client.close()
        except Exception:
            pass
        _client = None
