"""
Retrieval over the three ChromaDB collections.

Each retriever is wrapped in `LazyRagChain`: the underlying LangChain retriever is only
built the first time it is used, and any failure (Chroma down, no API key, embedding
model retired) is reported as an empty context string. Agents therefore run with or
without a populated knowledge base — retrieval is an enhancement, not a hard
dependency.

This returns the retrieved passages themselves. It used to pipe them through a
second Gemini call and hand that model's *answer* to the agent as "context", which
doubled every agent's LLM usage and replaced source text with a paraphrase.
"""
from __future__ import annotations

import time

import structlog

from core.config import settings
from core.rag.vector_store import vector_store

log = structlog.get_logger()

DEFAULT_K = 5
MAX_CONTEXT_CHARS = 4000


def _format_docs(docs) -> str:
    text = "\n\n".join(d.page_content for d in docs if getattr(d, "page_content", ""))
    return text[:MAX_CONTEXT_CHARS]


def build_retriever(collection: str, k: int = DEFAULT_K):
    """Returns a retriever backed by the given ChromaDB collection."""
    return vector_store.as_retriever(collection, search_kwargs={"k": k})


class LazyRagChain:
    """Deferred, failure-tolerant retriever with a back-off after errors."""

    def __init__(self, collection_setting: str, label: str):
        self._collection_setting = collection_setting
        self.label = label
        self._retriever = None
        self._disabled = False
        self._retry_after = 0.0

    @property
    def collection(self) -> str:
        return getattr(settings, self._collection_setting)

    def _build(self):
        if self._retriever is None:
            self._retriever = build_retriever(self.collection)
        return self._retriever

    def _available(self) -> bool:
        return not self._disabled and settings.rag_enabled and time.monotonic() >= self._retry_after

    def _failed(self, exc: Exception) -> str:
        # Drop the half-built retriever so the next attempt reconnects, and stop
        # retrying on every call: a dead embedding model used to cost a failed API
        # request (and a warning) per agent step.
        self._retriever = None
        self._retry_after = time.monotonic() + max(settings.rag_retry_after_seconds, 0)
        log.warning(
            "rag.unavailable", collection=self.collection, error=str(exc),
            retry_in_s=settings.rag_retry_after_seconds,
        )
        return ""

    async def ainvoke(self, question: str) -> str:
        """Retrieve context. Returns "" instead of raising when RAG is unavailable."""
        if not self._available():
            return ""
        try:
            return _format_docs(await self._build().ainvoke(question))
        except Exception as exc:
            return self._failed(exc)

    def invoke(self, question: str) -> str:
        if not self._available():
            return ""
        try:
            return _format_docs(self._build().invoke(question))
        except Exception as exc:
            return self._failed(exc)

    def disable(self) -> None:
        self._disabled = True

    def reset(self) -> None:
        self._retriever = None
        self._disabled = False
        self._retry_after = 0.0


threat_rag = LazyRagChain("chroma_collection_threats", "threat intelligence")
vuln_rag = LazyRagChain("chroma_collection_vulns", "vulnerability knowledge base")
compliance_rag = LazyRagChain("chroma_collection_compliance", "compliance policies")
