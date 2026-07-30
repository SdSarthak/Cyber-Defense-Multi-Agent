from __future__ import annotations
import structlog
from langchain_core.documents import Document
from core.config import settings

log = structlog.get_logger()


def _make_embeddings():
    from langchain_google_genai import GoogleGenerativeAIEmbeddings
    return GoogleGenerativeAIEmbeddings(
        model="models/text-embedding-004",
        google_api_key=settings.google_api_key,
    )


def _make_chroma_client():
    import chromadb
    from chromadb.config import Settings as ChromaSettings
    return chromadb.HttpClient(
        host=settings.chroma_host,
        port=settings.chroma_port,
        settings=ChromaSettings(anonymized_telemetry=False),
    )


class SecurityVectorStore:
    """
    Wraps three ChromaDB collections:
      - threat_intel        : IOCs, TTPs, threat actor profiles
      - vulnerability_kb    : CVE descriptions, remediation guides
      - compliance_policies : framework controls, policy text

    The ChromaDB client and the embedding model are created lazily on first use so
    that importing an agent never requires a running vector database. When Chroma is
    unreachable the store degrades to "no context" rather than raising — agents still
    run, they just lose their retrieval augmentation.
    """

    def __init__(self):
        self._client = None
        self._embeddings = None
        self._stores: dict = {}

    # ── Lazy resources ───────────────────────────────────────────────────────

    @property
    def client(self):
        if self._client is None:
            self._client = _make_chroma_client()
        return self._client

    @property
    def embeddings(self):
        if self._embeddings is None:
            self._embeddings = _make_embeddings()
        return self._embeddings

    def _get_store(self, collection: str):
        if collection not in self._stores:
            from langchain_chroma import Chroma
            self._stores[collection] = Chroma(
                client=self.client,
                collection_name=collection,
                embedding_function=self.embeddings,
            )
        return self._stores[collection]

    def is_available(self) -> bool:
        """True when ChromaDB answers a heartbeat. Never raises."""
        if not settings.rag_enabled:
            return False
        try:
            self.client.heartbeat()
            return True
        except Exception as exc:
            log.warning("vector_store.unavailable", error=str(exc))
            return False

    def reset(self) -> None:
        """Drop cached clients so the next call reconnects (used after config change)."""
        self._client = None
        self._embeddings = None
        self._stores = {}

    # ── Collections ──────────────────────────────────────────────────────────

    @property
    def threats(self):
        return self._get_store(settings.chroma_collection_threats)

    @property
    def vulnerabilities(self):
        return self._get_store(settings.chroma_collection_vulns)

    @property
    def compliance(self):
        return self._get_store(settings.chroma_collection_compliance)

    # ── Writes ───────────────────────────────────────────────────────────────

    def add_threat_intel(self, docs: list[Document]) -> None:
        self.threats.add_documents(docs)

    def add_vulnerability(self, docs: list[Document]) -> None:
        self.vulnerabilities.add_documents(docs)

    def add_compliance_policy(self, docs: list[Document]) -> None:
        self.compliance.add_documents(docs)

    # ── Reads ────────────────────────────────────────────────────────────────

    def search_threats(self, query: str, k: int = 5) -> list[Document]:
        return self.threats.similarity_search(query, k=k)

    def search_vulnerabilities(self, query: str, k: int = 5) -> list[Document]:
        return self.vulnerabilities.similarity_search(query, k=k)

    def search_compliance(self, query: str, k: int = 5) -> list[Document]:
        return self.compliance.similarity_search(query, k=k)

    def as_retriever(self, collection: str, **kwargs):
        return self._get_store(collection).as_retriever(**kwargs)


vector_store = SecurityVectorStore()
