from __future__ import annotations
import chromadb
from chromadb.config import Settings as ChromaSettings
from langchain_community.vectorstores import Chroma
from langchain_google_genai import GoogleGenerativeAIEmbeddings
from langchain_core.documents import Document
from core.config import settings


def _make_embeddings() -> GoogleGenerativeAIEmbeddings:
    return GoogleGenerativeAIEmbeddings(
        model="models/text-embedding-004",
        google_api_key=settings.google_api_key,
    )


def _make_chroma_client() -> chromadb.HttpClient:
    return chromadb.HttpClient(
        host=settings.chroma_host,
        port=settings.chroma_port,
        settings=ChromaSettings(anonymized_telemetry=False),
    )


class SecurityVectorStore:
    """
    Wraps three ChromaDB collections:
      - threat_intel   : IOCs, TTPs, threat actor profiles
      - vulnerability_kb : CVE descriptions, remediation guides
      - compliance_policies : framework controls, policy text
    """

    def __init__(self):
        self._client = _make_chroma_client()
        self._embeddings = _make_embeddings()
        self._stores: dict[str, Chroma] = {}

    def _get_store(self, collection: str) -> Chroma:
        if collection not in self._stores:
            self._stores[collection] = Chroma(
                client=self._client,
                collection_name=collection,
                embedding_function=self._embeddings,
            )
        return self._stores[collection]

    @property
    def threats(self) -> Chroma:
        return self._get_store(settings.chroma_collection_threats)

    @property
    def vulnerabilities(self) -> Chroma:
        return self._get_store(settings.chroma_collection_vulns)

    @property
    def compliance(self) -> Chroma:
        return self._get_store(settings.chroma_collection_compliance)

    def add_threat_intel(self, docs: list[Document]) -> None:
        self.threats.add_documents(docs)

    def add_vulnerability(self, docs: list[Document]) -> None:
        self.vulnerabilities.add_documents(docs)

    def add_compliance_policy(self, docs: list[Document]) -> None:
        self.compliance.add_documents(docs)

    def search_threats(self, query: str, k: int = 5) -> list[Document]:
        return self.threats.similarity_search(query, k=k)

    def search_vulnerabilities(self, query: str, k: int = 5) -> list[Document]:
        return self.vulnerabilities.similarity_search(query, k=k)

    def search_compliance(self, query: str, k: int = 5) -> list[Document]:
        return self.compliance.similarity_search(query, k=k)

    def as_retriever(self, collection: str, **kwargs):
        return self._get_store(collection).as_retriever(**kwargs)


vector_store = SecurityVectorStore()
