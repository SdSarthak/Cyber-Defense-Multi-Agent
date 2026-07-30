"""
Retrieval-augmented chains over the three ChromaDB collections.

Each chain is wrapped in `LazyRagChain`: the underlying LangChain runnable is only
built the first time it is invoked, and any failure (Chroma down, no API key, empty
collection) is swallowed and reported as an empty context string. Agents therefore
run with or without a populated knowledge base — retrieval is an enhancement, not a
hard dependency.
"""
from __future__ import annotations
import structlog
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.output_parsers import StrOutputParser
from langchain_core.runnables import RunnablePassthrough
from core.config import settings
from core.rag.vector_store import vector_store

log = structlog.get_logger()


def _format_docs(docs) -> str:
    return "\n\n".join(d.page_content for d in docs)


def build_rag_chain(collection: str, system_prompt: str):
    """Returns a RAG chain backed by the given ChromaDB collection."""
    from langchain_google_genai import ChatGoogleGenerativeAI

    llm = ChatGoogleGenerativeAI(
        model=settings.gemini_model,
        google_api_key=settings.google_api_key,
        temperature=0.1,
    )
    retriever = vector_store.as_retriever(collection, search_kwargs={"k": 5})

    prompt = ChatPromptTemplate.from_messages([
        ("system", system_prompt + "\n\nContext from knowledge base:\n{context}"),
        ("human", "{question}"),
    ])

    return (
        {"context": retriever | _format_docs, "question": RunnablePassthrough()}
        | prompt
        | llm
        | StrOutputParser()
    )


class LazyRagChain:
    """Deferred, failure-tolerant wrapper around a RAG chain."""

    def __init__(self, collection_setting: str, system_prompt: str):
        self._collection_setting = collection_setting
        self._system_prompt = system_prompt
        self._chain = None
        self._disabled = False

    @property
    def collection(self) -> str:
        return getattr(settings, self._collection_setting)

    def _build(self):
        if self._chain is None:
            self._chain = build_rag_chain(self.collection, self._system_prompt)
        return self._chain

    async def ainvoke(self, question: str) -> str:
        """Retrieve and answer. Returns "" instead of raising when RAG is unavailable."""
        if self._disabled or not settings.rag_enabled:
            return ""
        try:
            return await self._build().ainvoke(question)
        except Exception as exc:
            log.warning("rag.unavailable", collection=self.collection, error=str(exc))
            # Drop the half-built chain so a later call can retry against a
            # recovered ChromaDB instead of reusing a broken retriever.
            self._chain = None
            return ""

    def invoke(self, question: str) -> str:
        if self._disabled or not settings.rag_enabled:
            return ""
        try:
            return self._build().invoke(question)
        except Exception as exc:
            log.warning("rag.unavailable", collection=self.collection, error=str(exc))
            self._chain = None
            return ""

    def disable(self) -> None:
        self._disabled = True

    def reset(self) -> None:
        self._chain = None
        self._disabled = False


threat_rag = LazyRagChain(
    "chroma_collection_threats",
    "You are a cyber threat intelligence analyst. Use the provided context to answer questions "
    "about threats, IOCs, TTPs, and threat actors. Be precise and cite MITRE ATT&CK where applicable.",
)

vuln_rag = LazyRagChain(
    "chroma_collection_vulns",
    "You are a vulnerability management expert. Use the provided context to analyze CVEs, "
    "assess risk, and recommend remediation steps.",
)

compliance_rag = LazyRagChain(
    "chroma_collection_compliance",
    "You are a compliance and security policy expert. Use the provided context to evaluate "
    "compliance status against frameworks like SOC2, ISO 27001, NIST CSF, and PCI-DSS.",
)
