from langchain_core.prompts import ChatPromptTemplate
from langchain_core.output_parsers import StrOutputParser
from langchain_core.runnables import RunnablePassthrough
from langchain_google_genai import ChatGoogleGenerativeAI
from core.config import settings
from core.rag.vector_store import vector_store


def _format_docs(docs) -> str:
    return "\n\n".join(d.page_content for d in docs)


def build_rag_chain(collection: str, system_prompt: str):
    """Returns a RAG chain backed by the given ChromaDB collection."""
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


threat_rag = build_rag_chain(
    "threat_intel",
    "You are a cyber threat intelligence analyst. Use the provided context to answer questions "
    "about threats, IOCs, TTPs, and threat actors. Be precise and cite MITRE ATT&CK where applicable.",
)

vuln_rag = build_rag_chain(
    "vulnerability_kb",
    "You are a vulnerability management expert. Use the provided context to analyze CVEs, "
    "assess risk, and recommend remediation steps.",
)

compliance_rag = build_rag_chain(
    "compliance_policies",
    "You are a compliance and security policy expert. Use the provided context to evaluate "
    "compliance status against frameworks like SOC2, ISO 27001, NIST CSF, and PCI-DSS.",
)
