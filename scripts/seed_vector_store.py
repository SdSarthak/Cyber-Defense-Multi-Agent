"""
Seed the ChromaDB vector store with baseline threat intel, CVE knowledge,
and compliance policy documents. Run once after first `docker-compose up`.

Usage:
    python scripts/seed_vector_store.py
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from langchain_core.documents import Document
from core.rag.vector_store import vector_store

# ── Threat Intel Seeds ────────────────────────────────────────────────────────

THREAT_DOCS = [
    Document(page_content=(
        "Brute force attack: repeated failed authentication attempts against SSH, RDP, or web login. "
        "MITRE ATT&CK T1110. Indicators: >10 failed logins per minute from same IP. "
        "Response: block source IP, enforce account lockout, enable MFA."
    ), metadata={"type": "ttp", "technique": "T1110", "tactic": "Credential Access"}),

    Document(page_content=(
        "Port scanning: systematic probing of network ports to discover open services. "
        "MITRE ATT&CK T1046. Indicators: sequential port connections, SYN packets without completion, "
        "high connection rate from single source. Tools: nmap, masscan, zmap."
    ), metadata={"type": "ttp", "technique": "T1046", "tactic": "Discovery"}),

    Document(page_content=(
        "Command and Control (C2) beaconing: compromised host periodically contacts attacker infrastructure. "
        "MITRE ATT&CK T1071. Indicators: periodic outbound connections at fixed intervals (30s/60s/300s), "
        "unusual DNS queries, encrypted traffic to unknown IPs on port 443/80."
    ), metadata={"type": "ttp", "technique": "T1071", "tactic": "Command and Control"}),

    Document(page_content=(
        "Data exfiltration: large volume of data transferred from internal hosts to external IPs. "
        "MITRE ATT&CK T1041. Indicators: unusually large outbound transfers (>100MB), "
        "traffic to cloud storage or unusual domains, compressed archives being sent."
    ), metadata={"type": "ttp", "technique": "T1041", "tactic": "Exfiltration"}),

    Document(page_content=(
        "SQL injection: malicious SQL code inserted into application queries. "
        "MITRE ATT&CK T1190. Indicators: UNION SELECT in HTTP parameters, OR 1=1 patterns, "
        "database error messages in responses, unusual query execution times."
    ), metadata={"type": "ttp", "technique": "T1190", "tactic": "Initial Access"}),

    Document(page_content=(
        "Ransomware: malware that encrypts files and demands payment. "
        "MITRE ATT&CK T1486. Indicators: mass file rename/extension changes, "
        "ransom notes created in directories, shadow copy deletion, high disk I/O."
    ), metadata={"type": "ttp", "technique": "T1486", "tactic": "Impact"}),

    Document(page_content=(
        "Phishing: deceptive emails or websites to steal credentials. "
        "MITRE ATT&CK T1566. Indicators: suspicious sender domains, lookalike URLs, "
        "credential harvesting pages, macro-enabled Office documents."
    ), metadata={"type": "ttp", "technique": "T1566", "tactic": "Initial Access"}),

    Document(page_content=(
        "Lateral movement via pass-the-hash: attacker uses stolen NTLM hash to authenticate. "
        "MITRE ATT&CK T1550.002. Indicators: authentication events with no corresponding logon, "
        "unusual internal SMB traffic, admin share access from non-admin hosts."
    ), metadata={"type": "ttp", "technique": "T1550.002", "tactic": "Lateral Movement"}),

    Document(page_content=(
        "Privilege escalation via sudo abuse: attacker uses misconfigured sudo rules to gain root. "
        "MITRE ATT&CK T1548.003. Indicators: sudo commands from non-admin users, "
        "setuid binary execution, /etc/sudoers modification."
    ), metadata={"type": "ttp", "technique": "T1548.003", "tactic": "Privilege Escalation"}),

    Document(page_content=(
        "Bulletproof hosting ASNs commonly associated with malicious activity: "
        "AS60068 (CDN77), AS49453 (Global Layer), AS206728 (Media Land), "
        "AS9009 (M247 Ltd). Traffic from these ASNs warrants elevated scrutiny."
    ), metadata={"type": "threat_intel", "category": "infrastructure"}),
]

# ── CVE / Vulnerability Knowledge Base Seeds ─────────────────────────────────

VULN_DOCS = [
    Document(page_content=(
        "CVE-2021-44228 Log4Shell: Critical RCE in Apache Log4j 2.x (CVSS 10.0). "
        "Attacker sends malicious JNDI lookup string in logged input. "
        "Remediation: upgrade to Log4j 2.17.1+. Workaround: set LOG4J_FORMAT_MSG_NO_LOOKUPS=true."
    ), metadata={"cve": "CVE-2021-44228", "cvss": 10.0, "product": "Apache Log4j"}),

    Document(page_content=(
        "CVE-2021-34527 PrintNightmare: Critical RCE in Windows Print Spooler (CVSS 8.8). "
        "Allows authenticated users to execute code as SYSTEM. "
        "Remediation: apply KB5004945 patch. Workaround: disable Print Spooler service."
    ), metadata={"cve": "CVE-2021-34527", "cvss": 8.8, "product": "Windows Print Spooler"}),

    Document(page_content=(
        "CVE-2022-0847 Dirty Pipe: Linux kernel privilege escalation (CVSS 7.8). "
        "Allows overwriting read-only files. Affects Linux kernel 5.8 to 5.16.10. "
        "Remediation: upgrade kernel to 5.16.11+, 5.15.25+, or 5.10.102+."
    ), metadata={"cve": "CVE-2022-0847", "cvss": 7.8, "product": "Linux Kernel"}),

    Document(page_content=(
        "CVE-2023-44487 HTTP/2 Rapid Reset Attack: DoS vulnerability in HTTP/2 protocol (CVSS 7.5). "
        "Attacker rapidly resets streams to exhaust server resources. "
        "Remediation: update web server software (nginx 1.25.3+, Apache 2.4.58+)."
    ), metadata={"cve": "CVE-2023-44487", "cvss": 7.5, "product": "HTTP/2 servers"}),

    Document(page_content=(
        "CVE-2024-3094 XZ Utils backdoor: Critical supply chain compromise in liblzma (CVSS 10.0). "
        "Malicious code injected into XZ Utils 5.6.0 and 5.6.1. "
        "Remediation: downgrade to XZ Utils 5.4.6 or earlier immediately."
    ), metadata={"cve": "CVE-2024-3094", "cvss": 10.0, "product": "XZ Utils"}),

    Document(page_content=(
        "Redis exposed without authentication: CVE-2022-0543. "
        "Unauthenticated Redis instances are frequently exploited for cryptomining, "
        "data theft, and lateral movement. Remediation: enable requirepass, bind to 127.0.0.1, "
        "use firewall rules to restrict port 6379."
    ), metadata={"type": "misconfiguration", "service": "Redis", "port": 6379}),

    Document(page_content=(
        "MongoDB exposed without authentication: Default MongoDB installations before 2.6 had no auth. "
        "Remediation: enable authorization in mongod.conf, bind to localhost, "
        "restrict port 27017 with firewall rules."
    ), metadata={"type": "misconfiguration", "service": "MongoDB", "port": 27017}),
]

# ── Compliance Policy Seeds ───────────────────────────────────────────────────

COMPLIANCE_DOCS = [
    Document(page_content=(
        "SOC 2 CC6.1 Logical and Physical Access Controls: "
        "The entity implements logical access security software, infrastructure, and architectures "
        "over protected information assets to protect them from security events. "
        "Evidence required: access control policy, user provisioning records, MFA enforcement logs."
    ), metadata={"framework": "SOC2", "control": "CC6.1"}),

    Document(page_content=(
        "SOC 2 CC7.1 System Monitoring: "
        "The entity uses detection and monitoring procedures to identify changes to configurations "
        "and new vulnerabilities. "
        "Evidence required: SIEM alerts, vulnerability scan reports, IDS/IPS logs."
    ), metadata={"framework": "SOC2", "control": "CC7.1"}),

    Document(page_content=(
        "NIST CSF DE.CM-1 Network Monitoring: "
        "The network is monitored to detect potential cybersecurity events. "
        "Implementation: deploy IDS/IPS, network flow analysis, anomaly detection. "
        "Evidence: network monitoring tool logs, alert records, baseline documentation."
    ), metadata={"framework": "NIST_CSF", "control": "DE.CM-1"}),

    Document(page_content=(
        "NIST CSF RS.RP-1 Response Planning: "
        "Response plan is executed during or after an incident. "
        "Implementation: documented IRP, trained response team, tabletop exercises. "
        "Evidence: incident response plan document, exercise records, post-incident reports."
    ), metadata={"framework": "NIST_CSF", "control": "RS.RP-1"}),

    Document(page_content=(
        "ISO 27001 A.12.4.1 Event Logging: "
        "Event logs recording user activities, exceptions, faults and information security events "
        "shall be produced, kept and regularly reviewed. "
        "Implementation: centralised log management, minimum 90-day retention, tamper protection."
    ), metadata={"framework": "ISO27001", "control": "A.12.4.1"}),

    Document(page_content=(
        "ISO 27001 A.16.1.1 Incident Management: "
        "Management responsibilities and procedures shall be established to ensure a quick, effective "
        "and orderly response to information security incidents. "
        "Implementation: CSIRT, escalation procedures, communication templates, SLA targets."
    ), metadata={"framework": "ISO27001", "control": "A.16.1.1"}),

    Document(page_content=(
        "ISO 27001 A.12.6.1 Technical Vulnerability Management: "
        "Information about technical vulnerabilities of information systems shall be obtained in a "
        "timely fashion. Evidence: vulnerability scan results, patch management records, "
        "risk acceptance documentation for unpatched systems."
    ), metadata={"framework": "ISO27001", "control": "A.12.6.1"}),

    Document(page_content=(
        "PCI DSS Requirement 6.3.3: All system components are protected from known vulnerabilities "
        "by installing applicable security patches/updates. Critical patches must be installed within "
        "one month of release. Evidence: patch management policy, scan reports, change records."
    ), metadata={"framework": "PCI_DSS", "control": "6.3.3"}),
]


def seed():
    print("Seeding threat intel vector store...")
    ids = [f"threat_{i}" for i in range(len(THREAT_DOCS))]
    vector_store.add_threat_intel(THREAT_DOCS)
    print(f"  ✓ {len(THREAT_DOCS)} threat intel documents added")

    print("Seeding vulnerability knowledge base...")
    vector_store.add_vulnerability(VULN_DOCS)
    print(f"  ✓ {len(VULN_DOCS)} vulnerability documents added")

    print("Seeding compliance policy store...")
    vector_store.add_compliance_policy(COMPLIANCE_DOCS)
    print(f"  ✓ {len(COMPLIANCE_DOCS)} compliance policy documents added")

    print("\nSeed complete. Vector store is ready.")


if __name__ == "__main__":
    seed()
