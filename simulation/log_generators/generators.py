"""Realistic log generators for SIEM simulation."""
import random
import uuid
from datetime import datetime, timezone

INTERNAL_IPS = [f"10.0.{random.randint(0,5)}.{random.randint(1,254)}" for _ in range(30)]
EXTERNAL_IPS = [
    "185.220.101.45", "91.108.4.0", "198.51.100.23", "203.0.113.99",
    "45.33.32.156", "104.21.14.91", "172.64.155.30", "1.1.1.1",
    "8.8.8.8", "66.240.192.138",
]
USERNAMES = ["admin", "root", "guest", "jenkins", "ubuntu", "ec2-user", "dbuser", "svcaccount"]
SERVICES = ["sshd", "apache2", "nginx", "mysql", "postgresql", "docker", "systemd", "kernel"]
HTTP_PATHS = ["/", "/admin", "/login", "/api/v1/users", "/wp-admin", "/.env", "/config.php",
              "/api/data", "/static/app.js", "/health"]
HTTP_METHODS = ["GET", "POST", "PUT", "DELETE", "OPTIONS"]
HTTP_STATUS = [200, 200, 200, 301, 302, 400, 401, 403, 404, 500, 503]


def _ts() -> str:
    return datetime.now(timezone.utc).isoformat()


def _src_ip(attack: bool = False) -> str:
    return random.choice(EXTERNAL_IPS) if attack else random.choice(INTERNAL_IPS + EXTERNAL_IPS)


def make_normal_auth_log() -> dict:
    user = random.choice(USERNAMES)
    ip = _src_ip()
    success = random.random() > 0.05
    msg = (
        f"Accepted password for {user} from {ip} port {random.randint(1024,65535)} ssh2"
        if success else
        f"Failed password for {user} from {ip} port {random.randint(1024,65535)} ssh2"
    )
    return {"id": str(uuid.uuid4()), "timestamp": _ts(), "source": "sshd",
            "log_level": "INFO", "message": msg, "host": f"host-{random.randint(1,20)}",
            "service": "sshd", "parsed_fields": {"user": user, "src_ip": ip, "success": success}}


def make_brute_force_log(target_ip: str | None = None) -> dict:
    user = random.choice(USERNAMES)
    ip = target_ip or _src_ip(attack=True)
    msg = f"Failed password for {user} from {ip} port {random.randint(1024,65535)} ssh2"
    return {"id": str(uuid.uuid4()), "timestamp": _ts(), "source": "sshd",
            "log_level": "WARNING", "message": msg, "host": random.choice(INTERNAL_IPS),
            "service": "sshd", "parsed_fields": {"user": user, "src_ip": ip, "attack_type": "brute_force"}}


def make_web_log(attack: bool = False) -> dict:
    ip = _src_ip(attack)
    method = random.choice(HTTP_METHODS)
    if attack:
        path = random.choice([
            "/?id=1' UNION SELECT * FROM users--",
            "/admin?cmd=ls+-la",
            "/<script>alert(1)</script>",
            "/../../../etc/passwd",
            "/login?user=admin&pass=' OR '1'='1",
        ])
        status = random.choice([200, 400, 403, 500])
    else:
        path = random.choice(HTTP_PATHS)
        status = random.choice(HTTP_STATUS)
    msg = f'{ip} - - [{_ts()}] "{method} {path} HTTP/1.1" {status} {random.randint(100,50000)}'
    return {"id": str(uuid.uuid4()), "timestamp": _ts(), "source": "nginx",
            "log_level": "INFO" if status < 400 else "WARNING", "message": msg,
            "host": random.choice(INTERNAL_IPS), "service": "nginx",
            "parsed_fields": {"src_ip": ip, "method": method, "path": path,
                              "status": status, "attack": attack}}


def make_port_scan_log(attacker_ip: str | None = None) -> dict:
    ip = attacker_ip or _src_ip(attack=True)
    ports = random.sample(range(1, 65535), random.randint(50, 500))
    msg = f"nmap scan detected from {ip} scanning {len(ports)} ports"
    return {"id": str(uuid.uuid4()), "timestamp": _ts(), "source": "firewall",
            "log_level": "WARNING", "message": msg, "host": "firewall-01",
            "service": "iptables", "parsed_fields": {"src_ip": ip, "ports_scanned": len(ports),
                                                      "attack_type": "port_scan"}}


def make_data_exfil_log() -> dict:
    src = random.choice(INTERNAL_IPS)
    dst = _src_ip(attack=True)
    size_mb = random.randint(50, 2000)
    msg = f"Large outbound transfer {size_mb}MB from {src} to {dst}:443 detected"
    return {"id": str(uuid.uuid4()), "timestamp": _ts(), "source": "dlp",
            "log_level": "CRITICAL", "message": msg, "host": src,
            "service": "dlp-agent", "parsed_fields": {"src_ip": src, "dst_ip": dst,
                                                       "size_mb": size_mb, "attack_type": "data_exfiltration"}}


def make_c2_beacon_log() -> dict:
    src = random.choice(INTERNAL_IPS)
    c2 = _src_ip(attack=True)
    interval = random.choice([30, 60, 120, 300])
    msg = f"Periodic beacon from {src} to {c2}:443 every {interval}s — possible C2 activity"
    return {"id": str(uuid.uuid4()), "timestamp": _ts(), "source": "ids",
            "log_level": "CRITICAL", "message": msg, "host": src,
            "service": "suricata", "parsed_fields": {"src_ip": src, "c2_ip": c2,
                                                      "interval_s": interval, "attack_type": "c2_beacon"}}


NORMAL_GENERATORS = [make_normal_auth_log, make_web_log]
ATTACK_GENERATORS = [
    make_brute_force_log, make_web_log, make_port_scan_log,
    make_data_exfil_log, make_c2_beacon_log,
]


def generate_batch(size: int = 50, attack_probability: float = 0.05) -> list[dict]:
    logs = []
    for _ in range(size):
        if random.random() < attack_probability:
            gen = random.choice(ATTACK_GENERATORS)
            if gen == make_web_log:
                logs.append(gen(attack=True))
            else:
                logs.append(gen())
        else:
            gen = random.choice(NORMAL_GENERATORS)
            if gen == make_web_log:
                logs.append(gen(attack=False))
            else:
                logs.append(gen())
    return logs
