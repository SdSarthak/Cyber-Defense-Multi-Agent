"""SIEM simulation engine — continuously generates log events and feeds them to agents."""
import asyncio
import random
import structlog
from core.config import settings
from core.database.redis_client import cache
from simulation.log_generators.generators import generate_batch, ATTACK_GENERATORS, make_web_log

log = structlog.get_logger()


class SimulationEngine:
    def __init__(self):
        self._running = False
        self._tick = 0

    async def start(self):
        self._running = True
        log.info("simulation.start", mode=settings.simulation_mode,
                 rate=settings.simulation_log_rate,
                 attack_prob=settings.simulation_attack_probability)
        await asyncio.gather(
            self._log_producer(),
            self._attack_scenario_injector(),
            self._heartbeat(),
        )

    async def _log_producer(self):
        """Generate logs at the configured rate and push to Redis for log analysis agent."""
        while self._running:
            batch = generate_batch(
                size=settings.simulation_log_rate,
                attack_probability=settings.simulation_attack_probability,
            )
            # Push each log to ES-simulation queue and Redis
            for entry in batch:
                await cache.lpush("sim:log_queue", entry)
            # Notify log analysis agent
            await cache.publish("agent_events", {
                "agent": "simulation",
                "event": "logs_ready",
                "count": len(batch),
            })
            self._tick += 1
            await asyncio.sleep(1.0)

    async def _attack_scenario_injector(self):
        """Periodically inject full attack scenarios for end-to-end testing."""
        scenarios = [
            self._inject_brute_force_campaign,
            self._inject_sql_injection_attack,
            self._inject_apt_scenario,
        ]
        while self._running:
            # Wait between 30-120s between scenarios
            await asyncio.sleep(random.randint(30, 120))
            scenario = random.choice(scenarios)
            log.info("simulation.inject_scenario", scenario=scenario.__name__)
            await scenario()

    async def _inject_brute_force_campaign(self):
        attacker_ip = "185.220.101.45"
        batch = [
            {"source": "sshd", "message": f"Failed password for root from {attacker_ip} port {p} ssh2",
             "log_level": "WARNING", "parsed_fields": {"src_ip": attacker_ip, "attack_type": "brute_force"}}
            for p in range(10000, 10050)
        ]
        for entry in batch:
            await cache.lpush("sim:log_queue", entry)
        await cache.publish("escalations", {
            "agent": "simulation",
            "severity": "high",
            "threat_type": "brute_force",
            "source_ip": attacker_ip,
            "event": batch[0],
        })

    async def _inject_sql_injection_attack(self):
        attacker_ip = "91.108.4.0"
        payloads = [
            "/?id=1' UNION SELECT username,password FROM users--",
            "/search?q=' OR 1=1--",
            "/login?user=admin'--&pass=x",
        ]
        batch = [
            {"source": "nginx", "log_level": "WARNING",
             "message": f'200 GET {p} HTTP/1.1 from {attacker_ip}',
             "parsed_fields": {"src_ip": attacker_ip, "path": p, "attack_type": "sql_injection"}}
            for p in payloads
        ]
        for entry in batch:
            await cache.lpush("sim:log_queue", entry)
        await cache.publish("escalations", {
            "agent": "simulation",
            "severity": "critical",
            "threat_type": "sql_injection",
            "source_ip": attacker_ip,
            "event": batch[0],
        })

    async def _inject_apt_scenario(self):
        """Multi-stage APT: recon → exploit → C2 → exfil."""
        attacker_ip = "198.51.100.23"
        victim_ip = "10.0.1.50"
        stages = [
            {"source": "firewall", "log_level": "WARNING",
             "message": f"Port scan from {attacker_ip} - 1024 ports",
             "parsed_fields": {"src_ip": attacker_ip, "attack_type": "port_scan", "stage": "recon"}},
            {"source": "nginx", "log_level": "CRITICAL",
             "message": f"Exploit attempt: /../../../etc/passwd from {attacker_ip}",
             "parsed_fields": {"src_ip": attacker_ip, "attack_type": "path_traversal", "stage": "exploit"}},
            {"source": "ids", "log_level": "CRITICAL",
             "message": f"C2 beacon from {victim_ip} to {attacker_ip} every 60s",
             "parsed_fields": {"src_ip": victim_ip, "c2_ip": attacker_ip,
                               "attack_type": "c2_beacon", "stage": "c2"}},
            {"source": "dlp", "log_level": "CRITICAL",
             "message": f"Data exfiltration: 500MB from {victim_ip} to {attacker_ip}:443",
             "parsed_fields": {"src_ip": victim_ip, "dst_ip": attacker_ip,
                               "size_mb": 500, "attack_type": "data_exfiltration", "stage": "exfil"}},
        ]
        for stage in stages:
            await cache.lpush("sim:log_queue", stage)
            await asyncio.sleep(2)
        await cache.publish("escalations", {
            "agent": "simulation",
            "severity": "critical",
            "threat_type": "apt_campaign",
            "attacker_ip": attacker_ip,
            "victim_ip": victim_ip,
            "event": stages[-1],
        })

    async def _heartbeat(self):
        while self._running:
            await cache.set("sim:heartbeat", {"tick": self._tick, "running": self._running}, ttl=60)
            await asyncio.sleep(10)

    def stop(self):
        self._running = False


async def main():
    engine = SimulationEngine()
    try:
        await engine.start()
    except KeyboardInterrupt:
        engine.stop()


if __name__ == "__main__":
    asyncio.run(main())
