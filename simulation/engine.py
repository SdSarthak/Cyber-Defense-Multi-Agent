"""SIEM simulation engine — continuously generates log events and feeds them to agents."""
import asyncio
import random
import structlog
from core.config import settings
# Reached through the module object rather than imported by value, so the one
# patch point used everywhere else in the codebase also swaps the store here.
from core.database import redis_client
from simulation.log_generators.generators import generate_batch, ATTACK_GENERATORS, make_web_log

log = structlog.get_logger()

LOG_QUEUE_KEY = "sim:log_queue"

# The producer runs forever; the consumer only runs when the API is up and
# SIMULATION_CONSUMER_ENABLED is set. Without a cap, a simulation left running
# against a stopped consumer grows an untrimmed, never-expiring Redis list at
# SIMULATION_LOG_RATE entries per second until the instance runs out of memory.
# Trimming to the newest N drops the stalest backlog, which is the right policy
# for a live SIEM feed.
MAX_QUEUE_LENGTH = 10_000

# Spacing between APT stages, so the multi-stage campaign arrives as a sequence of
# distinct events rather than one indistinguishable burst.
APT_STAGE_DELAY_SECONDS = 2.0


class SimulationEngine:
    def __init__(self):
        self._running = False
        self._tick = 0
        self._tasks: list[asyncio.Task] = []

    async def start(self):
        self._running = True
        log.info("simulation.start", mode=settings.simulation_mode,
                 rate=settings.simulation_log_rate,
                 attack_prob=settings.simulation_attack_probability)
        self._tasks = [
            asyncio.create_task(self._log_producer(), name="sim.log_producer"),
            asyncio.create_task(self._attack_scenario_injector(), name="sim.injector"),
            asyncio.create_task(self._heartbeat(), name="sim.heartbeat"),
        ]
        try:
            # FIRST_EXCEPTION, not gather(): a bare gather leaves the surviving
            # coroutines running detached when one of them dies, so a Redis outage
            # in the producer left the heartbeat happily reporting "running".
            done, pending = await asyncio.wait(
                self._tasks, return_when=asyncio.FIRST_EXCEPTION
            )
            for task in done:
                task.result()  # re-raise the first failure
        finally:
            await self._shutdown()

    async def _shutdown(self) -> None:
        self._running = False
        for task in self._tasks:
            task.cancel()
        if self._tasks:
            await asyncio.gather(*self._tasks, return_exceptions=True)
        self._tasks = []

    async def _enqueue(self, entries: list[dict]) -> None:
        """Push log entries onto the shared queue, keeping it bounded."""
        for entry in entries:
            await redis_client.cache.lpush(LOG_QUEUE_KEY, entry)
        if entries:
            await redis_client.cache.ltrim(LOG_QUEUE_KEY, 0, MAX_QUEUE_LENGTH - 1)

    async def _log_producer(self):
        """Generate logs at the configured rate and push to Redis for log analysis agent."""
        while self._running:
            batch = generate_batch(
                size=max(int(settings.simulation_log_rate), 0),
                attack_probability=settings.simulation_attack_probability,
            )
            await self._enqueue(batch)
            # Notify log analysis agent
            await redis_client.cache.publish("agent_events", {
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
        await self._enqueue(batch)
        await redis_client.cache.publish("escalations", {
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
        await self._enqueue(batch)
        await redis_client.cache.publish("escalations", {
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
        for i, stage in enumerate(stages):
            await self._enqueue([stage])
            # Space the stages apart, but do not idle after the final one — the
            # escalation for a completed campaign should not wait on a dead delay.
            if i < len(stages) - 1:
                await asyncio.sleep(APT_STAGE_DELAY_SECONDS)
        await redis_client.cache.publish("escalations", {
            "agent": "simulation",
            "severity": "critical",
            "threat_type": "apt_campaign",
            "attacker_ip": attacker_ip,
            "victim_ip": victim_ip,
            "event": stages[-1],
        })

    async def _heartbeat(self):
        while self._running:
            await redis_client.cache.set("sim:heartbeat", {"tick": self._tick, "running": self._running}, ttl=60)
            await asyncio.sleep(10)

    def stop(self):
        """Ask the loops to finish. Cancels immediately so a 120s sleep is not awaited."""
        self._running = False
        for task in self._tasks:
            task.cancel()


async def main():
    engine = SimulationEngine()
    try:
        await engine.start()
    except (KeyboardInterrupt, asyncio.CancelledError):
        # `start()` already drained its tasks in its finally block; this only keeps
        # Ctrl-C from printing a traceback over a clean shutdown.
        log.info("simulation.stopped")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
