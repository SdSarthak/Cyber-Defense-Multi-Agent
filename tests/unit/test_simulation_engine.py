"""
Simulation engine tests.

The engine is the only unbounded producer in the system: it pushes to a Redis list
forever, while the consumer only exists when the API process is up. The cases below
cover the queue staying bounded and the loops actually stopping.
"""
import asyncio

import pytest

from simulation import engine as sim_engine
from simulation.engine import LOG_QUEUE_KEY, SimulationEngine


@pytest.fixture
def small_queue(monkeypatch):
    monkeypatch.setattr(sim_engine, "MAX_QUEUE_LENGTH", 5)
    return 5


class TestQueueBound:
    async def test_enqueue_trims_to_the_cap(self, fake_cache, small_queue):
        engine = SimulationEngine()
        await engine._enqueue([{"i": i} for i in range(20)])
        assert await fake_cache.llen(LOG_QUEUE_KEY) == small_queue

    async def test_trim_keeps_the_newest_entries(self, fake_cache, small_queue):
        engine = SimulationEngine()
        await engine._enqueue([{"i": i} for i in range(20)])
        remaining = await fake_cache.lrange(LOG_QUEUE_KEY, 0, -1)
        # lpush puts newest at the head, so the head is the last entry pushed.
        assert remaining[0] == {"i": 19}
        assert all(item["i"] >= 15 for item in remaining)

    async def test_repeated_producer_ticks_do_not_grow_the_queue(
        self, fake_cache, small_queue, monkeypatch
    ):
        """
        The failure this guards: with the consumer down, the producer used to push
        `simulation_log_rate` entries every second into a list with no cap and no TTL.
        """
        from core.config import settings

        monkeypatch.setattr(settings, "simulation_log_rate", 10)
        monkeypatch.setattr(settings, "simulation_attack_probability", 0.2)

        engine = SimulationEngine()
        for _ in range(5):
            await engine._enqueue(
                sim_engine.generate_batch(size=10, attack_probability=0.2)
            )
        assert await fake_cache.llen(LOG_QUEUE_KEY) == small_queue

    async def test_empty_batch_does_not_trim(self, fake_cache):
        engine = SimulationEngine()
        await fake_cache.lpush(LOG_QUEUE_KEY, {"pre": "existing"})
        await engine._enqueue([])
        assert await fake_cache.llen(LOG_QUEUE_KEY) == 1


class TestScenarioInjection:
    async def test_apt_scenario_does_not_idle_after_the_last_stage(
        self, fake_cache, monkeypatch
    ):
        monkeypatch.setattr(sim_engine, "APT_STAGE_DELAY_SECONDS", 0.05)
        engine = SimulationEngine()

        started = asyncio.get_event_loop().time()
        await engine._inject_apt_scenario()
        elapsed = asyncio.get_event_loop().time() - started

        # Four stages, three gaps — a trailing sleep would push this past 0.2s.
        assert elapsed < 0.19
        assert await fake_cache.llen(LOG_QUEUE_KEY) == 4
        escalations = fake_cache.messages_on("escalations")
        assert len(escalations) == 1
        assert escalations[0]["threat_type"] == "apt_campaign"

    async def test_brute_force_campaign_is_capped_like_everything_else(
        self, fake_cache, small_queue
    ):
        engine = SimulationEngine()
        await engine._inject_brute_force_campaign()
        assert await fake_cache.llen(LOG_QUEUE_KEY) == small_queue
        assert len(fake_cache.messages_on("escalations")) == 1

    async def test_sql_injection_scenario_queues_every_payload(self, fake_cache):
        engine = SimulationEngine()
        await engine._inject_sql_injection_attack()
        queued = await fake_cache.lrange(LOG_QUEUE_KEY, 0, -1)
        assert len(queued) == 3
        assert all(e["parsed_fields"]["attack_type"] == "sql_injection" for e in queued)


class TestLifecycle:
    async def test_stop_cancels_the_loops_instead_of_waiting_out_a_sleep(self, fake_cache):
        """
        The injector sleeps up to 120s between scenarios. Flipping a flag alone left
        `start()` hanging for that long on shutdown.
        """
        engine = SimulationEngine()
        runner = asyncio.create_task(engine.start())
        await asyncio.sleep(0.05)
        assert len(engine._tasks) == 3

        engine.stop()
        try:
            await asyncio.wait_for(runner, timeout=2.0)
        except asyncio.CancelledError:
            pass
        assert engine._running is False
        assert engine._tasks == []

    async def test_a_failing_loop_takes_the_others_down_with_it(self, fake_cache, monkeypatch):
        """A bare gather() left the surviving loops running detached, so the
        heartbeat kept reporting "running" after the producer died."""
        async def _boom(self):
            raise RuntimeError("redis gone")

        monkeypatch.setattr(SimulationEngine, "_log_producer", _boom)
        engine = SimulationEngine()

        with pytest.raises(RuntimeError, match="redis gone"):
            await asyncio.wait_for(engine.start(), timeout=2.0)

        assert engine._tasks == []
        assert engine._running is False
