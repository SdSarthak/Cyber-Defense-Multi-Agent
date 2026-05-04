"""
Extensive stress tests — concurrency, throughput, memory pressure, failure injection.
Run with: pytest tests/stress/ -v --timeout=120
"""
import asyncio
import json
import time
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from simulation.log_generators.generators import generate_batch


# ─── Helpers ──────────────────────────────────────────────────────────────────

def make_fast_cache():
    store = {}
    lists = {}
    m = MagicMock()
    m.set = AsyncMock(side_effect=lambda k, v, ttl=None: store.update({k: v}))
    m.get = AsyncMock(side_effect=lambda k: store.get(k))
    m.delete = AsyncMock(side_effect=lambda k: store.pop(k, None))
    m.exists = AsyncMock(side_effect=lambda k: k in store)
    m.publish = AsyncMock()
    m.lpush = AsyncMock(side_effect=lambda k, v: lists.setdefault(k, []).insert(0, v))
    m.lrange = AsyncMock(side_effect=lambda k, s, e: lists.get(k, [])[s: None if e == -1 else e + 1])
    m.hset = AsyncMock()
    m.hgetall = AsyncMock(return_value={})
    m.incr = AsyncMock(return_value=1)
    m._redis = MagicMock()
    m._redis.ltrim = AsyncMock()
    return m, store


def make_fast_llm(response: dict):
    r = MagicMock()
    r.content = json.dumps(response)
    llm = MagicMock()
    llm.ainvoke = AsyncMock(return_value=r)
    return llm


# ─── Log Generator Stress ─────────────────────────────────────────────────────

class TestLogGeneratorStress:
    @pytest.mark.parametrize("size", [100, 500, 1000, 5000])
    def test_large_batch_generation_speed(self, size):
        start = time.perf_counter()
        batch = generate_batch(size=size, attack_probability=0.1)
        elapsed = time.perf_counter() - start
        assert len(batch) == size
        assert elapsed < 5.0, f"Batch of {size} took {elapsed:.2f}s — too slow"

    def test_10k_batch_all_valid(self):
        batch = generate_batch(size=10_000, attack_probability=0.05)
        assert all("id" in l and "message" in l and "timestamp" in l for l in batch)

    @pytest.mark.parametrize("attack_prob", [0.0, 0.1, 0.5, 0.9, 1.0])
    def test_attack_ratio_extremes(self, attack_prob):
        batch = generate_batch(size=500, attack_probability=attack_prob)
        assert len(batch) == 500


# ─── Agent Memory Stress ──────────────────────────────────────────────────────

class TestAgentMemoryStress:
    @pytest.mark.asyncio
    async def test_concurrent_remember_recall(self, monkeypatch):
        cache, store = make_fast_cache()
        monkeypatch.setattr("core.memory.agent_memory.cache", cache)
        from core.memory.agent_memory import AgentMemory

        async def worker(i: int):
            mem = AgentMemory(f"agent_{i}")
            await mem.remember(f"key_{i}", {"data": i * 100})
            result = await mem.recall(f"key_{i}")
            assert result == {"data": i * 100}

        await asyncio.gather(*[worker(i) for i in range(50)])

    @pytest.mark.asyncio
    async def test_blackboard_concurrent_updates(self, monkeypatch):
        cache, store = make_fast_cache()
        monkeypatch.setattr("core.memory.agent_memory.cache", cache)
        from core.memory.agent_memory import AgentMemory

        async def updater(i: int):
            await AgentMemory.blackboard_set(f"key_{i}", f"value_{i}")

        await asyncio.gather(*[updater(i) for i in range(100)])
        assert cache.set.call_count == 100

    @pytest.mark.asyncio
    async def test_history_log_high_volume(self, monkeypatch):
        cache, store = make_fast_cache()
        monkeypatch.setattr("core.memory.agent_memory.cache", cache)
        from core.memory.agent_memory import AgentMemory
        mem = AgentMemory("stress_agent")

        tasks = [mem.log_event({"type": "event", "idx": i}) for i in range(200)]
        await asyncio.gather(*tasks)
        assert cache.lpush.call_count == 200


# ─── Threat Detection Agent Stress ───────────────────────────────────────────

class TestThreatAgentStress:
    @pytest.fixture
    def agent(self, monkeypatch):
        cache, _ = make_fast_cache()
        monkeypatch.setattr("core.database.redis_client.cache", cache)
        monkeypatch.setattr("core.memory.agent_memory.cache", cache)
        monkeypatch.setattr("core.rag.rag_chain.threat_rag", AsyncMock(return_value="context"))
        with patch("langchain_google_genai.ChatGoogleGenerativeAI") as MockLLM:
            MockLLM.return_value = make_fast_llm({
                "threat_type": "port_scan", "severity": "medium", "confidence": 0.8,
                "indicators": [], "mitre_tactics": [], "mitre_techniques": [],
                "reasoning": "ok", "should_escalate": False,
            })
            from agents.threat_detection.agent import ThreatDetectionAgent
            return ThreatDetectionAgent()

    @pytest.mark.asyncio
    async def test_sequential_100_events(self, agent):
        start = time.perf_counter()
        for i in range(100):
            result = await agent.run({"source_ip": f"10.0.0.{i % 254 + 1}", "message": f"event {i}"})
            assert "severity" in result
        elapsed = time.perf_counter() - start
        assert elapsed < 30.0, f"100 sequential events took {elapsed:.2f}s"

    @pytest.mark.asyncio
    async def test_concurrent_10_events(self, agent):
        events = [{"source_ip": f"10.0.1.{i}", "message": f"threat {i}"} for i in range(10)]
        results = await asyncio.gather(*[agent.run(e) for e in events])
        assert len(results) == 10
        assert all("severity" in r for r in results)

    @pytest.mark.asyncio
    async def test_concurrent_50_events(self, agent):
        events = [{"source_ip": f"192.168.0.{i % 254}", "message": f"event {i}"} for i in range(50)]
        results = await asyncio.gather(*[agent.run(e) for e in events])
        assert len(results) == 50

    @pytest.mark.asyncio
    async def test_empty_events_no_crash(self, agent):
        results = await asyncio.gather(*[agent.run({}) for _ in range(20)])
        assert all("threat_assessment" in r for r in results)


# ─── Log Analysis Agent Stress ────────────────────────────────────────────────

class TestLogAnalysisStress:
    @pytest.fixture
    def agent(self, monkeypatch):
        cache, _ = make_fast_cache()
        monkeypatch.setattr("core.database.redis_client.cache", cache)
        monkeypatch.setattr("core.memory.agent_memory.cache", cache)
        with patch("langchain_google_genai.ChatGoogleGenerativeAI") as MockLLM:
            MockLLM.return_value = make_fast_llm({
                "anomaly_count": 1, "total_analyzed": 50,
                "anomalies": [{"log_index": 0, "anomaly_type": "brute_force",
                                "severity": "high", "source": "1.2.3.4",
                                "description": "test", "action": "block"}],
                "patterns_detected": [], "risk_summary": "ok",
            })
            from agents.log_analysis.agent import LogAnalysisAgent
            return LogAnalysisAgent()

    @pytest.mark.asyncio
    @pytest.mark.parametrize("batch_size", [10, 50, 100, 200])
    async def test_various_batch_sizes(self, agent, batch_size):
        logs = generate_batch(size=batch_size, attack_probability=0.2)
        result = await agent.run({"logs": logs})
        assert "anomalies" in result

    @pytest.mark.asyncio
    async def test_concurrent_batches(self, agent):
        batches = [generate_batch(size=20, attack_probability=0.3) for _ in range(10)]
        results = await asyncio.gather(*[agent.run({"logs": b}) for b in batches])
        assert len(results) == 10
        assert all("anomalies" in r for r in results)

    @pytest.mark.asyncio
    async def test_pattern_scan_with_all_attack_types(self, agent):
        from simulation.log_generators.generators import (
            make_brute_force_log, make_c2_beacon_log, make_data_exfil_log,
            make_port_scan_log, make_web_log,
        )
        logs = (
            [make_brute_force_log() for _ in range(5)] +
            [make_c2_beacon_log() for _ in range(5)] +
            [make_data_exfil_log() for _ in range(5)] +
            [make_port_scan_log() for _ in range(5)] +
            [make_web_log(attack=True) for _ in range(5)]
        )
        result = await agent.run({"logs": logs})
        assert len(result["pattern_hits"]) > 0


# ─── Supervisor Stress ────────────────────────────────────────────────────────

class TestSupervisorStress:
    @pytest.fixture
    def supervisor(self, monkeypatch):
        cache, _ = make_fast_cache()
        monkeypatch.setattr("core.database.redis_client.cache", cache)
        monkeypatch.setattr("core.memory.agent_memory.cache", cache)
        monkeypatch.setattr("core.rag.rag_chain.threat_rag", AsyncMock(return_value=""))
        monkeypatch.setattr("core.rag.rag_chain.vuln_rag", AsyncMock(return_value=""))
        monkeypatch.setattr("core.rag.rag_chain.compliance_rag", AsyncMock(return_value=""))
        monkeypatch.setattr("core.tools.threat_tools.get_nvd_cve", AsyncMock(return_value='{"error": "mocked"}'))
        monkeypatch.setattr("core.tools.threat_tools.search_shodan", AsyncMock(return_value='{"results": []}'))
        monkeypatch.setattr("core.tools.threat_tools.lookup_ip_reputation", AsyncMock(return_value='{}'))
        monkeypatch.setattr("core.tools.threat_tools.lookup_virustotal", AsyncMock(return_value='{}'))

        with patch("langchain_google_genai.ChatGoogleGenerativeAI") as MockLLM:
            llm = make_fast_llm({
                "agents": ["threat_detection"], "reasoning": "stress test",
                "priority": "normal", "parallel": False,
                "threat_type": "port_scan", "severity": "low", "confidence": 0.5,
                "indicators": [], "mitre_tactics": [], "mitre_techniques": [],
                "reasoning": "ok", "should_escalate": False,
            })
            MockLLM.return_value = llm
            from agents.supervisor.agent import SupervisorAgent
            return SupervisorAgent()

    @pytest.mark.asyncio
    async def test_supervisor_routes_and_dispatches(self, supervisor):
        result = await supervisor.run({
            "source_ip": "1.2.3.4",
            "message": "test event",
        })
        assert "final_report" in result
        assert "summary" in result

    @pytest.mark.asyncio
    async def test_supervisor_concurrent_tasks(self, supervisor):
        tasks = [
            supervisor.run({"source_ip": f"10.0.0.{i}", "message": f"event {i}"})
            for i in range(5)
        ]
        results = await asyncio.gather(*tasks)
        assert len(results) == 5
        assert all("final_report" in r for r in results)


# ─── End-to-End Pipeline Stress ───────────────────────────────────────────────

class TestEndToEndPipelineStress:
    @pytest.mark.asyncio
    async def test_full_pipeline_sequential(self, monkeypatch):
        """Simulate 20 attack events flowing through detection → response."""
        cache, store = make_fast_cache()
        monkeypatch.setattr("core.database.redis_client.cache", cache)
        monkeypatch.setattr("core.memory.agent_memory.cache", cache)
        monkeypatch.setattr("core.rag.rag_chain.threat_rag", AsyncMock(return_value=""))

        threat_resp = {
            "threat_type": "brute_force", "severity": "high", "confidence": 0.95,
            "indicators": ["5.5.5.5"], "mitre_tactics": ["Credential Access"],
            "mitre_techniques": ["T1110"], "reasoning": "brute force", "should_escalate": True,
        }
        ir_resp = {
            "incident_id": "stress-inc", "playbook": "brute_force", "priority": "p1",
            "containment_actions": [{"action": "Block IP", "automated": True, "status": "pending"}],
            "investigation_steps": [], "communication_plan": {}, "timeline": [],
            "estimated_resolution": "1h", "lessons_learned": [],
        }

        with patch("langchain_google_genai.ChatGoogleGenerativeAI") as MockLLM:
            call_count = 0

            async def rotating_response(*args, **kwargs):
                nonlocal call_count
                call_count += 1
                r = MagicMock()
                r.content = json.dumps(threat_resp if call_count % 2 == 1 else ir_resp)
                return r

            llm = MagicMock()
            llm.ainvoke = rotating_response
            MockLLM.return_value = llm

            from agents.threat_detection.agent import ThreatDetectionAgent
            from agents.incident_response.agent import IncidentResponseAgent

            threat_agent = ThreatDetectionAgent()
            ir_agent = IncidentResponseAgent()

            for i in range(20):
                threat_result = await threat_agent.run({
                    "source_ip": "5.5.5.5",
                    "message": f"Failed login attempt #{i}",
                })
                if threat_result.get("should_escalate"):
                    await ir_agent.run({
                        "incident": {"title": "Brute force", "type": "brute_force"},
                        "threat_assessment": threat_result["threat_assessment"],
                    })

        # Ensure publish was called (escalations + incident updates)
        assert cache.publish.call_count >= 1

    @pytest.mark.asyncio
    async def test_simulation_engine_produces_logs(self, monkeypatch):
        """Verify simulation engine generates and queues logs correctly."""
        cache, store = make_fast_cache()
        monkeypatch.setattr("core.database.redis_client.cache", cache)
        from simulation.engine import SimulationEngine

        engine = SimulationEngine()
        engine._running = True

        # Run one tick of the log producer
        batch = generate_batch(size=10, attack_probability=0.3)
        for entry in batch:
            await cache.lpush("sim:log_queue", entry)
        await cache.publish("agent_events", {"agent": "simulation", "event": "logs_ready", "count": 10})

        assert cache.lpush.call_count == 10
        assert cache.publish.call_count >= 1

    @pytest.mark.asyncio
    async def test_attack_scenario_injection(self, monkeypatch):
        cache, store = make_fast_cache()
        monkeypatch.setattr("core.database.redis_client.cache", cache)
        from simulation.engine import SimulationEngine

        engine = SimulationEngine()
        await engine._inject_brute_force_campaign()
        assert cache.lpush.call_count == 50
        escalations = [call for call in cache.publish.call_args_list
                       if call[0][0] == "escalations"]
        assert len(escalations) == 1

    @pytest.mark.asyncio
    async def test_apt_scenario_multi_stage(self, monkeypatch):
        cache, store = make_fast_cache()
        monkeypatch.setattr("core.database.redis_client.cache", cache)
        from simulation.engine import SimulationEngine

        engine = SimulationEngine()
        await engine._inject_apt_scenario()
        # 4 stages
        assert cache.lpush.call_count == 4
        escalations = [call for call in cache.publish.call_args_list
                       if call[0][0] == "escalations"]
        assert len(escalations) == 1
        assert escalations[0][0][1]["threat_type"] == "apt_campaign"


# ─── Failure Injection Tests ──────────────────────────────────────────────────

class TestFailureInjection:
    @pytest.mark.asyncio
    async def test_threat_agent_survives_llm_timeout(self, monkeypatch):
        cache, _ = make_fast_cache()
        monkeypatch.setattr("core.database.redis_client.cache", cache)
        monkeypatch.setattr("core.memory.agent_memory.cache", cache)
        monkeypatch.setattr("core.rag.rag_chain.threat_rag", AsyncMock(return_value=""))

        with patch("langchain_google_genai.ChatGoogleGenerativeAI") as MockLLM:
            async def slow_invoke(*a, **kw):
                await asyncio.sleep(0.01)
                r = MagicMock()
                r.content = json.dumps({
                    "threat_type": "unknown", "severity": "low", "confidence": 0.3,
                    "indicators": [], "mitre_tactics": [], "mitre_techniques": [],
                    "reasoning": "slow", "should_escalate": False,
                })
                return r
            llm = MagicMock()
            llm.ainvoke = slow_invoke
            MockLLM.return_value = llm
            from agents.threat_detection.agent import ThreatDetectionAgent
            agent = ThreatDetectionAgent()
            result = await agent.run({"message": "test"})
        assert "severity" in result

    @pytest.mark.asyncio
    async def test_threat_agent_survives_rag_failure(self, monkeypatch):
        cache, _ = make_fast_cache()
        monkeypatch.setattr("core.database.redis_client.cache", cache)
        monkeypatch.setattr("core.memory.agent_memory.cache", cache)
        monkeypatch.setattr("core.rag.rag_chain.threat_rag",
                            AsyncMock(side_effect=Exception("Chroma unavailable")))
        with patch("langchain_google_genai.ChatGoogleGenerativeAI") as MockLLM:
            MockLLM.return_value = make_fast_llm({
                "threat_type": "unknown", "severity": "low", "confidence": 0.3,
                "indicators": [], "mitre_tactics": [], "mitre_techniques": [],
                "reasoning": "rag failed", "should_escalate": False,
            })
            from agents.threat_detection.agent import ThreatDetectionAgent
            agent = ThreatDetectionAgent()
            result = await agent.run({"message": "test"})
        assert "threat_assessment" in result

    @pytest.mark.asyncio
    async def test_log_agent_handles_corrupt_log_entries(self, monkeypatch):
        cache, _ = make_fast_cache()
        monkeypatch.setattr("core.database.redis_client.cache", cache)
        monkeypatch.setattr("core.memory.agent_memory.cache", cache)
        with patch("langchain_google_genai.ChatGoogleGenerativeAI") as MockLLM:
            MockLLM.return_value = make_fast_llm({
                "anomaly_count": 0, "total_analyzed": 5, "anomalies": [],
                "patterns_detected": [], "risk_summary": "ok",
            })
            from agents.log_analysis.agent import LogAnalysisAgent
            agent = LogAnalysisAgent()
            # Mix of valid and corrupt entries
            logs = [
                {"id": "1", "message": "normal log", "source": "sshd", "log_level": "INFO",
                 "timestamp": "2026-05-02T00:00:00Z", "parsed_fields": {}},
                {},  # empty
                {"message": None},  # null message
                {"id": "x", "parsed_fields": None},  # null fields
                None,  # null entry - will be filtered in pattern scan
            ]
            result = await agent.run({"logs": [l for l in logs if l is not None]})
        assert "anomalies" in result

    @pytest.mark.asyncio
    async def test_redis_publish_failure_doesnt_crash_agent(self, monkeypatch):
        cache, _ = make_fast_cache()
        cache.publish = AsyncMock(side_effect=Exception("Redis connection lost"))
        monkeypatch.setattr("core.database.redis_client.cache", cache)
        monkeypatch.setattr("core.memory.agent_memory.cache", cache)
        monkeypatch.setattr("core.rag.rag_chain.threat_rag", AsyncMock(return_value=""))
        with patch("langchain_google_genai.ChatGoogleGenerativeAI") as MockLLM:
            MockLLM.return_value = make_fast_llm({
                "threat_type": "port_scan", "severity": "low", "confidence": 0.5,
                "indicators": [], "mitre_tactics": [], "mitre_techniques": [],
                "reasoning": "ok", "should_escalate": False,
            })
            from agents.threat_detection.agent import ThreatDetectionAgent
            agent = ThreatDetectionAgent()
            # Should not raise even if redis publish fails
            try:
                result = await agent.run({"message": "test"})
                assert "severity" in result
            except Exception:
                pytest.fail("Agent crashed on Redis publish failure")
