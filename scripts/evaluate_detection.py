"""
Measure detection quality against the simulator's ground-truth labels.

The simulator tags every attack log with ``parsed_fields.attack_type``; the detector
never reads that field. This script builds batches of normal traffic, plants one
attack of each kind in every batch (brute force as a burst from one source, the way
it actually presents), runs the detector, and reports per-type recall plus the false
positive rate on normal logs.

    python scripts/evaluate_detection.py                  # deterministic detector
    python scripts/evaluate_detection.py --batches 200 --seed 7
    python scripts/evaluate_detection.py --llm            # also the full agent (needs GOOGLE_API_KEY)

Exit status is 1 when any type's recall is below --min-recall, so CI can gate on it.
"""
from __future__ import annotations

import argparse
import asyncio
import random
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from agents.log_analysis.agent import detect  # noqa: E402
from core.metrics import threat_type_label  # noqa: E402
from simulation.log_generators import generators as gen  # noqa: E402

BRUTE_FORCE_BURST = 8


def _attacks() -> list[tuple[str, list[dict]]]:
    """One planted attack per type: (expected type, its log entries)."""
    attacker = random.choice(gen.EXTERNAL_IPS)
    planted = [("brute_force", [gen.make_brute_force_log(attacker) for _ in range(BRUTE_FORCE_BURST)])]
    for payload, attack_type in gen.WEB_ATTACK_PAYLOADS:
        log = gen.make_web_log(attack=False)
        log["message"] = log["message"].replace(log["parsed_fields"]["path"], payload)
        log["parsed_fields"].update(path=payload, attack=True, attack_type=attack_type)
        planted.append((attack_type, [log]))
    planted.append(("port_scan", [gen.make_port_scan_log()]))
    planted.append(("data_exfiltration", [gen.make_data_exfil_log()]))
    planted.append(("c2_beacon", [gen.make_c2_beacon_log()]))
    return planted


def build_batch(normal: int) -> tuple[list[dict], list[tuple[str, set[int]]]]:
    batch = [g() if g is not gen.make_web_log else g(attack=False)
             for g in random.choices(gen.NORMAL_GENERATORS, k=normal)]
    truth: list[tuple[str, set[int]]] = []
    for attack_type, entries in _attacks():
        start = len(batch)
        batch.extend(entries)
        truth.append((attack_type, set(range(start, start + len(entries)))))
    order = list(range(len(batch)))
    random.shuffle(order)
    position = {old: new for new, old in enumerate(order)}
    shuffled = [batch[i] for i in order]
    return shuffled, [(t, {position[i] for i in idx}) for t, idx in truth]


def score(batches: int, normal: int, anomalies_for) -> dict:
    found = defaultdict(int)
    planted = defaultdict(int)
    false_positives = 0
    normal_logs = 0
    for _ in range(batches):
        batch, truth = build_batch(normal)
        anomalies = anomalies_for(batch)
        attack_indices = set().union(*(idx for _, idx in truth))
        normal_logs += len(batch) - len(attack_indices)
        for attack_type, indices in truth:
            planted[attack_type] += 1
            if any(threat_type_label(a.get("anomaly_type")) == threat_type_label(attack_type)
                   and a.get("log_index") in indices for a in anomalies):
                found[attack_type] += 1
        flagged = {a.get("log_index") for a in anomalies}
        false_positives += len({i for i in flagged if isinstance(i, int)} - attack_indices)
    return {
        "recall": {t: found[t] / planted[t] for t in sorted(planted)},
        "false_positive_rate": false_positives / max(normal_logs, 1),
        "batches": batches,
    }


def _print(name: str, result: dict) -> None:
    print(f"\n{name} - {result['batches']} batches")
    for attack_type, recall in result["recall"].items():
        print(f"  {attack_type:<20} recall {recall:6.1%}")
    print(f"  {'false positives':<20} {result['false_positive_rate']:6.2%} of normal logs")


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--batches", type=int, default=100)
    parser.add_argument("--normal", type=int, default=80, help="normal logs per batch")
    parser.add_argument("--seed", type=int, default=1)
    parser.add_argument("--min-recall", type=float, default=0.9)
    parser.add_argument("--llm", action="store_true", help="also evaluate the full LLM agent")
    args = parser.parse_args(argv)

    random.seed(args.seed)
    result = score(args.batches, args.normal, lambda batch: detect(batch)[1])
    _print("Deterministic detector", result)
    worst = min(result["recall"].values())

    if args.llm:
        from agents.log_analysis.agent import LogAnalysisAgent
        agent = LogAnalysisAgent()

        def via_agent(batch):
            return asyncio.run(agent.run({"logs": batch}))["anomalies"]

        random.seed(args.seed)
        llm_result = score(min(args.batches, 10), args.normal, via_agent)
        _print("Full agent (pattern + LLM)", llm_result)
        worst = min(worst, min(llm_result["recall"].values()))

    return 0 if worst >= args.min_recall else 1


if __name__ == "__main__":
    sys.exit(main())
