"""
Detection quality against the simulator's ground truth (scripts/evaluate_detection.py).

These numbers describe the simulator's attack phrasing, not real-world traffic; the
point is to catch regressions — a pattern edit that stops detecting an attack class,
or starts flagging normal logs.
"""
import random

from scripts.evaluate_detection import main, score
from agents.log_analysis.agent import detect


def test_every_planted_attack_class_is_detected_without_false_positives():
    random.seed(3)
    result = score(batches=60, normal=80, anomalies_for=lambda batch: detect(batch)[1])
    assert all(recall == 1.0 for recall in result["recall"].values()), result["recall"]
    assert result["false_positive_rate"] < 0.005


def test_cli_exit_status_gates_on_recall():
    assert main(["--batches", "20", "--seed", "5"]) == 0
