"""Metric accumulators used by the Level 2 evaluation framework."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


def _ratio(numerator: int, denominator: int) -> float:
    return numerator / denominator if denominator else 0.0


@dataclass
class PRFCounts:
    """Micro-averaged true-positive, false-positive and false-negative counts."""

    tp: int = 0
    fp: int = 0
    fn: int = 0

    def add(self, other: "PRFCounts") -> None:
        self.tp += other.tp
        self.fp += other.fp
        self.fn += other.fn

    def result(self) -> dict[str, Any]:
        precision = _ratio(self.tp, self.tp + self.fp)
        recall = _ratio(self.tp, self.tp + self.fn)
        f1 = (
            2 * precision * recall / (precision + recall)
            if precision + recall
            else 0.0
        )
        return {
            "precision": precision,
            "recall": recall,
            "f1": f1,
            "tp": self.tp,
            "fp": self.fp,
            "fn": self.fn,
        }


@dataclass
class AccuracyCounts:
    """Exact-label accuracy counts."""

    correct: int = 0
    total: int = 0

    def add(self, other: "AccuracyCounts") -> None:
        self.correct += other.correct
        self.total += other.total

    def result(self) -> dict[str, Any]:
        return {
            "accuracy": _ratio(self.correct, self.total),
            "correct": self.correct,
            "total": self.total,
        }
