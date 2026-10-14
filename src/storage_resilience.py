"""Deterministic, safe storage-telemetry emulator and reference detector.

This module never encrypts, renames, deletes, or opens user files. It generates
numeric telemetry only, making it suitable for reproducible architecture tests.
"""

from __future__ import annotations

from dataclasses import dataclass
from math import sqrt
from random import Random
from statistics import median
from typing import Iterable, Sequence

FEATURES = ("overwrite", "rmw", "entropy_delta", "namespace", "snapshot_delta")
WORKLOADS = ("office", "source", "media", "archive", "virtual_disk", "database")
ATTACKS = ("fast", "slow", "partial", "rename_churn")

# Public policy constants. Keeping these values named and versioned makes the
# reported benchmark independently reproducible and prevents silent tuning.
DETECTOR_WEIGHTS = (0.23, 0.21, 0.22, 0.17, 0.17)
DEFAULT_THRESHOLD = 2.30
CONCURRENCE_MIN_FEATURES = 3
CONCURRENCE_Z = 2.0
CONCURRENCE_BONUS = 0.42
Z_CLIP_MAX = 6.0
SUSTAIN_WINDOWS = 2
RELEASE_RATIO = 0.72

WORKLOAD_PROFILE = {
    "office": (0.18, 0.20, 0.12, 0.20, 0.16),
    "source": (0.26, 0.30, 0.09, 0.36, 0.22),
    "media": (0.40, 0.28, 0.05, 0.08, 0.38),
    "archive": (0.58, 0.48, 0.42, 0.12, 0.55),
    "virtual_disk": (0.62, 0.56, 0.08, 0.03, 0.60),
    "database": (0.52, 0.66, 0.06, 0.04, 0.48),
}

ATTACK_SHIFT = {
    "fast": (0.72, 0.70, 0.70, 0.62, 0.74),
    "slow": (0.24, 0.28, 0.34, 0.24, 0.27),
    "partial": (0.39, 0.48, 0.20, 0.30, 0.38),
    "rename_churn": (0.28, 0.34, 0.30, 0.78, 0.35),
}

BENIGN_JOBS = {
    "backup": (0.22, 0.18, 0.02, 0.01, 0.26),
    "restore": (0.38, 0.30, 0.03, 0.05, 0.36),
    "migration": (0.46, 0.36, 0.05, 0.08, 0.44),
    "compression": (0.34, 0.32, 0.48, 0.12, 0.36),
    "bulk_rename": (0.06, 0.08, 0.02, 0.58, 0.08),
    "deployment": (0.28, 0.24, 0.12, 0.28, 0.25),
}


@dataclass(frozen=True)
class Window:
    workload: str
    values: tuple[float, ...]
    label: str = "benign"


@dataclass(frozen=True)
class Baseline:
    center: tuple[float, ...]
    mad: tuple[float, ...]


class TelemetryEmulator:
    def __init__(self, seed: int):
        self.rng = Random(seed)

    def _sample(self, centers: Sequence[float], spread: float = 0.045) -> tuple[float, ...]:
        return tuple(max(0.0, min(1.0, self.rng.gauss(c, spread))) for c in centers)

    def benign(self, workload: str, job: str | None = None) -> Window:
        base = WORKLOAD_PROFILE[workload]
        if job:
            shift = BENIGN_JOBS[job]
            centers = tuple(min(1.0, b + s) for b, s in zip(base, shift))
            return Window(workload, self._sample(centers, 0.055), f"benign:{job}")
        return Window(workload, self._sample(base), "benign:steady")

    def attack(self, workload: str, scenario: str, progress: float = 1.0) -> Window:
        base = WORKLOAD_PROFILE[workload]
        shift = ATTACK_SHIFT[scenario]
        centers = tuple(min(1.0, b + s * progress) for b, s in zip(base, shift))
        return Window(workload, self._sample(centers, 0.05), f"attack:{scenario}")


def fit_baseline(windows: Iterable[Window]) -> Baseline:
    rows = [w.values for w in windows]
    if len(rows) < 20:
        raise ValueError("at least 20 baseline windows are required")
    columns = list(zip(*rows))
    centers = tuple(median(c) for c in columns)
    mads = tuple(max(median(abs(x - m) for x in c), 0.012) for c, m in zip(columns, centers))
    return Baseline(centers, mads)


class Detector:
    weights = DETECTOR_WEIGHTS

    def __init__(self, baseline: Baseline, threshold: float = DEFAULT_THRESHOLD, sustain: int = SUSTAIN_WINDOWS):
        self.baseline = baseline
        self.threshold = threshold
        self.sustain = sustain
        self.streak = 0
        self.contained = False

    def score(self, window: Window) -> float:
        z = [max(0.0, min(Z_CLIP_MAX, (x - m) / (1.4826 * d))) for x, m, d in zip(window.values, self.baseline.center, self.baseline.mad)]
        weighted = sum(w * value for w, value in zip(self.weights, z))
        concurrence = CONCURRENCE_BONUS if sum(value >= CONCURRENCE_Z for value in z) >= CONCURRENCE_MIN_FEATURES else 0.0
        return weighted + concurrence

    def update(self, window: Window) -> tuple[float, bool]:
        score = self.score(window)
        self.streak = self.streak + 1 if score >= self.threshold else 0
        entered = self.streak >= self.sustain and not self.contained
        if entered:
            self.contained = True
        elif score < self.threshold * RELEASE_RATIO:
            self.contained = False
            self.streak = 0
        return score, entered


def empirical_quantile(values: Sequence[float], quantile: float) -> float:
    if not values or not 0.0 <= quantile <= 1.0:
        raise ValueError("non-empty values and a quantile in [0, 1] are required")
    ordered = sorted(values)
    index = min(len(ordered) - 1, int(quantile * (len(ordered) - 1)))
    return ordered[index]


def wilson_interval(successes: int, total: int, z: float = 1.96) -> tuple[float, float]:
    if total == 0:
        return (0.0, 0.0)
    p = successes / total
    denominator = 1 + z * z / total
    center = (p + z * z / (2 * total)) / denominator
    half = z * sqrt((p * (1 - p) + z * z / (4 * total)) / total) / denominator
    return (max(0.0, center - half), min(1.0, center + half))
