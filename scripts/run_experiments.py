#!/usr/bin/env python3
"""Run the deterministic synthetic benchmark and publish aggregate evidence."""

from __future__ import annotations

import csv
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from storage_resilience import (
    ATTACKS, BENIGN_JOBS, WORKLOADS, CONCURRENCE_BONUS,
    CONCURRENCE_MIN_FEATURES, CONCURRENCE_Z, DEFAULT_THRESHOLD,
    DETECTOR_WEIGHTS, FEATURES, RELEASE_RATIO, SUSTAIN_WINDOWS, Z_CLIP_MAX,
    Detector, TelemetryEmulator, empirical_quantile, fit_baseline,
    wilson_interval,
)

SEEDS = tuple(range(40))
BASELINE_WINDOWS = 240
STEADY_WINDOWS = 360
BENIGN_JOB_WINDOWS = 24
CALIBRATION_WINDOWS_PER_JOB = 80
ATTACK_TRIALS = 30
ATTACK_WINDOWS = 12
WINDOW_SECONDS = 60


def run() -> dict:
    benign_decisions = 0
    benign_windows = 0
    attack_rows = []
    by_attack = {name: {"trials": 0, "detected": 0, "latencies": []} for name in ATTACKS}
    by_benign = {name: {"windows": 0, "decisions": 0} for name in ("steady", *BENIGN_JOBS)}
    thresholds = {name: [] for name in WORKLOADS}

    for seed in SEEDS:
        emulator = TelemetryEmulator(seed)
        for workload in WORKLOADS:
            baseline = fit_baseline(emulator.benign(workload) for _ in range(BASELINE_WINDOWS))
            calibration = [emulator.benign(workload) for _ in range(400)]
            for job in BENIGN_JOBS:
                calibration.extend(emulator.benign(workload, job) for _ in range(CALIBRATION_WINDOWS_PER_JOB))
            scorer = Detector(baseline)
            threshold = max(2.30, empirical_quantile([scorer.score(w) for w in calibration], .995))
            thresholds[workload].append(threshold)
            detector = Detector(baseline, threshold=threshold)
            benign_sequence = [("steady", emulator.benign(workload)) for _ in range(STEADY_WINDOWS)]
            for job in BENIGN_JOBS:
                benign_sequence.extend((job, emulator.benign(workload, job)) for _ in range(BENIGN_JOB_WINDOWS))
            for job, window in benign_sequence:
                _, contain = detector.update(window)
                benign_decisions += int(contain)
                benign_windows += 1
                by_benign[job]["windows"] += 1
                by_benign[job]["decisions"] += int(contain)

            for scenario in ATTACKS:
                for trial in range(ATTACK_TRIALS):
                    detector = Detector(baseline, threshold=threshold)
                    latency = None
                    for index in range(ATTACK_WINDOWS):
                        progress = min(1.0, 0.34 + index * 0.11) if scenario == "slow" else 1.0
                        _, contain = detector.update(emulator.attack(workload, scenario, progress))
                        if contain:
                            latency = (index + 1) * WINDOW_SECONDS
                            break
                    record = by_attack[scenario]
                    record["trials"] += 1
                    if latency is not None:
                        record["detected"] += 1
                        record["latencies"].append(latency)
                    attack_rows.append((seed, workload, scenario, trial, latency or "not_detected"))

    hours = benign_windows * WINDOW_SECONDS / 3600
    overall_trials = sum(v["trials"] for v in by_attack.values())
    overall_detected = sum(v["detected"] for v in by_attack.values())
    attack_summary = {}
    for name, values in by_attack.items():
        lo, hi = wilson_interval(values["detected"], values["trials"])
        latencies = sorted(values["latencies"])
        attack_summary[name] = {
            "trials": values["trials"],
            "detected": values["detected"],
            "detection_rate": round(values["detected"] / values["trials"], 6),
            "wilson_95": [round(lo, 6), round(hi, 6)],
            "median_latency_seconds": latencies[len(latencies) // 2] if latencies else None,
            "p95_latency_seconds": latencies[min(len(latencies) - 1, int(len(latencies) * .95))] if latencies else None,
        }
    lo, hi = wilson_interval(overall_detected, overall_trials)
    benign_summary = {}
    for name, values in by_benign.items():
        job_hours = values["windows"] * WINDOW_SECONDS / 3600
        benign_summary[name] = {
            "windows": values["windows"],
            "hours": job_hours,
            "false_containment_decisions": values["decisions"],
            "false_containments_per_1000_hours": round(values["decisions"] / job_hours * 1000, 6),
        }
    threshold_summary = {
        name: {
            "minimum": round(min(values), 6),
            "median": round(sorted(values)[len(values) // 2], 6),
            "maximum": round(max(values), 6),
        }
        for name, values in thresholds.items()
    }
    result = {
        "schema_version": "1.0",
        "evidence_type": "deterministic synthetic telemetry emulator",
        "claim_boundary": "Not malware execution, array benchmarking, or production validation.",
        "configuration": {
            "seeds": len(SEEDS), "workloads": list(WORKLOADS), "attacks": list(ATTACKS),
            "baseline_windows_per_workload_seed": BASELINE_WINDOWS,
            "benign_steady_windows_per_workload_seed": STEADY_WINDOWS,
            "benign_job_windows_per_job_workload_seed": BENIGN_JOB_WINDOWS,
            "calibration_windows_per_job_workload_seed": CALIBRATION_WINDOWS_PER_JOB,
            "threshold_calibration_quantile": 0.995,
            "minimum_threshold": DEFAULT_THRESHOLD,
            "features": list(FEATURES),
            "feature_weights": dict(zip(FEATURES, DETECTOR_WEIGHTS)),
            "z_clip_max": Z_CLIP_MAX,
            "concurrence_z": CONCURRENCE_Z,
            "concurrence_min_features": CONCURRENCE_MIN_FEATURES,
            "concurrence_bonus": CONCURRENCE_BONUS,
            "sustain_windows": SUSTAIN_WINDOWS,
            "release_ratio": RELEASE_RATIO,
            "attack_trials_per_scenario_workload_seed": ATTACK_TRIALS,
            "attack_windows_per_trial": ATTACK_WINDOWS, "window_seconds": WINDOW_SECONDS,
        },
        "aggregate": {
            "benign_windows": benign_windows, "benign_hours": hours,
            "false_containment_decisions": benign_decisions,
            "false_containments_per_1000_hours": round(benign_decisions / hours * 1000, 6),
            "attack_trials": overall_trials, "detected_trials": overall_detected,
            "detection_rate": round(overall_detected / overall_trials, 6),
            "wilson_95": [round(lo, 6), round(hi, 6)],
        },
        "thresholds_by_workload": threshold_summary,
        "false_containment_by_benign_activity": benign_summary,
        "by_attack": attack_summary,
    }
    return result, attack_rows


def write_outputs(result: dict, attack_rows: list[tuple]) -> None:
    out = ROOT / "evidence" / "results"
    out.mkdir(parents=True, exist_ok=True)
    json_path = out / "synthetic-benchmark.json"
    csv_path = out / "attack-trials.csv"
    json_path.write_text(json.dumps(result, indent=2) + "\n")
    with csv_path.open("w", newline="") as handle:
        writer = csv.writer(handle, lineterminator="\n")
        writer.writerow(("seed", "workload", "scenario", "trial", "decision_latency_seconds"))
        writer.writerows(attack_rows)
    manifest = {
        path.name: hashlib.sha256(path.read_bytes()).hexdigest()
        for path in (json_path, csv_path)
    }
    (out / "SHA256SUMS.json").write_text(json.dumps(manifest, indent=2) + "\n")


if __name__ == "__main__":
    findings, rows = run()
    write_outputs(findings, rows)
    print(json.dumps(findings["aggregate"], indent=2))
