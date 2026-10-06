# Evaluation protocol

## Workloads

Use representative office documents, source trees, media, compressed archives, virtual-disk images, and database-like write streams. Include benign backup, restore, migration, bulk rename, compression, deployment, and media-processing jobs.

## Adversarial scenarios

Exercise fast encryption, slow encryption, partial-file modification, rename churn, snapshot deletion attempts, telemetry loss, and replication contamination. Use safe emulators or legally obtained samples only in an isolated testbed.

## Measures

- detection latency from first malicious write;
- files and bytes modified before containment;
- false containments per 1,000 benign workload-hours;
- age of the last validated recovery point;
- recovery-candidate validation yield; and
- time to validated application handoff.

Report the median, tail values, confidence intervals, independent-run count, hardware, software versions, workload split, detector thresholds, and missing telemetry. Compare no containment, each single signal, the complete detector, and feature ablations. Configuration targets must not be reported as observed results.

## Included synthetic benchmark

The companion implementation uses numeric feature vectors only; it never touches user files. Forty deterministic seeds cover office, source, media, archive, virtual-disk, and database profiles. Each seed/workload pair uses separate baseline, calibration, and test splits. Calibration includes backup, restore, migration, compression, bulk rename, and deployment confounders. The 99.5th percentile calibration score becomes the workload-specific containment threshold.

The published aggregate covers 2,016 simulated benign workload-hours and 28,800 adversarial trials. Wilson score intervals are reported for proportions. A trial has twelve 60-second decision windows and requires two consecutive threshold crossings. The raw per-trial table and SHA-256 manifest are in `evidence/results/`.

This benchmark is a reference-implementation test, not a substitute for replaying storage traces, executing institutionally approved ransomware samples, validating vendor APIs, measuring array overhead, or testing application-consistent recovery.
