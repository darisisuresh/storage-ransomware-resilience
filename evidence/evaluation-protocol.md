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

