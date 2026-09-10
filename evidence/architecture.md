# Architecture specification

The reference design separates observation, decision, containment, and recovery authority.

1. Storage telemetry collectors observe block, file, object, namespace, and snapshot-delta events.
2. Workload-aware normalization compares each window with a robust rolling baseline.
3. A confidence gate selects monitoring, increased sampling, or bounded containment.
4. Reversible containment preserves an evidence point, narrows write access, and pauses affected replication.
5. Recovery candidates remain under independent retention and management authority.
6. An isolated validation zone performs integrity, contamination, and application checks before promotion.
7. An audit ledger records inputs, policy version, action, approval, and outcome.

The analytics plane has no permission to delete immutable recovery points. Promotion to production requires operator approval. Exfiltration-only extortion remains outside the detector's scope.

