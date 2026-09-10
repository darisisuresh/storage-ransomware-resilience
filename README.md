# Storage Ransomware Resilience

[![Pages](https://img.shields.io/badge/GitHub%20Pages-live-1c67ff)](https://darisisuresh.github.io/storage-ransomware-resilience/)
[![License: MIT](https://img.shields.io/badge/License-MIT-0b7285.svg)](LICENSE)

**Website:** https://darisisuresh.github.io/storage-ransomware-resilience/

Private companion repository for the research manuscript *Storage-Based Ransomware Detection and Recovery: A Closed-Loop Architecture for Array-Level Resilience*.

The project describes a vendor-neutral control plane that joins storage telemetry, workload-aware anomaly scoring, reversible containment, immutable recovery points, and isolated recovery validation. This repository intentionally excludes the manuscript and raw integrity reports.

## Research boundary

The current work presents an architecture and evaluation protocol. It does not claim production measurements, universal detection accuracy, or guaranteed recovery. Timing thresholds are configuration examples that require calibration against each workload.

## Repository contents

- `docs/` — responsive project website
- `evidence/architecture.md` — sanitized architectural specification
- `evidence/evaluation-protocol.md` — reproducible test plan
- `scripts/privacy_check.py` — publication privacy gate
- `tests/` — privacy-check regression tests

## Validate

```bash
python3 scripts/privacy_check.py
python3 -m unittest discover -s tests -v
```

## Citation

```bibtex
@article{darisi_storage_ransomware_resilience,
  author = {Suresh Kumar Darisi},
  title = {Storage-Based Ransomware Detection and Recovery: A Closed-Loop Architecture for Array-Level Resilience},
  year = {2026},
  note = {Manuscript under preparation},
  url = {https://github.com/darisisuresh/storage-ransomware-resilience}
}
```

## Author

**Suresh kumar Darisi**

## License

Code is provided under the MIT License. Documentation is provided under CC BY 4.0. Third-party names remain the property of their respective owners.
