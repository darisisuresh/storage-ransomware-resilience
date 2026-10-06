import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1] / "src"))

from storage_resilience import Detector, TelemetryEmulator, empirical_quantile, fit_baseline, wilson_interval


class DetectorTests(unittest.TestCase):
    def setUp(self):
        self.emulator = TelemetryEmulator(7)
        self.baseline = fit_baseline(self.emulator.benign("office") for _ in range(240))

    def test_fast_attack_requires_sustained_windows(self):
        detector = Detector(self.baseline)
        self.assertFalse(detector.update(self.emulator.attack("office", "fast"))[1])
        self.assertTrue(detector.update(self.emulator.attack("office", "fast"))[1])

    def test_steady_benign_does_not_contain(self):
        detector = Detector(self.baseline)
        decisions = [detector.update(self.emulator.benign("office"))[1] for _ in range(100)]
        self.assertFalse(any(decisions))

    def test_baseline_minimum(self):
        with self.assertRaises(ValueError):
            fit_baseline(self.emulator.benign("office") for _ in range(19))

    def test_wilson_interval_bounds_rate(self):
        low, high = wilson_interval(90, 100)
        self.assertLess(low, .9)
        self.assertGreater(high, .9)

    def test_empirical_quantile(self):
        self.assertEqual(empirical_quantile([1, 2, 3, 4], .75), 3)


if __name__ == "__main__":
    unittest.main()
