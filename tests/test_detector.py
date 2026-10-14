import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1] / "src"))

from storage_resilience import (
    CONCURRENCE_BONUS, DETECTOR_WEIGHTS, FEATURES, Detector,
    TelemetryEmulator, empirical_quantile, fit_baseline, wilson_interval,
)


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

    def test_published_weights_are_complete_and_normalized(self):
        self.assertEqual(len(DETECTOR_WEIGHTS), len(FEATURES))
        self.assertAlmostEqual(sum(DETECTOR_WEIGHTS), 1.0)

    def test_concurrence_bonus_is_applied(self):
        detector = Detector(self.baseline, threshold=100.0)
        window = self.emulator.attack("office", "fast")
        z = [max(0.0, min(6.0, (x - m) / (1.4826 * d))) for x, m, d in zip(window.values, self.baseline.center, self.baseline.mad)]
        weighted = sum(weight * value for weight, value in zip(DETECTOR_WEIGHTS, z))
        self.assertAlmostEqual(detector.score(window), weighted + CONCURRENCE_BONUS)

    def test_release_hysteresis_allows_a_later_transition(self):
        detector = Detector(self.baseline)
        detector.update(self.emulator.attack("office", "fast"))
        self.assertTrue(detector.update(self.emulator.attack("office", "fast"))[1])
        for _ in range(20):
            detector.update(self.emulator.benign("office"))
        self.assertFalse(detector.contained)


if __name__ == "__main__":
    unittest.main()
