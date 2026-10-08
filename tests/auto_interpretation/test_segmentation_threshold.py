import unittest

import numpy as np

from urh.ainterpretation.AutoInterpretation import (
    detect_noise_level,
    otsu_threshold,
    segmentation_threshold,
)


def _rayleigh(rng, n, mean):
    return np.abs(rng.normal(0, mean / 1.2533, n)).astype(np.float32)


class TestSegmentationThreshold(unittest.TestCase):
    """
    `detect_noise_level` estimates the noise power, but its value is not always
    usable as a segmentation threshold: it is the maximum over the quietest
    chunks, so a single deep-fade chunk can pull it far below the actual noise
    floor. `segmentation_threshold` must return a level that still separates
    noise from signal in that case.
    """

    def test_deep_fade_chunk_does_not_break_segmentation(self):
        rng = np.random.default_rng(0)
        chunk = 400
        parts = []
        for i in range(100):
            if i == 7:
                # One 1%-of-length chunk fades far below the noise floor.
                parts.append(np.full(chunk, 0.05, dtype=np.float32))
            elif i % 5 < 2:
                parts.append(np.full(chunk, 0.65, dtype=np.float32))  # carrier
            else:
                parts.append(_rayleigh(rng, chunk, 0.20))  # noise
        magnitudes = np.concatenate(parts)

        noise = detect_noise_level(magnitudes)
        # The noise estimate admits almost the whole buffer as signal ...
        self.assertGreater(float((magnitudes > noise).mean()), 0.7)

        threshold = segmentation_threshold(magnitudes, noise)
        # ... the segmentation threshold does not: it sits between noise and
        # carrier and leaves roughly the true signal duty above it.
        above = float((magnitudes > threshold).mean())
        self.assertTrue(0.2 < above < 0.6, f"above={above} thr={threshold}")
        self.assertGreater(threshold, noise)

    def test_noise_floor_above_carrier_is_not_used(self):
        # A high noise floor can make detect_noise_level exceed the carrier, so
        # nothing is classified as signal. The segmentation level must be below
        # the carrier.
        rng = np.random.default_rng(1)
        noise = _rayleigh(rng, 20000, 0.8)
        carrier = np.full(20000, 1.0, dtype=np.float32)
        magnitudes = np.concatenate([noise, carrier])

        noise_level = detect_noise_level(magnitudes)
        threshold = segmentation_threshold(magnitudes, noise_level)
        self.assertLess(threshold, 1.0)

    def test_otsu_threshold_splits_bimodal_magnitudes(self):
        rng = np.random.default_rng(2)
        low = np.abs(rng.normal(0, 0.1, 5000)).astype(np.float32)
        high = np.abs(rng.normal(0, 0.05, 5000)).astype(np.float32) + 0.8
        threshold = otsu_threshold(np.concatenate([low, high]))
        self.assertTrue(0.2 < threshold < 0.8, threshold)

    def test_zero_noise_disables_detection(self):
        magnitudes = np.ones(1000, dtype=np.float32)
        self.assertEqual(segmentation_threshold(magnitudes, 0), 0)


if __name__ == "__main__":
    unittest.main()
