import unittest

import numpy as np

from urh.ainterpretation import AutoInterpretation


def _two_tone_burst(bits, symbol_samples, deviation, sample_rate, noise=0.1, seed=1):
    """Continuous-phase 2-FSK at +/- deviation, sampled at sample_rate."""
    rng = np.random.default_rng(seed)
    phase = 0.0
    out = []
    for bit in bits:
        freq = deviation if bit == "1" else -deviation
        for _ in range(symbol_samples):
            phase += 2.0 * np.pi * freq / sample_rate
            out.append(np.exp(1j * phase))
    signal = np.asarray(out, dtype=np.complex64)
    signal += (
        rng.normal(0, noise, len(signal)) + 1j * rng.normal(0, noise, len(signal))
    ).astype(np.complex64)
    return signal


def _single_tone_burst(n, frequency, sample_rate, amplitude=0.8, noise=0.25, seed=0):
    rng = np.random.default_rng(seed)
    t = np.arange(n) / sample_rate
    signal = (amplitude * np.exp(1j * 2.0 * np.pi * frequency * t)).astype(np.complex64)
    signal += (
        rng.normal(0, noise, n) + 1j * rng.normal(0, noise, n)
    ).astype(np.complex64)
    return signal


class TestShortBurstClassification(unittest.TestCase):
    """
    A single short tone burst (an OOK pulse) is much shorter than a real FSK
    message. On such segments the FFT has one strong peak plus leakage/noise
    maxima only ~20-30 dB down, which the multi-peak test used to count as extra
    tones, so an OOK pulse was classified as FSK. The spectral tests must not be
    trusted below a minimum segment length.
    """

    def test_short_single_tone_pulse_is_not_fsk(self):
        sample_rate = 1_800_000
        # A short, low-noise single-tone burst (an OOK pulse): its spectrum is
        # one strong peak plus leakage maxima only ~20-30 dB down.
        for frequency in (100_000, 400_000, 800_000):
            pulse = _single_tone_burst(
                840, frequency, sample_rate, noise=0.1, seed=frequency
            )
            self.assertNotEqual(
                AutoInterpretation.detect_modulation(pulse),
                "FSK",
                f"a short single tone burst at {frequency} Hz must not be FSK",
            )

    def test_long_two_tone_burst_is_fsk(self):
        signal = _two_tone_burst(
            bits="1011010010110100" * 4,
            symbol_samples=500,
            deviation=20_000,
            sample_rate=1_000_000,
        )
        self.assertEqual(AutoInterpretation.detect_modulation(signal), "FSK")


if __name__ == "__main__":
    unittest.main()
