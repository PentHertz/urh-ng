"""
Frame Analyzer for URH auto-detection.

Analyzes raw demodulated bits to detect:
1. Encoding type (NRZ, Manchester, PWM) per segment
2. Preamble boundaries
3. Sync word boundaries
4. Data boundaries

Works like rtl_433/Flipper: detect timing first, then decode.
"""

from collections import Counter
from typing import List, Tuple, Optional


class FrameSegment:
    """A segment of the frame with detected encoding."""

    def __init__(
        self,
        start: int,
        end: int,
        encoding: str,
        role: str,
        decoded_bits: str = "",
    ):
        self.start = start
        self.end = end
        self.encoding = encoding  # "nrz", "manchester", "pwm", "gap"
        self.role = role  # "preamble", "sync", "data", "gap", "padding"
        self.decoded_bits = decoded_bits

    @property
    def raw_bits(self):
        return self.end - self.start

    def __repr__(self):
        return (
            f"Segment({self.role}, bits {self.start}-{self.end}, "
            f"{self.encoding}, decoded={len(self.decoded_bits)}b)"
        )


def analyze_frame(raw_bits: str) -> List[FrameSegment]:
    """
    Analyze a raw demodulated bitstream and detect its structure.

    Returns a list of FrameSegments describing each part of the frame:
    preamble, sync/gap, data, padding.

    Each segment has its detected encoding and decoded bits.
    """
    if not raw_bits or len(raw_bits) < 8:
        return []

    segments = []

    # Step 1: Build run-length encoding
    runs = _build_runs(raw_bits)
    if not runs:
        return []

    # Step 2: Find leading zeros / silence
    pos = 0
    if raw_bits[0] == "0":
        zero_len = 0
        while zero_len < len(raw_bits) and raw_bits[zero_len] == "0":
            zero_len += 1
        if zero_len >= 4:
            segments.append(FrameSegment(0, zero_len, "nrz", "padding"))
            pos = zero_len

    # Step 3: Detect preamble type and boundaries
    preamble_end, preamble_type = _detect_preamble(raw_bits, pos)

    has_preamble = preamble_end > pos

    # If no preamble found at the start, scan forward for one.
    # This handles captures that start mid-packet (e.g., HCS200
    # where data comes before the preamble of the next repeat).
    if not has_preamble and len(raw_bits) > 32:
        scan_pos = pos
        while scan_pos < len(raw_bits) - 16:
            # Skip to the next run of zeros (inter-packet gap)
            while scan_pos < len(raw_bits) and raw_bits[scan_pos] != "0":
                scan_pos += 1
            # Skip the zeros
            gap_start = scan_pos
            while scan_pos < len(raw_bits) and raw_bits[scan_pos] == "0":
                scan_pos += 1
            if scan_pos - gap_start < 4:
                scan_pos += 1
                continue
            # Try to detect preamble after this gap
            pe, pt = _detect_preamble(raw_bits, scan_pos)
            if pe > scan_pos:
                # Found a preamble further in the signal.
                # Everything before it is a partial/previous packet.
                if gap_start > pos:
                    segments.append(FrameSegment(pos, gap_start, "nrz", "padding"))
                segments.append(FrameSegment(gap_start, scan_pos, "nrz", "padding"))
                pos = scan_pos
                preamble_end, preamble_type = pe, pt
                has_preamble = True
                break
            scan_pos += 1
    if has_preamble:
        # Decode preamble
        preamble_raw = raw_bits[pos:preamble_end]
        if preamble_type == "manchester":
            dec = _manchester_decode(preamble_raw)
        elif preamble_type == "pwm":
            dec = _pwm_decode(preamble_raw)
        else:
            dec = preamble_raw
        segments.append(
            FrameSegment(
                pos,
                preamble_end,
                preamble_type,
                "preamble",
                dec,
            )
        )
        pos = preamble_end

    # Step 4: Detect gap / sync between preamble and data
    # Only look for gap if a preamble was found — otherwise
    # the signal has no preamble (common in rtl_433 sensors)
    # and we should treat everything as data.
    if has_preamble:
        gap_end = _detect_gap(raw_bits, pos)
        if gap_end > pos:
            segments.append(FrameSegment(pos, gap_end, "nrz", "gap"))
            pos = gap_end

    # Step 5: Detect data encoding
    if pos < len(raw_bits):
        data_raw = raw_bits[pos:]

        # Find the end of the first packet: stop at a long zero gap
        # (>= 20 consecutive zeros = inter-packet boundary).
        # This prevents repeated packets from being merged.
        packet_end = len(data_raw)
        zero_run = 0
        for k in range(len(data_raw)):
            if data_raw[k] == "0":
                zero_run += 1
                if zero_run >= 20:
                    packet_end = k - zero_run + 1
                    break
            else:
                zero_run = 0
        data_raw = data_raw[:packet_end]

        # Strip trailing zeros
        trail_start = len(data_raw)
        while trail_start > 0 and data_raw[trail_start - 1] == "0":
            trail_start -= 1
        trailing_zeros = len(data_raw) - trail_start

        if trail_start > 0:
            data_portion = data_raw[:trail_start]
            data_encoding = _detect_encoding(data_portion)

            # For Manchester encoding, ensure even data length so the
            # last pair is complete.  A trailing "10" (decoded 0) loses
            # its final '0' to zero-stripping or packet boundary truncation.
            if data_encoding == "manchester" and trail_start % 2 != 0:
                # Try to recover one more bit from the original raw signal
                abs_end = pos + trail_start
                if abs_end < len(raw_bits):
                    trail_start += 1
                    data_portion = raw_bits[pos : pos + trail_start]

            # Decode data
            if data_encoding == "manchester":
                decoded = _manchester_decode(data_portion)
                # Manchester alignment correction: the gap/preamble
                # boundary may be off by 1 bit. Try shifting the data
                # start by -1 (include last gap bit in data) and see
                # if we get fewer violations → more decoded bits.
                if pos > 0:
                    alt_data = raw_bits[pos - 1 : pos + trail_start]
                    alt_decoded = _manchester_decode(alt_data)
                    if len(alt_decoded) > len(decoded):
                        decoded = alt_decoded
                        data_portion = alt_data
                        pos -= 1
                        trail_start += 1
                        # Update gap segment end if it exists
                        if segments and segments[-1].role == "gap":
                            segments[-1].end = pos
            elif data_encoding == "pwm":
                decoded = _pwm_decode(data_portion)
            else:
                decoded = data_portion

            segments.append(
                FrameSegment(
                    pos,
                    pos + trail_start,
                    data_encoding,
                    "data",
                    decoded,
                )
            )

        # Trailing padding
        if trailing_zeros >= 4:
            segments.append(
                FrameSegment(
                    pos + trail_start,
                    len(raw_bits),
                    "nrz",
                    "padding",
                )
            )

    return segments


def get_decoded_data(segments: List[FrameSegment]) -> str:
    """Extract just the decoded data bits from segments."""
    for seg in segments:
        if seg.role == "data":
            return seg.decoded_bits
    return ""


def get_frame_summary(segments: List[FrameSegment]) -> dict:
    """Get a summary of the frame analysis."""
    data_seg = None
    preamble_seg = None
    for seg in segments:
        if seg.role == "data":
            data_seg = seg
        elif seg.role == "preamble":
            preamble_seg = seg

    return {
        "segments": len(segments),
        "preamble_encoding": (preamble_seg.encoding if preamble_seg else "none"),
        "preamble_bits": (preamble_seg.raw_bits if preamble_seg else 0),
        "data_encoding": (data_seg.encoding if data_seg else "none"),
        "data_bits_raw": (data_seg.raw_bits if data_seg else 0),
        "data_bits_decoded": (len(data_seg.decoded_bits) if data_seg else 0),
    }


# ── Internal helpers ─────────────────────────────────


def _build_runs(bits: str) -> List[Tuple[str, int]]:
    """Build run-length encoding."""
    if not bits:
        return []
    runs = []
    cur = bits[0]
    cnt = 1
    for c in bits[1:]:
        if c == cur:
            cnt += 1
        else:
            runs.append((cur, cnt))
            cur = c
            cnt = 1
    runs.append((cur, cnt))
    return runs


def _detect_encoding(bits: str) -> str:
    """
    Detect the encoding of a bit segment by analyzing
    pulse/gap timing patterns.

    Returns: "nrz", "manchester", or "pwm"
    """
    if len(bits) < 6:
        return "nrz"

    # Skip leading zeros so period analysis starts on HIGH
    first_one = bits.find("1")
    if first_one < 0:
        return "nrz"
    analysis_bits = bits[first_one:]

    runs = _build_runs(analysis_bits)
    if len(runs) < 4:
        return "nrz"

    # Analyze HIGH+LOW periods
    periods = []
    for i in range(0, len(runs) - 1, 2):
        if runs[i][0] == "1":
            periods.append(runs[i][1] + runs[i + 1][1])

    if not periods:
        return "nrz"

    period_counts = Counter(periods)
    dominant_period, dominant_count = period_counts.most_common(1)[0]
    total = len(periods)

    # HIGH run analysis
    hi_runs = [c for v, c in runs if v == "1"]
    hi_counts = Counter(hi_runs)
    hi_vals = sorted(hi_counts.keys())

    # PWM: dominant period = 3 (100=short+2gap, 110=long+1gap)
    # HIGH runs are 1 and 2
    if (
        dominant_period == 3
        and dominant_count > total * 0.5
        and set(hi_vals).issubset({1, 2})
    ):
        return "pwm"

    # Manchester: pairs of (1,1) or (2,2) with period 2 or 4
    # HIGH and LOW runs are equal and only 1-2 values
    if (
        dominant_period == 2
        and dominant_count > total * 0.4
        and set(hi_vals).issubset({1, 2})
    ):
        return "manchester"

    # If periods are mixed 2 and 3, could be Manchester
    # with some violations
    if set(hi_vals).issubset({1, 2}):
        p2 = period_counts.get(2, 0)
        p3 = period_counts.get(3, 0)
        p4 = period_counts.get(4, 0)
        if p2 + p4 > p3:
            return "manchester"
        if p3 > p2 + p4:
            return "pwm"

    return "nrz"


def _detect_preamble(bits: str, start: int) -> Tuple[int, str]:
    """
    Detect preamble pattern starting at 'start'.

    Handles all Flipper-ARF preamble types:
    1. NRZ alternating: 101010... (KeeLoq, HCS200, KIA V0, Subaru)
    2. Manchester pairs: 10011001... or 01100110... (Ford V0, Somfy, KIA V5/V6)
    3. Constant value: 111111... or 000000... (CAME, some gates)
    4. PWM preamble: 100100100... or 110110110... (HCS200 PWM-encoded 1s/0s)
    5. Header pattern: 111000111000... (Nice Flor-S 3x HIGH + 3x LOW)
    6. Somfy sync: 1111111100000000 after Manchester preamble

    Returns (end_position, encoding_type).
    """
    if start >= len(bits):
        return start, "nrz"

    remaining = len(bits) - start

    # Try 1: NRZ alternating (101010...)
    alt_end = start
    while alt_end < len(bits) - 1:
        if bits[alt_end] == bits[alt_end + 1]:
            break
        alt_end += 1
    alt_len = alt_end - start
    alt_len = alt_len + (alt_len % 2) if alt_len >= 4 else 0

    # Try 2: Manchester pairs (1001 or 0110 repeating)
    man_end = start
    while man_end + 3 < len(bits):
        chunk = bits[man_end : man_end + 4]
        if chunk in ("1001", "0110"):
            man_end += 4
        else:
            break
    man_len = man_end - start

    # Try 3: Constant value (111... or 000...)
    const_end = start
    if start < len(bits):
        val = bits[start]
        while const_end < len(bits) and bits[const_end] == val:
            const_end += 1
    const_len = const_end - start

    # Try 4: PWM preamble (100 or 110 repeating)
    pwm_end = start
    if remaining >= 6:
        pwm_pattern = bits[start : start + 3]
        if pwm_pattern in ("100", "110"):
            while pwm_end + 2 < len(bits):
                chunk = bits[pwm_end : pwm_end + 3]
                if chunk == pwm_pattern:
                    pwm_end += 3
                else:
                    break
    pwm_len = pwm_end - start

    # Try 5: Header pattern — repeating N-bit HIGH + N-bit LOW
    # Nice Flor-S: 111000 (3+3), Porsche: long constant pairs
    # Strict: first 2 cycles must be exact match, require >= 4 cycles
    hdr_end = start
    if remaining >= 12:
        n = 0
        pos = start
        if bits[start] == "1":
            while pos < len(bits) and bits[pos] == "1":
                n += 1
                pos += 1
            if 3 <= n <= 8:
                m = 0
                while pos < len(bits) and bits[pos] == "0":
                    m += 1
                    pos += 1
                # First cycle must be exact (no tolerance)
                if m == n:
                    hdr_end = pos
                    period = n + m
                    cycle_count = 1
                    while hdr_end + period <= len(bits):
                        cycle = bits[hdr_end : hdr_end + period]
                        ones = cycle.count("1")
                        zeros = cycle.count("0")
                        # Second cycle exact, rest ±1
                        tol = 0 if cycle_count < 2 else 1
                        if abs(ones - n) <= tol and abs(zeros - m) <= tol:
                            hdr_end += period
                            cycle_count += 1
                        else:
                            break
                    # Require at least 4 full cycles
                    if cycle_count < 4:
                        hdr_end = start
    hdr_len = hdr_end - start

    # Pick the longest valid preamble with minimum thresholds.
    # Higher minimums prevent false positives on random data.
    candidates = [
        (alt_len, start + alt_len, "nrz"),
        (man_len, man_end, "manchester"),
        (const_len, const_end, "nrz"),
        (pwm_len, pwm_end, "pwm"),
        (hdr_len, hdr_end, "nrz"),
    ]

    best_len = 0
    best_end = start
    best_type = "nrz"

    for clen, cend, ctype in candidates:
        # Minimum thresholds to avoid false positives:
        # NRZ alternating: 8 bits (4 cycles of 10)
        # Manchester: 8 bits (2 cycles of 1001)
        # Constant: 8 bits (8 consecutive same)
        # PWM: 9 bits (3 cycles of 100/110)
        # Header: 12 bits (handled by cycle_count >= 4)
        min_req = 8 if ctype in ("manchester", "nrz") else 9 if ctype == "pwm" else 8
        if clen >= min_req and clen > best_len:
            best_len = clen
            best_end = cend
            best_type = ctype

    if best_len < 8:
        return start, "nrz"

    return best_end, best_type


def _detect_gap(bits: str, start: int) -> int:
    """
    Detect gap/sync region after preamble.

    Handles all Flipper-ARF sync types:
    1. Zero gap (consecutive 0s) — KeeLoq, HCS200, CAME
    2. Manchester violations (00/11 pairs) — Ford V0
    3. Long sync pulse (1111...0000...) — Somfy (4x TE high + 4x TE low)
    4. KeeLoq-style sync (10x TE low gap after alternating preamble)
    """
    pos = start

    # Zero gap
    while pos < len(bits) and bits[pos] == "0":
        pos += 1

    # Somfy-style sync: block of 1s followed by block of 0s
    if pos == start and pos < len(bits) and bits[pos] == "1":
        ones_start = pos
        while pos < len(bits) and bits[pos] == "1":
            pos += 1
        ones_len = pos - ones_start
        zeros_start = pos
        while pos < len(bits) and bits[pos] == "0":
            pos += 1
        zeros_len = pos - zeros_start
        # Accept as sync if roughly equal high+low (Somfy: 4+4)
        if ones_len >= 2 and zeros_len >= 2 and abs(ones_len - zeros_len) <= 2:
            return pos  # sync pulse consumed
        # Not a sync pulse — revert
        pos = start

    # Manchester violation gap (00 or 11 pairs)
    while pos + 1 < len(bits):
        pair = bits[pos : pos + 2]
        if pair in ("00", "11"):
            pos += 2
        else:
            break

    return pos


def _manchester_decode(bits: str) -> str:
    """Manchester I decode: 01->1, 10->0, violations skipped."""
    decoded = ""
    for i in range(0, len(bits) - 1, 2):
        pair = bits[i : i + 2]
        if pair == "01":
            decoded += "1"
        elif pair == "10":
            decoded += "0"
        # Skip violations (00, 11)
    return decoded


def _pwm_decode(bits: str) -> str:
    """PWM decode: 100->1 (short), 110->0 (long), pass-through else."""
    decoded = ""
    i = 0
    while i < len(bits):
        if i + 2 < len(bits):
            s = bits[i : i + 3]
            if s == "100":
                decoded += "1"
                i += 3
                continue
            elif s == "110":
                decoded += "0"
                i += 3
                continue
        decoded += bits[i]
        i += 1
    return decoded
