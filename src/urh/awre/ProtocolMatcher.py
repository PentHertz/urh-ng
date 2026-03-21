"""
Automatic protocol identification engine.

Matches demodulated URH messages against known protocol signatures
extracted from the rtl_433 project database. Can also auto-detect
the best decoder (Manchester, PWM, differential, etc.) and strip
leading zeros/noise before the preamble.
"""
import array
import copy
import re
from collections import defaultdict
from typing import List, Tuple, Optional

import numpy as np

from urh.awre.protocol_db import PROTOCOL_DATABASE
from urh.signalprocessing.Encoding import Encoding
from urh.signalprocessing.FieldType import FieldType
from urh.signalprocessing.Message import Message
from urh.signalprocessing.MessageType import MessageType
from urh.signalprocessing.ProtocoLabel import ProtocolLabel
from urh.util.Logger import logger


class ProtocolMatch:
    """Result of matching messages against a known protocol."""

    def __init__(self, protocol_entry: dict, score: float, details: dict,
                 recommended_decoder: Optional[Encoding] = None,
                 leading_zeros_count: int = 0):
        self.name = protocol_entry.get("name", "Unknown")
        self.entry = protocol_entry
        self.score = score  # 0.0 to 1.0
        self.details = details  # explanation of scoring
        self.recommended_decoder = recommended_decoder
        self.leading_zeros_count = leading_zeros_count

    @property
    def percentage(self) -> int:
        return int(self.score * 100)

    def __repr__(self):
        return f"ProtocolMatch({self.name!r}, {self.percentage}%)"


class ProtocolMatcher:
    """
    Matches URH protocol messages against known protocol signatures
    from the rtl_433 database.

    Scoring criteria:
    - Message length match (after stripping leading zeros)
    - Preamble pattern match
    - Sync word match
    - Checksum validation
    - Field structure plausibility
    - Decoder error rate
    """

    MIN_SCORE_THRESHOLD = 0.15

    # Modulation-to-decoder mapping: rtl_433 modulation → URH decoding candidates
    # Names must match URH's default decodings in ProjectManager.py
    MODULATION_DECODERS = {
        "OOK_PULSE_MANCHESTER_ZEROBIT": [
            "Manchester I", "Manchester II", "Differential Manchester",
        ],
        "OOK_PULSE_DMC": [
            "Differential Manchester", "Manchester I", "Manchester II",
        ],
        "OOK_PULSE_PCM": [
            "Non Return To Zero (NRZ)", "Non Return To Zero + Invert",
        ],
        "OOK_PULSE_NRZS": [
            "Non Return To Zero (NRZ)", "Differential Manchester",
        ],
        "FSK_PULSE_MANCHESTER_ZEROBIT": [
            "Manchester I", "Manchester II", "Differential Manchester",
        ],
        "OOK_PULSE_PWM": [
            "PWM (Short=1, Long=0)", "PWM (Short=0, Long=1)",
        ],
        "OOK_PULSE_PPM": [
            "Non Return To Zero (NRZ)", "Non Return To Zero + Invert",
        ],
        "OOK_PULSE_PIWM_RAW": [
            "PWM (Short=1, Long=0)", "PWM (Short=0, Long=1)",
        ],
        "OOK_PULSE_PIWM_DC": [
            "PWM (Short=1, Long=0)", "PWM (Short=0, Long=1)",
        ],
        "FSK_PULSE_PCM": [
            "Non Return To Zero (NRZ)", "Non Return To Zero + Invert",
        ],
        "FSK_PULSE_PWM": [
            "PWM (Short=1, Long=0)", "PWM (Short=0, Long=1)",
        ],
        # RZ (Return-to-Zero) is same as PCM/NRZ for decoding purposes
        "OOK_PULSE_RZ": [
            "Non Return To Zero (NRZ)", "Non Return To Zero + Invert",
        ],
        # Oregon Scientific v1 — special, try PWM and Manchester
        "OOK_PULSE_PWM_OSV1": [
            "PWM (Short=1, Long=0)", "Manchester I", "Manchester II",
        ],
    }

    def __init__(self, messages: List[Message], available_decodings: list = None):
        self.messages = messages
        self.available_decodings = list(available_decodings or [])
        self._ensure_essential_decodings()

    def _ensure_essential_decodings(self):
        """
        Make sure all essential decodings are available for bruteforce.
        If the user's project doesn't have them, create them on the fly.
        """
        from urh import settings

        existing_names = {d.name for d in self.available_decodings}

        essential = [
            (
                "Non Return To Zero (NRZ)",
                ["Non Return To Zero (NRZ)"],
            ),
            (
                "Manchester I",
                ["Manchester I", settings.DECODING_EDGE],
            ),
            (
                "Manchester II",
                ["Manchester II", settings.DECODING_EDGE, settings.DECODING_INVERT],
            ),
            (
                "Differential Manchester",
                [
                    "Differential Manchester",
                    settings.DECODING_EDGE,
                    settings.DECODING_DIFFERENTIAL,
                ],
            ),
            (
                "PWM (Short=1, Long=0)",
                ["PWM (Short=1, Long=0)", settings.DECODING_PWM, "1;0"],
            ),
            (
                "PWM (Short=0, Long=1)",
                ["PWM (Short=0, Long=1)", settings.DECODING_PWM, "0;1"],
            ),
            (
                "Miller",
                ["Miller", settings.DECODING_MILLER],
            ),
        ]

        for name, chain in essential:
            if name not in existing_names:
                try:
                    self.available_decodings.append(Encoding(chain))
                except Exception:
                    pass

    def find_matches(self, max_results: int = 10) -> List[ProtocolMatch]:
        """
        Find the best matching protocols by bruteforcing all decoder
        combinations against each protocol in the database.

        For each protocol, tries every available decoder, decodes the raw
        bits, and checks if the decoded length matches the expected
        protocol length. Decoders that produce the right number of data
        bits get a large score bonus.

        If a message contains multiple repeated packets (same preamble
        appearing multiple times), only the first complete packet is used
        for scoring.
        """
        if not self.messages:
            return []

        features = self._extract_message_features()
        if not features:
            return []

        # Split messages that contain repeated packets.
        # Use only the first complete packet for scoring.
        raw_bits = []
        for bs in features["bit_strings"]:
            first_pkt = _extract_first_packet(bs)
            raw_bits.append(first_pkt)
        decoded_cache = {}  # decoder_name -> list of (decoded_data, errors, state)
        for dec in self.available_decodings:
            try:
                results = []
                for bs in raw_bits[:5]:  # sample first 5 messages
                    # Find data start: skip preamble + gap + framing
                    data_start = _find_pwm_data_start(bs)
                    data_portion = bs[data_start:]
                    inpt = array.array("B", [int(b) for b in data_portion])
                    decoded, errors, state = dec.code(True, inpt)
                    decoded_str = "".join(str(b) for b in decoded)
                    results.append((decoded_str, errors, state, data_start))
                decoded_cache[dec.name] = results
            except Exception as e:
                logger.debug(f"ProtocolMatcher: decoder {dec.name} failed: {e}")

        scored = []
        for proto in PROTOCOL_DATABASE:
            base_score, details = self._score_protocol(proto, features)

            # Now try each decoder and see if the decoded length matches
            best_decoder = None
            best_decode_bonus = 0.0
            best_decode_info = ""
            proto_len = proto.get("msg_len_bits", 0)
            modulation = proto.get("modulation", "")

            # Get candidate decoders for this modulation type
            candidate_names = list(self.MODULATION_DECODERS.get(modulation, []))
            # Always also try NRZ as baseline
            if "Non Return To Zero (NRZ)" not in candidate_names:
                candidate_names.append("Non Return To Zero (NRZ)")

            for dec in self.available_decodings:
                if dec.name not in candidate_names:
                    # Also allow partial name matches
                    if not any(cn in dec.name or dec.name in cn for cn in candidate_names):
                        continue

                if dec.name not in decoded_cache:
                    continue

                dec_results = decoded_cache[dec.name]
                if not dec_results:
                    continue

                # Check decoded data lengths against protocol expectation.
                # The decoded_cache contains data-only decoded bits
                # (preamble+gap already stripped before decoding).
                decoded_lens = [len(bits) for bits, _, _, _ in dec_results if bits]
                if not decoded_lens:
                    continue

                total_errors = sum(e for _, e, _, _ in dec_results)
                avg_errors = total_errors / len(dec_results)

                # Compare decoded data against protocol length.
                # Try both with and without trailing zeros stripped,
                # and pick whichever is closer to the protocol's expected length.
                data_lens = []
                for bits, _, _, _ in dec_results:
                    if not bits:
                        continue
                    stripped = bits.rstrip("0")
                    full_len = len(bits)
                    stripped_len = len(stripped)
                    # Pick whichever is closer to proto_len
                    if proto_len > 0:
                        if abs(stripped_len - proto_len) <= abs(full_len - proto_len):
                            data_lens.append(stripped_len)
                        else:
                            data_lens.append(full_len)
                    else:
                        data_lens.append(stripped_len)

                if not data_lens:
                    continue

                median_data_len = int(np.median(data_lens))

                if proto_len > 0:
                    len_diff = abs(median_data_len - proto_len)
                    tolerance = max(proto_len * 0.15, 8)

                    if len_diff <= tolerance:
                        len_match = 1.0 - len_diff / tolerance
                        error_penalty = min(avg_errors / 50.0, 0.3)
                        bonus = 0.4 * len_match * (1.0 - error_penalty)

                        # Padding bonus: if decoded bits after the
                        # expected data are all zeros (padding/silence),
                        # it's a strong structural confirmation
                        for bits, _, _, _ in dec_results:
                            if not bits:
                                continue
                            # bits is already data-only (preamble/gap stripped)
                            after_data = bits[proto_len:]
                            if len(after_data) >= 4:
                                zero_ratio = after_data.count("0") / len(after_data)
                                if zero_ratio >= 0.9:
                                    bonus += 0.1 * zero_ratio
                            break  # check first message only

                        if bonus > best_decode_bonus:
                            best_decode_bonus = bonus
                            best_decoder = dec
                            best_decode_info = (
                                f"{dec.name}: decoded_data={median_data_len} "
                                f"vs proto={proto_len}, errors={avg_errors:.0f}"
                            )

            final_score = min(base_score + best_decode_bonus, 1.0)
            if best_decode_info:
                details["decoder_match"] = best_decode_info

            if final_score >= self.MIN_SCORE_THRESHOLD:
                # If no decoder matched via bruteforce, fall back to modulation mapping
                if best_decoder is None:
                    best_decoder = self._find_best_decoder(proto, features)

                match = ProtocolMatch(
                    proto, final_score, details,
                    recommended_decoder=best_decoder,
                    leading_zeros_count=features.get("leading_zeros", 0),
                )
                scored.append(match)

        scored.sort(key=lambda m: m.score, reverse=True)
        return scored[:max_results]

    def find_best_decoder(self) -> Tuple[Optional[Encoding], float, str]:
        """
        Try all available decodings and return the one with the lowest error rate.
        Returns (best_decoder, error_rate, explanation).
        """
        if not self.messages or not self.available_decodings:
            return None, 1.0, "No decodings available"

        best_decoder = None
        best_score = -1.0
        best_explanation = ""

        for decoding in self.available_decodings:
            total_errors = 0
            total_bits = 0
            success_count = 0

            for msg in self.messages:
                bits = msg.plain_bits
                if len(bits) == 0:
                    continue

                try:
                    decoded, errors, state = decoding.code(True, bits)
                    total_errors += errors
                    total_bits += len(bits)
                    if state == Encoding.ErrorState.SUCCESS and len(decoded) > 0:
                        success_count += 1
                except Exception:
                    total_errors += len(bits)
                    total_bits += len(bits)

            if total_bits == 0:
                continue

            error_rate = total_errors / total_bits
            success_rate = success_count / len(self.messages)
            # Score: combination of low error rate and high success rate
            score = (1.0 - error_rate) * 0.6 + success_rate * 0.4

            if score > best_score:
                best_score = score
                best_decoder = decoding
                best_explanation = (
                    f"{decoding.name}: errors={error_rate:.1%}, "
                    f"success={success_rate:.0%}"
                )

        return best_decoder, 1.0 - best_score, best_explanation

    # ── Feature extraction ───────────────────────────────────────────

    def _extract_message_features(self) -> dict:
        """Extract features from messages for matching."""
        if not self.messages:
            return {}

        bit_strings_raw = []
        for msg in self.messages:
            bits = msg.decoded_bits_str if msg.decoded_bits_str else msg.plain_bits_str
            bit_strings_raw.append(bits)

        if not bit_strings_raw:
            return {}

        # Strip leading zeros from all messages
        stripped, leading_zeros = self._strip_leading_zeros(bit_strings_raw)

        bit_lengths = [len(bs) for bs in stripped]
        if not bit_lengths or max(bit_lengths) == 0:
            return {}

        # Find common preamble in stripped messages
        preamble = self._find_common_preamble(stripped)

        # Find common sync word (after preamble)
        sync_word = self._find_sync_after_preamble(stripped, preamble)

        # Convert to hex for matching
        preamble_hex = self._bits_to_hex(preamble) if len(preamble) >= 8 else ""
        sync_hex = self._bits_to_hex(sync_word) if len(sync_word) >= 8 else ""

        return {
            "bit_lengths": bit_lengths,
            "median_length": int(np.median(bit_lengths)),
            "min_length": min(bit_lengths),
            "max_length": max(bit_lengths),
            "num_messages": len(self.messages),
            "preamble_bits": preamble,
            "preamble_hex": preamble_hex,
            "sync_bits": sync_word,
            "sync_hex": sync_hex,
            "bit_strings": stripped,
            "bit_strings_raw": bit_strings_raw,
            "leading_zeros": leading_zeros,
        }

    @staticmethod
    def _strip_leading_zeros(bit_strings: List[str]) -> Tuple[List[str], int]:
        """
        Strip leading zeros/noise before the actual preamble.
        Returns (stripped_strings, number_of_zeros_stripped).

        Leading zeros are common in URH when the demodulator captures
        silence/noise before the transmitter starts.
        """
        if not bit_strings:
            return bit_strings, 0

        # Find the first non-zero position that's consistent across messages
        # Look for the start of a preamble pattern (alternating bits)
        strip_counts = []
        for bs in bit_strings:
            # Find first '1' bit
            first_one = bs.find('1')
            if first_one < 0:
                strip_counts.append(0)
                continue

            # Look for alternating pattern starting slightly before first '1'
            # Sometimes there's a partial bit before the preamble
            start = max(0, first_one - 1)

            # Check if the pattern at 'start' looks like a preamble (alternating)
            if start > 0 and start < len(bs) - 4:
                chunk = bs[start:start + 8]
                if _is_alternating(chunk):
                    strip_counts.append(start)
                else:
                    strip_counts.append(first_one)
            else:
                strip_counts.append(first_one)

        if not strip_counts:
            return bit_strings, 0

        # Use the minimum strip count to be safe
        strip = min(strip_counts)
        if strip <= 0:
            return bit_strings, 0

        stripped = [bs[strip:] for bs in bit_strings]
        return stripped, strip

    @staticmethod
    def _find_common_preamble(bit_strings: List[str]) -> str:
        """Find the common alternating preamble pattern across messages."""
        if not bit_strings:
            return ""

        min_len = min(len(bs) for bs in bit_strings)
        if min_len < 4:
            return ""

        # First find common prefix
        common_len = 0
        for i in range(min(min_len, 128)):
            bits_at_pos = set(bs[i] for bs in bit_strings if len(bs) > i)
            if len(bits_at_pos) != 1:
                break
            common_len = i + 1

        if common_len < 4:
            return ""

        common = bit_strings[0][:common_len]

        # Find where the alternating pattern ends
        alt_len = 0
        for i in range(len(common)):
            if i > 0 and common[i] == common[i - 1]:
                break
            alt_len = i + 1

        if alt_len >= 4:
            return common[:alt_len]

        # If no alternating pattern, return common prefix as-is
        # (some protocols have fixed preambles like 0xFFFF)
        return common

    @staticmethod
    def _find_sync_after_preamble(bit_strings: List[str], preamble: str) -> str:
        """Find common sync word after the preamble."""
        if not preamble or not bit_strings:
            return ""

        preamble_len = len(preamble)
        post_preamble = [
            bs[preamble_len: preamble_len + 32]
            for bs in bit_strings
            if len(bs) > preamble_len + 8
        ]
        if not post_preamble:
            return ""

        sync_word = _find_common_prefix(post_preamble)
        # Sync word should be non-trivial
        if len(sync_word) < 4:
            return ""
        if sync_word == "0" * len(sync_word) or sync_word == "1" * len(sync_word):
            return ""
        return sync_word

    # ── Protocol scoring ─────────────────────────────────────────────

    def _score_protocol(self, proto: dict, features: dict) -> Tuple[float, dict]:
        """Score how well a protocol matches the extracted features."""
        score = 0.0
        details = {}
        weights_used = 0.0

        # 1. Message length match (weight: 0.35)
        # For PWM/PPM modulations, raw bits are ~2-3x the data bits
        # (short pulse = 2 raw bits, long pulse = 3 raw bits)
        weight = 0.35
        proto_len = proto.get("msg_len_bits", 0)
        modulation = proto.get("modulation", "")
        if proto_len > 0:
            median_len = features["median_length"]

            # Account for preamble/sync overhead in raw stream
            preamble_overhead = len(features.get("preamble_bits", ""))
            data_bits_raw = median_len - preamble_overhead

            # For PWM/PPM, each data bit takes 2-3 raw bits
            # Try multiple expansion factors and pick the best match
            if "PWM" in modulation or "PPM" in modulation:
                # Try expansion factors 2.0, 2.5, 3.0 — pick best
                best_diff = float("inf")
                best_eff = data_bits_raw
                for factor in (2.0, 2.5, 3.0):
                    eff = data_bits_raw / factor
                    d = abs(eff - proto_len)
                    if d < best_diff:
                        best_diff = d
                        best_eff = eff
                effective_data_bits = best_eff
                len_diff = best_diff
                tolerance = max(proto_len * 0.35, 16)
                which = f"raw={median_len}, ~data={int(effective_data_bits)}"
            else:
                # PCM/Manchester: raw bits ≈ data bits (or 2x for Manchester)
                if "MANCHESTER" in modulation:
                    effective_data_bits = data_bits_raw / 2.0
                else:
                    effective_data_bits = data_bits_raw
                len_diff = abs(effective_data_bits - proto_len)
                tolerance = max(proto_len * 0.25, 16)
                which = f"raw={median_len}, ~data={int(effective_data_bits)}"

            if len_diff <= tolerance:
                len_score = max(0, 1.0 - len_diff / tolerance)
                score += weight * len_score
                details["length"] = f"{which} vs proto={proto_len} ({int(len_score * 100)}%)"
            else:
                details["length"] = f"{which} vs proto={proto_len} (no match)"
            weights_used += weight
        else:
            details["length"] = "proto has no length info"

        # 2. Preamble match (weight: 0.25)
        weight = 0.25
        proto_preamble = proto.get("preamble_bits", "")
        if proto_preamble and features["preamble_hex"]:
            preamble_score = self._hex_similarity(
                features["preamble_hex"], proto_preamble
            )
            score += weight * preamble_score
            details["preamble"] = f"similarity={int(preamble_score * 100)}%"
            weights_used += weight
        elif not proto_preamble and features["preamble_hex"]:
            ph = features["preamble_hex"].lower()
            if all(c in "a5f0" for c in ph):
                score += weight * 0.3
                details["preamble"] = "generic preamble detected"
                weights_used += weight
        else:
            details["preamble"] = "no preamble info"

        # 3. Sync word match (weight: 0.2)
        weight = 0.2
        proto_sync = proto.get("sync_bytes", "")
        if proto_sync and features["sync_hex"]:
            sync_score = self._hex_similarity(features["sync_hex"], proto_sync)
            score += weight * sync_score
            details["sync"] = f"similarity={int(sync_score * 100)}%"
            weights_used += weight
        else:
            details["sync"] = "no sync match"

        # 4. Field structure plausibility (weight: 0.1)
        weight = 0.1
        fields = proto.get("fields", [])
        if fields and proto_len > 0:
            min_bits = len(fields) * 4
            max_bits = len(fields) * 32
            median_len = features["median_length"]
            if min_bits <= median_len <= max_bits:
                field_score = 0.8
            elif median_len > min_bits:
                field_score = 0.4
            else:
                field_score = 0.1
            score += weight * field_score
            details["fields"] = f"{len(fields)} fields"
            weights_used += weight

        # 5. Checksum (weight: 0.1)
        weight = 0.1
        checksum = proto.get("checksum", "")
        if checksum:
            score += weight * 0.5
            details["checksum"] = checksum
            weights_used += weight

        if weights_used > 0 and weights_used < 1.0:
            score = score / weights_used * 0.8

        return min(score, 1.0), details

    # ── Decoder selection ────────────────────────────────────────────

    def _find_best_decoder(self, proto: dict, features: dict) -> Optional[Encoding]:
        """Find the best URH decoder for a protocol based on its modulation."""
        if not self.available_decodings:
            return None

        modulation = proto.get("modulation", "")

        # Get candidate decoder names for this modulation
        candidate_names = self.MODULATION_DECODERS.get(modulation, [])

        # Special cases based on protocol name
        proto_name = proto.get("name", "").lower()
        if "manchester" in proto_name:
            candidate_names = ["Manchester I", "Manchester II", "Differential Manchester"] + candidate_names
        if "differential" in proto_name:
            candidate_names = ["Differential Manchester"] + candidate_names

        # Also try NRZ as fallback
        if "Non Return To Zero (NRZ)" not in candidate_names:
            candidate_names.append("Non Return To Zero (NRZ)")

        # Try each candidate and pick the one with lowest errors
        best_decoder = None
        best_error_rate = float("inf")

        for dec_name in candidate_names:
            decoder = self._find_decoding_by_name(dec_name)
            if decoder is None:
                continue

            error_rate = self._evaluate_decoder(decoder)
            if error_rate < best_error_rate:
                best_error_rate = error_rate
                best_decoder = decoder

        return best_decoder

    def _find_decoding_by_name(self, name: str) -> Optional[Encoding]:
        """Find a decoding by name (partial match) in available decodings."""
        name_lower = name.lower()
        for dec in self.available_decodings:
            if dec.name.lower() == name_lower:
                return dec
            if name_lower in dec.name.lower():
                return dec
        return None

    def _evaluate_decoder(self, decoder: Encoding) -> float:
        """Evaluate a decoder's error rate across all messages. Lower is better."""
        total_errors = 0
        total_bits = 0

        for msg in self.messages[:20]:  # Sample first 20 messages for speed
            bits = msg.plain_bits
            if len(bits) == 0:
                continue
            try:
                decoded, errors, state = decoder.code(True, bits)
                total_errors += errors
                total_bits += len(bits)
            except Exception:
                total_errors += len(bits)
                total_bits += len(bits)

        return total_errors / total_bits if total_bits > 0 else 1.0

    # ── Known protocol bitstream layouts ─────────────────────────────
    # Maps protocol names (substring match) to their actual bit layout.
    # Each entry: (field_name, bit_count, bit_order, endianness, display_format)
    #   bit_order: 0=MSB, 1=LSB
    #   endianness: "big"/"little"
    #   display_format: 0=Bit, 1=Hex, 2=ASCII, 3=Decimal, 4=BCD
    KNOWN_LAYOUTS = {
        "HCS200": [
            ("encrypted", 32, 1, "big", 1),   # Hex
            ("id", 28, 1, "big", 1),           # Hex
            ("button", 4, 1, "big", 3),        # Decimal
            ("battery_ok", 1, 0, "big", 0),    # Bit
            ("repeat", 1, 0, "big", 0),        # Bit
        ],
        "HCS300": [
            ("encrypted", 32, 1, "big", 1),   # Hex
            ("id", 28, 1, "big", 1),           # Hex
            ("button", 4, 1, "big", 3),        # Decimal
            ("battery_ok", 1, 0, "big", 0),    # Bit
            ("repeat", 1, 0, "big", 0),        # Bit
        ],
    }

    # ── Label/MessageType building ───────────────────────────────────

    def build_labels_from_match(self, match: ProtocolMatch) -> Optional[MessageType]:
        """
        Create a MessageType with ProtocolLabels from a matched protocol.

        Labels are placed on the **decoded** bit stream (after the recommended
        decoder has been applied).  The method decodes a sample message to
        find the actual preamble/gap/data boundaries in decoded space.
        """
        entry = match.entry
        fields = entry.get("fields", [])
        msg_len = entry.get("msg_len_bits", 0)
        if not fields:
            return None

        field_type_map = {
            "model": FieldType.Function.CUSTOM,
            "id": FieldType.Function.SRC_ADDRESS,
            "channel": FieldType.Function.CUSTOM,
            "battery_ok": FieldType.Function.CUSTOM,
            "temperature_C": FieldType.Function.DATA,
            "temperature_F": FieldType.Function.DATA,
            "humidity": FieldType.Function.DATA,
            "pressure_hPa": FieldType.Function.DATA,
            "wind_avg_km_h": FieldType.Function.DATA,
            "wind_max_km_h": FieldType.Function.DATA,
            "wind_dir_deg": FieldType.Function.DATA,
            "rain_mm": FieldType.Function.DATA,
            "mic": FieldType.Function.CHECKSUM,
            "checksum": FieldType.Function.CHECKSUM,
            "crc": FieldType.Function.CHECKSUM,
            "status": FieldType.Function.CUSTOM,
            "subtype": FieldType.Function.TYPE,
            "button": FieldType.Function.DATA,
            "code": FieldType.Function.DATA,
            "data": FieldType.Function.DATA,
            "encrypted": FieldType.Function.DATA,
            "cmd": FieldType.Function.CUSTOM,
            "learn": FieldType.Function.CUSTOM,
            "repeat": FieldType.Function.CUSTOM,
            "battery": FieldType.Function.CUSTOM,
        }

        field_sizes = {
            "id": 8, "channel": 4, "battery_ok": 1, "battery": 1,
            "temperature_C": 12, "temperature_F": 12,
            "humidity": 8, "pressure_hPa": 16,
            "wind_avg_km_h": 8, "wind_max_km_h": 8, "wind_dir_deg": 9,
            "rain_mm": 16,
            "mic": 8, "checksum": 8, "crc": 8,
            "status": 4, "subtype": 4,
            "button": 4, "code": 8, "cmd": 4, "data": 8,
            "encrypted": 32, "learn": 1, "repeat": 1,
        }

        # Work on RAW plain bits to find structure boundaries.
        # Labels are positioned on raw bits; preamble/gap get apply_decoding=False
        # so they pass through unchanged, while data fields get PWM-decoded.
        sample_bits = ""
        if self.messages:
            msg = self.messages[0]
            sample_bits = msg.plain_bits_str

        if not sample_bits:
            return None

        # Skip leading zeros
        i = 0
        while i < len(sample_bits) and sample_bits[i] == '0':
            i += 1
        leading_zeros = i

        # Detect alternating preamble (101010...)
        # Preamble is always even length (pairs of 10 or 01)
        preamble_start = i
        alt_i = i
        while alt_i < len(sample_bits) - 1:
            if sample_bits[alt_i] == sample_bits[alt_i + 1]:
                break
            alt_i += 1
        raw_len = alt_i - i
        # Round up to even (the last bit of the alternating pattern
        # may blend into the gap but still belongs to the preamble)
        preamble_len = raw_len + (raw_len % 2) if raw_len >= 4 else 0

        # Gap/guard between preamble and PWM data.
        # After the preamble, there are zeros (the gap), then possibly
        # framing bits (short pulse + long gap), before the actual PWM data.
        # The sync/gap label covers everything up to the first clean PWM data.
        gap_start = preamble_start + preamble_len
        gap_end = gap_start

        # Skip zeros
        while gap_end < len(sample_bits) and sample_bits[gap_end] == '0':
            gap_end += 1

        # Skip past any framing/guard bits before clean PWM data.
        # Framing shows as short HIGH runs followed by outlier LOW runs (>2).
        # Clean PWM data has LOW runs of 1-2 only.
        if gap_end < len(sample_bits):
            scan = gap_end
            while scan < len(sample_bits):
                # Find next HIGH run
                if sample_bits[scan] != '1':
                    scan += 1
                    continue
                # Measure HIGH run
                hi_end = scan
                while hi_end < len(sample_bits) and sample_bits[hi_end] == '1':
                    hi_end += 1
                # Measure following LOW run
                lo_end = hi_end
                while lo_end < len(sample_bits) and sample_bits[lo_end] == '0':
                    lo_end += 1
                lo_len = lo_end - hi_end
                if lo_len > 2:
                    # Outlier LOW — this is still framing, skip past it
                    gap_end = lo_end
                    scan = lo_end
                else:
                    # Clean pair — PWM data starts here
                    gap_end = scan
                    break

        # Find end of meaningful data (strip trailing zeros)
        data_end = _find_data_end(sample_bits)

        mt = MessageType(name=match.name)
        data_fields = [f for f in fields if f != "model"]
        if not data_fields:
            return None

        # ProtocolLabel constructor does self.end = end + 1
        # So pass end = start + bits - 1 to get non-overlapping labels
        current_bit = 0

        # Label: leading zeros
        if leading_zeros > 0:
            lbl = ProtocolLabel(
                name="Leading noise",
                start=0, end=leading_zeros - 1,
                color_index=8,
                field_type=FieldType("noise", FieldType.Function.CUSTOM),
                auto_created=True,
            )
            lbl.apply_decoding = False
            mt.append(lbl)
            current_bit = leading_zeros

        # Label: preamble
        if preamble_len >= 4:
            lbl = ProtocolLabel(
                name="Preamble",
                start=preamble_start, end=preamble_start + preamble_len - 1,
                color_index=0,
                field_type=FieldType("preamble", FieldType.Function.PREAMBLE),
                auto_created=True,
            )
            lbl.apply_decoding = False
            mt.append(lbl)
            current_bit = preamble_start + preamble_len

        # Label: gap/sync
        gap_len = gap_end - gap_start
        if gap_len > 0:
            lbl = ProtocolLabel(
                name="Sync/Gap",
                start=gap_start, end=gap_end - 1,
                color_index=1,
                field_type=FieldType("sync", FieldType.Function.SYNC),
                auto_created=True,
            )
            lbl.apply_decoding = False
            mt.append(lbl)
            current_bit = gap_end

        # Check if we have a known bitstream layout for this protocol
        proto_name = entry.get("name", "")
        known_layout = None
        for key, layout in self.KNOWN_LAYOUTS.items():
            if key in proto_name:
                known_layout = layout
                break

        if known_layout:
            color_idx = 2
            for layout_entry in known_layout:
                field_name = layout_entry[0]
                field_bits = layout_entry[1]
                bit_order = layout_entry[2] if len(layout_entry) > 2 else 0
                endianness = layout_entry[3] if len(layout_entry) > 3 else "big"
                display_fmt = layout_entry[4] if len(layout_entry) > 4 else None

                func = field_type_map.get(field_name, FieldType.Function.CUSTOM)
                ft = FieldType(field_name, func)
                lbl = ProtocolLabel(
                    name=field_name,
                    start=current_bit,
                    end=current_bit + field_bits - 1,
                    color_index=color_idx % 26,
                    field_type=ft,
                    auto_created=True,
                )
                lbl.display_bit_order_index = bit_order
                lbl.display_endianness = endianness
                if display_fmt is not None:
                    lbl.display_format_index = display_fmt
                else:
                    lbl.display_format_index = _auto_display_format(
                        field_bits, field_name
                    )
                mt.append(lbl)
                current_bit += field_bits
                color_idx += 1
        else:
            total_field_bits = sum(field_sizes.get(f, 8) for f in data_fields)

            if msg_len > 0 and abs(total_field_bits - msg_len) <= 2:
                scale = 1.0
            else:
                data_raw_len = data_end - gap_end
                available = msg_len if msg_len > 0 else data_raw_len // 3
                scale = available / total_field_bits if total_field_bits > 0 else 1.0

            color_idx = 2
            for field_name in data_fields:
                est_bits = field_sizes.get(field_name, 8)
                actual_bits = max(1, int(est_bits * scale))

                func = field_type_map.get(field_name, FieldType.Function.CUSTOM)
                ft = FieldType(field_name, func)

                lbl = ProtocolLabel(
                    name=field_name,
                    start=current_bit,
                    end=current_bit + actual_bits - 1,
                    color_index=color_idx % 26,
                    field_type=ft,
                    auto_created=True,
                )
                lbl.display_format_index = _auto_display_format(
                    actual_bits, field_name
                )
                mt.append(lbl)
                current_bit += actual_bits
                color_idx += 1

        return mt

    # ── Utility functions ────────────────────────────────────────────


    @staticmethod
    def _bits_to_hex(bit_string: str) -> str:
        if not bit_string:
            return ""
        padded = (
            bit_string + "0" * (4 - len(bit_string) % 4)
            if len(bit_string) % 4
            else bit_string
        )
        return "".join(
            format(int(padded[i: i + 4], 2), "x")
            for i in range(0, len(padded), 4)
        )

    @staticmethod
    def _hex_similarity(hex1: str, hex2: str) -> float:
        if not hex1 or not hex2:
            return 0.0
        h1, h2 = hex1.lower(), hex2.lower()
        if h1 in h2 or h2 in h1:
            return min(len(h1), len(h2)) / max(len(h1), len(h2))
        min_len = min(len(h1), len(h2))
        matches = sum(1 for i in range(min_len) if h1[i] == h2[i])
        return matches / max(len(h1), len(h2))


# ── Module-level helpers ─────────────────────────────────────────────

def _auto_display_format(field_bits: int, field_name: str = "") -> int:
    """
    Auto-select display format based on field size and name.
    0=Bit, 1=Hex, 2=ASCII, 3=Decimal, 4=BCD
    """
    name = field_name.lower()

    # 1-bit fields are always Bit (flags)
    if field_bits <= 1:
        return 0  # Bit

    # Boolean/flag fields → Bit regardless of size
    if any(kw in name for kw in (
        "battery", "repeat", "learn", "status", "flag",
        "enable", "active", "parity", "ok",
    )):
        return 0  # Bit

    # Small numeric fields → Decimal
    if field_bits <= 4:
        return 3  # Decimal

    # Sensor values → Decimal (human-readable numbers)
    if any(kw in name for kw in (
        "temperature", "humidity", "pressure", "wind", "rain",
        "lux", "uvi", "speed", "voltage", "power",
        "channel", "button", "cmd", "sequence", "count",
        "length", "type", "subtype",
    )):
        return 3  # Decimal

    # Everything else (id, encrypted, code, checksum, data) → Hex
    return 1  # Hex


def _is_alternating(bits: str) -> bool:
    """Check if a bit string is alternating (010101... or 101010...)."""
    if len(bits) < 4:
        return False
    for i in range(1, len(bits)):
        if bits[i] == bits[i - 1]:
            return False
    return True


def _find_common_prefix(strings: List[str]) -> str:
    """Find the longest common prefix of a list of strings."""
    if not strings:
        return ""
    prefix = strings[0]
    for s in strings[1:]:
        while not s.startswith(prefix):
            prefix = prefix[:-1]
            if not prefix:
                return ""
    return prefix


def _find_data_start(bits: str) -> int:
    """
    Find where the actual data starts in a decoded bit string,
    skipping leading zeros, preamble, and gap.

    Handles both:
    - Alternating preamble (10101010...) in raw/NRZ signals
    - Constant preamble (111111... or 000000...) after PWM decoding
    """
    if not bits:
        return 0

    # Skip leading zeros
    i = 0
    while i < len(bits) and bits[i] == '0':
        i += 1

    if i >= len(bits):
        return 0

    # Try alternating preamble first
    alt_start = i
    alt_i = i
    while alt_i < len(bits) - 1:
        if bits[alt_i] == bits[alt_i + 1]:
            break
        alt_i += 1
    alt_len = alt_i - alt_start

    # Try constant-value preamble (run of same bit)
    const_start = i
    const_val = bits[i]
    const_i = i
    while const_i < len(bits) and bits[const_i] == const_val:
        const_i += 1
    const_len = const_i - const_start

    # Pick whichever preamble type is longer (and >= 4 bits)
    if alt_len >= 4 and alt_len >= const_len:
        i = alt_i
    elif const_len >= 4:
        i = const_i
    # else: no preamble found, i stays at first non-zero

    # Skip zero gap after preamble
    while i < len(bits) and bits[i] == '0':
        i += 1

    return i


def _find_data_end(bits: str) -> int:
    """
    Find where the actual data ends, stripping trailing zeros.
    """
    if not bits:
        return 0
    i = len(bits) - 1
    trailing_zeros = 0
    while i >= 0 and bits[i] == '0':
        trailing_zeros += 1
        i -= 1
    if trailing_zeros > 4:
        return len(bits) - trailing_zeros + 4
    return len(bits)


def _find_pwm_data_start(bits: str) -> int:
    """
    Find where the actual data starts in a RAW bit string,
    skipping preamble (alternating), gap (zeros), and any
    framing/guard bits before the clean PWM data.

    Clean PWM data has a consistent period (H+L) per bit,
    typically 3 samples (Te=1). Framing bits have irregular periods.
    """
    if not bits:
        return 0

    # Skip leading zeros
    i = 0
    while i < len(bits) and bits[i] == '0':
        i += 1

    # Skip alternating preamble (round to even — preamble is always pairs)
    ps = i
    while ps < len(bits) - 1:
        if bits[ps] == bits[ps + 1]:
            break
        ps += 1
    alt_len = ps - i
    if alt_len >= 4:
        preamble_len = alt_len + (alt_len % 2)
        i += preamble_len

    # Skip zero gap
    while i < len(bits) and bits[i] == '0':
        i += 1

    # Build pulse pairs from here and find the most common period
    pairs = []
    scan = i
    while scan < len(bits):
        if bits[scan] != '1':
            scan += 1
            continue
        hi_end = scan
        while hi_end < len(bits) and bits[hi_end] == '1':
            hi_end += 1
        lo_end = hi_end
        while lo_end < len(bits) and bits[lo_end] == '0':
            lo_end += 1
        hi_len = hi_end - scan
        lo_len = lo_end - hi_end
        period = hi_len + lo_len
        pairs.append((scan, hi_len, lo_len, period))
        scan = lo_end

    if len(pairs) < 4:
        return i

    # Find the most common period (= the correct PWM bit period)
    from collections import Counter
    period_counts = Counter(p for _, _, _, p in pairs)
    dominant_period = period_counts.most_common(1)[0][0]

    # Skip pairs until we find 3 consecutive ones with the dominant period
    for j in range(len(pairs) - 2):
        if (pairs[j][3] == dominant_period and
                pairs[j + 1][3] == dominant_period and
                pairs[j + 2][3] == dominant_period):
            return pairs[j][0]

    # Fallback: return first pair position
    return pairs[0][0] if pairs else i


def _extract_first_packet(bits: str) -> str:
    """
    If a raw bit string contains multiple repeated packets
    (same preamble pattern appearing again after data + silence),
    extract only the first complete packet.

    Looks for a second preamble (alternating 10101010 pattern of >= 8 bits)
    that appears after a long zero gap (>= 10 zeros). Returns everything
    before the inter-packet gap, keeping all data bits intact.
    """
    if not bits or len(bits) < 20:
        return bits

    # Find first preamble
    i = 0
    while i < len(bits) and bits[i] == '0':
        i += 1

    # Skip past the first preamble
    ps = i
    while ps < len(bits) - 1:
        if bits[ps] == bits[ps + 1]:
            break
        ps += 1

    if ps - i < 4:
        return bits  # no valid preamble found

    # Skip past the first packet's data (at least 30 bits after preamble)
    search_from = ps + 30

    # Look for a second preamble: alternating bits after a gap
    j = search_from
    while j < len(bits) - 10:
        if bits[j] == '0':
            zero_start = j
            while j < len(bits) and bits[j] == '0':
                j += 1
            zero_len = j - zero_start

            if zero_len >= 10 and j < len(bits) - 8:
                alt = 0
                k = j
                while k < len(bits) - 1:
                    if bits[k] == bits[k + 1]:
                        break
                    alt += 1
                    k += 1
                if alt >= 8:
                    # Found second preamble at bit j.
                    # Include the data + trailing zeros (padding) but
                    # stop before the second preamble starts.
                    # Keep half the zero gap as padding for the first
                    # packet (helps with padding-based scoring).
                    mid_gap = zero_start + (j - zero_start) // 2
                    return bits[:mid_gap]
        else:
            j += 1

    return bits
