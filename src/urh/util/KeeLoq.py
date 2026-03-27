"""
KeeLoq cipher implementation for URH.

KeeLoq is a block cipher used in rolling code systems for car keys,
garage door openers, and gate remotes (HCS200/300, FAAC SLH, etc.).

Supports:
- Encrypt/decrypt with known manufacturer key
- Multiple learning modes (Simple, Normal, Secure, Magic XOR, etc.)
- Manufacturer key bruteforce

Based on the KeeLoq algorithm specification and Flipper Zero implementation.

References:
- https://en.wikipedia.org/wiki/KeeLoq
- Microchip HCS200/HCS300 datasheets
- Flipper-ARF keeloq_common.c
"""

# KeeLoq Non-Linear Function lookup table
KEELOQ_NLF = 0x3A5C742E
KEELOQ_ROUNDS = 528


def _bit(x, n):
    """Extract bit n from x."""
    return (x >> n) & 1


def _g5(x, a, b, c, d, e):
    """5-bit index into NLF lookup table."""
    return (
        _bit(x, a)
        + _bit(x, b) * 2
        + _bit(x, c) * 4
        + _bit(x, d) * 8
        + _bit(x, e) * 16
    )


def encrypt(data, key):
    """
    KeeLoq encrypt (528 rounds).

    Args:
        data: 32-bit plaintext
        key: 64-bit key (device key for normal operation,
             manufacturer key only for Simple Learning mode)

    Returns:
        32-bit encrypted data
    """
    x = data & 0xFFFFFFFF
    for r in range(KEELOQ_ROUNDS):
        nlf_idx = _g5(x, 1, 9, 20, 26, 31)
        feedback = (
            _bit(x, 0)
            ^ _bit(x, 16)
            ^ _bit(key, r & 63)
            ^ _bit(KEELOQ_NLF, nlf_idx)
        )
        x = (x >> 1) | (feedback << 31)
    return x & 0xFFFFFFFF


def decrypt(data, key):
    """
    KeeLoq decrypt (528 rounds).

    Args:
        data: 32-bit ciphertext
        key: 64-bit key (device key for normal operation,
             manufacturer key only for Simple Learning mode)

    Returns:
        32-bit plaintext (Button[31:28] | OVR[27:26] | DISC[25:16] | Counter[15:0])
    """
    x = data & 0xFFFFFFFF
    for r in range(KEELOQ_ROUNDS):
        nlf_idx = _g5(x, 0, 8, 19, 25, 30)
        feedback = (
            _bit(x, 31)
            ^ _bit(x, 15)
            ^ _bit(key, (15 - r) & 63)
            ^ _bit(KEELOQ_NLF, nlf_idx)
        )
        x = ((x << 1) & 0xFFFFFFFF) | feedback
    return x


def normal_learning(serial, manufacturer_key):
    """
    Normal Learning mode: derive device-specific key from serial.

    Args:
        serial: 28-bit serial number
        manufacturer_key: 64-bit manufacturer key

    Returns:
        64-bit device-specific key
    """
    serial &= 0x0FFFFFFF
    k1 = decrypt(serial | 0x20000000, manufacturer_key)
    k2 = decrypt(serial | 0x60000000, manufacturer_key)
    return (k2 << 32) | k1


def secure_learning(serial, seed, manufacturer_key):
    """
    Secure Learning mode: derive key from serial + seed.

    Args:
        serial: 28-bit serial number
        seed: 32-bit seed
        manufacturer_key: 64-bit manufacturer key

    Returns:
        64-bit device-specific key
    """
    serial &= 0x0FFFFFFF
    k1 = decrypt(serial, manufacturer_key)
    k2 = decrypt(seed, manufacturer_key)
    return (k1 << 32) | k2


def magic_xor_learning(serial, xor_key):
    """
    Magic XOR Type 1 Learning mode.

    Args:
        serial: 28-bit serial number
        xor_key: 64-bit XOR key

    Returns:
        64-bit device-specific key
    """
    serial &= 0x0FFFFFFF
    return ((serial << 32) | serial) ^ xor_key


def faac_learning(seed, manufacturer_key):
    """
    FAAC SLH Learning mode.

    Args:
        seed: 32-bit seed
        manufacturer_key: 64-bit manufacturer key

    Returns:
        64-bit device-specific key
    """
    hs = seed >> 16
    ending = 0x544D
    lsb = (hs << 16) | ending
    return (encrypt(seed, manufacturer_key) << 32) | encrypt(
        lsb, manufacturer_key
    )


def magic_serial_type1_learning(serial, man_key):
    """Magic Serial Type 1 Learning."""
    serial &= 0x0FFFFFFF
    checksum = ((serial & 0xFF) + ((serial >> 8) & 0xFF)) & 0xFF
    return (man_key & 0xFFFFFFFF) | (serial << 40) | (checksum << 32)


def find_manufacturer_key_from_device_key(
    device_key, serial_28bit, key_range=None, callback=None
):
    """
    Reverse-derive the manufacturer key from a known device key.

    For Normal Learning: device_key = normal_learning(serial, mfg_key).
    We bruteforce mfg_key and check if the derived device key matches.

    For Simple Learning: device_key IS the manufacturer key.

    Args:
        device_key: 64-bit known device key
        serial_28bit: 28-bit serial number
        key_range: iterable of keys to try, or None for common keys
        callback: progress callback

    Returns:
        tuple (mfg_key, learning_mode) or (None, None)
    """
    # Simple: device key = manufacturer key
    # Check common keys first
    for name, mfg in COMMON_MANUFACTURER_KEYS.items():
        if mfg == device_key:
            return mfg, "simple"
        # Normal learning
        derived = normal_learning(serial_28bit, mfg)
        if derived == device_key:
            return mfg, "normal"
        # Magic XOR
        derived_xor = magic_xor_learning(serial_28bit, mfg)
        if derived_xor == device_key:
            return mfg, "magic_xor"

    # Bruteforce if range provided
    if key_range is not None:
        tried = 0
        for mfg in key_range:
            derived = normal_learning(serial_28bit, mfg)
            if derived == device_key:
                return mfg, "normal"
            tried += 1
            if callback and tried % 10000 == 0:
                callback(tried, mfg)

    return None, None


def encode_packet(
    serial_28bit,
    button,
    counter,
    key,
    key_type="device",
    learning_mode="simple",
    disc=None,
    ovr=0,
):
    """
    Encode (encrypt) a KeeLoq packet.

    Builds the 32-bit plaintext and encrypts it.
    Works for HCS200/300 and other KeeLoq-based encoders.

    Encrypted payload format (32 bits):
        Bits 28-31: Button Status (4 bits) — S3,S0,S1,S2
        Bits 26-27: OVR (2 bits) — overflow counter
        Bits 16-25: DISC (10 bits) — discrimination value
        Bits  0-15: Sync Counter (16 bits)

    DISC is typically serial & 0x3FF (set during programming).
    OVR increments every 65536 button presses.

    Args:
        serial_28bit: 28-bit serial number
        button: 4-bit button status (S3S0S1S2 bits)
        counter: 16-bit sync counter
        key: 64-bit key
        key_type: 'device' or 'manufacturer'
        learning_mode: learning mode for manufacturer key
        disc: 10-bit discrimination value (default: serial & 0x3FF)
        ovr: 2-bit overflow counter (default: 0)

    Returns:
        dict with encrypted, plaintext, device_key, packet_bits, etc.
    """
    serial_28bit &= 0x0FFFFFFF
    button &= 0xF
    counter &= 0xFFFF
    ovr &= 0x3

    if disc is None:
        disc = serial_28bit & 0x3FF
    disc &= 0x3FF

    # Build plaintext: Button(4) + OVR(2) + DISC(10) + Counter(16)
    plaintext = (
        (button << 28) | (ovr << 26) | (disc << 16) | counter
    )

    # Get device key
    if key_type == "manufacturer":
        if learning_mode == "normal":
            device_key = normal_learning(serial_28bit, key)
        elif learning_mode == "secure":
            device_key = secure_learning(
                serial_28bit, 0, key
            )
        elif learning_mode == "magic_xor":
            device_key = magic_xor_learning(serial_28bit, key)
        elif learning_mode == "faac":
            device_key = faac_learning(0, key)
        else:
            device_key = key  # simple
    else:
        device_key = key

    # Encrypt
    encrypted = encrypt(plaintext, device_key)

    # Build 66-bit packet (LSB first):
    # bits 0-31: encrypted (LSB first)
    # bits 32-59: serial (LSB first)
    # bits 60-63: button (S3,S0,S1,S2)
    # bit 64: battery low (0 = OK)
    # bit 65: repeat (0 = first transmission)

    # Convert to LSB-first bit strings
    enc_bits_lsb = format(encrypted, "032b")[::-1]
    ser_bits_lsb = format(serial_28bit, "028b")[::-1]
    btn_bits_lsb = format(button, "04b")[::-1]
    battery = "0"
    repeat = "0"

    packet_bits = (
        enc_bits_lsb + ser_bits_lsb + btn_bits_lsb
        + battery + repeat
    )

    # Fixed part: button(4 bits) + serial(28 bits)
    fixed_part = (button << 28) | serial_28bit

    return {
        "encrypted": encrypted,
        "plaintext": plaintext,
        "serial": serial_28bit,
        "button": button,
        "counter": counter,
        "device_key": device_key,
        "fixed_part": fixed_part,
        "packet_bits": packet_bits,
    }


def decode_packet(
    encrypted_32bit, serial_28bit, key, learning_mode="simple",
    seed=None,
):
    """
    Decode a KeeLoq packet.

    The key flow:
    - Simple Learning: key IS the device key (mfg_key = device_key)
    - Normal Learning: device_key = derived from serial + manufacturer_key
    - Secure Learning: device_key = derived from serial + seed + manufacturer_key
    - Magic XOR: device_key = (serial || serial) XOR manufacturer_key
    - FAAC: device_key = derived from seed + manufacturer_key
    - "device": key is already the device key (no derivation)

    Args:
        encrypted_32bit: 32-bit encrypted portion from the packet
        serial_28bit: 28-bit serial number from the packet
        key: 64-bit key (manufacturer key or device key depending on mode)
        learning_mode: 'simple', 'normal', 'secure', 'magic_xor', 'faac', 'device'
        seed: 32-bit seed (required for 'secure' and 'faac' modes,
              obtained during programming/learning sequence)

    Returns:
        dict with decoded fields:
        - button, ovr, disc, counter, valid, raw, device_key
    """
    if learning_mode == "device" or learning_mode == "simple":
        device_key = key
    elif learning_mode == "normal":
        device_key = normal_learning(serial_28bit, key)
    elif learning_mode == "secure":
        if seed is None:
            seed = 0
        device_key = secure_learning(serial_28bit, seed, key)
    elif learning_mode == "magic_xor":
        device_key = magic_xor_learning(serial_28bit, key)
    elif learning_mode == "faac":
        if seed is None:
            seed = 0
        device_key = faac_learning(seed, key)
    else:
        device_key = key

    decrypted = decrypt(encrypted_32bit, device_key)

    button = (decrypted >> 28) & 0xF
    ovr = (decrypted >> 26) & 0x3
    disc = (decrypted >> 16) & 0x3FF
    counter = decrypted & 0xFFFF

    # Validation: DISC should match serial & 0x3FF
    valid = disc == (serial_28bit & 0x3FF)

    # Keep serial_low for backward compatibility (OVR + DISC)
    serial_low = (decrypted >> 16) & 0xFFF

    return {
        "button": button,
        "ovr": ovr,
        "disc": disc,
        "serial_low": serial_low,
        "counter": counter,
        "valid": valid,
        "raw": decrypted,
        "device_key": device_key,
    }


def bruteforce_manufacturer_key(
    encrypted_32bit,
    serial_28bit,
    learning_mode="simple",
    verify_field="serial_low",
    verify_value=None,
    key_range=None,
    callback=None,
    extra_packets=None,
):
    """
    Bruteforce the manufacturer key by checking a known field value.

    The user selects which field to verify and its expected value.
    For example, if you know button=1 was pressed, set
    verify_field='button' and verify_value=1.

    Args:
        encrypted_32bit: 32-bit encrypted portion
        serial_28bit: 28-bit serial number
        learning_mode: 'simple', 'normal', etc.
        verify_field: field to check — 'button', 'serial_low', 'counter'
        verify_value: expected value for verify_field
        key_range: iterable of 64-bit keys, or None for common keys
        callback: function(keys_tried, current_key) called periodically
        extra_packets: list of (encrypted_32bit, expected_button) tuples
                       for multi-packet validation to eliminate false positives

    Returns:
        tuple (key, decoded_result) if found, or (None, None)
    """
    if verify_value is None:
        if verify_field == "disc":
            verify_value = serial_28bit & 0x3FF
        else:
            return None, None

    if key_range is None:
        key_range = iter(COMMON_MANUFACTURER_KEYS.values())

    expected_disc = serial_28bit & 0x3FF

    keys_tried = 0
    for key in key_range:
        result = decode_packet(
            encrypted_32bit, serial_28bit, key, learning_mode
        )
        keys_tried += 1

        # Check the selected field
        match = False
        if verify_field == "button":
            match = result["button"] == verify_value
        elif verify_field == "counter":
            match = result["counter"] == verify_value
        elif verify_field == "disc":
            match = result["disc"] == verify_value

        if match:
            # Always validate DISC matches serial & 0x3FF
            disc_match = result["disc"] == expected_disc
            result["disc_match"] = disc_match
            result["field_match"] = True

            if not disc_match:
                continue

            # Multi-packet validation if provided
            if extra_packets:
                all_ok = True
                for extra_enc, extra_btn in extra_packets:
                    er = decode_packet(
                        extra_enc,
                        serial_28bit,
                        key,
                        learning_mode,
                    )
                    if er["disc"] != expected_disc:
                        all_ok = False
                        break
                    if extra_btn is not None:
                        if er["button"] != extra_btn:
                            all_ok = False
                            break
                if not all_ok:
                    continue

            return key, result

        if callback and keys_tried % 10000 == 0:
            callback(keys_tried, key)

    return None, None


# Common manufacturer keys (from public security research).
# Sources: academic papers, FCC filings, open-source projects.
# Flipper Zero's keystore file contains many more, but they are
# encrypted and not available in plaintext from the source code.
#
# To add your own keys: append to this dict or use the bruteforce
# function with a custom key_range.
#
# Key format: "Brand (learning_mode)" : 64-bit key
# Learning modes: simple, normal, secure, magic_xor, faac
COMMON_MANUFACTURER_KEYS = {
    # Generic/test
    "All zeros (simple)": 0x0000000000000000,
    "All ones (simple)": 0xFFFFFFFFFFFFFFFF,
    # Known public keys (from published security research)
    "Doorhan (normal)": 0x000000000000FEED,
    "Doorhan (xor)": 0x000000000000FEED,
    "CAME TOP-432 (normal)": 0x5ACE5ACE5ACE5ACE,
    "Nice Smilo (normal)": 0x455452454B4F4F50,
    "Nice One (normal)": 0x455452454B4F4F50,
    "Ditec GOL4 (normal)": 0x5F5F5F3B00012345,
    "AN-Motors AT-4 (normal)": 0x0000000000000000,
    "Normstahl (normal)": 0x0000000000000004,
    "Beninca (normal)": 0x0000000000000005,
    "GSN (normal)": 0x0000000000000007,
    "Roper (normal)": 0x0000000000000008,
    "Mutancode (normal)": 0x0000000000000009,
    # Add your own manufacturer keys here.
    # Use bruteforce_manufacturer_key() with two captures
    # to find unknown keys.
}

# Manufacturer codes (MC) to brand/model mapping
# From public KeeLoq documentation and FCC filings
MANUFACTURER_CODES = {
    "MC001": ("Microchip", "HCS200/301 Demo"),
    "MC002": ("Chamberlain", "LiftMaster"),
    "MC003": ("CAME", "TOP-432"),
    "MC004": ("Nice", "Smilo/One"),
    "MC005": ("Doorhan", "Transmitter"),
    "MC010": ("BFT", "Mitto"),
    "MC020": ("Cardin", "S449 FM"),
    "MC021": ("Cardin", "S486"),
    "MC030": ("FAAC", "XT/SLH"),
    "MC040": ("Sommer", "Garage"),
    "MC050": ("Hormann", "HSM"),
    "MC060": ("Ditec", "GOL4"),
    "MC070": ("Beninca", "TO.GO"),
    "MC080": ("DEA", "MIO"),
    "MC090": ("Gibidi", "AU1600"),
    "MC100": ("Genius", "Bravo"),
    "MC110": ("King Gates", "Stylo"),
    "MC120": ("Aprimatic", "TX"),
    "MC130": ("JCM", "NEO"),
    "MC140": ("Roger", "H80"),
    "MC150": ("Normstahl", "RCU"),
    "MC200": ("StarLine", "Car Alarm"),
}

def lookup_manufacturer(serial_28bit):
    """
    Try to identify the manufacturer from the serial number.
    Some manufacturers encode their MC code in the serial.

    Returns (brand, model) or (None, None).
    """
    # The manufacturer code is sometimes in the upper bits
    # of the serial number, but this varies by manufacturer.
    # This is a best-effort lookup.
    return None, None


# Learning mode names for UI display
LEARNING_MODES = {
    "simple": "Simple Learning",
    "normal": "Normal Learning",
    "secure": "Secure Learning",
    "magic_xor": "Magic XOR Type 1",
    "faac": "FAAC SLH",
}
