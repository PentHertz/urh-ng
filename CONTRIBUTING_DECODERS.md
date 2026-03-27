# Contributing: Protocols, Crypto & Decoders

Guide for extending URH's protocol database, crypto toolkit, encoding decoders, and auto-decode pipeline.

## Architecture

```
Signal Capture ─► Demodulation ─► FrameAnalyzer ─► ProtocolMatcher ─► Auto-Decode ─► Labels
                                      │                  │                │
                                 Detects encoding    Scores 327       CryptoToolkit
                                 (PWM/Manchester/    protocols,       runs cipher if
                                 NRZ), segments      matches fields   key known/derivable
                                 preamble/gap/data
```

### Key Files

| File | Lines | Purpose |
|------|-------|---------|
| `awre/protocol_db.py` | 6678 | 327 protocol definitions (rtl_433 + Flipper-ARF + ProtoPirate) |
| `awre/ProtocolMatcher.py` | 1921 | Scoring engine, 39 cipher mappings, 17 field layouts |
| `awre/FrameAnalyzer.py` | 491 | Encoding detection, 6 preamble types, 4 gap types |
| `util/CryptoToolkit.py` | 2245 | 23 ciphers, 41 functions |
| `util/KeeLoq.py` | 567 | KeeLoq cipher, 26 manufacturer keys, brute-force |
| `signalprocessing/Encoding.py` | — | PWM, Miller, Manchester, NRZ bit-level decoders |
| `controller/CompareFrameController.py` | — | Auto-decode wiring for 15 cipher types |

---

## 1. Adding a New Protocol

### Step 1: Protocol Database Entry

Edit `src/urh/awre/protocol_db.py`:

```python
{
    "name": "My Protocol v1",
    "modulation": "OOK_PULSE_PWM",       # See modulation table below
    "short_width": 400,                    # Short pulse (us)
    "long_width": 800,                     # Long pulse (us)
    "sync_width": 0,                       # Sync pulse (us), 0 if none
    "gap_limit": 1500,                     # Max gap between pulses (us)
    "reset_limit": 9000,                   # Packet reset threshold (us)
    "preamble_bits": "",                   # Preamble hex, empty if none
    "sync_bytes": "",                      # Sync word hex, empty if none
    "msg_len_bits": 64,                    # Expected decoded data length
    "checksum": "crc8",                    # "crc8", "crc16", "xor", "" etc.
    "fields": ["id", "button", "counter", "checksum"],
    "source": "custom",
},
```

**Modulation types** (maps to URH decoders):

| Modulation | URH Decoder | Protocols |
|------------|-------------|-----------|
| `OOK_PULSE_PWM` | PWM (`100->1`, `110->0`) | HCS200, KeeLoq remotes |
| `OOK_PULSE_PCM` | NRZ (passthrough) | Simple sensors |
| `OOK_PULSE_MANCHESTER_ZEROBIT` | Manchester I/II | Ford V0, Somfy, VAG |
| `OOK_PULSE_DMC` | Differential Manchester | Ford Car Key |
| `OOK_PULSE_PPM` | NRZ | Pulse Position |
| `FSK_PULSE_PCM` | NRZ | FSK sensors |

### Step 2: Field Layout (recommended)

Edit `ProtocolMatcher.py`, add to `KNOWN_LAYOUTS`:

```python
"My Protocol": [
    # (name, bits, bit_order, endianness, display_format)
    # display_format: 0=Bit, 1=Hex, 2=ASCII, 3=Decimal
    ("serial", 28, 0, "big", 1),      # 28-bit serial, MSB, Hex
    ("button", 4, 0, "big", 3),       # 4-bit button, Decimal
    ("counter", 16, 0, "big", 1),     # 16-bit counter, Hex
    ("crc", 8, 0, "big", 1),          # 8-bit CRC, Hex
],
```

### Step 3: Cipher Mapping (if encrypted)

Edit `ProtocolMatcher.py`, add to `PROTOCOL_CIPHERS`:

```python
"My Protocol": "My-Cipher-ID",
```

---

## 2. Adding a New Cipher / Protocol Decoder

### Step 1: Implement in CryptoToolkit.py

Three patterns depending on key availability:

#### Pattern A: Zero-Key (key derived from data)

```python
def my_protocol_decode(raw_payload):
    """No external key needed."""
    buf = list(raw_payload)
    # Undo obfuscation
    counter = (buf[4] << 8) | buf[5]     # counter often in clear
    mask = counter ^ 0xFF                 # derive XOR mask
    for i in range(4):
        buf[i] ^= mask
    serial = (buf[0] << 24) | (buf[1] << 16) | (buf[2] << 8) | buf[3]
    return {"serial": serial, "counter": counter, "button": buf[6]}
```

Examples: Ford V0, Mitsubishi V0, Somfy, Came Atomo, Mazda Siemens, Phoenix V2

#### Pattern B: Known-Key (hardcoded key)

```python
MY_MASTER_KEY = 0xA8F5DFFC8DAA5CDB

def my_protocol_decode(key1, key2):
    """Hardcoded key, tries all built-in keys."""
    for key in MY_KEY_TABLE:
        dec = my_cipher_decrypt(block, key)
        if validate(dec):
            return extract_fields(dec)
    return {"error": "No valid key"}
```

Examples: KIA V3/V4, KIA V5 (STFRKE00), KIA V6, VAG (3 AUT64 + 1 TEA)

#### Pattern C: Brute-Force Counter Recovery

```python
def my_protocol_decode(packet):
    """Brute-force counter from cipher output."""
    serial = extract_serial(packet)
    target = packet[4:8]
    for cnt in range(65536):
        if encrypt(serial, cnt) == target:
            return {"serial": serial, "counter": cnt}
    return {"error": "Counter not found"}
```

Examples: Porsche Cayenne (0.2s for 65K candidates), Subaru (bit-scatter)

### Step 2: Register in CIPHER_INFO

```python
CIPHER_INFO = {
    ...,
    "My-Cipher-ID": {
        "name": "My Cipher Description",
        "key_bits": 64,           # 0 if no external key needed
        "block_bits": 32,
        "used_by": "My Protocol v1, My Protocol v2",
    },
}
```

### Step 3: Wire Auto-Decode

In `CompareFrameController.py`, add to `_auto_decode_crypto()`:

```python
elif cipher == "My-Cipher-ID":
    from urh.util.CryptoToolkit import my_protocol_decode
    val = bits_to_int(bits_str, 64)
    if val:
        r = my_protocol_decode(val)
        lines = [
            f"--- {name} Decode ---",
            f"SN:      {r['serial']:08X}",
            f"Button:  0x{r['button']:X}",
            f"Counter: 0x{r['counter']:04X}",
        ]
```

Add to `_AUTOCRACK_CIPHERS` set (for Crypto Toolkit shortcut):

```python
_AUTOCRACK_CIPHERS = {
    ...,
    "My-Cipher-ID",
}
```

---

## 3. Adding a Bit-Level Decoder

### Step 1: Settings Constant

In `src/urh/settings.py`:

```python
DECODING_MYENCODING = "My Encoding Name"
```

### Step 2: Decoder Method

In `src/urh/signalprocessing/Encoding.py`:

```python
def code_myencoding(self, decoding, inpt):
    errors = 0
    output = array.array("B", [])
    if decoding:
        # Decode: raw bits -> data bits
        i = 0
        while i < len(inpt):
            if i + 2 < len(inpt):
                s = (inpt[i], inpt[i+1], inpt[i+2])
                if s == (1, 0, 0):
                    output.append(True); i += 3; continue
                elif s == (1, 1, 0):
                    output.append(False); i += 3; continue
            output.append(inpt[i]); i += 1
    else:
        # Encode: data bits -> raw bits
        for bit in inpt:
            if bit:
                output.extend([True, False, False])
            else:
                output.extend([True, True, False])
    return output, errors, self.ErrorState.SUCCESS
```

### Step 3: Register

In `Encoding.py` `set_chain()` and `get_chain()`, in `settings.py` add the constant, in `ProjectManager.py` add default decoding, in `DecoderDialog.py` add to UI list, in `ProtocolMatcher.py` add to `MODULATION_DECODERS` and `_ensure_essential_decodings`.

### Existing Decoders

| Decoder | Method | Rule | Protocols |
|---------|--------|------|-----------|
| NRZ | (none) | Passthrough | PCM sensors |
| Manchester I | `code_edge` | `01->1`, `10->0` | Weather sensors |
| Manchester II | `code_edge`+`code_invert` | `10->1`, `01->0` | Ford, Somfy |
| Diff. Manchester | `code_edge`+`code_differential` | Transition=1 | Ford keys |
| PWM | `code_pwm` | `100->1`, `110->0` | HCS200, KeeLoq |
| Miller | `code_miller` | Mid-bit transition=1 | RFID ISO 14443 |

---

## 4. Current Status

### 23 Ciphers (15 auto-decode + 8 guided)

#### Auto-Decode (no user input)

| Cipher ID | Algorithm | Extracts |
|-----------|-----------|----------|
| `Ford-GF2-CRC` | XOR + bit interleave + GF(2) matrix CRC | SN, BTN, CNT, CRC |
| `Mitsubishi-XOR` | Counter-derived XOR (bytes 0-3) | SN, BTN, CNT |
| `Somfy-XOR` | Cascading XOR `data^(data>>8)` | Address, BTN, CNT, CRC |
| `Came-Atomo` | LFSR bit-flip cipher | SN, BTN, CNT |
| `Came-Twee` | 15x 32-bit XOR rainbow table | SN, BTN, DIP |
| `Mazda-Siemens` | Parity XOR + 0xAA/0x55 deinterleave | SN, BTN, CNT, checksum |
| `Phoenix-V2` | 16-iter MSB/LSB bit-shuffle | SN, BTN, CNT |
| `SecurityPlus` | Base-3 ternary encoding | Rolling, Fixed, BTN |
| `Porsche-Cayenne` | 24-bit rotating register (brute-force) | SN, BTN, CNT |
| `Subaru-XOR` | 24-bit serial rotation + scattered bits | SN, BTN, CNT |
| `KIA-V3-V4` | KeeLoq (master key `0xA8F5DFFC8DAA5CDB`) | SN, BTN, CNT, DISC |
| `KIA-V5-Mixer` | 18-round substitution (key `STFRKE00`) | SN, BTN, CNT |
| `KIA-V6-AES` | AES-128 ECB (hardcoded key) | SN, BTN, CNT, CRC |
| `VAG` | AUT64 (3 keys) + TEA (1 key), auto-type | SN, BTN, CNT, vehicle |
| `PSA-TEA` | TEA mode 0x23 XOR | SN, decrypted block |

#### Guided Decode (user provides key)

| Cipher ID | User Provides | Built-in Help |
|-----------|---------------|---------------|
| `KeeLoq` | 64-bit manufacturer key | 26 common keys, brute-force with 2 captures |
| `FAAC-SLH` | Manufacturer key + seed | Capture prog sequence for seed |
| `Nice-FlorS` | 32-byte rainbow table | Extract from remote EEPROM |
| `Alutech-AT4N` | Rainbow table file | Modified TEA cipher |
| `Scher-Khan` | Pi-derived key tables built-in | CRC poly determines PRO1/PRO2 |
| `TEA` | 128-bit key | Standard TEA cipher |
| `AES-128` | 128-bit key | Standard AES-128-ECB |
| `AUT64` | Key nibbles + S-box + P-box | Vehicle-specific |

### 327 Protocol Database

| Source | Count | Types |
|--------|-------|-------|
| [rtl_433](https://github.com/merbanan/rtl_433) | 293 | Sensors, TPMS, doorbells, meters |
| [Flipper-ARF](https://github.com/D4C1-Labs/Flipper-ARF) | 30 | Car keys, gates, alarms |
| [ProtoPirate](https://github.com/RocketGod-git/ProtoPirate) | 4 | KIA, Ford, Mitsubishi, Subaru |

### FrameAnalyzer

**6 preamble types:** NRZ alternating, Manchester pairs, constant, PWM preamble, header cycle, Somfy sync

**4 gap types:** Zero gap, Somfy sync pulse, Manchester violations, combined

**3 encoding types:** NRZ, Manchester (pair-based), PWM (3-bit symbols)

### Scoring System

| Factor | Weight/Effect |
|--------|---------------|
| Length match (FrameAnalyzer decoded) | 0.35 base weight |
| Preamble pattern match | 0.25 |
| Field structure plausibility | 0.10 |
| Checksum type match | 0.10 |
| Modulation mismatch (PWM vs NRZ) | x0.5 penalty |
| Decoder length match (exact) | +0.40 bonus |
| Tight field coverage (data = expected) | +0.08 bonus |
| Large leftover (>30% unlabeled) | -0.15 penalty |
| Known layout entry | +0.05 |
| Cipher support entry | +0.05 |

---

## 5. Adding Hardware (SDR)

1. **Native wrapper** (`dev/native/lib/mydevice.pyx` or `.py`) — `open/close`, `set_freq/rate/bw`, `start/stop_rx`, `get_iq_data`
2. **Device class** (`dev/native/MyDevice.py`) — extends `Device`, implements `setup_device/shutdown_device/enter_async_receive_mode`
3. **Config** (`dev/config.py`) — sample rates, gain, bandwidth ranges
4. **Backend** (`dev/BackendHandler.py`) — detection logic
5. **CI** (`.github/workflows/`) — build steps

**Supported:** RTL-SDR, HackRF, USRP, Airspy, LimeSDR, HydraSDR, Harogic, Signal Hound BB60

---

## 6. Testing

```bash
# Syntax check
python3 -c "import py_compile; py_compile.compile('src/urh/util/CryptoToolkit.py', doraise=True)"

# Ford V0 round-trip
python3 -c "
import sys; sys.path.insert(0, 'src')
from urh.util.CryptoToolkit import ford_v0_encode, ford_v0_decode
k1, k2 = ford_v0_encode(0xDEADBEEF, 1, 0x1234)
r = ford_v0_decode(k1, k2)
assert r['serial'] == 0xDEADBEEF and r['crc_ok']
print('Ford V0: OK')
"

# VAG AUT64+TEA round-trip
python3 -c "
import sys; sys.path.insert(0, 'src')
from urh.util.CryptoToolkit import *
uk = aut64_unpack(VAG_AUT64_KEYS[0])
block = [0xDE, 0xAD, 0xBE, 0xEF, 0x34, 0x12, 0x00, 0x20]
enc = aut64_encrypt(block, uk['key'], uk['sbox'], uk['pbox'])
dec = aut64_decrypt(enc, uk['key'], uk['sbox'], uk['pbox'])
assert dec == block
print('AUT64: OK')
"

# Formatting
black .

# Tests
pytest tests/ -v
```

---

## 7. Protocol Sources: How to Add More

### From rtl_433

1. Find device in [rtl_433/src/devices](https://github.com/merbanan/rtl_433/tree/master/src/devices)
2. Extract: `r_device` struct (modulation, pulse widths), `output_fields` (field names), decode function (msg_len, checksum)
3. Add entry to `protocol_db.py`

### From Flipper Zero

1. Find protocol in [Flipper-ARF/lib/subghz/protocols](https://github.com/D4C1-Labs/Flipper-ARF/tree/main/lib/subghz/protocols)
2. Extract: timing constants (`te_short/te_long`), preamble detection (state machine), decrypt algorithm, field layout
3. Implement cipher in `CryptoToolkit.py`
4. Add to `protocol_db.py`, `KNOWN_LAYOUTS`, `PROTOCOL_CIPHERS`
5. Wire auto-decode in `CompareFrameController.py`

### From ProtoPirate

1. Find protocol in [ProtoPirate/lib/subghz/protocols](https://github.com/RocketGod-git/ProtoPirate)
2. Same process as Flipper-ARF (shared codebase)

---

## Questions?

Open an issue at https://github.com/PentHertz/URH/issues
