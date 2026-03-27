# URH Crypto Toolkit

URH 3.0.0-phz includes a crypto toolkit with **23 ciphers** covering car key fobs, gate remotes, and rolling code systems. **15 protocols auto-decode** without any user input.

## Quick Start

1. **Demodulate** a signal in URH
2. **Analyze -> Auto-identify protocol (PHZ DB)** -- identifies the protocol and its cipher
3. The result dialog shows the **decoded fields** (SN, button, counter) if the cipher can auto-decode
4. For user-key ciphers: **Analyze -> Crypto Toolkit** opens with data pre-filled and guidance on what to provide

## Auto-Decode Protocols (15)

These protocols are fully decoded automatically -- no key needed:

| Protocol | Algorithm | Fields Extracted |
|----------|-----------|-----------------|
| Ford V0 | XOR + bit interleave + GF(2) CRC | SN, Button, Counter, CRC |
| Mitsubishi V0 | Counter-derived XOR | SN, Button, Counter |
| Somfy Telis/Keytis | Cascading XOR | Address, Button, Counter, CRC |
| Came Atomo | LFSR bit-flip cipher | SN, Button, Counter |
| Came Twee | 32-bit XOR rainbow table | SN, Button, DIP switch |
| Mazda Siemens | Parity-XOR + bit deinterleave | SN, Button, Counter, Checksum |
| Phoenix V2 | 16-iter bit-shuffle (serial-keyed) | SN, Button, Counter |
| Security+ v1/v2 | Base-3 ternary encoding | Rolling code, Fixed code, Button |
| Porsche Cayenne | 24-bit rotating register (brute-force) | SN, Button, Counter |
| Subaru | 24-bit serial rotation + scattered XOR | SN, Button, Counter |
| KIA V3/V4 | KeeLoq (master key `0xA8F5DFFC8DAA5CDB`) | SN, Button, Counter, DISC |
| KIA V5 | 18-round mixer (key: `STFRKE00`) | SN, Button, Counter |
| KIA V6 | AES-128 ECB (hardcoded key) | SN, Button, Counter, CRC |
| VAG VW/Audi/Skoda/Seat | AUT64 (3 keys) + TEA, auto-type | SN, Button, Counter, Vehicle type |
| PSA Peugeot/Citroen | TEA mode 0x23 XOR | SN, Decrypted block |

## Guided Decode Protocols (8)

These need user-provided keys -- the UI tells you exactly what to provide:

| Protocol | What You Provide | Built-in Help |
|----------|-----------------|---------------|
| KeeLoq (HCS200/300, NICE, StarLine, etc.) | 64-bit manufacturer key | 26 common keys, brute-force with 2 captures |
| FAAC SLH | Manufacturer key + seed | Capture programming sequence to extract seed |
| Nice Flor-S | 32-byte rainbow table | Extract from remote's EEPROM |
| Alutech AT-4N | Rainbow table file | Modified TEA cipher |
| Scher-Khan Magicar | (Pi tables built-in) | Auto-detects PRO1 vs PRO2 by CRC poly |
| TEA (generic) | 128-bit key (4x32) | Standard 32-round TEA |
| AES-128 (generic) | 128-bit key (16 bytes) | Standard AES-128-ECB |
| AUT64 (generic) | Key nibbles + S-box + P-box | Vehicle-specific, from key dump |

## Protocol -> Cipher Mapping (39 protocols)

When the auto-identifier matches a protocol, it selects the right cipher:

| Protocol Contains | Cipher Used |
|-------------------|-------------|
| HCS200, HCS300, KeeLoq, StarLine, Sheriff, Suzuki | KeeLoq |
| KIA V3, KIA V4 | KIA V3/V4 KeeLoq (known master key) |
| KIA V5 | KIA V5 Mixer |
| KIA V6 | KIA V6 AES (hardcoded key) |
| Ford V0 | Ford V0 Protocol Decoder |
| VAG VW, VAG Audi | VAG (AUT64 + TEA) |
| Mitsubishi | Mitsubishi V0 XOR |
| Porsche Cayenne | Porsche Cayenne Rotating Register |
| Subaru | Subaru Rotating XOR |
| Mazda | Mazda Siemens Parity-XOR |
| Somfy Telis/Keytis/RTS | Somfy XOR |
| Came Atomo | Came Atomo XOR |
| Came Twee | Came Twee XOR |
| Scher-Khan | Scher-Khan Pi-XOR |
| Phoenix | Phoenix V2 Bit-Shuffle |
| Alutech | Alutech AT-4N Rainbow |
| FAAC SLH | FAAC SLH KeeLoq |
| NICE Flor | Nice Flor-S |
| PSA, PSA Peugeot | PSA TEA (brute-force) |
| Security+, LiftMaster, Chamberlain | Security+ Ternary |
| Fiat Marelli, Fiat SPA | TEA |

## KeeLoq Details

- **26 built-in manufacturer keys**: AN-Motors, HCS101, NICE Smilo, Beninca, Came, DTM Neo, FAAC, Genius, GSN, Roper, Stilmatic, and more
- **Learning modes**: Simple, Normal, Secure, Magic XOR, FAAC
- **Brute-force**: Single capture (fast, may have false positives) or dual capture (validates key)
- **Key derivation**: From device key + serial to manufacturer key

## How It Works

### Ford V0 Example

1. URH captures OOK signal at 433 MHz
2. FrameAnalyzer detects Manchester preamble (`10011001...`) + zero gap + data
3. Manchester pair decode: 160 raw bits -> 80 decoded bits
4. URH's Thomas convention cancels with Ford's OTA inversion -> key1(64) + key2(16)
5. XOR de-obfuscation (parity-based mask selection)
6. Bit interleave on counter bytes
7. Serial extraction (LE -> BE byte swap)
8. GF(2) matrix CRC verification
9. Result: SN, Button (Lock/Unlock/Trunk), Counter, CRC OK/FAIL

### VAG Example

1. FrameAnalyzer detects Manchester data (80 bits)
2. Type byte identifies vehicle: VAG NEW (0x00), VAG OLD (0xC0), AUDI (0xC1), SEAT (0xC2), SKODA (0xC3)
3. Tries all 3 AUT64 keys (12-round Feistel with GF(2^4) S-box/P-box)
4. Falls back to TEA if AUT64 fails
5. Validates button dispatch byte (0x2A=Lock, 0x1C=Unlock, 0x46=Trunk, 0x88=Panic)
6. Result: SN, Button, 24-bit Counter, Vehicle Type, Cipher Used

## See Also

- [CONTRIBUTING_DECODERS.md](CONTRIBUTING_DECODERS.md) -- How to add protocols, ciphers, and decoders
- [SUPPORTED_PROTOCOLS.md](SUPPORTED_PROTOCOLS.md) -- Full list of 327 supported protocols
- [CONTRIBUTORS.md](CONTRIBUTORS.md) -- Project contributors and data sources
