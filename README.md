![URH image](https://raw.githubusercontent.com/Penthertz/urh-ng/master/data/icons/banner.png)

# URH-NG: Universal Radio Hacker - Next Generation

[![CI](https://github.com/PentHertz/urh-ng/actions/workflows/ci.yml/badge.svg)](https://github.com/PentHertz/urh-ng/actions/workflows/ci.yml)
[![Code style: black](https://img.shields.io/badge/code%20style-black-black)](https://github.com/psf/black)
[![Blackhat Arsenal 2017](https://rawgit.com/toolswatch/badges/master/arsenal/usa/2017.svg)](http://www.toolswatch.org/2017/06/the-black-hat-arsenal-usa-2017-phenomenal-line-up-announced/)
[![Blackhat Arsenal 2018](https://rawgit.com/toolswatch/badges/master/arsenal/europe/2018.svg)](http://www.toolswatch.org/2018/09/black-hat-arsenal-europe-2018-lineup-announced/)

> **Beta** -- URH-NG is currently in beta and under active testing. It will be available in the [RF Swift](https://rfswift.io) image starting with **v0.1.6**.

**URH-NG** is a next-generation fork of [Universal Radio Hacker](https://github.com/jopohl/urh), maintained by [PentHertz](https://penthertz.com). It extends URH with **automatic protocol identification against 327 protocols**, an **automotive RF crypto toolkit with 23 ciphers**, and support for **new SDR hardware** including HydraSDR, Harogic spectrum analyzers, and Signal Hound BB60.

URH-NG is a complete suite for wireless protocol investigation with native support for many common Software Defined Radios. It allows easy demodulation of signals combined with [automatic](https://dl.acm.org/doi/10.1145/3375894.3375896) detection of modulation parameters making it a breeze to identify the bits and bytes that fly over the air.
As data often gets encoded before transmission, URH-NG offers customizable decodings to crack even sophisticated encodings like CC1101 data whitening.
When it comes to protocol reverse-engineering, URH-NG is helpful in two ways. You can either manually assign protocol fields and message types or let URH-NG **automatically infer protocol fields** with a [rule-based intelligence](https://www.usenix.org/conference/woot19/presentation/pohl).
Finally, URH-NG entails a fuzzing component aimed at stateless protocols and a simulation environment for stateful attacks.

---

## What's New in URH-NG

### Auto Protocol Identification (PHZ DB)

A database of **327 protocol signatures** sourced from [rtl_433](https://github.com/merbanan/rtl_433), [Flipper-ARF](https://github.com/D4C1-Labs/Flipper-ARF), and [ProtoPirate](https://github.com/RocketGod-git/ProtoPirate). URH-NG matches captured signals against all 327 protocols using a modulation-aware scoring engine that detects encoding type (PWM, Manchester, NRZ, Miller), preamble patterns (6 types), gap structures (4 types), and field layouts (17 types).

See [SUPPORTED_PROTOCOLS.md](SUPPORTED_PROTOCOLS.md) for the full list.

### Automotive RF Crypto Toolkit (23 Ciphers)

**15 protocols auto-decode** without any user input -- just capture, demodulate, and identify:

| Protocol | Algorithm |
|----------|-----------|
| Ford V0 | XOR + bit interleave + GF(2) CRC |
| KIA V3/V4 | KeeLoq (known master key) |
| KIA V5 | 18-round mixer cipher |
| KIA V6 | AES-128 ECB |
| VAG (VW/Audi/Skoda/Seat) | AUT64 (3 key sets) + TEA |
| Somfy Telis/Keytis | Cascading XOR |
| Came Atomo | LFSR bit-flip cipher |
| Came Twee | 32-bit XOR rainbow table |
| Mazda Siemens | Parity-XOR + deinterleave |
| Phoenix V2 | 16-iter bit-shuffle |
| Security+ v1/v2 | Base-3 ternary encoding |
| Porsche Cayenne | 24-bit rotating register |
| Subaru | 24-bit serial rotation + XOR |
| Mitsubishi V0 | Counter-derived XOR |
| PSA (Peugeot/Citroen) | TEA mode 0x23 XOR |

**8 guided-decode protocols** with built-in key management and brute-force:

| Protocol | What You Provide |
|----------|-----------------|
| KeeLoq (HCS200/300, NICE, StarLine, etc.) | 64-bit manufacturer key (26 built-in keys, brute-force with 2 captures) |
| FAAC SLH | Manufacturer key + seed |
| Nice Flor-S | 32-byte rainbow table |
| Alutech AT-4N | Rainbow table (modified TEA) |
| Scher-Khan Magicar | Auto-detects PRO1 vs PRO2 |
| TEA (generic) | 128-bit key |
| AES-128 (generic) | 128-bit key |
| AUT64 (generic) | Key nibbles + S-box + P-box |

See [CRYPTO_TOOLKIT.md](CRYPTO_TOOLKIT.md) for full details.

### New SDR Hardware Support

| Device | Type | Notes |
|--------|------|-------|
| **HydraSDR** | IQ stream SDR | Multi-device support, sample rate combobox |
| **Harogic** | HTRA spectrum analyzer | Multi-device support via HTRA SDK |
| **Signal Hound BB60** | Spectrum analyzer | Native integration via Signal Hound SDK |

### Enhanced Signal Processing

- **PWM encoding support** -- proper short/long pulse width demodulation
- **Miller encoding support** -- mid-bit transition detection (RFID ISO 14443, EPC Gen2)
- **FrameAnalyzer** -- detects 6 preamble types, 4 gap types, 3 encoding types automatically
- **Modulation-aware scoring** -- protocol matching considers PWM vs NRZ vs Manchester
- **Field coverage scoring** -- penalizes unlabeled trailing data for better protocol fits

### Additional Improvements

- Sample rate combobox for fixed-rate devices
- Multi-device support for HydraSDR and Harogic
- Flipper Zero SubGHz plugin
- CI/CD workflows for multi-arch builds (`.deb` packages)
- Contributing guide for adding protocols, crypto, and decoders ([CONTRIBUTING_DECODERS.md](CONTRIBUTING_DECODERS.md))

---

## Getting Started

- View the [installation instructions](#installation) below
- Download the [original userguide (PDF)](https://github.com/jopohl/urh/releases/download/v2.0.0/userguide.pdf) (URH basics still apply)
- Watch the [demonstration videos (YouTube)](https://www.youtube.com/watch?v=kuubkTDAxwA&index=1&list=PLlKjreY6G-1EKKBs9sucMdk8PwzcFuIPB)
- Check out the [wiki](https://github.com/jopohl/urh/wiki) for device info and SDR setup

### Quick Start: Auto Protocol Identification

1. **Capture or load** a signal in URH-NG
2. **Demodulate** the signal (auto-interpretation handles most parameters)
3. **Analyze -> Auto-identify protocol (PHZ DB)** -- matches against 327 protocols
4. If a crypto cipher is mapped, the result dialog shows **decoded fields** (SN, button, counter)
5. For user-key ciphers: **Analyze -> Crypto Toolkit** opens pre-filled with guidance

## Installation

URH-NG runs on Windows, Linux, and macOS. Python 3.9+ is required.

### Linux (recommended)

#### From source
```bash
git clone https://github.com/PentHertz/urh-ng.git
cd urh-ng
pip install -e .
```

#### Using `.deb` package
Pre-built `.deb` packages are available from [GitHub Releases](https://github.com/PentHertz/urh-ng/releases).

In order to access your SDR as non-root user, install the according udev rules. You can find them [in the wiki](https://github.com/jopohl/urh/wiki/SDR-udev-rules).

### Windows

```bash
pip install urh-ng
```

If you get an error about missing `api-ms-win-crt-runtime-l1-1-0.dll`, run Windows Update or install [KB2999226](https://support.microsoft.com/en-us/help/2999226/update-for-universal-c-runtime-in-windows).

### macOS

```bash
pip install urh-ng
```

### Running from source (all platforms)
```bash
git clone https://github.com/PentHertz/urh-ng.git
cd urh-ng/src/urh
PYTHONPATH=.. ./main.py
```

Note: C++ extensions will be built before first usage.


## Native SDR Backends

Install the `-dev` package for your SDR **before** installing URH-NG for native support:

| SDR | Library | Package |
|-----|---------|---------|
| RTL-SDR | librtlsdr | `librtlsdr-dev` |
| HackRF | libhackrf | `hackrf-dev` |
| BladeRF | libbladerf | `libbladerf-dev` |
| LimeSDR | limesuite | `limesuite-dev` |
| PlutoSDR | libiio | `libiio-dev` |
| USRP | uhd | `libuhd-dev` |
| AirSpy | libairspy | `airspy-dev` |
| SDRPlay | sdrplay | SDRPlay API |
| HydraSDR | hydrasdr | [hydrasdr-host](https://github.com/hydrasdr/hydrasdr-host) |
| Harogic | HTRA SDK | Vendor SDK |
| Signal Hound BB60 | Signal Hound SDK | Vendor SDK |
| GNU Radio | gnuradio | `gnuradio-dev` |

---

## Citing URH

We encourage researchers working with URH to cite the [WOOT'18 paper](https://www.usenix.org/conference/woot18/presentation/pohl):

<details>
<summary><b>BibTeX entry</b></summary>

```bibtex
@inproceedings {220562,
author = {Johannes Pohl and Andreas Noack},
title = {Universal Radio Hacker: A Suite for Analyzing and Attacking Stateful Wireless Protocols},
booktitle = {12th {USENIX} Workshop on Offensive Technologies ({WOOT} 18)},
year = {2018},
address = {Baltimore, MD},
url = {https://www.usenix.org/conference/woot18/presentation/pohl},
publisher = {{USENIX} Association},
}
```

</details>

## Credits

URH was originally created by **Johannes Pohl** ([@jopohl](https://github.com/jopohl)).

URH-NG is maintained by **Sebastien Dudek** at [PentHertz](https://penthertz.com) ([@FlUxIuS](https://github.com/FlUxIuS)).

See [CONTRIBUTORS.md](CONTRIBUTORS.md) for the full list of contributions.

## Articles

### Hacking stuff with URH
* [Hacking Burger Pagers](https://www.rtl-sdr.com/using-a-hackrf-to-reverse-engineer-and-control-restaurant-pagers/)
* [Reverse-engineer and Clone a Remote Control](https://www.rtl-sdr.com/video-tutorial-using-universal-radio-hacker-an-rtl-sdr-and-a-microcontroller-to-clone-433-mhz-remotes/)
* [Reverse-engineering Weather Station RF Signals](https://www.rtl-sdr.com/tag/universal-radio-hacker/)
* [Reverse-engineering Wireless Blinds](https://www.rtl-sdr.com/reverse-engineering-wireless-blinds-with-an-rtl-sdr-and-controlling-them-with-amazon-alexa/)
* [Attacking Logitech Wireless Presenters (German Article)](https://www.heise.de/security/meldung/Wireless-Presenter-von-Logitech-und-Inateck-anfaellig-fuer-Angriffe-ueber-Funk-4439795.html)
* [Attacking Wireless Keyboards](https://threatpost.com/fujitsu-wireless-keyboard-unpatched-flaws/149477/)
* [Reverse-engineering a 433MHz Remote-controlled Power Socket for use with Arduino](http://www.ignorantofthings.com/2018/11/reverse-engineering-433mhz-remote.html)

### General presentations and tutorials on URH
* [Hackaday Article](https://hackaday.com/2017/02/23/universal-radio-hacker/)
* [RTL-SDR.com Article](https://www.rtl-sdr.com/reverse-engineering-signals-universal-radio-hacker-software/)
* [Short Tutorial on URH with LimeSDR Mini](https://www.crowdsupply.com/lime-micro/limesdr-mini/updates/investigating-wireless-protocols-with-universal-radio-hacker)
* [Brute-forcing a RF Device: a Step-by-step Guide](https://pandwarf.com/news/brute-forcing-a-new-device-a-step-by-step-guide/)
* [Hacking wireless sockets like a NOOB](https://olof-astrand.medium.com/hacking-wireless-sockets-like-a-noob-b57d4b4812d5)

## External Decodings
See [wiki](https://github.com/jopohl/urh/wiki/External-decodings) for community-provided decodings.

## Screenshots

### Get the data out of raw signals
![Interpretation phase](http://i.imgur.com/Wy17Zv3.png)

### Keep an overview even on complex protocols
![Analysis phase](http://i.imgur.com/ubAL3pE.png)

### Record and send signals
![Record](http://i.imgur.com/BfQpg23.png)

## License

GNU General Public License (GPL)
