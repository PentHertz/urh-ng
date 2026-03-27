# Contributors

## Original Author

- **Johannes Pohl** -- Creator of Universal Radio Hacker (URH)
  - GitHub: [@jopohl](https://github.com/jopohl)
  - Original project: https://github.com/jopohl/urh

## URH 3.0.0-phz (PentHertz Fork)

- **Sebastien Dudek** -- PentHertz
  - GitHub: [@FlUxIuS](https://github.com/FlUxIuS)
  - Organization: [PentHertz](https://github.com/PentHertz)
  - Website: https://penthertz.com

  Contributions:
  - Harogic spectrum analyzer integration (HTRA SDK)
  - HydraSDR software-defined radio integration
  - Signal Hound BB60 integration
  - Auto protocol identification engine (PHZ DB -- 327 protocols)
  - PWM / Miller encoding support
  - KeeLoq decoder/encoder with key brute-force (26 manufacturer keys)
  - Automotive RF crypto toolkit (23 ciphers, 41 functions):
    - Ford V0 full protocol (XOR + interleave + GF(2) CRC)
    - VAG full protocol (AUT64 with 3 key sets + TEA)
    - Porsche Cayenne rotating register cipher
    - Subaru rotating register XOR
    - KIA V3/V4 KeeLoq (known master key)
    - KIA V5 mixer (18-round substitution)
    - KIA V6 AES-128 (hardcoded key derivation)
    - Mitsubishi V0 counter-derived XOR
    - Mazda Siemens parity-XOR + deinterleave
    - Somfy Telis/Keytis cascading XOR
    - Came Atomo LFSR cipher
    - Came Twee rainbow table XOR
    - Nice Flor-S rainbow table decrypt
    - Phoenix V2 bit-shuffle cipher
    - Scher-Khan Pi-derived XOR
    - Security+ v1/v2 ternary decode
    - PSA TEA brute-force modes
    - FAAC SLH KeeLoq learning
    - Alutech AT-4N modified TEA
    - TEA / AES-128 / AUT64 generic ciphers
  - FrameAnalyzer: 6 preamble types, 4 gap types, 3 encoding types
  - Auto-decode: 15 zero-key/known-key protocols decoded automatically
  - Modulation-aware scoring (PWM vs NRZ vs Manchester)
  - Field coverage scoring (penalizes unlabeled trailing data)
  - Flipper-ARF and ProtoPirate protocol database integration
  - Sample rate combobox for fixed-rate devices
  - Multi-device support for HydraSDR and Harogic
  - CI/CD workflows for multi-arch builds

## Data Sources

- **[rtl_433](https://github.com/merbanan/rtl_433)** -- 293 protocol signatures for sensors, weather stations, TPMS, meters
- **[Flipper-ARF](https://github.com/D4C1-Labs/Flipper-ARF)** -- 30 automotive RF protocols (car keys, gates, alarms)
- **[ProtoPirate](https://github.com/RocketGod-git/ProtoPirate)** -- 4 additional automotive protocols
- **[HydraSDR](https://github.com/hydrasdr/hydrasdr-host)** -- HydraSDR host library
