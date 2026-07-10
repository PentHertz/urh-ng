# Changelog

All notable changes to URH-NG are documented here.

## [0.0.2] - 2026-07-10

### Build system
- Modernized packaging with a `pyproject.toml` (PEP 517) build backend, fixing
  `pip install -e .` which previously failed on the old `from src.urh...`
  imports. `setup.py` is now trimmed to just the Cython/C++ extension build and
  loads its helpers by file path so it works under build isolation.
- Kept `numpy<3.0` (URH-NG runs fine on NumPy 2.x) and kept `cython` /
  `setuptools` as runtime dependencies, since URH compiles SDR device backends
  on the fly at runtime.
- Added a `uv.lock` for reproducible development environments and modernized
  `.gitignore`.

### Fixed
- Fixed wrong int8 magnitude/demodulation on ARM/AArch64 (e.g. Raspberry Pi):
  the `iq` fused type now uses `signed char` instead of a bare `char`, whose
  signedness is platform-dependent (upstream jopohl/urh#1160). Added a
  regression test.

### Chores
- Bumped version to `0.0.2`.
- Applied `black` formatting so CI stays green.

### Credits
Thanks to the contributors whose pull requests this release builds on:

- **[@wyattearp](https://github.com/wyattearp)** — `pyproject.toml` build
  modernization and updated `.gitignore` ([#1](https://github.com/PentHertz/urh-ng/pull/1)).
- **[@pd0wm](https://github.com/pd0wm)** — `uv` integration and the isolation-safe
  build import approach ([#2](https://github.com/PentHertz/urh-ng/pull/2)).
- **[@munzzyy](https://github.com/munzzyy)** — the ARM `signed char` int8 fix and
  regression test ([#3](https://github.com/PentHertz/urh-ng/pull/3)).
