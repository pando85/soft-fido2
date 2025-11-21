# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [v0.2.0](https://github.com/pando85/soft-fido2/tree/v0.2.0) - 2025-11-21

### Added

- Add `constant_sign_count` config param to Authenticator ([40fe112](https://github.com/pando85/soft-fido2/commit/40fe112ddeee250af65a2164746e4a87fdad3c3e))

### Documentation

- Fix readme header and badges ([3c3c680](https://github.com/pando85/soft-fido2/commit/3c3c6802a8cc71bea3de73bab55f5e5e453805b2))

## [v0.1.0](https://github.com/pando85/soft-fido2/tree/v0.1.0) - 2025-11-20

### Added

- Expose enumarate_rps and credential_count callbacks ([9d59f4a](https://github.com/pando85/soft-fido2/commit/9d59f4ad7203afe8ce6ef73ce6db6491a6eaf4e3))
- Expose custom CTAP command handler API ([d151290](https://github.com/pando85/soft-fido2/commit/d151290ab2148637be5b50979edee72eba3b8c85))
- Implement embedded system optimizations (Phases 1-4) ([de2983f](https://github.com/pando85/soft-fido2/commit/de2983ff61f3d6e7068276cc90a4b5a167bdd9bd))
- Add embedded example and documentation (Phase 5) ([91c064d](https://github.com/pando85/soft-fido2/commit/91c064d0978743e75db0214eed7214a1736bd9a4))
- Complete full no_std support for soft-fido2-ctap ([ea35a86](https://github.com/pando85/soft-fido2/commit/ea35a865db94dd8688b8a4b04fab19e965226b31))

### Fixed

- Make clippy happy ([bfdb000](https://github.com/pando85/soft-fido2/commit/bfdb000d70db60fb575a65f47669ad98be8deb57))

### Refactor

- Clean repo, docs and reorder imports ([d09e57b](https://github.com/pando85/soft-fido2/commit/d09e57ba56f0a7839b5c8870930d8524497221eb))
- Remove debug traces in examples ([16f3631](https://github.com/pando85/soft-fido2/commit/16f36316e75ebbda833f859e86a014b14afe6c14))

### Testing

- Refactor e2e clean spaghetti code and remove repeated tests ([e248141](https://github.com/pando85/soft-fido2/commit/e248141a0d287b5171165ba6853fec6381cd3612))

## [v0.0.0](https://github.com/pando85/soft-fido2/tree/v0.0.0) - 2025-11-19

Initial release
